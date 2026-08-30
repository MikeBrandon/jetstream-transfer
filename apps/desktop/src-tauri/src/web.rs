//! Hosting the browser receiver from the desktop app.
//!
//! Bridges [`jetstream_web`] to the same prompt, trust rules, and transfer list
//! the native path uses, so a phone uploading a photo shows up in exactly the
//! same place as a paired laptop sending a folder.
//!
//! The one deliberate asymmetry: **a browser guest is prompted every time.** A
//! paired device can be set to auto-accept because it proved possession of a
//! key; a browser holds no key, so "remember this device" would be remembering
//! a cookie, and a cookie is not an identity.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use jetstream_core::transfer::Progress;
use jetstream_web::{GuestInfo, OfferedFile, UploadGrant, UploadOffer, WebHandler, WebServer};
use tauri::{AppHandle, Emitter};

use crate::state::AppState;
use crate::views::{Direction, OfferView, TransferState};

/// How long a browser upload waits for someone to answer the prompt.
const OFFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

pub struct DesktopWebHandler {
    app: AppHandle,
    state: Arc<AppState>,
}

impl DesktopWebHandler {
    pub fn new(app: AppHandle, state: Arc<AppState>) -> Self {
        Self { app, state }
    }
}

impl WebHandler for DesktopWebHandler {
    fn device_name(&self) -> String {
        self.state
            .settings
            .lock()
            .expect("settings poisoned")
            .device_name
            .clone()
    }

    fn accept_upload(
        &self,
        guest: GuestInfo,
        offer: UploadOffer,
    ) -> Pin<Box<dyn Future<Output = Option<UploadGrant>> + Send>> {
        let app = self.app.clone();
        let state = Arc::clone(&self.state);

        Box::pin(async move {
            let (destination, conflict) = {
                let settings = state.settings.lock().expect("settings poisoned");
                (settings.download_dir.clone(), settings.on_conflict)
            };

            let id = state.next_id();
            let progress = Arc::new(Progress::default());

            let summary = format!(
                "{} {}, {}",
                offer.file_count,
                if offer.file_count == 1 { "file" } else { "files" },
                jetstream_core::transfer::human_bytes(offer.total_bytes),
            );

            // Shown in the same transfer list as everything else, so a user does
            // not have to know which mechanism carried a file.
            state.add_transfer(
                id,
                Direction::Receiving,
                format!("{} (browser)", guest.label),
                // A browser has no device identity. A zero id keeps the record
                // shaped like every other transfer without implying a key.
                jetstream_core::DeviceId::from_bytes([0; 32]),
                summary.clone(),
                Arc::clone(&progress),
            );

            let view = OfferView {
                id,
                peer_name: format!("{} (browser)", guest.label),
                peer_device_id: String::new(),
                fingerprint: String::new(),
                fingerprint_words: Vec::new(),
                // Always true: there is no key to have seen before, and the
                // prompt should say so rather than imply a prior relationship.
                first_contact: true,
                summary,
                file_count: offer.file_count,
                total_bytes: offer.total_bytes,
                top_level: offer.top_level,
                more_top_level: false,
            };

            let answer = state.register_offer(id);
            let _ = app.emit("offer", &view);

            let accepted = match tokio::time::timeout(OFFER_TIMEOUT, answer).await {
                Ok(Ok(answer)) => answer.accept,
                // Nobody at the machine. Declining is the safe default.
                _ => {
                    state.forget_offer(id);
                    let _ = app.emit("offer-expired", id);
                    false
                }
            };

            if !accepted {
                state.set_state(id, TransferState::Rejected, Some("declined".into()));
                let _ = app.emit("transfers", state.transfer_views());
                return None;
            }

            state.set_state(id, TransferState::Active, None);
            state.remember_web_transfer(guest.label.clone(), id);
            let _ = app.emit("transfers", state.transfer_views());

            Some(UploadGrant {
                destination,
                conflict,
                progress,
            })
        })
    }

    fn upload_finished(&self, guest: GuestInfo, files: Vec<String>) {
        if let Some(id) = self.state.take_web_transfer(&guest.label) {
            self.state.set_state(
                id,
                TransferState::Done,
                Some(match files.len() {
                    0 => "nothing was saved".to_string(),
                    1 => format!("saved {}", files[0]),
                    n => format!("{n} item(s) saved"),
                }),
            );
        }
        let _ = self.app.emit("transfers", self.state.transfer_views());
    }

    fn offered_files(&self) -> Vec<OfferedFile> {
        self.state
            .web_offers()
            .into_iter()
            .filter_map(|path| {
                let metadata = std::fs::metadata(&path).ok()?;
                if !metadata.is_file() {
                    return None;
                }

                Some(OfferedFile {
                    // An opaque id derived from the path, so a browser can ask
                    // for a file without ever naming one. It cannot request
                    // something that was not offered.
                    id: hex::encode(&blake3::hash(path.to_string_lossy().as_bytes()).as_bytes()[..8]),
                    name: path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "file".into()),
                    size: metadata.len(),
                    path,
                })
            })
            .collect()
    }

    fn receive_text(&self, guest: GuestInfo, text: String) {
        let _ = self.app.emit(
            "web-text",
            serde_json::json!({
                "from": format!("{} (browser)", guest.label),
                "text": text,
            }),
        );
    }

    fn text_to_share(&self) -> Option<String> {
        self.state.web_shared_text()
    }
}

/// Start the browser receiver, returning the running server.
pub async fn start(
    app: AppHandle,
    state: Arc<AppState>,
) -> Result<WebServer, jetstream_web::WebError> {
    let handler = Arc::new(DesktopWebHandler::new(app, state));
    WebServer::start(handler).await
}

/// Paths the user is offering for browsers to download.
pub fn offered_paths(paths: Vec<String>) -> Vec<PathBuf> {
    paths.into_iter().map(PathBuf::from).collect()
}
