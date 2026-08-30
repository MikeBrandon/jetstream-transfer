//! HTTP surface.
//!
//! Every route except `/j/{token}` requires a valid session cookie. That is
//! enforced in one place — [`guest`] — rather than per-handler, because a
//! forgotten check on a single route would expose the upload endpoint to
//! anything that can reach the port.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use jetstream_core::chunk::CHUNK_SIZE;
use serde::{Deserialize, Serialize};

use crate::session::{COOKIE, GuestInfo, label_from_user_agent};
use crate::upload::{UploadError, UploadRequest};
use crate::{AppState, UploadOffer};

/// The page, compiled in. One self-contained file — no bundler, no framework,
/// no second build pipeline for what is a handful of screens.
const PAGE: &str = include_str!("../assets/index.html");

/// Room for one chunk plus framing overhead.
const BODY_LIMIT: usize = CHUNK_SIZE as usize + 64 * 1024;

/// Longest text snippet a browser may send.
const MAX_TEXT: usize = 64 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/j/{token}", get(redeem))
        .route("/", get(page))
        .route("/api/session", get(session_info))
        .route("/api/upload", post(begin_upload))
        .route("/api/upload/{transfer}/status", get(upload_status))
        .route("/api/upload/{transfer}/finish", post(finish_upload))
        .route("/api/upload/{transfer}/{entry}/{chunk}", put(put_chunk))
        .route("/api/download/{id}", get(download))
        .route("/api/text", post(post_text).get(get_text))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(state)
}

/// Exchange a pairing token for a session cookie.
///
/// The token is in the path, which means it lands in server logs — acceptable
/// because it is single-use and spent by the time anything could read one. The
/// long-lived credential is the cookie, which never appears in a URL.
async fn redeem(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let guest = GuestInfo {
        label: label_from_user_agent(user_agent(&headers)),
        address: String::new(),
    };

    match state.sessions.redeem(&token, guest) {
        Some(id) => {
            tracing::info!("a browser paired with the receiver");

            // `SameSite=Strict` so another site cannot make a browser act on
            // this session. Not `Secure`: the connection is plain HTTP, and a
            // Secure cookie would simply never be sent.
            let cookie = format!(
                "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
                crate::SESSION_LIFETIME.as_secs()
            );

            (
                StatusCode::SEE_OTHER,
                [(header::SET_COOKIE, cookie), (header::LOCATION, "/".into())],
            )
                .into_response()
        }
        None => (
            StatusCode::FORBIDDEN,
            Html(expired_page()),
        )
            .into_response(),
    }
}

async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if guest(&state, &headers).is_none() {
        return (StatusCode::FORBIDDEN, Html(expired_page())).into_response();
    }
    Html(PAGE).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInfo {
    device_name: String,
    guest_label: String,
    chunk_size: u64,
    files: Vec<crate::OfferedFile>,
    shared_text: Option<String>,
}

async fn session_info(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(guest) = guest(&state, &headers) else {
        return unauthorised();
    };

    Json(SessionInfo {
        device_name: state.handler.device_name(),
        guest_label: guest.label,
        chunk_size: CHUNK_SIZE,
        files: state.handler.offered_files(),
        shared_text: state.handler.text_to_share(),
    })
    .into_response()
}

/// Declare an upload and get back the plan — which, on a resume, names only the
/// chunks still missing.
async fn begin_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<UploadRequest>,
) -> Response {
    let Some(guest) = guest(&state, &headers) else {
        return unauthorised();
    };

    let offer = UploadOffer {
        file_count: request.files.len() as u64,
        total_bytes: request.files.iter().map(|f| f.size).sum(),
        top_level: top_level_names(&request),
    };

    // The prompt on the desktop. A browser guest is asked about every time:
    // there is no key to pin, so there is nothing that could be remembered.
    let Some(grant) = state.handler.accept_upload(guest.clone(), offer).await else {
        return (StatusCode::FORBIDDEN, "The other device declined.").into_response();
    };

    match state
        .uploads
        .begin(&request, grant.destination, grant.conflict, grant.progress)
    {
        Ok(plan) => Json(plan).into_response(),
        Err(e) => upload_error(e),
    }
}

async fn upload_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(transfer): Path<String>,
) -> Response {
    if guest(&state, &headers).is_none() {
        return unauthorised();
    }

    match state.uploads.status(&transfer).await {
        Ok(plan) => Json(plan).into_response(),
        Err(e) => upload_error(e),
    }
}

#[derive(Deserialize)]
struct ChunkQuery {
    /// CRC-32 of the body, hex. See [`crate::crc32`] for what this does and
    /// does not guarantee.
    crc: String,
}

async fn put_chunk(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((transfer, entry, chunk)): Path<(String, u32, u32)>,
    Query(query): Query<ChunkQuery>,
    body: axum::body::Bytes,
) -> Response {
    if guest(&state, &headers).is_none() {
        return unauthorised();
    }

    let Ok(expected) = u32::from_str_radix(&query.crc, 16) else {
        return (StatusCode::BAD_REQUEST, "malformed checksum").into_response();
    };

    match state
        .uploads
        .write_chunk(&transfer, entry, chunk, expected, &body)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => upload_error(e),
    }
}

async fn finish_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(transfer): Path<String>,
) -> Response {
    let Some(guest) = guest(&state, &headers) else {
        return unauthorised();
    };

    match state.uploads.finish(&transfer).await {
        Ok(files) => {
            state.handler.upload_finished(guest, files.clone());
            Json(files).into_response()
        }
        Err(e) => upload_error(e),
    }
}

/// Serve an offered file, honouring `Range`.
///
/// Ranges are what make downloads resumable: the browser's own download manager
/// retries with `Range: bytes=N-` after an interruption, so this path needs no
/// client-side logic at all.
async fn download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    if guest(&state, &headers).is_none() {
        return unauthorised();
    }

    // Look the id up against what the app is actually offering. A browser never
    // names a path, so it cannot ask for a file that was not offered.
    let Some(file) = state
        .handler
        .offered_files()
        .into_iter()
        .find(|f| f.id == id)
    else {
        return (StatusCode::NOT_FOUND, "no longer being shared").into_response();
    };

    let service = tower_http::services::ServeFile::new(&file.path);
    let disposition = format!(
        "attachment; filename*=UTF-8''{}",
        urlencode(&file.name)
    );

    match tower::ServiceExt::oneshot(service, request).await {
        Ok(mut response) => {
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                disposition.parse().expect("ascii header"),
            );
            response.into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not serve an offered file");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not read that file").into_response()
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TextBody {
    text: String,
}

async fn post_text(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TextBody>,
) -> Response {
    let Some(guest) = guest(&state, &headers) else {
        return unauthorised();
    };

    if body.text.len() > MAX_TEXT {
        return (StatusCode::PAYLOAD_TOO_LARGE, "that text is too long").into_response();
    }

    state.handler.receive_text(guest, body.text);
    StatusCode::NO_CONTENT.into_response()
}

async fn get_text(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if guest(&state, &headers).is_none() {
        return unauthorised();
    }

    match state.handler.text_to_share() {
        Some(text) => Json(TextBody { text }).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// Resolve the session cookie. **The only authorisation check in this module.**
fn guest(state: &AppState, headers: &HeaderMap) -> Option<GuestInfo> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;

    let id = cookies
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value)?;

    state.sessions.lookup(id)
}

fn unauthorised() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        "This link has expired. Scan the code again from Jetstream.",
    )
        .into_response()
}

fn upload_error(error: UploadError) -> Response {
    let status = match &error {
        UploadError::Unknown => StatusCode::NOT_FOUND,
        UploadError::BadChecksum => StatusCode::UNPROCESSABLE_ENTITY,
        UploadError::Invalid(_) => StatusCode::BAD_REQUEST,
    };
    (status, error.to_string()).into_response()
}

fn user_agent(headers: &HeaderMap) -> &str {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

/// Distinct first path segments, for the accept prompt.
fn top_level_names(request: &UploadRequest) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();

    for file in &request.files {
        let top = file
            .path
            .split(['/', '\\'])
            .find(|part| !part.is_empty())
            .unwrap_or(&file.path);
        seen.insert(jetstream_core::proto::sanitize_name(top));

        if seen.len() >= 12 {
            break;
        }
    }
    seen.into_iter().collect()
}

/// Percent-encode for a `filename*` parameter.
fn urlencode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn expired_page() -> String {
    // Deliberately not the app page: a stranger who found the port should learn
    // nothing except that they need a code.
    r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jetstream</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1417;color:#e8eef0;
font-family:system-ui,sans-serif;text-align:center;padding:24px}p{color:#93a5ad;max-width:30ch;line-height:1.6}</style>
<div><h1 style="letter-spacing:.06em;font-size:19px">JETSTREAM</h1>
<p>This link has expired or has already been used. Open Jetstream on the other device and scan the code again.</p></div>"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(paths: &[&str]) -> UploadRequest {
        UploadRequest {
            files: paths
                .iter()
                .map(|p| crate::upload::UploadFile {
                    path: (*p).to_string(),
                    size: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn top_level_names_are_deduplicated() {
        let names = top_level_names(&request_with(&[
            "photos/a.jpg",
            "photos/b.jpg",
            "docs/c.pdf",
            "readme.txt",
        ]));

        assert_eq!(names, vec!["docs", "photos", "readme.txt"]);
    }

    #[test]
    fn a_hostile_top_level_name_is_defanged_before_the_prompt() {
        let names = top_level_names(&request_with(&["\u{202E}gnp.exe/inner.txt"]));
        assert!(!names[0].contains('\u{202E}'));
    }

    #[test]
    fn filenames_are_encoded_safely_for_the_header() {
        assert_eq!(urlencode("report.pdf"), "report.pdf");
        assert_eq!(urlencode("my file.txt"), "my%20file.txt");
        assert_eq!(urlencode("café.txt"), "caf%C3%A9.txt");
        // A header injection attempt must not survive.
        assert!(!urlencode("a\r\nX-Evil: 1").contains('\r'));
    }

    #[test]
    fn the_session_cookie_is_parsed_out_of_a_realistic_header() {
        let state = AppState {
            handler: Arc::new(TestHandler),
            sessions: Arc::new(crate::session::Sessions::new()),
            uploads: Arc::new(crate::upload::Uploads::new()),
        };

        let code = state.sessions.issue_code("http://x");
        let id = state
            .sessions
            .redeem(
                &code.token,
                GuestInfo {
                    label: "iPhone".into(),
                    address: String::new(),
                },
            )
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("other=1; {COOKIE}={id}; another=2").parse().unwrap(),
        );
        assert!(guest(&state, &headers).is_some());

        // A wrong or absent cookie must not authorise.
        let mut wrong = HeaderMap::new();
        wrong.insert(header::COOKIE, format!("{COOKIE}=deadbeef").parse().unwrap());
        assert!(guest(&state, &wrong).is_none());
        assert!(guest(&state, &HeaderMap::new()).is_none());
    }

    struct TestHandler;

    impl crate::WebHandler for TestHandler {
        fn device_name(&self) -> String {
            "Test".into()
        }
        fn accept_upload(
            &self,
            _guest: GuestInfo,
            _offer: UploadOffer,
        ) -> std::pin::Pin<Box<dyn Future<Output = Option<crate::UploadGrant>> + Send>> {
            Box::pin(async { None })
        }
        fn upload_finished(&self, _guest: GuestInfo, _files: Vec<String>) {}
        fn offered_files(&self) -> Vec<crate::OfferedFile> {
            Vec::new()
        }
        fn receive_text(&self, _guest: GuestInfo, _text: String) {}
        fn text_to_share(&self) -> Option<String> {
            None
        }
    }
}
