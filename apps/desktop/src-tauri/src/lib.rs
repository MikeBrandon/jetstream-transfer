//! Jetstream desktop application.
//!
//! Thin by design. Everything of substance lives in `jetstream-core` and
//! `jetstream-discovery`; this crate turns those into a window. The rule is that
//! nothing here should ever be the only place a behaviour is implemented,
//! because the CLI has to be able to reproduce any bug without a UI attached.

mod commands;
mod devices;
mod folders;
mod history;
mod manual;
mod sendto;
mod state;
mod titlebar;
mod tray;
mod views;
mod web;

use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager};

use state::AppState;

/// How often the UI is refreshed while something is happening.
///
/// ~8 fps: fast enough that a progress bar looks continuous, slow enough that
/// serialising the transfer list is not itself a cost.
const TICK: Duration = Duration::from_millis(120);

/// How often the peer list is pushed when idle.
const IDLE_TICK: Duration = Duration::from_millis(800);

/// Add the firewall rule and return a process exit code.
///
/// Runs in the elevated helper instance, with no window and no Tauri runtime.
/// The failure detail is deliberately not surfaced from here — there is nowhere
/// to show it — so the parent re-checks the rule status instead of trusting an
/// exit code it cannot explain.
pub fn install_firewall_rule() -> i32 {
    use jetstream_discovery::firewall;

    match firewall::current_exe().and_then(|exe| firewall::install(&exe)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("could not add the firewall rule: {e}");
            1
        }
    }
}

/// Move unidentified networks to Private and return a process exit code.
///
/// Runs in the elevated helper instance. Same shape as
/// [`install_firewall_rule`]: the parent re-checks the real status afterwards
/// rather than trusting an exit code it cannot explain.
pub fn set_network_private() -> i32 {
    match jetstream_discovery::netprofile::set_private() {
        Ok(changed) => {
            eprintln!("moved {changed} network(s) to Private");
            0
        }
        Err(e) => {
            eprintln!("could not change the network profile: {e}");
            1
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "jetstream_core=info,jetstream_discovery=info,jetstream_lib=info".into()),
        )
        .with_target(false)
        .init();

    tauri::Builder::default()
        // Single instance first, before any window exists. A second launch —
        // from the Start menu, or from Send To — must reach the copy that is
        // already running and holding the port, not start a rival.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            tray::reveal(app);

            // A Send To launch arrives as arguments on the second instance.
            let paths = send_to_paths(&argv);
            if !paths.is_empty() {
                let _ = app.emit("external-send", paths);
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            // Started minimised: an app launched by the OS at login should be
            // ready to receive, not competing for the user's attention.
            Some(vec!["--hidden"]),
        ))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // `JETSTREAM_DATA_DIR` lets two independent devices run on one
            // machine — essential for testing. A `Jetstream Data` folder beside
            // the executable makes the copy portable. Otherwise, per-user state.
            let location = jetstream_core::identity::store::resolve_location()?;
            if location.is_portable() {
                tracing::info!(dir = %location.dir.display(), "running portable");
            }

            // Inside Tauri's runtime, not merely alongside it. Binding the QUIC
            // endpoint registers a UDP socket with the tokio reactor, and
            // discovery spawns tasks — neither works from the bare setup hook,
            // which runs before any runtime context is entered.
            let state = tauri::async_runtime::block_on(async { AppState::new(location) })?;

            let id = state.identity.device_id();
            tracing::info!(
                device = %id.short(),
                fingerprint = %id.fingerprint(),
                "Jetstream starting"
            );

            app.manage(Arc::clone(&state));

            // Stop the OS accent colour painting a bright band above our own
            // header. Follows the system theme, as the stylesheet does.
            if let Some(window) = app.get_webview_window("main") {
                let dark = !matches!(window.theme(), Ok(tauri::Theme::Light));
                titlebar::apply(&window, dark);
            }

            tray::install(app.handle())?;

            // Closing the window hides it. A transfer app that stops running
            // stops being reachable, and a user pressing the close button
            // means "get out of my way", not "make me unreachable".
            if let Some(window) = app.get_webview_window("main") {
                let handle = app.handle().clone();
                let state_for_close = Arc::clone(&state);

                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();

                        if let Some(window) = handle.get_webview_window("main") {
                            // Explained once, so it is never a silent surprise.
                            if tray::hide_instead_of_closing(&window, &state_for_close) {
                                let _ = handle.emit("hidden-to-tray", ());
                            }
                        }
                    }
                });

                // The window is configured invisible so this decides. Hiding it
                // here instead would not stick — Tauri shows the window after
                // setup returns — and starting invisible also avoids a flash of
                // window when the OS launches us at login.
                let quiet = std::env::args().any(|arg| arg == "--hidden");
                if !quiet {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }

            // Retry interrupted sends when their peer comes back.
            {
                let handle = app.handle().clone();
                let state = Arc::clone(&state);
                tauri::async_runtime::spawn(commands::watch_for_retries(handle, state));
            }

            // Send changes in watched folders.
            {
                let handle = app.handle().clone();
                let state = Arc::clone(&state);
                tauri::async_runtime::spawn(commands::watch_folders(handle, state));
            }

            // Keep devices that discovery cannot see — added by address, or
            // owed a resume across a VPN — listed while they answer.
            {
                let state = Arc::clone(&state);
                tauri::async_runtime::spawn(commands::keep_reachable(state));
            }

            // Accept inbound sessions for the life of the app.
            {
                let handle = app.handle().clone();
                let state = Arc::clone(&state);
                tauri::async_runtime::spawn(commands::serve_incoming(handle, state));
            }

            // Push peer and transfer updates. Polling rather than wiring change
            // notifications through every layer: the data is tiny, and a single
            // predictable tick is far easier to reason about than a web of
            // callbacks that must all remember to fire.
            {
                let handle = app.handle().clone();
                let state = Arc::clone(&state);
                tauri::async_runtime::spawn(async move {
                    let mut last_peers = String::new();
                    let mut last_status = String::new();
                    let mut last_states = Vec::new();

                    loop {
                        let transfers = state.transfer_views();
                        let busy = transfers.iter().any(|t| !t.state.is_finished());

                        // Also whenever a row changes state by itself — a browser
                        // upload going quiet stops being busy, and would otherwise
                        // never reach the window.
                        let states: Vec<_> = transfers.iter().map(|t| (t.id, t.state)).collect();
                        if busy || states != last_states {
                            let _ = handle.emit("transfers", &transfers);
                            last_states = states;
                        }

                        let status = tray::status_text(&transfers);
                        if status != last_status {
                            tray::set_status(&handle, &status);
                            last_status = status;
                        }

                        // Peers change rarely, so only emit when they actually
                        // do — otherwise every tick would re-render the grid.
                        let peers = commands::list_peers(state_ref(&handle));
                        if let Ok(encoded) = serde_json::to_string(&peers)
                            && encoded != last_peers
                        {
                            last_peers = encoded;
                            let _ = handle.emit("peers", &peers);
                        }

                        tokio::time::sleep(if busy { TICK } else { IDLE_TICK }).await;
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_self,
            commands::list_peers,
            commands::list_trusted,
            commands::set_trust,
            commands::forget_device,
            commands::list_transfers,
            commands::cancel_transfer,
            commands::pause_transfer,
            commands::reveal_transfer,
            commands::set_transfer_limit,
            commands::clear_finished,
            commands::get_settings,
            commands::save_settings,
            commands::run_diagnostics,
            commands::firewall_status,
            commands::allow_through_firewall,
            commands::network_profile_status,
            commands::make_network_private,
            commands::respond_to_offer,
            commands::send_to_peer,
            commands::add_device_by_address,
            commands::set_device_folder,
            commands::wake_device,
            commands::list_watched_folders,
            commands::add_watched_folder,
            commands::remove_watched_folder,
            commands::set_watched_folder_enabled,
            commands::sync_folder_now,
            commands::list_manual_devices,
            commands::forget_manual_device,
            commands::start_web,
            commands::stop_web,
            commands::web_status,
            commands::set_web_shared,
            commands::list_history,
            commands::forget_history,
            commands::clear_history,
            commands::retry_transfer,
            commands::send_to_status,
            commands::set_send_to,
            commands::autostart_status,
            commands::set_autostart,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Jetstream");
}

/// Extract file paths from a second instance's command line.
///
/// Windows' Send To passes the selected paths as bare arguments. Flags are
/// skipped, and each path must actually exist — a stray argument must never be
/// treated as something to send.
fn send_to_paths(argv: &[String]) -> Vec<String> {
    argv.iter()
        .skip(1)
        .filter(|arg| !arg.starts_with('-'))
        .filter(|arg| std::path::Path::new(arg).exists())
        .cloned()
        .collect()
}

/// Borrow the managed state as a command would see it.
fn state_ref(handle: &tauri::AppHandle) -> tauri::State<'_, Arc<AppState>> {
    handle.state::<Arc<AppState>>()
}
