//! Tray icon and window lifecycle.
//!
//! A transfer app has to be *running* to receive anything, which makes the tray
//! more than decoration: it is the difference between "Jetstream works" and
//! "Jetstream works when I remember to open it". Dukto had the same shape and it
//! is the right one.
//!
//! Two decisions here that are easy to get wrong:
//!
//! - **Closing the window hides it; it does not quit.** Anything else means a
//!   user closes the window, walks away, and silently stops being reachable.
//!   Quitting is available from the tray menu, deliberately explicit.
//! - **The first close says so.** Silently continuing to run after a user
//!   pressed the close button is the behaviour people rightly find creepy, so
//!   the first time it happens we say what we did and how to actually quit.

use std::sync::Arc;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WebviewWindow};

use crate::state::AppState;

/// Build the tray icon and its menu.
pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Open Jetstream", true, None::<&str>)?;
    let send = MenuItem::with_id(app, "send", "Send files…", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Jetstream", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &send, &separator, &quit])?;

    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().cloned().ok_or_else(|| {
            tauri::Error::Anyhow(anyhow::anyhow!("the bundled window icon is missing"))
        })?)
        .tooltip("Jetstream")
        .menu(&menu)
        // Left click should open the window, not pop the menu — the menu is what
        // right click is for, and on Windows that is what users expect.
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "show" => reveal(app),
            "send" => {
                reveal(app);
                // The window owns the file picker, so ask it to open one.
                let _ = app.emit("tray-send", ());
            }
            "quit" => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                reveal(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

/// Show and focus the main window, un-minimising if needed.
pub fn reveal(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Quit for real, letting in-flight work close cleanly.
fn quit_app(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Stop the browser receiver if it is running, so the port is released
        // and browser sessions end rather than dangling.
        if let Some(state) = app.try_state::<Arc<AppState>>()
            && let Some(server) = state.web_server.lock().await.take()
        {
            server.stop().await;
        }
        app.exit(0);
    });
}

/// Intercept the window's close button and hide instead.
///
/// Returns `true` if this was the first time, so the caller can explain itself.
pub fn hide_instead_of_closing(window: &WebviewWindow, state: &AppState) -> bool {
    let _ = window.hide();
    state.note_first_hide()
}
