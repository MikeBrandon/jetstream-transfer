//! Making the Windows title bar match the app instead of fighting it.
//!
//! Windows 11 paints the active window's title bar in the user's accent colour
//! when "Show accent colour on title bars" is on. For an app with its own dark
//! chrome that produces a bright band across the top in whatever colour the
//! user happens to like — magenta, lime, anything — directly above our own
//! header. It reads as an unfinished app rather than a personalised one.
//!
//! The alternative to this is hiding the decorations entirely and drawing our
//! own title bar, which means reimplementing dragging, snapping, the system
//! menu, and the window buttons — a lot of surface to get subtly wrong for the
//! sake of a strip of colour. Telling DWM which colours to use is three calls.
//!
//! Everything here is best-effort and silent on failure. A title bar that stays
//! the wrong colour is a blemish; a startup that fails because of one is not
//! acceptable.

/// Match the title bar to the app's chrome for the given theme.
#[cfg(windows)]
pub fn apply(window: &tauri::WebviewWindow, dark: bool) {
    use windows::Win32::Foundation::HWND;
    use windows::core::BOOL;
    use windows::Win32::Graphics::Dwm::{
        DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR,
        DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute,
    };

    let Ok(handle) = window.hwnd() else {
        return;
    };
    let hwnd = HWND(handle.0 as *mut _);

    // COLORREF is 0x00BBGGRR — byte-reversed from the CSS hex, which is a
    // classic source of "why is my dark bar orange".
    //
    // These track --bg-raised and --text in styles.css. If those change, these
    // should too; a title bar one shade off the header is more noticeable than
    // it sounds.
    let (caption, text, border) = if dark {
        (0x0021_1D16, 0x00F0_EEE8, 0x0021_1D16) // #161d21 on #e8eef0
    } else {
        (0x00FF_FFFF, 0x002A_2316, 0x00E3_E0D5) // #ffffff on #16232a
    };

    let immersive_dark = BOOL::from(dark);

    // SAFETY: `hwnd` is a live window handle owned by Tauri for the lifetime of
    // the app, and each attribute is passed with the exact size DWM documents
    // for it. Unsupported attributes return an error we deliberately ignore —
    // caption colouring only exists from Windows 11 22000 onward.
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            (&raw const immersive_dark).cast(),
            size_of::<BOOL>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR,
            (&raw const caption).cast(),
            size_of::<u32>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_TEXT_COLOR,
            (&raw const text).cast(),
            size_of::<u32>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_BORDER_COLOR,
            (&raw const border).cast(),
            size_of::<u32>() as u32,
        );
    }
}

#[cfg(not(windows))]
pub fn apply(_window: &tauri::WebviewWindow, _dark: bool) {
    // macOS and Linux window managers already respect the app's own theme.
}
