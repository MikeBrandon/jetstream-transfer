//! Windows "Send to" integration.
//!
//! Right-click a file in Explorer, `Send to → Jetstream`, pick a device. For
//! most people this is how a transfer app actually gets used — going to the app
//! first and browsing for a file you were already looking at is backwards.
//!
//! The mechanism is a shortcut in the user's `SendTo` folder. Explorer passes the
//! selected paths as arguments; the single-instance plugin routes them to the
//! copy already running, which shows its window with the files ready to send.
//!
//! Per-user, so no administrator rights and no UAC prompt — unlike the firewall
//! rule, this needs nothing privileged.

use std::path::PathBuf;

/// Name of the shortcut, and what appears in the Send to menu.
pub const SHORTCUT_NAME: &str = "Jetstream.lnk";

/// The user's `SendTo` folder.
pub fn send_to_dir() -> Option<PathBuf> {
    // `%APPDATA%\Microsoft\Windows\SendTo`. Resolved from the environment rather
    // than via SHGetKnownFolderPath to keep this dependency-free; the variable is
    // set on every Windows install.
    let appdata = std::env::var_os("APPDATA")?;
    Some(
        PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("SendTo"),
    )
}

pub fn shortcut_path() -> Option<PathBuf> {
    Some(send_to_dir()?.join(SHORTCUT_NAME))
}

/// Whether the Send to entry is currently installed.
pub fn is_installed() -> bool {
    shortcut_path().is_some_and(|path| path.exists())
}

/// Create or replace the Send to shortcut.
#[cfg(windows)]
pub fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this program: {e}"))?;
    let target = shortcut_path().ok_or("cannot locate the Send to folder")?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot use the Send to folder: {e}"))?;
    }

    // A `.lnk` is a COM-serialised structure, so it is built through IShellLink
    // rather than written by hand. Writing the binary format directly is possible
    // and a bad idea — it is undocumented in the details that matter.
    windows_impl::write_shortcut(&exe, &target)
}

#[cfg(not(windows))]
pub fn install() -> Result<(), String> {
    Err("Send to is a Windows feature".into())
}

/// Remove the shortcut. Succeeds if it was already gone.
pub fn uninstall() -> Result<(), String> {
    let Some(path) = shortcut_path() else {
        return Ok(());
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not remove the Send to entry: {e}")),
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::path::Path;

    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize, IPersistFile,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::{HSTRING, Interface, PCWSTR};

    struct ComGuard(bool);

    impl ComGuard {
        fn new() -> Self {
            // Apartment-threaded, because the shell COM objects require it.
            // SAFETY: paired with CoUninitialize in Drop.
            let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            Self(hr.is_ok())
        }
    }

    impl Drop for ComGuard {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: balances the successful CoInitializeEx above.
                unsafe { CoUninitialize() };
            }
        }
    }

    pub fn write_shortcut(exe: &Path, target: &Path) -> Result<(), String> {
        let _com = ComGuard::new();

        // SAFETY: standard COM activation; the interface is reference-counted by
        // the `windows` crate.
        let link: IShellLinkW =
            unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| format!("could not create a shortcut: {e}"))?;

        let exe_wide = HSTRING::from(exe.as_os_str());
        let description = HSTRING::from("Send these files to another device");
        let working_dir = HSTRING::from(
            exe.parent()
                .unwrap_or(Path::new("."))
                .as_os_str(),
        );

        // SAFETY: `link` is live and every string outlives the call.
        unsafe {
            link.SetPath(PCWSTR(exe_wide.as_ptr()))
                .and_then(|_| link.SetDescription(PCWSTR(description.as_ptr())))
                .and_then(|_| link.SetWorkingDirectory(PCWSTR(working_dir.as_ptr())))
                .and_then(|_| link.SetIconLocation(PCWSTR(exe_wide.as_ptr()), 0))
        }
        .map_err(|e| format!("could not configure the shortcut: {e}"))?;

        // SAFETY: IShellLink always implements IPersistFile.
        let file: IPersistFile = link
            .cast()
            .map_err(|e| format!("could not save the shortcut: {e}"))?;

        let target_wide = HSTRING::from(target.as_os_str());

        // SAFETY: `file` is live and `target_wide` outlives the call.
        unsafe { file.Save(PCWSTR(target_wide.as_ptr()), true) }
            .map_err(|e| format!("could not write the Send to entry: {e}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_send_to_folder_resolves_on_windows() {
        if cfg!(windows) {
            let dir = send_to_dir().expect("APPDATA should be set on Windows");
            assert!(dir.ends_with("SendTo"), "got {dir:?}");
        }
    }

    #[test]
    fn checking_installation_never_panics() {
        // Runs on a diagnostics screen, so it has to be safe to call blind.
        let _ = is_installed();
    }

    #[test]
    fn uninstalling_when_absent_succeeds() {
        // Idempotent: the settings toggle calls this without checking first.
        if !is_installed() {
            assert!(uninstall().is_ok());
        }
    }
}
