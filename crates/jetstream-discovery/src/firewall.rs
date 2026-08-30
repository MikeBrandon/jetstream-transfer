//! Getting Jetstream through Windows Firewall, from inside Jetstream.
//!
//! # Why this exists
//!
//! Windows blocks inbound connections to any program that has not been allowed
//! through the firewall. For a peer-to-peer transfer app that is fatal in a
//! quiet way: outbound announcements still go out, the device still appears in
//! everybody else's list, and it can still *send* — it simply never receives.
//! Nothing looks broken.
//!
//! The normal fix is a Windows prompt on first bind, but it only appears for a
//! foreground process at the right moment, it is easy to dismiss, and once
//! dismissed it never returns. What remains is a trip through Windows Security
//! settings that no non-technical user should be asked to make.
//!
//! So the app checks for its own rule and offers to add it. That needs
//! administrator rights, which means a UAC prompt — unavoidable, since being
//! able to silently punch holes in the firewall is exactly what UAC is for.
//! What we *can* do is make it one button, one prompt, and an honest
//! explanation of what is about to happen.
//!
//! # Shape of the flow
//!
//! ```text
//! app (normal rights)          elevated helper (same exe, --allow-firewall)
//!   status() -> Absent
//!   user clicks "Allow"
//!   request_elevation() ──UAC──> install() adds the rule via COM
//!                                exits 0
//!   status() -> Present
//! ```
//!
//! The helper is the same executable rather than a separate binary: a second
//! signed artifact to ship and keep in sync, purely to add one firewall rule,
//! is not worth it.

use std::path::PathBuf;

/// Rule name, and the key we look up by.
///
/// Also what the user sees in the Windows Firewall list, so it is the product
/// name rather than something internal.
pub const RULE_NAME: &str = "Jetstream";

/// Argument that turns a normal launch into the elevated helper.
pub const INSTALL_ARG: &str = "--allow-firewall";

/// Whether this machine will accept inbound connections for us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleStatus {
    /// A rule exists and is enabled.
    Present,
    /// A rule exists but is switched off — the user, or a policy, disabled it.
    /// Worth distinguishing: re-adding it will not help.
    Disabled,
    /// No rule for this application.
    Absent,
    /// A rule with our name exists, but it names a **different executable**.
    ///
    /// Distinguished from `Absent` because it needs a different explanation, not
    /// a different fix. A permission granted to `D:\Jetstream\Jetstream.exe` does
    /// nothing for a copy now running from `E:\`, so a user who already allowed
    /// Jetstream once sees it blocked again and reasonably concludes the fix did
    /// not work. Naming the old path turns that into an obvious cause.
    ///
    /// Portable copies hit this every time they are moved or updated into a new
    /// folder, which makes it the common case rather than an edge one.
    Moved(String),
    /// We could not tell. Never guess here; an unnecessary UAC prompt is worse
    /// than saying "unknown".
    Unknown(String),
}

impl RuleStatus {
    pub fn is_present(&self) -> bool {
        *self == Self::Present
    }

    /// Whether offering the "allow through firewall" button makes sense.
    pub fn is_fixable(&self) -> bool {
        matches!(self, Self::Absent | Self::Moved(_))
    }
}

/// Path to the running executable, which is what a rule must name.
pub fn current_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("could not determine this program's path: {e}"))
}

#[cfg(windows)]
pub use windows_impl::{install, is_elevated, request_elevation, status};

#[cfg(not(windows))]
mod stubs {
    use super::*;

    /// Other platforms have firewalls too, but none that block a per-user
    /// program by default the way Windows does, and none with a common API.
    /// Reporting `Unknown` keeps the UI honest instead of claiming a check ran.
    pub fn status(_exe: &std::path::Path) -> RuleStatus {
        RuleStatus::Unknown("firewall checks are only implemented on Windows".into())
    }

    pub fn install(_exe: &std::path::Path) -> Result<(), String> {
        Err("firewall rules can only be added automatically on Windows".into())
    }

    pub fn request_elevation(_exe: &std::path::Path, _arg: &str) -> Result<(), String> {
        Err("elevation is only implemented on Windows".into())
    }

    pub fn is_elevated() -> bool {
        false
    }
}

#[cfg(not(windows))]
pub use stubs::{install, is_elevated, request_elevation, status};

#[cfg(windows)]
mod windows_impl {
    use std::path::Path;

    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, INetFwRule, NET_FW_ACTION_ALLOW, NET_FW_IP_PROTOCOL_UDP,
        NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NetFwPolicy2, NetFwRule,
    };
    use windows::Win32::Security::{TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::{BSTR, PCWSTR};

    use super::{RULE_NAME, RuleStatus};

    /// Initialises COM for the duration of a call. See the identical guard in
    /// [`crate::diagnostics`] for why this is per-call rather than global.
    struct ComGuard(bool);

    impl ComGuard {
        fn new() -> Self {
            // SAFETY: paired with CoUninitialize in Drop, and only when this
            // call was the one that initialised the apartment.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
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

    fn policy() -> Result<INetFwPolicy2, String> {
        // SAFETY: standard COM activation; lifetime managed by the crate.
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL) }
            .map_err(|e| format!("could not talk to Windows Firewall: {e}"))
    }

    /// Look for our rule by name.
    ///
    /// By name rather than by enumerating every rule and comparing paths:
    /// `INetFwRules::Item` is a direct lookup, while enumeration means driving
    /// `IEnumVARIANT` over several hundred entries on a typical machine.
    ///
    /// The path is still verified once found, so a stale rule left behind by an
    /// install in a different location is treated as absent rather than
    /// silently trusted.
    pub fn status(exe: &Path) -> RuleStatus {
        let _com = ComGuard::new();

        let policy = match policy() {
            Ok(policy) => policy,
            Err(e) => return RuleStatus::Unknown(e),
        };

        // SAFETY: `policy` is a live interface pointer.
        let rules = match unsafe { policy.Rules() } {
            Ok(rules) => rules,
            Err(e) => return RuleStatus::Unknown(format!("could not read firewall rules: {e}")),
        };

        // SAFETY: as above. A missing rule is reported as an error, which is
        // the documented behaviour and not a failure on our part.
        let rule = match unsafe { rules.Item(&BSTR::from(RULE_NAME)) } {
            Ok(rule) => rule,
            Err(_) => return RuleStatus::Absent,
        };

        // SAFETY: `rule` is live.
        let recorded = unsafe { rule.ApplicationName() }
            .map(|name| BSTR::to_string(&name))
            .unwrap_or_default();

        if !paths_match(&recorded, exe) {
            // A rule with our name pointing somewhere else: an old install, or a
            // portable copy that moved. `install` replaces by name, so the fix is
            // the same button — but the explanation is not.
            return RuleStatus::Moved(recorded);
        }

        // SAFETY: `rule` is live.
        match unsafe { rule.Enabled() } {
            Ok(enabled) if enabled.as_bool() => RuleStatus::Present,
            Ok(_) => RuleStatus::Disabled,
            Err(e) => RuleStatus::Unknown(format!("could not read the rule's state: {e}")),
        }
    }

    /// Compare two executable paths tolerantly.
    ///
    /// Windows paths are case-insensitive and may differ in separators or
    /// short-name form, so an exact string comparison would report a false
    /// mismatch and prompt the user to re-add a rule that already works.
    fn paths_match(recorded: &str, exe: &Path) -> bool {
        let normalise = |p: &str| p.replace('/', "\\").trim_matches('"').to_lowercase();

        let recorded = normalise(recorded);
        let actual = normalise(&exe.display().to_string());

        if recorded == actual {
            return true;
        }

        // Fall back to comparing canonical forms, which resolves `..`, short
        // names, and symlinked install directories.
        match (
            std::fs::canonicalize(&recorded).ok(),
            std::fs::canonicalize(exe).ok(),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Add the inbound rule. **Requires administrator rights.**
    ///
    /// Only UDP inbound is opened, because that is all QUIC uses. A narrower
    /// hole than the "allow this app everything" a user would end up clicking
    /// in the Windows dialog.
    pub fn install(exe: &Path) -> Result<(), String> {
        let _com = ComGuard::new();
        let policy = policy()?;

        // SAFETY: `policy` is live.
        let rules = unsafe { policy.Rules() }
            .map_err(|e| format!("could not open the firewall rule list: {e}"))?;

        // Replace rather than duplicate: re-running after moving the app should
        // update the path, not leave two rules behind.
        // SAFETY: removing a rule that does not exist is a no-op error we drop.
        let _ = unsafe { rules.Remove(&BSTR::from(RULE_NAME)) };

        // SAFETY: standard COM activation.
        let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_ALL) }
            .map_err(|e| format!("could not create a firewall rule: {e}"))?;

        let exe_path = BSTR::from(exe.display().to_string());

        // SAFETY: `rule` is a live interface pointer and every argument
        // outlives the call.
        unsafe {
            rule.SetName(&BSTR::from(RULE_NAME))
                .and_then(|_| {
                    rule.SetDescription(&BSTR::from(
                        "Lets other devices on your network send files to Jetstream.",
                    ))
                })
                .and_then(|_| rule.SetApplicationName(&exe_path))
                .and_then(|_| rule.SetProtocol(NET_FW_IP_PROTOCOL_UDP.0))
                .and_then(|_| rule.SetDirection(NET_FW_RULE_DIR_IN))
                .and_then(|_| rule.SetAction(NET_FW_ACTION_ALLOW))
                .and_then(|_| rule.SetProfiles(NET_FW_PROFILE2_ALL.0))
                .and_then(|_| rule.SetGrouping(&BSTR::from(RULE_NAME)))
                .and_then(|_| rule.SetEnabled(VARIANT_BOOL::from(true)))
        }
        .map_err(|e| format!("could not configure the firewall rule: {e}"))?;

        // SAFETY: `rules` and `rule` are both live.
        unsafe { rules.Add(&rule) }.map_err(|e| {
            format!("could not add the firewall rule (are you running as administrator?): {e}")
        })?;

        Ok(())
    }

    /// Re-launch this executable elevated, passing `arg` to ask it to do one
    /// privileged job and exit.
    ///
    /// Generic over the argument because more than one thing needs elevation —
    /// the firewall rule and the network profile — and each having its own copy
    /// of this `ShellExecuteW` dance would be one copy too many.
    ///
    /// Returns as soon as the user answers the UAC prompt. It does **not** wait
    /// for the helper to finish, so the caller should re-check status rather than
    /// assume success — an elevated process can still fail, and a user can still
    /// click No.
    pub fn request_elevation(exe: &Path, arg: &str) -> Result<(), String> {
        let file: Vec<u16> = encode(&exe.display().to_string());
        let verb: Vec<u16> = encode("runas");
        let args: Vec<u16> = encode(arg);

        // SAFETY: all three buffers are NUL-terminated and outlive the call.
        // ShellExecuteW returns a pseudo-HINSTANCE that is an error code when
        // 32 or below — the documented convention for this API.
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(file.as_ptr()),
                PCWSTR(args.as_ptr()),
                PCWSTR::null(),
                SW_HIDE,
            )
        };

        const SE_ERR_ACCESSDENIED: isize = 5;
        match result.0 as isize {
            code if code > 32 => Ok(()),
            SE_ERR_ACCESSDENIED => {
                Err("Windows needs your permission to change firewall settings. \
                     Choose Yes on the prompt and try again."
                    .into())
            }
            code => Err(format!("could not start the elevated helper (code {code})")),
        }
    }

    fn encode(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Whether this process is already running with administrator rights.
    pub fn is_elevated() -> bool {
        let mut token = windows::Win32::Foundation::HANDLE::default();

        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `token` receives a real handle we close below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;

        // SAFETY: the buffer matches the size we declare, and TokenElevation
        // is documented to return a TOKEN_ELEVATION.
        let ok = unsafe {
            windows::Win32::Security::GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &raw mut returned,
            )
        }
        .is_ok();

        // SAFETY: `token` came from OpenProcessToken and is not used again.
        unsafe { let _ = windows::Win32::Foundation::CloseHandle(token); };

        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_never_panics_and_names_this_executable() {
        // Whatever this machine's firewall looks like, the check must return
        // rather than crash — it runs on a user-facing diagnostics screen.
        let exe = current_exe().expect("the test binary has a path");
        let status = status(&exe);

        // The test binary has no rule of its own. On a machine where Jetstream
        // has been allowed, the rule exists under our name but names the app, so
        // `Moved` is also a correct answer here.
        if cfg!(windows) {
            assert!(
                matches!(
                    status,
                    RuleStatus::Absent | RuleStatus::Moved(_) | RuleStatus::Unknown(_)
                ),
                "unexpected status for a binary that cannot have its own rule: {status:?}"
            );
        }
    }

    #[test]
    fn a_missing_or_misplaced_rule_is_fixable_and_nothing_else_is() {
        assert!(RuleStatus::Absent.is_fixable());

        // A rule naming another path is fixable by the same button — `install`
        // replaces by name — even though it needs a different explanation.
        assert!(RuleStatus::Moved("D:\\old\\Jetstream.exe".into()).is_fixable());

        // Re-adding a rule the user deliberately disabled would not help, and
        // burning a UAC prompt to achieve nothing is worse than saying so.
        assert!(!RuleStatus::Disabled.is_fixable());
        assert!(!RuleStatus::Present.is_fixable());
        assert!(!RuleStatus::Unknown("...".into()).is_fixable());
    }

    #[test]
    fn present_is_the_only_status_that_counts_as_working() {
        assert!(RuleStatus::Present.is_present());
        assert!(!RuleStatus::Disabled.is_present());
        assert!(!RuleStatus::Absent.is_present());
        // The most important one: a rule for a copy that has moved is a rule
        // that does nothing, and must never read as working.
        assert!(!RuleStatus::Moved("D:\\old\\Jetstream.exe".into()).is_present());
    }

    #[cfg(windows)]
    #[test]
    fn an_ordinary_test_run_is_not_elevated() {
        // Guards the elevation check against always returning true, which
        // would hide the UAC step and make `install` fail confusingly.
        // If this fails, the test suite is being run as administrator.
        assert!(!is_elevated(), "run the tests without administrator rights");
    }
}
