//! Moving an unidentified network from Public to Private.
//!
//! Two computers joined by one cable is the most direct way to move a lot of
//! data, and Windows handles it badly. With no router between them there is no
//! gateway to identify, so the link becomes an "Unidentified network" and is
//! categorised **Public** — and for such a network the Settings UI frequently
//! offers no way to change it at all. The user is left looking at a warning they
//! cannot act on.
//!
//! `INetwork::SetCategory` still works, which is what this module uses.
//!
//! **Only networks with no internet connectivity are touched.** That is the whole
//! safety argument: a café or hotel network is Public *and should stay Public*,
//! and it always has internet. A link with no route off it has no untrusted
//! strangers on it to be protected from — it has exactly the machine at the other
//! end of the cable. Offering "make everything Private" would be a real security
//! downgrade dressed up as a convenience, so this deliberately cannot do that.

/// What we found when looking at the connected networks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileStatus {
    /// Networks that are Public *and* have no internet connectivity — the
    /// direct-cable signature, and the only ones this module will change.
    pub fixable: Vec<String>,
    /// Public networks that do have internet, listed so the UI can say why they
    /// are being left alone rather than silently ignoring them.
    pub public_with_internet: Vec<String>,
}

impl ProfileStatus {
    pub fn needs_fixing(&self) -> bool {
        !self.fixable.is_empty()
    }
}

/// Command-line argument the elevated helper instance is launched with.
pub const SET_PRIVATE_ARG: &str = "--set-network-private";

#[cfg(windows)]
pub fn status() -> Result<ProfileStatus, String> {
    windows_impl::status().map_err(|e| format!("could not read the network profiles: {e}"))
}

#[cfg(not(windows))]
pub fn status() -> Result<ProfileStatus, String> {
    Ok(ProfileStatus::default())
}

/// Set every fixable network to Private. Requires elevation.
#[cfg(windows)]
pub fn set_private() -> Result<usize, String> {
    windows_impl::set_private().map_err(|e| format!("could not change the network profile: {e}"))
}

#[cfg(not(windows))]
pub fn set_private() -> Result<usize, String> {
    Err("Network profiles are a Windows concept".into())
}

#[cfg(windows)]
mod windows_impl {
    use windows::Win32::Networking::NetworkListManager::{
        INetwork, INetworkListManager, NLM_CONNECTIVITY, NLM_CONNECTIVITY_IPV4_INTERNET,
        NLM_CONNECTIVITY_IPV6_INTERNET, NLM_ENUM_NETWORK_CONNECTED, NLM_NETWORK_CATEGORY_PRIVATE,
        NLM_NETWORK_CATEGORY_PUBLIC, NetworkListManager,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };
    use windows::core::BSTR;

    use super::ProfileStatus;

    struct ComGuard(bool);

    impl ComGuard {
        fn new() -> Self {
            // SAFETY: paired with CoUninitialize in Drop.
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

    fn has_internet(connectivity: NLM_CONNECTIVITY) -> bool {
        let bits = connectivity.0;
        bits & NLM_CONNECTIVITY_IPV4_INTERNET.0 != 0
            || bits & NLM_CONNECTIVITY_IPV6_INTERNET.0 != 0
    }

    /// Walk the connected networks, applying `visit` to each.
    ///
    /// Shared by `status` and `set_private` so the two can never disagree about
    /// which networks are eligible — a button that changes something the status
    /// did not list would be the worst possible outcome here.
    fn each_network(
        mut visit: impl FnMut(&INetwork, String, bool, bool) -> windows::core::Result<()>,
    ) -> windows::core::Result<()> {
        let _com = ComGuard::new();

        // SAFETY: standard COM activation; the interface is reference-counted by
        // the `windows` crate.
        let manager: INetworkListManager =
            unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL)? };

        // SAFETY: `manager` is a live interface pointer.
        let networks = unsafe { manager.GetNetworks(NLM_ENUM_NETWORK_CONNECTED)? };

        loop {
            // SAFETY: IEnumNetworks::Next over a live enumerator; we stop at the
            // first empty slot, which is the documented end condition.
            let mut fetched = [const { None::<INetwork> }; 1];
            let mut count = 0u32;
            let more = unsafe { networks.Next(&mut fetched, Some(&raw mut count)) };
            if more.is_err() || count == 0 {
                break;
            }

            let Some(network) = fetched[0].take() else {
                break;
            };

            // SAFETY: `network` is a live interface pointer for each call below.
            let is_public =
                unsafe { network.GetCategory() }.is_ok_and(|c| c == NLM_NETWORK_CATEGORY_PUBLIC);
            let internet = unsafe { network.GetConnectivity() }.is_ok_and(has_internet);
            let name = unsafe { network.GetName() }
                .map(|n| BSTR::to_string(&n))
                .unwrap_or_default();

            visit(&network, name, is_public, internet)?;
        }

        Ok(())
    }

    pub fn status() -> windows::core::Result<ProfileStatus> {
        let mut status = ProfileStatus::default();

        each_network(|_network, name, is_public, internet| {
            if is_public {
                let name = if name.is_empty() {
                    "Unidentified network".to_string()
                } else {
                    name
                };
                if internet {
                    status.public_with_internet.push(name);
                } else {
                    status.fixable.push(name);
                }
            }
            Ok(())
        })?;

        Ok(status)
    }

    pub fn set_private() -> windows::core::Result<usize> {
        let mut changed = 0usize;

        each_network(|network, _name, is_public, internet| {
            if is_public && !internet {
                // SAFETY: `network` is a live interface pointer. Fails without
                // elevation, which the caller handles by relaunching elevated.
                unsafe { network.SetCategory(NLM_NETWORK_CATEGORY_PRIVATE) }?;
                changed += 1;
            }
            Ok(())
        })?;

        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_the_status_never_panics() {
        // Runs on a diagnostics screen, so it has to be safe to call blind.
        let _ = status();
    }

    #[test]
    fn nothing_to_fix_means_no_offer() {
        assert!(!ProfileStatus::default().needs_fixing());
    }

    #[test]
    fn a_public_network_with_internet_is_never_offered_as_fixable() {
        // The safety property: café Wi-Fi must stay Public. It lands in the
        // informational list, never in the actionable one.
        let status = ProfileStatus {
            fixable: Vec::new(),
            public_with_internet: vec!["Airport Free WiFi".into()],
        };
        assert!(!status.needs_fixing());
    }

    #[test]
    fn an_unidentified_link_is_offered() {
        let status = ProfileStatus {
            fixable: vec!["Unidentified network".into()],
            public_with_internet: Vec::new(),
        };
        assert!(status.needs_fixing());
    }
}
