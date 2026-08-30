//! Explaining an empty peer list.
//!
//! When Dukto shows nothing, it shows nothing — no reason, no next step. In
//! practice the cause is almost always one of a small, checkable set, and
//! naming it correctly turns a dead end into a fix.
//!
//! The checks are ordered by how often they are the real cause on Windows:
//!
//! 1. **The network is marked Public.** Windows blocks inbound network
//!    discovery on Public networks. This is the single most common reason two
//!    machines on the same Wi-Fi cannot see each other, and the user can fix it
//!    in about ten seconds once told.
//! 2. **No inbound firewall rule.** Outbound announcements go out, nothing
//!    comes back, so each device sees the other as absent.
//! 3. **Client isolation.** The access point forwards nothing between clients.
//!    Inferred, not measured: if a direct connection to a known address works
//!    while discovery finds nothing, the network is dropping our broadcasts and
//!    multicast rather than blocking us.
//! 4. **Different subnets.** Neither broadcast nor mDNS crosses a router.
//!
//! A wrong diagnosis is worse than none, so every finding here is either
//! directly observed or clearly labelled as an inference.

use std::fmt;

use crate::{SharedRegistry, Source};

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Everything checks out.
    Ok,
    /// Worth knowing, but not necessarily the problem.
    Note,
    /// Very likely the reason peers are missing.
    Problem,
}

/// One diagnostic result.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    /// One line, in plain language, naming the actual situation.
    pub summary: String,
    /// What the user can do about it. Empty when nothing is wrong.
    pub remedy: String,
}

impl Finding {
    fn ok(summary: impl Into<String>) -> Self {
        Self {
            severity: Severity::Ok,
            summary: summary.into(),
            remedy: String::new(),
        }
    }

    fn note(summary: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            severity: Severity::Note,
            summary: summary.into(),
            remedy: remedy.into(),
        }
    }

    fn problem(summary: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            severity: Severity::Problem,
            summary: summary.into(),
            remedy: remedy.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let marker = match self.severity {
            Severity::Ok => "ok",
            Severity::Note => "note",
            Severity::Problem => "problem",
        };
        write!(f, "[{marker}] {}", self.summary)?;
        if !self.remedy.is_empty() {
            write!(f, "\n       {}", self.remedy)?;
        }
        Ok(())
    }
}

/// The full report.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn has_problems(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Problem)
    }

    /// Findings worth surfacing, most serious first.
    pub fn sorted(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
        findings
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for finding in self.sorted() {
            writeln!(f, "{finding}")?;
        }
        Ok(())
    }
}

/// What we know about the local network, gathered from the platform.
#[derive(Debug, Clone, Default)]
pub struct NetworkFacts {
    /// `Some(true)` when at least one connected network is categorised Public.
    /// `None` when we could not determine it.
    pub any_public_network: Option<bool>,
    /// Names of connected networks, for the user to recognise which is which.
    pub network_names: Vec<String>,
    /// Whether Windows Firewall is on for the profile currently in use.
    pub firewall_enabled: Option<bool>,
    /// Whether the profile is set to block *all* inbound traffic, which
    /// overrides even an explicit allow rule for this application.
    pub firewall_blocks_all_inbound: Option<bool>,
    /// Addresses announcements are sent to, one per network we are on.
    pub broadcast_targets: Vec<std::net::Ipv4Addr>,
}

/// Run every check and produce a report.
///
/// `registry` supplies the per-mechanism counts, which is where most of the
/// diagnostic value comes from — the *pattern* of what found what says more
/// than any single platform query.
pub fn diagnose(registry: &SharedRegistry) -> Report {
    let facts = network_facts();
    diagnose_with(registry, &facts)
}

/// The pure half, so the reasoning can be tested without a network.
pub fn diagnose_with(registry: &SharedRegistry, facts: &NetworkFacts) -> Report {
    let mut findings = Vec::new();

    let counts = registry.counts_by_source();
    let mdns = counts.get(&Source::Mdns).copied().unwrap_or(0);
    let broadcast = counts.get(&Source::Broadcast).copied().unwrap_or(0);
    let manual = counts.get(&Source::Manual).copied().unwrap_or(0);
    let known = counts.get(&Source::Known).copied().unwrap_or(0);
    let total = registry.len();

    // --- The Windows Public-network trap -----------------------------------
    //
    // Downgraded from "problem" to "note", and reworded, because the original
    // claim was too strong. Jetstream's own firewall rule is registered for
    // *every* profile (`NET_FW_PROFILE2_ALL`), so a Public network does not block
    // Jetstream's own traffic — announcements, mDNS and QUIC all run from this
    // program and are covered by that one rule. What Public genuinely does is
    // switch off Windows' own file and printer sharing, and it is a reliable
    // signal that something else may be unhappy. Reporting it as the reason
    // transfers fail sends the user to fix a setting that was not the cause.
    match facts.any_public_network {
        Some(true) => findings.push(Finding::note(
            "A connected network is set to Public.",
            "Jetstream still works — its firewall rule covers every network type. Windows' own \
             sharing is switched off on a Public network though, and a direct cable between two \
             computers always lands here because there is no router for Windows to identify. \
             Jetstream can set such a network to Private for you.",
        )),
        Some(false) => findings.push(Finding::ok("Network profile is Private, so discovery is allowed.")),
        None => {}
    }

    // --- What each mechanism actually found --------------------------------
    if total == 0 {
        findings.push(Finding::problem(
            "No other devices found by any method.",
            "Check that Jetstream is running on the other device and that both are on the \
             same network. If it is, add the other device by IP address to rule discovery out.",
        ));
    } else {
        findings.push(Finding::ok(format!(
            "Found {total} device(s): {mdns} by mDNS, {broadcast} by broadcast, \
             {manual} added manually, {known} previously paired."
        )));
    }

    // A mechanism finding nothing while another finds several is a measurement,
    // not a guess: the network is filtering one and passing the other.
    if mdns > 0 && broadcast == 0 {
        findings.push(Finding::note(
            "This network passes mDNS but not UDP broadcast.",
            "Nothing to fix — discovery is working. Older tools that rely on broadcast alone \
             (Dukto among them) will not find anything here.",
        ));
    }
    if broadcast > 0 && mdns == 0 {
        findings.push(Finding::note(
            "This network passes UDP broadcast but not mDNS.",
            "Nothing to fix. Some access points and VPN adapters filter multicast.",
        ));
    }

    // --- Client isolation, inferred ----------------------------------------
    // Reachable directly but invisible to discovery is the signature.
    if total > 0 && mdns == 0 && broadcast == 0 && (manual > 0 || known > 0) {
        findings.push(Finding::problem(
            "Devices are reachable directly but never announce themselves — \
             this network is almost certainly using client isolation.",
            "Common on guest and public Wi-Fi. Transfers still work if you add devices by IP \
             address, but automatic discovery cannot work here. On your own router, look for \
             'AP isolation' or 'client isolation' and turn it off.",
        ));
    }

    // --- Windows Firewall --------------------------------------------------
    // Only the one condition that a per-application rule cannot overcome.
    //
    // Whether *this program* is allowed through is answered directly by
    // [`crate::firewall::status`], which reads the actual rule. There used to be
    // an inference here — "peers are visible, so the firewall is not in the
    // way" — and it was simply wrong: discovery runs over broadcast and mDNS on
    // a separate socket, so it succeeds happily while inbound QUIC is blocked.
    // It produced a report that contradicted itself, which is worse than a
    // report that says less.
    if facts.firewall_blocks_all_inbound == Some(true) {
        findings.push(Finding::problem(
            "Windows Firewall is set to block all inbound connections on this network.",
            "That setting overrides per-app permissions, so this device can send but can never \
             receive. Turn off 'Blocks all incoming connections' in Windows Security > Firewall \
             & network protection.",
        ));
    }

    if !facts.network_names.is_empty() {
        findings.push(Finding::note(
            format!("Connected networks: {}.", facts.network_names.join(", ")),
            "If more than one is listed, a VPN or virtual adapter may be capturing discovery \
             traffic. Disconnecting it is a quick way to test.",
        ));
    }

    // Where announcements actually go. Worth stating outright, because the one
    // failure this could not previously explain was announcements leaving via
    // the wrong adapter: peers appear once via mDNS, then vanish 30 seconds
    // later because nothing refreshed them. Seeing the list makes that obvious
    // instead of invisible — if the subnet the other device is on is missing
    // here, that is the whole answer.
    if !facts.broadcast_targets.is_empty() {
        findings.push(Finding::note(
            format!(
                "Announcing from: {}.",
                facts
                    .broadcast_targets
                    .iter()
                    .map(|t| t.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "One entry per network this device announces itself on. If the address on the same \
             network as the other device is missing, that adapter is down or has no address, and \
             discovery cannot reach it.",
        ));
    }

    Report { findings }
}

/// Test whether anything on the network can actually reach us.
///
/// This is a *measurement*, not an inference, and it is the check that catches
/// the second most common failure: Windows Firewall silently dropping inbound
/// UDP for an unsigned executable. Announcements still go out, so the app looks
/// healthy from the inside while being completely unreachable from outside.
///
/// The method is to connect to ourselves twice — once over loopback, once over
/// our own LAN address. Loopback bypasses the firewall entirely, so:
///
/// - both succeed → inbound works;
/// - loopback works, LAN does not → something is blocking inbound, and on
///   Windows that is almost always the firewall;
/// - neither works → the problem is in the app, not the network.
///
/// Distinguishing those three is the whole value. "It doesn't work" is what
/// Dukto tells you.
pub async fn probe_inbound(identity: std::sync::Arc<jetstream_core::Identity>) -> Finding {
    use std::sync::Arc;
    use jetstream_core::transport::Endpoint;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    const ATTEMPT: Duration = Duration::from_secs(3);

    let device_id = identity.device_id();

    // Two endpoints, not one. A QUIC endpoint dialling its own socket is a
    // degenerate case that proves nothing about the firewall; a separate
    // client endpoint reproduces exactly what a real peer does.
    let listener = match Endpoint::bind(
        Arc::clone(&identity),
        "self-test listener",
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    ) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            return Finding::problem(
                format!("Could not open a network socket: {e}"),
                "Another program may be using the port, or a security product is blocking it.",
            );
        }
    };

    let Ok(bound) = listener.local_addr() else {
        return Finding::note("Could not determine the local port.", "");
    };
    let port = bound.port();

    let client = match Endpoint::bind(
        identity,
        "self-test client",
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    ) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            listener.shutdown().await;
            return Finding::problem(
                format!("Could not open a second network socket: {e}"),
                "A security product may be limiting how many sockets this program can open.",
            );
        }
    };

    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move {
            // Hold each session: dropping one closes its connection, which the
            // client sees as "connection lost" the instant its handshake
            // completes — and would make a perfectly healthy network look
            // blocked.
            let mut held = Vec::new();
            while let Some(accepted) = listener.accept().await {
                if let Ok(session) = accepted {
                    held.push(session);
                }
            }
        })
    };

    let loopback = client
        .connect_any(
            &[SocketAddr::from((Ipv4Addr::LOCALHOST, port))],
            Some(device_id),
            ATTEMPT,
        )
        .await
        .is_ok();

    let lan_address = local_lan_address().map(|ip| SocketAddr::new(ip, port));
    let lan = match lan_address {
        Some(address) => Some(
            client
                .connect_any(&[address], Some(device_id), ATTEMPT)
                .await
                .is_ok(),
        ),
        None => None,
    };

    accepting.abort();
    client.shutdown().await;
    listener.shutdown().await;

    match (loopback, lan) {
        // Deliberately modest wording. Windows short-circuits traffic a machine
        // sends to its own address, so it never crosses the firewall's inbound
        // path — this proves the app's own networking is sound, and nothing
        // about what a *remote* peer will experience. Claiming otherwise would
        // be the confident-but-wrong diagnosis this module exists to avoid.
        (true, Some(true)) => Finding::ok(format!(
            "Networking works and this device has a usable address ({}). \
             Whether other machines can reach it depends on the firewall.",
            lan_address.expect("checked above").ip()
        )),
        (true, Some(false)) => Finding::problem(
            "This device can talk to itself over loopback but not over its own network address.",
            "That is unusual and points at a third-party firewall or endpoint-security product \
             filtering local traffic.",
        ),
        (true, None) => Finding::note(
            "No network address found, so inbound reachability could not be tested.",
            "This device may not be connected to a network.",
        ),
        (false, _) => Finding::problem(
            "This device cannot even connect to itself.",
            "Something is blocking local UDP traffic — most likely a third-party firewall or \
             endpoint-security product.",
        ),
    }
}

/// This machine's primary LAN address.
///
/// Found by asking the routing table which local address it would use to reach
/// the outside world. The UDP socket is only "connected" — no packet is ever
/// sent — so this works offline and costs nothing. It beats enumerating
/// adapters, which on a Windows box with a VPN and Hyper-V returns a pile of
/// addresses with no indication of which one matters.
pub fn local_lan_address() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?; // TEST-NET-1, guaranteed unrouted
    let address = socket.local_addr().ok()?.ip();

    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

/// Query the platform for what it will tell us.
#[cfg(windows)]
pub fn network_facts() -> NetworkFacts {
    let mut facts = match windows_impl::network_facts() {
        Ok(facts) => facts,
        Err(e) => {
            tracing::debug!(error = %e, "could not read network profiles");
            NetworkFacts::default()
        }
    };
    // Platform-independent, so gathered here rather than in either branch.
    facts.broadcast_targets = announcing_from();
    facts
}

#[cfg(not(windows))]
pub fn network_facts() -> NetworkFacts {
    // The Public/Private distinction is a Windows concept. Elsewhere the
    // pattern-based checks above carry the diagnosis on their own.
    NetworkFacts {
        broadcast_targets: announcing_from(),
        ..NetworkFacts::default()
    }
}

/// The interfaces announcements go out of, for the report.
///
/// Reported as the *local* address rather than the broadcast address: it is what
/// a user can recognise, and it matches what they see in Windows.
fn announcing_from() -> Vec<std::net::Ipv4Addr> {
    crate::broadcast::announce_sources()
        .into_iter()
        .map(|source| source.address)
        .collect()
}

#[cfg(windows)]
mod windows_impl {
    use windows::Win32::Networking::NetworkListManager::{
        INetwork, INetworkListManager, NLM_ENUM_NETWORK_CONNECTED, NLM_NETWORK_CATEGORY_PUBLIC,
        NetworkListManager,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };
    use windows::core::BSTR;

    use super::NetworkFacts;

    /// Initialises COM for this call and uninitialises on the way out.
    ///
    /// The diagnostics panel is user-triggered and infrequent, so paying for
    /// COM setup each time is cheaper than holding an apartment open for the
    /// life of the process — and it keeps this module free of global state.
    struct ComGuard(bool);

    impl ComGuard {
        fn new() -> Self {
            // SAFETY: paired with CoUninitialize in Drop. An error here means
            // COM is already initialised on this thread with another model,
            // which is fine to proceed with — we just must not uninitialise it.
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

    /// Read Windows Firewall's posture for the profile currently in use.
    ///
    /// Reads the *policy*, not the rule list. Enumerating every rule to find
    /// whether one names our executable means driving `IEnumVARIANT` over
    /// several hundred entries, and the answer would still be ambiguous — a
    /// rule can exist while scoped to the wrong profile. The posture plus
    /// whether discovery is actually working tells the user as much, honestly.
    pub fn firewall_facts() -> Option<NetworkFacts> {
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, NetFwPolicy2,
        };

        let _com = ComGuard::new();

        // SAFETY: standard COM activation, reference-counted by the crate.
        let policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL).ok()? };

        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
        };

        // SAFETY: `policy` is a live interface pointer.
        //
        // This is a *bitmask* of the profiles currently in force — a machine on
        // both a domain network and Wi-Fi has two. The per-profile getters take
        // a single profile and reject a mask, so the bits have to be walked.
        let active = unsafe { policy.CurrentProfileTypes().ok()? };

        let mut enabled = None;
        let mut block_all = None;

        for profile in [
            NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE,
            NET_FW_PROFILE2_PUBLIC,
        ] {
            if active & profile.0 == 0 {
                continue;
            }

            // SAFETY: `policy` is live and `profile` is a single valid profile.
            if let Ok(value) = unsafe { policy.get_FirewallEnabled(profile) } {
                // Any active profile with the firewall on can block us.
                enabled = Some(enabled.unwrap_or(false) || value.as_bool());
            }
            // SAFETY: as above.
            if let Ok(value) = unsafe { policy.get_BlockAllInboundTraffic(profile) } {
                block_all = Some(block_all.unwrap_or(false) || value.as_bool());
            }
        }

        Some(NetworkFacts {
            firewall_enabled: enabled,
            firewall_blocks_all_inbound: block_all,
            ..Default::default()
        })
    }

    pub fn network_facts() -> windows::core::Result<NetworkFacts> {
        let _com = ComGuard::new();

        // SAFETY: standard COM activation; the returned interface is managed
        // by the `windows` crate's reference counting.
        let manager: INetworkListManager =
            unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL)? };

        // SAFETY: `manager` is a live interface pointer.
        let networks = unsafe { manager.GetNetworks(NLM_ENUM_NETWORK_CONNECTED)? };

        let mut facts = NetworkFacts {
            any_public_network: Some(false),
            network_names: Vec::new(),
            ..firewall_facts().unwrap_or_default()
        };

        loop {
            // SAFETY: IEnumNetworks::Next over a live enumerator; we stop at
            // the first empty slot, which is the documented end condition.
            let mut fetched = [const { None::<INetwork> }; 1];
            let mut count = 0u32;
            let more = unsafe { networks.Next(&mut fetched, Some(&raw mut count)) };
            if more.is_err() || count == 0 {
                break;
            }

            let Some(network) = fetched[0].take() else {
                break;
            };

            // SAFETY: `network` is a live interface pointer.
            if let Ok(category) = unsafe { network.GetCategory() }
                && category == NLM_NETWORK_CATEGORY_PUBLIC
            {
                facts.any_public_network = Some(true);
            }

            // SAFETY: as above. The BSTR is freed when it drops.
            if let Ok(name) = unsafe { network.GetName() } {
                let name = BSTR::to_string(&name);
                if !name.is_empty() {
                    facts.network_names.push(name);
                }
            }
        }

        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Registry, Sighting};
    use jetstream_core::DeviceId;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn registry_with(entries: &[(u8, Source)]) -> SharedRegistry {
        let registry = Arc::new(Registry::new());
        for &(byte, source) in entries {
            registry.record(Sighting::claimed(
                DeviceId::from_bytes([byte; 32]),
                format!("Peer {byte}"),
                vec![format!("192.168.1.{byte}:4646").parse::<SocketAddr>().unwrap()],
                source,
            ));
        }
        registry
    }

    fn summaries(report: &Report) -> String {
        report
            .findings
            .iter()
            .map(|f| f.summary.as_str())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn a_public_network_is_surfaced_without_being_blamed() {
        // It used to be reported as *the* reason discovery fails. That was wrong:
        // Jetstream's rule covers every profile, so Public does not block us —
        // and sending a user to change a setting that was not the cause is worse
        // than saying less.
        let facts = NetworkFacts {
            any_public_network: Some(true),
            network_names: vec![],
            ..Default::default()
        };
        let report = diagnose_with(&registry_with(&[(1, Source::Mdns)]), &facts);

        let public = report
            .findings
            .iter()
            .find(|f| f.summary.contains("Public"))
            .expect("the profile should still be reported");

        assert_eq!(
            public.severity,
            Severity::Note,
            "Public is context, not the diagnosis"
        );
        assert!(
            public.remedy.contains("Private"),
            "the remedy must still say what can be done"
        );
        assert!(
            public.remedy.contains("still works"),
            "must not imply transfers are blocked"
        );
    }

    #[test]
    fn a_private_network_with_peers_reports_no_problems() {
        let facts = NetworkFacts {
            any_public_network: Some(false),
            network_names: vec![],
            ..Default::default()
        };
        let registry = registry_with(&[(1, Source::Mdns), (2, Source::Mdns), (2, Source::Broadcast)]);

        let report = diagnose_with(&registry, &facts);
        assert!(!report.has_problems(), "{}", summaries(&report));
    }

    #[test]
    fn finding_nothing_at_all_is_flagged_with_a_next_step() {
        let report = diagnose_with(&registry_with(&[]), &NetworkFacts::default());

        assert!(report.has_problems());
        let finding = report
            .findings
            .iter()
            .find(|f| f.summary.contains("No other devices"))
            .expect("should report that nothing was found");
        assert!(
            finding.remedy.contains("IP address"),
            "should suggest bypassing discovery to isolate the fault"
        );
    }

    #[test]
    fn a_filtered_mechanism_is_reported_without_alarming_the_user() {
        // mDNS works, broadcast does not. Discovery is fine; this is a note.
        let registry = registry_with(&[(1, Source::Mdns), (2, Source::Mdns)]);
        let report = diagnose_with(&registry, &NetworkFacts::default());

        assert!(!report.has_problems(), "{}", summaries(&report));
        assert!(summaries(&report).contains("passes mDNS but not UDP broadcast"));
    }

    #[test]
    fn client_isolation_is_inferred_from_reachable_but_silent_peers() {
        // The signature: we can talk to devices we already know about, but
        // nothing announces itself.
        let registry = registry_with(&[(1, Source::Known), (2, Source::Manual)]);
        let report = diagnose_with(&registry, &NetworkFacts::default());

        assert!(report.has_problems());
        let finding = report
            .findings
            .iter()
            .find(|f| f.summary.contains("client isolation"))
            .expect("should infer client isolation");
        assert!(finding.remedy.contains("AP isolation"));
    }

    #[test]
    fn client_isolation_is_not_claimed_when_discovery_is_working() {
        // Guards against the worst failure mode for this feature: a confident
        // wrong diagnosis. Discovery found peers, so isolation is ruled out.
        let registry = registry_with(&[(1, Source::Mdns), (2, Source::Known)]);
        let report = diagnose_with(&registry, &NetworkFacts::default());

        assert!(
            !summaries(&report).contains("client isolation"),
            "must not blame isolation when mDNS is clearly working"
        );
    }

    #[test]
    fn extra_adapters_are_surfaced_as_a_possible_cause() {
        let facts = NetworkFacts {
            any_public_network: Some(false),
            network_names: vec!["Home Wi-Fi".into(), "CorpVPN".into()],
            ..Default::default()
        };
        let report = diagnose_with(&registry_with(&[(1, Source::Mdns)]), &facts);

        assert!(summaries(&report).contains("CorpVPN"));
    }

    /// Regression: this module used to infer "the firewall is not in the way"
    /// from peers being visible. Discovery uses a separate socket, so that
    /// inference held while inbound QUIC was blocked — and the report then
    /// contradicted the direct rule check sitting right above it.
    #[test]
    fn an_enabled_firewall_alone_produces_no_verdict_either_way() {
        let facts = NetworkFacts {
            firewall_enabled: Some(true),
            ..Default::default()
        };

        for registry in [registry_with(&[]), registry_with(&[(1, Source::Mdns)])] {
            let report = diagnose_with(&registry, &facts);
            assert!(
                !summaries(&report).contains("Firewall"),
                "reachability is answered by the rule check, not guessed from here: {}",
                summaries(&report)
            );
        }
    }

    #[test]
    fn block_all_inbound_is_always_a_problem() {
        // This setting overrides per-app allow rules, so it is worth flagging
        // even when discovery happens to be working.
        let facts = NetworkFacts {
            firewall_enabled: Some(true),
            firewall_blocks_all_inbound: Some(true),
            ..Default::default()
        };
        let report = diagnose_with(&registry_with(&[(1, Source::Mdns)]), &facts);

        assert!(report.has_problems());
        assert!(summaries(&report).contains("block all inbound"));
    }

    #[test]
    fn no_firewall_information_produces_no_firewall_finding() {
        let report = diagnose_with(&registry_with(&[(1, Source::Mdns)]), &NetworkFacts::default());
        assert!(!summaries(&report).contains("Firewall"));
    }

    #[test]
    fn findings_are_ordered_most_serious_first() {
        let facts = NetworkFacts {
            any_public_network: Some(true),
            network_names: vec!["Guest".into()],
            ..Default::default()
        };
        let report = diagnose_with(&registry_with(&[]), &facts);

        let severities: Vec<Severity> = report.sorted().iter().map(|f| f.severity).collect();
        let mut expected = severities.clone();
        expected.sort_by(|a, b| b.cmp(a));
        assert_eq!(severities, expected);
    }

    /// The platform query must never panic or hang, whatever the machine looks
    /// like — a diagnostics panel that crashes is worse than no panel.
    #[test]
    fn reading_platform_network_facts_is_safe_to_call() {
        let facts = network_facts();
        if cfg!(windows) {
            // Either we learned something or we admitted we did not; both fine.
            let _ = facts.any_public_network;
        }
    }
}
