//! End-to-end checks on the authenticated QUIC handshake.
//!
//! These run two real endpoints over loopback. The point is to prove the
//! security property the whole product rests on — that a peer is identified by
//! the key it holds and nothing else — rather than to unit-test the pieces.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use jetstream_core::identity::Identity;
use jetstream_core::transport::{Endpoint, Session};
use jetstream_core::{DeviceId, Error};

/// Bind a fresh device on loopback with an OS-assigned port.
fn spawn_device(name: &str) -> (Endpoint, DeviceId, SocketAddr) {
    let identity = Arc::new(Identity::generate().expect("generate identity"));
    let device_id = identity.device_id();

    let endpoint = Endpoint::bind(
        identity,
        name,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("bind endpoint");

    let addr = endpoint.local_addr().expect("local addr");
    (endpoint, device_id, addr)
}

/// Accept exactly one session in the background.
fn accept_one(endpoint: Endpoint) -> tokio::task::JoinHandle<Arc<Session>> {
    tokio::spawn(async move {
        endpoint
            .accept()
            .await
            .expect("endpoint closed before a connection arrived")
            .expect("inbound handshake failed")
    })
}

/// Everything in this suite should settle in milliseconds on loopback. A
/// generous timeout still turns a deadlock into a failure rather than a hang.
async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("timed out")
}

#[tokio::test]
async fn both_sides_learn_each_others_proven_identity() {
    let (alice, alice_id, _) = spawn_device("Alice");
    let (bob, bob_id, bob_addr) = spawn_device("Bob");

    let inbound = accept_one(bob);
    let outbound = within(alice.connect(bob_addr, Some(bob_id))).await.unwrap();
    let received = within(inbound).await.unwrap();

    assert_eq!(outbound.peer().device_id, bob_id, "dialer identified the listener");
    assert_eq!(received.peer().device_id, alice_id, "listener identified the dialer");

    assert_eq!(outbound.peer().name, "Bob");
    assert_eq!(received.peer().name, "Alice");
}

#[tokio::test]
async fn first_contact_without_a_pin_still_yields_a_verified_identity() {
    // Pairing flow: we do not know the id yet, so we connect unpinned and show
    // the user the fingerprint we observed. It must still be the real one.
    let (alice, _, _) = spawn_device("Alice");
    let (bob, bob_id, bob_addr) = spawn_device("Bob");

    let inbound = accept_one(bob);
    let session = within(alice.connect(bob_addr, None)).await.unwrap();
    within(inbound).await.unwrap();

    assert_eq!(session.peer().device_id, bob_id);
    assert_eq!(
        session.peer().device_id.fingerprint(),
        bob_id.fingerprint(),
        "the fingerprint shown to the user must be the peer's real one"
    );
}

#[tokio::test]
async fn connecting_to_the_wrong_device_is_refused() {
    // The impersonation case: something answers at the address we remembered,
    // but it is not the device the user paired with. This must fail loudly,
    // not silently connect.
    let (alice, _, _) = spawn_device("Alice");
    let (bob, _, bob_addr) = spawn_device("Bob");
    let (_, mallory_id, _) = spawn_device("Mallory");

    let _inbound = accept_one(bob);
    let err = within(alice.connect(bob_addr, Some(mallory_id)))
        .await
        .expect_err("handshake must fail when the pinned identity does not match");

    let message = err.to_string();
    assert!(
        message.contains(&mallory_id.short()),
        "the error should name the device we expected, got: {message}"
    );
}

#[tokio::test]
async fn a_rejected_peer_does_not_take_down_the_listener() {
    // One peer failing to authenticate must not stop the daemon from serving
    // everybody else.
    let (bob, bob_id, bob_addr) = spawn_device("Bob");
    let (mallory, _, _) = spawn_device("Mallory");
    let (alice, alice_id, _) = spawn_device("Alice");

    let listener = {
        let bob = bob.clone();
        tokio::spawn(async move {
            // First arrival is Mallory, who will be rejected client-side.
            let _ = bob.accept().await;
            // The listener must still be alive for the next caller.
            bob.accept()
                .await
                .expect("listener stopped accepting")
                .expect("second handshake failed")
        })
    };

    let wrong_id = DeviceId::from_bytes([0xAB; 32]);
    let _ = within(mallory.connect(bob_addr, Some(wrong_id))).await;

    let session = within(alice.connect(bob_addr, Some(bob_id))).await.unwrap();
    let served = within(listener).await.unwrap();

    assert_eq!(session.peer().device_id, bob_id);
    assert_eq!(served.peer().device_id, alice_id);
}

#[tokio::test]
async fn control_channel_round_trips() {
    let (alice, _, _) = spawn_device("Alice");
    let (bob, bob_id, bob_addr) = spawn_device("Bob");

    let inbound = accept_one(bob);
    let session = within(alice.connect(bob_addr, Some(bob_id))).await.unwrap();
    let peer = within(inbound).await.unwrap();

    // Bob answers pings for the duration of the test.
    tokio::spawn(async move {
        while let Ok(message) = peer.recv_control().await {
            if let jetstream_core::proto::Control::Ping(nonce) = message {
                let _ = peer
                    .send_control(&jetstream_core::proto::Control::Pong(nonce))
                    .await;
            }
        }
    });

    let rtt = within(session.ping()).await.expect("ping failed");
    assert!(rtt < Duration::from_secs(5), "implausible loopback rtt: {rtt:?}");
}

#[tokio::test]
async fn a_hostile_display_name_cannot_disguise_itself() {
    // Peers choose their own display name. A name containing a bidi override
    // could render as a different device entirely in the peer list, so the
    // session must hand the UI something already defanged.
    let identity = Arc::new(Identity::generate().unwrap());
    let hostile = Endpoint::bind(
        identity,
        "\u{202E}suoicilam\nDevice",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let hostile_addr = hostile.local_addr().unwrap();

    let (alice, _, _) = spawn_device("Alice");
    let _inbound = accept_one(hostile);
    let session = within(alice.connect(hostile_addr, None)).await.unwrap();

    let name = &session.peer().name;
    assert!(!name.contains('\u{202E}'), "bidi override survived: {name:?}");
    assert!(!name.contains('\n'), "newline survived: {name:?}");
}

/// Regression: `bind_all` binds the IPv6 wildcard, and Windows defaults
/// `IPV6_V6ONLY` to on — so the endpoint accepted IPv6 only and silently
/// refused every IPv4 peer. The app advertised itself, appeared in peer lists,
/// and could not receive anything. Found by running two real instances.
#[tokio::test]
async fn an_endpoint_bound_to_all_interfaces_accepts_ipv4() {
    let identity = Arc::new(Identity::generate().unwrap());
    let listener_id = identity.device_id();

    // Port 0: an ephemeral port, so this never collides with a running app.
    let listener = Endpoint::bind_all(identity, "Dual Stack", 0).expect("bind all interfaces");
    let port = listener.local_addr().unwrap().port();

    let inbound = accept_one(listener);

    let (dialer, _, _) = spawn_device("IPv4 Dialer");
    let session = within(dialer.connect(
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        Some(listener_id),
    ))
    .await
    .expect("an IPv4 peer must be able to reach a wildcard-bound endpoint");

    assert_eq!(session.peer().device_id, listener_id);
    within(inbound).await.unwrap();
}

#[tokio::test]
async fn an_endpoint_bound_to_all_interfaces_also_accepts_ipv6() {
    use std::net::Ipv6Addr;

    let identity = Arc::new(Identity::generate().unwrap());
    let listener_id = identity.device_id();
    let listener = Endpoint::bind_all(identity, "Dual Stack", 0).unwrap();
    let port = listener.local_addr().unwrap().port();

    let inbound = accept_one(listener);

    let dialer = Endpoint::bind(
        Arc::new(Identity::generate().unwrap()),
        "IPv6 Dialer",
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let session = within(dialer.connect(
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        Some(listener_id),
    ))
    .await
    .expect("dual stack must not have cost us IPv6");

    assert_eq!(session.peer().device_id, listener_id);
    within(inbound).await.unwrap();
}

#[tokio::test]
async fn unreachable_peers_produce_an_actionable_error() {
    let (alice, _, _) = spawn_device("Alice");

    // Port 1 on loopback: nothing is listening, so this exercises the timeout
    // path a firewall-blocked peer would hit.
    let nowhere = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
    let result = tokio::time::timeout(
        Duration::from_secs(45),
        alice.connect(nowhere, None),
    )
    .await
    .expect("connect should give up on its own, not hang forever");

    let err = result.expect_err("connecting to nothing must fail");
    assert!(
        matches!(err, Error::Transport(_)),
        "expected a transport error, got {err:?}"
    );
}

/// A probe proves the key at an address without starting a session — which is
/// what lets a VPN peer be kept in the device list without the other side
/// seeing a stream of empty transfers.
#[tokio::test]
async fn a_probe_proves_the_key_and_starts_no_session() {
    let (prober, _, _) = spawn_device("Prober");
    let (target, target_id, target_addr) = spawn_device("Target");
    let (_, stranger_id, _) = spawn_device("Stranger");

    let accepting = tokio::spawn({
        let target = target.clone();
        async move { target.accept().await }
    });

    within(prober.probe(target_addr, target_id))
        .await
        .expect("the right device answering should pass");

    // The listener saw a connection that never became a session.
    let accepted = within(accepting).await.unwrap();
    assert!(
        matches!(accepted, Some(Err(_))),
        "a probe must not reach the application as a session"
    );

    // And the wrong key at that address is refused, as with a real connection.
    let accepting = tokio::spawn(async move { target.accept().await });
    assert!(within(prober.probe(target_addr, stranger_id)).await.is_err());
    accepting.abort();
}
