//! Establishment-path unit tests: riding the live session, the
//! operator-connect wait, the IP-filter refusals (literal and post-resolve),
//! the link a login takes under the Obfuscation Policy, and the peer
//! handshake context's literal-vs-DNS connected-server projection.

use tokio::sync::mpsc;

use super::super::tests::{FakeLink, client_id, identity, test_sinks};
use super::*;
use crate::own_identity::SharedOwnIdentity;
use crate::server_session::multiplexer::ServerSession;

/// No activity dials (ADR-0095, "Connecting is the operator's act"): the
/// live handle is ridden when there is one, and an empty slot answers
/// nothing rather than a login.
#[tokio::test]
async fn live_session_rides_the_live_handle_and_never_dials() {
    let shared = SharedServerSession::default();
    assert!(
        shared.live_session().await.is_none(),
        "no session: nothing to ride, and nothing is dialed"
    );
    let (_evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    *shared.slot().lock().await = Some(handle);
    let ridden = shared.live_session().await.expect("the live handle");
    assert_eq!(ridden.client_id(), client_id());
}

/// The connect/search race, the switch-flavored variant: while an operator connect is
/// in flight, `live_session` waits for it even when a live handle sits
/// in the slot — that handle is the session the connect is about to kill,
/// and riding it would hand the activity a doomed stream. The claim drop
/// is the release, whereupon the activity reads the slot as usual.
#[tokio::test]
async fn live_session_waits_out_an_operator_connect_before_reading_the_slot() {
    let (_evt_tx, evt_rx) = mpsc::channel(8);
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    let handle = ServerSession::spawn(
        FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        },
        client_id(),
        test_sinks(SharedOwnIdentity::default()),
    );
    let shared = SharedServerSession::default();
    *shared.slot().lock().await = Some(handle);

    let claim = shared.claim_connect();
    let waiting = {
        let shared = shared.clone();
        tokio::spawn(async move { shared.live_session().await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !waiting.is_finished(),
        "the activity parks while the operator connect holds the claim"
    );

    drop(claim);
    let reused = tokio::time::timeout(std::time::Duration::from_secs(2), waiting)
        .await
        .expect("the claim drop releases the waiter")
        .expect("the waiter task did not panic")
        .expect("the live slot handle is reused");
    assert_eq!(reused.client_id(), client_id());
}

#[tokio::test]
async fn connect_refuses_a_filtered_server_without_dialing() {
    // The IP filter, aMule `CServerSocket::OnHostnameResolved`: a filtered
    // server IP is never connected to. The distinct `ServerFiltered`
    // failure is the proof the *gate* fired — a dial to unbindable port 1
    // would fail as `ServerDisconnected` instead.
    let (filter, _) = crate::ip_filter::IpFilter::from_texts(
        &[b"127.0.0.0-127.0.0.255,0,loopback blocked\n".as_slice()],
        127,
        true,
        true,
    );
    let shared_filter = SharedIpFilter::default();
    *shared_filter.write().expect("ip filter lock") = filter;

    let refused = connect_to_server(
        &SharedServerSession::default(),
        ServerEndpoint::new("127.0.0.1", 1).unwrap(),
        identity(),
        &shared_filter,
    )
    .await;
    assert!(
        matches!(refused, Err(DownloadFailure::ServerFiltered)),
        "the filter gate refuses before any dial"
    );

    // The same dial with server filtering off reaches the connect and
    // fails as a plain disconnect — the gate honors its config switch.
    let (servers_off, _) = crate::ip_filter::IpFilter::from_texts(
        &[b"127.0.0.0-127.0.0.255,0,loopback blocked\n".as_slice()],
        127,
        true,
        false,
    );
    *shared_filter.write().expect("ip filter lock") = servers_off;
    let dialed = connect_to_server(
        &SharedServerSession::default(),
        ServerEndpoint::new("127.0.0.1", 1).unwrap(),
        identity(),
        &shared_filter,
    )
    .await;
    assert!(
        matches!(dialed, Err(DownloadFailure::ServerDisconnected)),
        "with the server gate off the dial proceeds and fails as a plain disconnect"
    );
}

#[tokio::test]
async fn connect_refuses_a_dns_named_server_whose_resolved_ip_is_filtered() {
    // aMule's check is post-resolve (`CServerSocket::OnHostnameResolved`,
    // ServerSocket.cpp:737) and DynIP names are exempt only at add time:
    // a *named* server whose A record lands in a blocked range is refused
    // too. `localhost` resolves to 127.0.0.1 everywhere this suite runs.
    let (filter, _) = crate::ip_filter::IpFilter::from_texts(
        &[b"127.0.0.0-127.0.0.255,0,loopback blocked\n".as_slice()],
        127,
        true,
        true,
    );
    let shared_filter = SharedIpFilter::default();
    *shared_filter.write().expect("ip filter lock") = filter;

    let refused = connect_to_server(
        &SharedServerSession::default(),
        ServerEndpoint::new("localhost", 1).unwrap(),
        identity(),
        &shared_filter,
    )
    .await;
    assert!(
        matches!(refused, Err(DownloadFailure::ServerFiltered)),
        "the resolved address is checked, not just a literal host"
    );
}

#[test]
fn handshake_context_resolves_an_ipv4_literal_server() {
    let server = ServerEndpoint::new("198.51.100.7", 4661).unwrap();
    let ctx = build_peer_handshake_context(client_id(), &server, &identity());
    assert_eq!(
        ctx.connected_server,
        Some(Ipv4Endpoint::new("198.51.100.7".parse().unwrap(), 4661)),
    );
    assert_eq!(ctx.client_id, client_id());
}

#[test]
fn handshake_context_leaves_a_dns_host_server_unresolved() {
    let server = ServerEndpoint::new("ed2k.example.invalid", 4661).unwrap();
    let ctx = build_peer_handshake_context(client_id(), &server, &identity());
    assert_eq!(ctx.connected_server, None);
}

/// A **Half-Bound Pair** advertises no port it cannot back:
/// the login's `0xF9` claims we can be punched, and a punch is IPv4 end
/// to end, so a client-UDP pair that came up on `::` alone contributes
/// nothing here and the tag is omitted rather than sent with a port no
/// IPv4 datagram can reach.
#[test]
fn the_login_advert_names_no_ipv4_udp_port_a_half_bound_pair_does_not_hold() {
    let addresses = crate::address_learning::SharedAddressLearning::new();
    addresses.record_bind(
        SocketRole::Udp,
        &rmule_net::family::FamilyBinds {
            bound: vec![AddressFamily::V6],
            refused: vec![(
                AddressFamily::V4,
                std::io::ErrorKind::AddrInUse,
                "in use".to_owned(),
            )],
        },
        4672,
    );
    assert_eq!(bound_ipv4_port(&addresses, SocketRole::Udp), None);
    assert_eq!(
        crate::natt::server_punch::udp_ports_advert(
            bound_ipv4_port(&addresses, SocketRole::Udp),
            None
        ),
        None,
        "no IPv4 client-UDP port means no 0xF9 tag at all — its presence is the flag"
    );
}

/// The mirror: a pair that holds IPv4 and lost only IPv6 advertises
/// exactly as it always did.
#[test]
fn the_login_advert_is_untouched_when_only_ipv6_refused() {
    let addresses = crate::address_learning::SharedAddressLearning::new();
    addresses.record_bind(
        SocketRole::Udp,
        &rmule_net::family::FamilyBinds {
            bound: vec![AddressFamily::V4],
            refused: vec![(
                AddressFamily::V6,
                std::io::ErrorKind::AddrInUse,
                "in use".to_owned(),
            )],
        },
        4672,
    );
    assert_eq!(bound_ipv4_port(&addresses, SocketRole::Udp), Some(4672));
}

/// The login's `0xF9` client-UDP half names the owner's current external
/// port, exactly like every hello's (ADR-0084): a
/// mapping grant learned after the bind reaches the very next login
/// frame, not just the next hello — `establish`'s own expression, not a
/// re-derivation of it.
#[test]
fn a_mapping_grant_after_the_bind_reaches_the_next_login_frame() {
    use std::time::Duration;

    use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};

    use crate::address_learning::AddressObservation;

    let addresses = crate::address_learning::SharedAddressLearning::new();
    addresses.record_bind(
        SocketRole::Udp,
        &rmule_net::family::FamilyBinds {
            bound: vec![AddressFamily::V4],
            refused: Vec::new(),
        },
        4672,
    );
    assert_eq!(
        effective_client_udp_port(&addresses, SocketRole::Udp),
        Some(4672),
        "nothing learned: the bound port, same as before login-config build"
    );

    let ours: Ipv4Addr = "203.0.113.50".parse().unwrap();
    addresses.observe(AddressObservation::mapping_grant(
        SocketRole::Udp,
        PeerEndpoint::V4(Ipv4Endpoint::new(ours, 24672)),
        Duration::from_secs(3600),
    ));

    assert_eq!(
        effective_client_udp_port(&addresses, SocketRole::Udp),
        Some(24672),
        "a grant learned after the bind rides the login's 0xF9, not the bound port"
    );
    assert_eq!(
        crate::natt::server_punch::udp_ports_advert(
            effective_client_udp_port(&addresses, SocketRole::Udp),
            None
        ),
        Some(rmule_ed2k::UdpPortsAdvert {
            kad_udp: 0,
            client_udp: 24672,
        }),
        "the login frame itself carries the external port"
    );
}

/// The login's `0xF9` Kad half reads the same cell `retire_kad` clears
/// The exact expression `establish` feeds
/// `server_punch::udp_ports_advert` sees `None` once the pump has died,
/// not the stale port — the login omits the Kad half exactly as if Kad
/// had never run.
#[test]
fn the_login_advert_reads_a_cleared_kad_half_as_not_running() {
    let advert = crate::adapters::SharedUdpPortsAdvert::default();
    advert.set_serving(4672);
    advert.set_kad(4672);
    advert.clear_kad();

    let kad_udp_port = advert
        .get()
        .map(|ports| ports.kad_udp())
        .filter(|port| *port != 0);
    assert_eq!(
        kad_udp_port, None,
        "a cleared Kad half must not survive into the login advert"
    );
    assert_eq!(
        crate::natt::server_punch::udp_ports_advert(Some(4672), kad_udp_port),
        Some(rmule_ed2k::UdpPortsAdvert {
            kad_udp: 0,
            client_udp: 4672,
        }),
        "the 0xF9 tag carries the serving port and a dead Kad's zero"
    );
}

/// A list holding only `server`, reporting every login step to the receiver.
/// The sender is returned because the facts hold it weakly.
fn facts_listing(
    server: &ServerEndpoint,
) -> (
    crate::server_list::ServerFacts,
    mpsc::Sender<crate::CoreEvent>,
    mpsc::Receiver<crate::CoreEvent>,
) {
    use crate::server_list::ServerListStore;
    let store = crate::DurableAppConfig::new(
        crate::open_durable_store_in_memory().expect("the in-memory store opens"),
    );
    store
        .merge_server(crate::server_list::ManagedServer::listed(server.clone()))
        .expect("seed the list");
    let (events_tx, events_rx) = mpsc::channel(64);
    let facts = crate::server_list::ServerFacts::new(
        std::sync::Arc::new(store),
        crate::diagnostics::DiagnosticsState::new(),
        Some(events_tx.downgrade()),
    );
    (facts, events_tx, events_rx)
}

/// A list holding `server`, whose last status answer named `obfuscation_port`
/// as its obfuscation TCP port and carried `TCPOBFUSCATION` in its UDP flags,
/// reporting every login step to the receiver.
async fn facts_saying_obfuscated(
    server: &ServerEndpoint,
    obfuscation_port: u16,
) -> (
    crate::server_list::ServerFacts,
    mpsc::Sender<crate::CoreEvent>,
    mpsc::Receiver<crate::CoreEvent>,
) {
    let (facts, events_tx, events_rx) = facts_listing(server);
    let mut datagram = vec![0xE3, rmule_ed2k::Opcode::GlobServStatRes.as_u8()];
    let udp_flags = rmule_ed2k::ServerUdpFlags::TCPOBFUSCATION;
    for word in [0x55AA_0001_u32, 1, 2, 3, 4, 5, udp_flags, 6] {
        datagram.extend_from_slice(&word.to_le_bytes());
    }
    datagram.extend_from_slice(&(obfuscation_port + 1).to_le_bytes());
    datagram.extend_from_slice(&obfuscation_port.to_le_bytes());
    datagram.extend_from_slice(&0xABCD_1234_u32.to_le_bytes());
    let status = rmule_ed2k::GlobServStatRes::decode_udp(&datagram).expect("a status answer");
    facts
        .answered(server, std::time::Duration::from_millis(5), &status, None)
        .await
        .expect("the answer is kept");
    (facts, events_tx, events_rx)
}

/// Every login step reported so far, in order.
fn login_steps(events: &mut mpsc::Receiver<crate::CoreEvent>) -> Vec<LoginStep> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            crate::CoreEvent::ServerLogin { step, .. } => Some(step),
            _ => None,
        })
        .collect()
}

/// A session cell under `policy` whose list is `facts`.
fn session_under(
    policy: Option<rmule_net::peer::ObfuscationPolicy>,
    facts: crate::server_list::ServerFacts,
) -> SharedServerSession {
    let shared = SharedServerSession::default();
    shared.install_facts(facts);
    shared.obfuscation().set(policy);
    shared
}

/// Under `Requested`, a server whose status answer named an obfuscation port
/// and `TCPOBFUSCATION` is dialed there, the crypt handshake runs, and the
/// login is answered over it (aMule `ServerSocket.cpp:786-791`).
#[tokio::test]
async fn a_requesting_policy_logs_in_obfuscated_where_the_server_said_it_takes_it() {
    let fake = rmule_testkit::FakeEd2kServer::start_obfuscated().await;
    let port = fake.local_addr().port();
    let (facts, _events_tx, mut events) = facts_saying_obfuscated(&fake.endpoint(), port).await;
    let shared = session_under(Some(rmule_net::peer::ObfuscationPolicy::Requested), facts);

    connect_to_server(
        &shared,
        fake.endpoint(),
        identity(),
        &SharedIpFilter::default(),
    )
    .await
    .expect("the obfuscated login is answered");

    let steps = login_steps(&mut events);
    assert_eq!(
        steps.first(),
        Some(&LoginStep::LinkChosen {
            link: LoginLink::Obfuscated { port }
        })
    );
    assert!(
        steps
            .iter()
            .any(|step| matches!(step, LoginStep::Answered { .. })),
        "the login was answered: {steps:?}"
    );
    assert_eq!(
        fake.obfuscated_sessions().await,
        1,
        "the server served it over crypt"
    );
}

/// A server listed by DNS name is one the status ping never reaches, so its
/// first login is plain; the obfuscation port its `OP_IDCHANGE` offered and the
/// `TCPOBFUSCATION` it granted are kept on the row, and the second login is
/// dialed obfuscated (aMule `ServerSocket.cpp:333-341`).
#[tokio::test]
async fn a_server_known_only_by_name_is_dialed_obfuscated_on_its_second_login() {
    let fake = rmule_testkit::FakeEd2kServer::start_obfuscated().await;
    let port = fake.local_addr().port();
    fake.set_tcp_flags(Some(rmule_ed2k::ServerTcpFlags::from_bits(
        rmule_ed2k::ServerTcpFlags::TCPOBFUSCATION,
    )))
    .await;
    fake.set_obfuscation_offer(Some(port)).await;
    let named = ServerEndpoint::new("localhost", port).expect("a named endpoint");
    let (facts, _events_tx, mut events) = facts_listing(&named);
    let shared = session_under(Some(rmule_net::peer::ObfuscationPolicy::Requested), facts);

    for _ in 0..2 {
        connect_to_server(
            &shared,
            named.clone(),
            identity(),
            &SharedIpFilter::default(),
        )
        .await
        .expect("the login is answered");
    }

    let links: Vec<_> = login_steps(&mut events)
        .into_iter()
        .filter_map(|step| match step {
            LoginStep::LinkChosen { link } => Some(link),
            _ => None,
        })
        .collect();
    assert_eq!(
        links,
        [
            LoginLink::Plain {
                why: crate::PlainLinkReason::ServerNotKnownToObfuscate
            },
            LoginLink::Obfuscated { port },
        ]
    );
    assert_eq!(fake.obfuscated_sessions().await, 1);
}

/// The login answer a live stock ed2k-server sent (run `1791815836`,
/// `sweep-792` announce-switch publisher marker, `idchange_hex`) names its
/// obfuscation TCP port 4661 and grants `TCPOBFUSCATION`: the row keeps the
/// port, so the next login is dialed obfuscated.
#[tokio::test]
async fn a_live_login_answers_obfuscation_port_lands_on_the_row() {
    let fake = rmule_testkit::FakeEd2kServer::start_obfuscated().await;
    fake.set_raw_id_change(vec![
        0xcb, 0x00, 0x71, 0x03, 0xdd, 0x05, 0x00, 0x00, 0x35, 0x12, 0x00, 0x00, 0xcb, 0x00, 0x71,
        0xc8, 0x35, 0x12, 0x00, 0x00,
    ])
    .await;
    let dialed = fake.local_addr().port();
    let listed = ServerEndpoint::new("localhost", dialed).expect("a named endpoint");
    let (facts, _events_tx, _events) = facts_listing(&listed);
    let shared = session_under(
        Some(rmule_net::peer::ObfuscationPolicy::Requested),
        facts.clone(),
    );

    connect_to_server(
        &shared,
        listed.clone(),
        identity(),
        &SharedIpFilter::default(),
    )
    .await
    .expect("the login is answered");

    let rows = facts.listed().expect("the list reads");
    let crypt = rows[0].udp_crypt.expect("the answer's port is kept");
    assert_eq!(crypt.obfuscation_tcp_port, 4661);
    assert_eq!(rows[0].obfuscation_tcp_port(), Some(4661));
}

/// An aux-port login names the server's standard port beside the obfuscation
/// offer; the row dialed on another port is re-ported to it, which is the port
/// every server-UDP datagram is then aimed from.
#[tokio::test]
async fn an_aux_port_login_re_ports_the_row_to_the_standard_port() {
    let fake = rmule_testkit::FakeEd2kServer::start_obfuscated().await;
    let dialed = fake.local_addr().port();
    let standard = if dialed == 4661 { 4662 } else { 4661 };
    fake.set_tcp_flags(Some(rmule_ed2k::ServerTcpFlags::from_bits(
        rmule_ed2k::ServerTcpFlags::TCPOBFUSCATION,
    )))
    .await;
    fake.set_obfuscation_offer(Some(dialed)).await;
    fake.set_aux_port_login(standard).await;
    let listed = ServerEndpoint::new("127.0.0.1", dialed).expect("an endpoint");
    let (facts, _events_tx, _events) = facts_listing(&listed);
    let shared = session_under(None, facts.clone());

    connect_to_server(
        &shared,
        listed.clone(),
        identity(),
        &SharedIpFilter::default(),
    )
    .await
    .expect("the login is answered");

    let rows = facts.listed().expect("the list reads");
    assert_eq!(rows[0].endpoint, listed, "the dialed port stays the key");
    assert_eq!(rows[0].standard_endpoint().port(), standard);
    assert_eq!(
        shared
            .own_identity()
            .connected_session()
            .and_then(|s| s.server),
        Some(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, standard)),
        "our hello names the server by its standard port, not the dialed one"
    );
}

/// Off, the same server is dialed plain: obfuscation is never initiated by a
/// policy that does not ask for it.
#[tokio::test]
async fn an_unset_policy_dials_plain_a_server_that_takes_obfuscation() {
    let fake = rmule_testkit::FakeEd2kServer::start_obfuscated().await;
    let port = fake.local_addr().port();
    let (facts, _events_tx, mut events) = facts_saying_obfuscated(&fake.endpoint(), port).await;
    let shared = session_under(None, facts);

    connect_to_server(
        &shared,
        fake.endpoint(),
        identity(),
        &SharedIpFilter::default(),
    )
    .await
    .expect("the plain login is answered");

    assert_eq!(
        login_steps(&mut events).first(),
        Some(&LoginStep::LinkChosen {
            link: LoginLink::Plain {
                why: crate::PlainLinkReason::PolicyDoesNotInitiate
            }
        })
    );
    assert_eq!(fake.obfuscated_sessions().await, 0);
}

/// `Requested` falls back to plain when the obfuscated attempt fails — here a
/// server that does not take obfuscation where its row said it would — and
/// the trail names both links (aMule `ServerConnect.cpp:465-470`).
#[tokio::test]
async fn requested_falls_back_to_plain_after_a_failed_obfuscated_attempt() {
    let fake = rmule_testkit::FakeEd2kServer::start_scripted().await;
    let port = fake.local_addr().port();
    let (facts, _events_tx, mut events) = facts_saying_obfuscated(&fake.endpoint(), port).await;
    let shared = session_under(Some(rmule_net::peer::ObfuscationPolicy::Requested), facts);

    connect_to_server(
        &shared,
        fake.endpoint(),
        identity(),
        &SharedIpFilter::default(),
    )
    .await
    .expect("the plain fallback is answered");

    let steps = login_steps(&mut events);
    assert!(
        matches!(
            steps.as_slice(),
            [
                LoginStep::LinkChosen {
                    link: LoginLink::Obfuscated { .. }
                },
                LoginStep::DialFailed {
                    cause: DialFailure::CryptHandshake { .. }
                },
                LoginStep::LinkChosen {
                    link: LoginLink::Plain {
                        why: crate::PlainLinkReason::ObfuscatedAttemptFailed
                    }
                },
                ..
            ]
        ),
        "obfuscated, failed, then plain: {steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|step| matches!(step, LoginStep::Answered { .. }))
    );
}

/// `Required` withholds that fallback: the failed obfuscated attempt is the
/// connect's failure.
#[tokio::test]
async fn required_withholds_the_plain_fallback() {
    let fake = rmule_testkit::FakeEd2kServer::start_scripted().await;
    let port = fake.local_addr().port();
    let (facts, _events_tx, mut events) = facts_saying_obfuscated(&fake.endpoint(), port).await;
    let shared = session_under(Some(rmule_net::peer::ObfuscationPolicy::Required), facts);

    let failed = connect_to_server(
        &shared,
        fake.endpoint(),
        identity(),
        &SharedIpFilter::default(),
    )
    .await;

    assert!(failed.is_err(), "no plain login under Required");
    let steps = login_steps(&mut events);
    assert!(
        matches!(
            steps.as_slice(),
            [
                LoginStep::LinkChosen {
                    link: LoginLink::Obfuscated { .. }
                },
                LoginStep::DialFailed {
                    cause: DialFailure::CryptHandshake { .. }
                },
            ]
        ),
        "one obfuscated attempt and no other: {steps:?}"
    );
}
