//! Kad-seam tests: the ed2k->Kad bootstrap handoff gate, the projection of a
//! Kad keyword row onto a search result, and the pump's ADR-0058 TCP-verdict
//! feed into the sans-I/O node.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rmule_peer::PeerIdentity;
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kText, Ipv4Endpoint, SearchResultOrigin, UserHash,
};
use tokio::sync::{Mutex, mpsc};

use super::*;
use crate::firewalled::recruit::RecruitRefusal;

/// The ed2k→Kad handoff broker's core-side decision (ADR-0067): the gate's
/// **running** leg (an empty sink drops the hint) and the projection that
/// pairs the peer's parsed Kad UDP port with the *live connection* IP (the
/// hello carries only the port). The peer-side `KadPort ∧ KadVersion > 1`
/// parse itself is proven in `rmule-peer`.
#[tokio::test]
async fn the_handoff_broker_gates_on_running_and_projects_the_connection_ip() {
    use rmule_peer::{MiscOptions2, PeerHelloBody};
    use rmule_primitives::{Tag, TagName, TagValue};

    let peer_ip = Ipv4Addr::new(198, 51, 100, 7);
    let peer = || PeerEndpoint::V4(Ipv4Endpoint::new(peer_ip, 4662));
    let peer_with_tags = |tags: Vec<Tag>| {
        PeerIdentity::from_hello_body(&PeerHelloBody {
            user_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            client_id: ClientId::from_u32(0),
            tcp_port: 4662,
            tags,
            connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
        })
    };
    // A peer advertising a Kad node: CT_EMULE_UDPPORTS kad half 4672 (high
    // 16), client half 4665 (low 16); Kad version 8 in MiscOptions2.
    let kad_peer = || {
        peer_with_tags(vec![
            Tag::new(
                TagName::compact_id(0xF9),
                TagValue::U32((4672u32 << 16) | 4665),
            ),
            MiscOptions2::from_bits(8).to_tag(),
        ])
    };

    let (tx, mut rx) = mpsc::channel::<Ipv4Endpoint>(4);
    let sink: SharedKadBootstrap = Arc::new(Mutex::new(None));

    // Kad not running (empty sink): the Kad-carrying peer's hint is dropped.
    broker_peer_kad_handoff(&sink, peer(), &kad_peer()).await;
    assert!(
        rx.try_recv().is_err(),
        "Kad not running ⇒ the hint is dropped"
    );

    // Kad running: install the sender (as the factory does on start). The
    // brokered endpoint is (live connection IP, parsed Kad UDP port).
    *sink.lock().await = Some(tx);
    broker_peer_kad_handoff(&sink, peer(), &kad_peer()).await;
    assert_eq!(
        rx.try_recv().ok(),
        Some(Ipv4Endpoint::new(peer_ip, 4672)),
        "a running node is brokered the peer's (connection IP, Kad UDP port)"
    );

    // A peer carrying no Kad hint is never brokered, even while running.
    broker_peer_kad_handoff(&sink, peer(), &peer_with_tags(Vec::new())).await;
    assert!(rx.try_recv().is_err(), "no Kad hint ⇒ nothing brokered");
}

fn keyword_row(
    complete_sources: Option<u32>,
    file_type: Option<&str>,
) -> rmule_kad::KadKeywordResult {
    rmule_kad::KadKeywordResult {
        file_id: rmule_kad::KadId::from_bytes([0x11; 16]),
        filename: Some("concert.mkv".to_owned()),
        size: Some(65_536),
        file_type: file_type.map(str::to_owned),
        complete_sources,
        publish_info: None,
    }
}

/// A Kad keyword row reaches the app with the counts and the classification
/// the storer served (without them every Kad-discovered row
/// rendered `Sources 0` / `Type —`). The count lands as
/// *availability* because that is what aMule's requester does with it.
#[test]
fn a_projected_kad_keyword_row_carries_its_source_count_and_type() {
    let projected = project_keyword_result(&keyword_row(Some(42), Some("Video")))
        .expect("a named, sized row projects");

    assert_eq!(projected.reported_availability(), Some(42));
    assert_eq!(
        projected.file_type().map(Ed2kText::to_display_string),
        Some("Video".to_owned())
    );
    assert_eq!(projected.origin(), SearchResultOrigin::Kad);
    assert!(
        projected.sources().is_empty(),
        "a keyword row carries a count, never endpoints"
    );
}

/// aMule's rogue-publisher guard (`Search.cpp:1035`): an implausible count
/// is zeroed rather than believed, and a row with no count at all stays
/// count-less so the merge can take another storer's figure.
#[test]
fn an_implausible_kad_availability_is_zeroed_and_a_missing_one_stays_absent() {
    let rogue = project_keyword_result(&keyword_row(Some(65_501), None)).unwrap();
    assert_eq!(rogue.reported_availability(), Some(0));

    let silent = project_keyword_result(&keyword_row(None, None)).unwrap();
    assert_eq!(silent.reported_availability(), None);
}

/// A keyword row the search cannot keep is dropped by its reason, never
/// silently: one above eD2k's 256 GiB limit, one with no name and one with no
/// size each say why, and the rows beside them stand. The rows are made here,
/// not captured.
#[test]
fn a_kad_keyword_row_that_cannot_stand_is_dropped_by_its_reason() {
    let oversize = rmule_kad::KadKeywordResult {
        size: Some(rmule_primitives::MAX_ED2K_FILE_SIZE + 1),
        ..keyword_row(Some(3), None)
    };
    let nameless = rmule_kad::KadKeywordResult {
        filename: None,
        ..keyword_row(None, None)
    };
    let sizeless = rmule_kad::KadKeywordResult {
        size: None,
        ..keyword_row(None, None)
    };
    let (rows, skipped) = project_keyword_rows(&[
        keyword_row(Some(5), None),
        oversize,
        nameless,
        sizeless,
        rmule_kad::KadKeywordResult {
            size: Some(rmule_primitives::MAX_ED2K_FILE_SIZE),
            ..keyword_row(None, None)
        },
    ]);

    assert_eq!(
        rows.iter().map(SearchResult::file_size).collect::<Vec<_>>(),
        [65_536, rmule_primitives::MAX_ED2K_FILE_SIZE]
    );
    assert_eq!(
        skipped,
        [
            SearchResultSkipReason::FileSizeAboveLimit,
            SearchResultSkipReason::MissingFileName,
            SearchResultSkipReason::MissingFileSize,
        ]
    );
}

/// Start the production Kad runtime over a loopback client-UDP bind, with no
/// bootstrap and no contacts — the posture of a home node that has just come
/// up behind a NAT. Returns the channel (kept alive by the caller: dropping it
/// tears the pump down) and the firewalled slot the recruit trigger writes.
async fn start_isolated_node(
    slot: &crate::firewalled::link::SharedFirewalledSlot,
) -> RuntimeKadChannel {
    let socket = Arc::new(
        rmule_net::ed2k::ClientUdpSocket::bind(0)
            .await
            .expect("a loopback client-UDP bind"),
    );
    let mut factory = RuntimeKadFactory::new(&{
        let cells = crate::adapters::AdapterCells::detached();
        cells
            .own_identity()
            .set_user_hash(UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]));
        cells
    })
    .with_firewalled(
        crate::adapters::HelloAdverts {
            firewalled_slot: slot.clone(),
            ..crate::adapters::HelloAdverts::default()
        },
        crate::firewalled::front::SharedFirewalledFront::default(),
    );
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-firewalled"),
        4662,
        60,
    );
    factory
        .start(
            &KadEnableConfig {
                kad_id: rmule_kad::KadId::from_bytes([0x11; rmule_kad::KadId::BYTE_LEN]),
                peer_credentials: identity.into(),
                bootstrap: Vec::new(),
                contacts: Vec::new(),
                nodes_dat_path: None,
                // The live posture: derive both verdicts, never declare them.
                assume_open_reachability: false,
                kad_udp_key: 0,
                kad_capture_dir: None,
                kad_shutdown: None,
            },
            ClientUdpBind {
                socket,
                kad_inlet: crate::client_udp::SharedKadInlet::default(),
                // The owner over this factory's own published verdicts,
                // exactly as the actor weaves it.
                reach: crate::reachability::SharedSelfReach::new(
                    factory.kad_reach(),
                    crate::own_identity::SharedOwnIdentity::default(),
                    crate::natt::front::SharedNattFront::default(),
                ),
            },
        )
        .await
        .expect("the Kad runtime starts over the bound client-UDP socket")
}

/// Poll the slot's recruit refusal until `wanted` reads true, and report how
/// long that took on the (paused) clock.
async fn refusal_settles(
    slot: &crate::firewalled::link::SharedFirewalledSlot,
    since: tokio::time::Instant,
    budget: Duration,
    wanted: impl Fn(Option<RecruitRefusal>) -> bool,
) -> Option<Duration> {
    tokio::time::timeout(budget, async {
        loop {
            if wanted(slot.recruit_refusal()) {
                return since.elapsed();
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .ok()
}

/// A firewalled node is told its own TCP verdict at Kad start, so the ADR-0058
/// UDP tester's six minutes run from the start and the ADR-0061 recruit gate
/// stops refusing `UdpUnverified` on its own.
///
/// The pump used to feed the sans-I/O node only TCP-verdict *edges*. A fresh
/// core store reads `Firewalled` and stays there, so no edge ever fired,
/// `UdpFirewallTester::check_timeout`'s conclude gate never saw a firewalled
/// TCP verdict, and the gate refused until the hourly recheck — measured at
/// 9.5 minutes behind a proven cone gateway, and only reached at
/// all there by forcing `RecheckReachability` from the driver.
#[tokio::test(start_paused = true)]
async fn a_firewalled_node_starts_the_udp_testers_clock_without_an_edge() {
    let slot = crate::firewalled::link::SharedFirewalledSlot::default();
    let started = tokio::time::Instant::now();
    let _channel = start_isolated_node(&slot).await;

    // The gate is live and has no UDP verdict yet: the pre-condition the fix
    // must not weaken (an unverified surface is not yet known to need a buddy).
    assert!(
        refusal_settles(&slot, started, Duration::from_secs(60), |refusal| refusal
            == Some(RecruitRefusal::UdpUnverified))
        .await
        .is_some(),
        "the recruit trigger refuses UdpUnverified while the tester runs"
    );

    // And it leaves that refusal on the tester's own six-minute budget, with
    // nothing forced — not an hour later on the recheck cadence.
    let settled = refusal_settles(&slot, started, Duration::from_secs(9 * 60), |refusal| {
        refusal != Some(RecruitRefusal::UdpUnverified)
    })
    .await
    .expect("the UDP tester concludes firewalled and the walk fires");
    assert!(
        settled >= Duration::from_secs(6 * 60) && settled < Duration::from_secs(7 * 60),
        "the recruit lands on the six-minute UDP budget measured from Kad start, not \
         on the hourly recheck: {settled:?}"
    );
}

/// `PublicIpFeed::sync` forwards Address Learning's IPv4 verdict to a real
/// running node: a contact's key, learned under the address the
/// feed had last told the node, retires the moment the feed re-syncs against
/// a moved verdict — the own key toward that same contact is unaffected.
///
/// Drives `PublicIpFeed` directly over a standalone `rmule_net::kad::spawn`
/// node rather than the full pump: the pump's own call sites (Kad start, the
/// recruit tick, the `AddressObserved` handler) are a few lines of plumbing
/// visible at the call sites in `node.rs`, and re-deriving them here would
/// mean waiting out a real 30 s recruit tick for no added assurance — the
/// wire effect a moved verdict must produce is exactly what this test pins.
#[tokio::test]
async fn public_ip_feed_sync_retires_a_learned_key_on_the_running_node() {
    use rmule_kad::{Kad2Message, Kad2NodeInfo, KadId, KadNodeConfig, udp_verify_key};
    use rmule_primitives::{ClientDecryptKeys, decrypt_datagram_client};
    use rmule_testkit::kad_node::{NODE_ID, crypt_to_node};

    use crate::adapters::kad_runtime::public_ip_feed::PublicIpFeed;

    const OWN_IP_A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 4);
    const OWN_IP_B: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const SEED: u32 = 0x0C0F_FEE5;
    let contact_id = KadId::from_bytes([0xC1; KadId::BYTE_LEN]);
    let sender_key: u32 = 0xABCD_0001;

    let own = crate::own_identity::SharedOwnIdentity::default();
    own.addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            OWN_IP_A,
        ));

    let handle = rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: KadNodeConfig {
                id: NODE_ID,
                tcp_port: 4662,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: true,
            verify_keys: Some((SEED, OWN_IP_A)),
            contact_admission: None,
        },
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .await
    .expect("a standalone crypt-armed Kad node starts");
    let mut ip_feed = PublicIpFeed::new(own.clone());
    // The pump's own start-time restatement: idempotent against
    // the `OWN_IP_A` the node was already armed with.
    ip_feed.sync(&handle);

    let peer_socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a loopback peer socket");

    // The peer hellos in keyed: the node learns and stores the sender key
    // bound to `OWN_IP_A`.
    let hello_req = Kad2Message::HelloReq(Kad2NodeInfo {
        id: contact_id,
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(peer_socket.local_addr().expect("bound").port()),
        misc_options: 0,
    })
    .encode()
    .encode();
    peer_socket
        .send_to(
            &crypt_to_node(&hello_req, 0, sender_key),
            handle.local_addr(),
        )
        .await
        .expect("send hello");

    // A plain LookupReq carries no fresh key of its own, so its LookupRes
    // rides the NodeID family keyed on the stored contact's own key — the
    // path that reads `own_public_ip`.
    let plain_lookup = |target| {
        Kad2Message::LookupReq {
            count: 1,
            target,
            check: NODE_ID,
        }
        .encode()
        .encode()
    };
    // The `LookupRes` toward `contact_id` among whatever the node sends: its
    // trailer's `(receiver_verify_key, sender_verify_key)`, once the reply
    // decrypts under the contact's own NodeID — the stored key it echoes
    // back, and the own key it hands this target, in one read.
    async fn lookup_res(peer_socket: &tokio::net::UdpSocket, contact_id: KadId) -> (u32, u32) {
        let mut buffer = vec![0u8; 2048];
        loop {
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(5), peer_socket.recv_from(&mut buffer))
                    .await
                    .expect("the node answers within budget")
                    .expect("recv");
            let Some(decrypted) = decrypt_datagram_client(
                &buffer[..len],
                &ClientDecryptKeys {
                    kad_id: Some(contact_id.as_bytes()),
                    ..ClientDecryptKeys::default()
                },
            ) else {
                continue; // some other reply family (a HELLO_RES, a ping)
            };
            let (rmule_kad::KadDecoded::Plain(envelope) | rmule_kad::KadDecoded::Packed(envelope)) =
                rmule_kad::decode_exact(&decrypted.payload).expect("a Kad envelope");
            if let Ok(Kad2Message::LookupRes { .. }) = Kad2Message::decode(&envelope) {
                return (
                    decrypted
                        .receiver_verify_key
                        .expect("a NodeID-keyed reply carries one"),
                    decrypted
                        .sender_verify_key
                        .expect("a NodeID-keyed reply carries one"),
                );
            }
        }
    }

    let SocketAddr::V4(peer_addr) = peer_socket.local_addr().expect("bound") else {
        panic!("loopback binds IPv4");
    };
    let own_key_for_peer = udp_verify_key(SEED, *peer_addr.ip());

    peer_socket
        .send_to(
            &plain_lookup(KadId::from_bytes([0xE0; KadId::BYTE_LEN])),
            handle.local_addr(),
        )
        .await
        .expect("send lookup");
    let (before_receiver, before_sender) = lookup_res(&peer_socket, contact_id).await;
    assert_eq!(
        before_receiver, sender_key,
        "the stored key echoes while the feed has told the node only OWN_IP_A"
    );
    assert_eq!(
        before_sender, own_key_for_peer,
        "the own key handed to this target: secret + target IP alone"
    );

    // The server re-assigns our public IP (`OP_IDCHANGE`, ADR-0084). The
    // feed forwards it immediately — no recruit tick to wait out here; the
    // pump's own tick call site is a documented, code-reviewed one-liner.
    own.addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            OWN_IP_B,
        ));
    ip_feed.sync(&handle);

    peer_socket
        .send_to(
            &plain_lookup(KadId::from_bytes([0xE1; KadId::BYTE_LEN])),
            handle.local_addr(),
        )
        .await
        .expect("send lookup");
    let (after_receiver, after_sender) = lookup_res(&peer_socket, contact_id).await;
    assert_eq!(
        after_receiver, 0,
        "the fed verdict retired the key learned under OWN_IP_A, exactly as aMule's \
         CKadUDPKey::GetKeyValue collapses to 0 once our own IP moves"
    );
    assert_eq!(
        after_sender, own_key_for_peer,
        "the own key handed to this same target is unaffected by our own IP moving \
         (GetUDPVerifyKey, Prefs.cpp:235-243, reads the target's IP alone)"
    );
}

/// `ExternPortFeed` owns the Extern Kad Port level the way `PublicIpFeed`
/// owns the own-IPv4 one: idempotent while the store's verdict
/// holds, and it restates the verdict once it moves — the wire mechanics of
/// a settled round following that restatement down to `0` are pinned at the
/// node's own level (`rmule-kad`'s `node_extern_port` tests), since the
/// store's 30-minute window ages out on real wall-clock time this feed
/// cannot fast-forward. This test pins the feed's own read-compare-tell
/// contract against the real store.
#[tokio::test]
async fn extern_port_feed_sync_is_idempotent_and_restates_on_a_store_change() {
    use crate::adapters::kad_runtime::extern_port_feed::ExternPortFeed;
    use crate::address_learning::{AddressObservation, SharedAddressLearning, SocketRole};

    let addresses = SharedAddressLearning::default();
    let handle = rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: rmule_kad::KadNodeConfig {
                id: rmule_kad::KadId::from_bytes([0x33; rmule_kad::KadId::BYTE_LEN]),
                tcp_port: 4662,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x44; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: true,
            verify_keys: None,
            contact_admission: None,
        },
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .await
    .expect("a standalone Kad node starts");
    let mut feed = ExternPortFeed::new(addresses.clone());

    // Nothing learned yet: the first sync states the "none" answer once.
    feed.sync(&handle);
    assert_eq!(feed.told(), Some(0));

    // Unchanged: a second sync costs no command.
    feed.sync(&handle);
    assert_eq!(feed.told(), Some(0));

    // Two agreeing observers give the store a fresh answer (ADR-0084's
    // port rung); the feed follows it on its very next sync.
    addresses.observe(AddressObservation::kad_observed_port(
        Ipv4Addr::new(203, 0, 113, 10),
        14672,
    ));
    addresses.observe(AddressObservation::kad_observed_port(
        Ipv4Addr::new(203, 0, 113, 11),
        14672,
    ));
    assert_eq!(addresses.learned_port(SocketRole::Udp), Some(14672));
    feed.sync(&handle);
    assert_eq!(feed.told(), Some(14672));
}

/// The round-boundary signal: `KadEvent::ExternPortRoundStarted`
/// reaches the pump as `ExternPortFeed::round_started`, which must forget the
/// store's UDP-role Kad port reports rather than let a report from before
/// the boundary back a fresh one named after it — aMule's
/// `FindExternKadPort(true)` starting every round's observer lists empty.
#[test]
fn extern_port_feed_round_started_forgets_the_store_s_kad_port_reports() {
    use crate::adapters::kad_runtime::extern_port_feed::ExternPortFeed;
    use crate::address_learning::{AddressObservation, SharedAddressLearning, SocketRole};

    let addresses = SharedAddressLearning::default();
    addresses.observe(AddressObservation::kad_observed_port(
        Ipv4Addr::new(203, 0, 113, 10),
        14672,
    ));
    addresses.observe(AddressObservation::kad_observed_port(
        Ipv4Addr::new(203, 0, 113, 11),
        14672,
    ));
    assert_eq!(addresses.learned_port(SocketRole::Udp), Some(14672));

    let mut feed = ExternPortFeed::new(addresses.clone());
    feed.round_started();

    assert_eq!(
        addresses.learned_port(SocketRole::Udp),
        None,
        "the round boundary forgot both reports; the port needs two fresh ones again"
    );
}

/// A datagram that opens with the Kad protocol byte but does not decode
/// `KadEvent::Diagnostic(UndecodableEnvelope)` must reach the
/// core as a counted, logged fact — not vanish into the adapter's catch-all
/// event arm, which is what left a crypt-armed bench verdict's own count
/// unfalsifiable in either direction.
#[tokio::test]
async fn an_undecodable_kad_envelope_counts_and_warns() {
    // A current-thread runtime (the `#[tokio::test]` default): every task this
    // test spawns polls on this one thread, so a thread-local subscriber set
    // for the test's duration sees them all, including the pump's own
    // `tokio::spawn`.
    let (log, _tracing) = rmule_testkit::capture_tracing(tracing::Level::WARN);

    let socket = Arc::new(
        rmule_net::ed2k::ClientUdpSocket::bind(0)
            .await
            .expect("a loopback client-UDP bind"),
    );
    let mut factory = RuntimeKadFactory::new(&{
        let cells = crate::adapters::AdapterCells::detached();
        cells
            .own_identity()
            .set_user_hash(UserHash::from_bytes([0x5B; UserHash::BYTE_LEN]));
        cells
    });
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    factory.install_diagnostics(diagnostics.clone());
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x5B; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-envelope"),
        4662,
        60,
    );
    let kad_inlet = crate::client_udp::SharedKadInlet::default();
    let _channel = factory
        .start(
            &KadEnableConfig {
                kad_id: rmule_kad::KadId::from_bytes([0x12; rmule_kad::KadId::BYTE_LEN]),
                peer_credentials: identity.into(),
                bootstrap: Vec::new(),
                contacts: Vec::new(),
                nodes_dat_path: None,
                assume_open_reachability: false,
                kad_udp_key: 0,
                kad_capture_dir: None,
                kad_shutdown: None,
            },
            ClientUdpBind {
                socket,
                kad_inlet: kad_inlet.clone(),
                // The owner over this factory's own published verdicts,
                // exactly as the actor weaves it.
                reach: crate::reachability::SharedSelfReach::new(
                    factory.kad_reach(),
                    crate::own_identity::SharedOwnIdentity::default(),
                    crate::natt::front::SharedNattFront::default(),
                ),
            },
        )
        .await
        .expect("the Kad runtime starts over the bound client-UDP socket");

    // Hand the node exactly what the client-UDP front would have demuxed to
    // it: a datagram whose leading byte is the plain Kad marker but which is
    // too short to hold an opcode — `decode_exact` rejects it before any
    // opcode dispatch runs.
    let sender = kad_inlet
        .lock()
        .expect("kad inlet lock")
        .clone()
        .expect("start() installed the inlet sender");
    sender
        .send((
            Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4672),
            vec![0xE4],
        ))
        .await
        .expect("the running node's inlet accepts the datagram");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if diagnostics
                .snapshot()
                .session
                .kad_undecodable_envelopes_total
                > 0
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the UndecodableEnvelope diagnostic reached the session counter");

    let text = log.text();
    assert!(
        text.contains("UndecodableEnvelope"),
        "the tracing::warn! line must name the reason; captured log: {text}"
    );
}

/// A standalone Kad node over loopback, crypt-armed at `public_ip` when given
/// — the feeds' counterparty in the Own Address tests below.
async fn standalone_node(verify_keys: Option<(u32, Ipv4Addr)>) -> rmule_net::kad::KadNetHandle {
    rmule_net::kad::spawn(
        rmule_net::kad::KadNetConfig {
            node: rmule_kad::KadNodeConfig {
                id: rmule_kad::KadId::from_bytes([0x51; rmule_kad::KadId::BYTE_LEN]),
                tcp_port: 4662,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x52; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: true,
            verify_keys,
            contact_admission: None,
        },
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .await
    .expect("a standalone Kad node starts")
}

/// Wait for one **Own Address Generation**, or fail: the event, not a clock,
/// is what a subscriber must hear.
async fn own_address_moved(changed: &mut tokio::sync::watch::Receiver<u64>) {
    tokio::time::timeout(Duration::from_secs(1), changed.changed())
        .await
        .expect("the store write announces itself")
        .expect("the store outlives its subscribers");
}

/// The Kad node's own-IPv4 cache follows its owner on the change event, not
/// the recruit tick (ADR-0084 "Own address ownership"): a
/// server-assigned IPv4 written on another task wakes the pump's
/// subscription, the feed re-binds the node, and a Low-ID withdrawal is a
/// change too — the node is re-bound to `0.0.0.0`, the value it is armed with
/// when no address is known, instead of keeping the withdrawn one.
#[tokio::test]
async fn the_kad_own_ipv4_follows_every_own_address_change_including_a_withdrawal() {
    use crate::adapters::kad_runtime::public_ip_feed::PublicIpFeed;

    const OWN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 4);
    let own = crate::own_identity::SharedOwnIdentity::default();
    let mut changed = own.addresses().own_address_changed();
    let handle = standalone_node(Some((0x0C0F_FEE5, Ipv4Addr::UNSPECIFIED))).await;
    let mut feed = PublicIpFeed::new(own.clone());
    feed.sync(&handle);
    assert_eq!(feed.told(), Some(Ipv4Addr::UNSPECIFIED));

    own.addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            OWN_IP,
        ));
    own_address_moved(&mut changed).await;
    feed.sync(&handle);
    assert_eq!(
        feed.told(),
        Some(OWN_IP),
        "the node is re-bound to the owner's IPv4"
    );

    // A Low-ID re-login withdraws the server's rung, and nothing else holds one.
    own.addresses()
        .observe_server_assigned(rmule_primitives::ClientId::from_u32(0), None, None);
    own_address_moved(&mut changed).await;
    feed.sync(&handle);
    assert_eq!(
        feed.told(),
        Some(Ipv4Addr::UNSPECIFIED),
        "a withdrawn IPv4 must not survive in the node's key binding"
    );
}

/// The Kad node's Extern Kad Port cache follows a store write the pump did
/// not cause: a port-mapping grant for the UDP socket is learned
/// on the port mapper's task, announces itself as one Own Address
/// Generation, and the feed restates it to the node on that wake — before
/// any `0x61` answer or recruit tick.
#[tokio::test]
async fn the_kad_extern_port_follows_a_mapping_grant_on_the_change_event() {
    use rmule_primitives::PeerEndpoint;

    use crate::adapters::kad_runtime::extern_port_feed::ExternPortFeed;
    use crate::address_learning::{AddressObservation, SharedAddressLearning, SocketRole};

    let addresses = SharedAddressLearning::default();
    let mut changed = addresses.own_address_changed();
    let handle = standalone_node(None).await;
    let mut feed = ExternPortFeed::new(addresses.clone());
    feed.sync(&handle);
    assert_eq!(feed.told(), Some(0), "nothing learned yet");

    addresses.observe(AddressObservation::mapping_grant(
        SocketRole::Udp,
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 20), 24672)),
        Duration::from_secs(3600),
    ));
    own_address_moved(&mut changed).await;
    feed.sync(&handle);
    assert_eq!(
        feed.told(),
        Some(24672),
        "the node's cache is the owner's port"
    );
}

/// The production channel's `next_sources` survives the discovery
/// sweep's `select!` dropping it mid-await. The call is parked on an empty
/// channel, an answer lands while it waits, the sweep tick wins the race and
/// the pending call is dropped unpolled — and the next call still delivers
/// that answer, so a sweep never costs a batch of sources.
#[tokio::test]
async fn a_next_sources_dropped_mid_await_loses_nothing_and_the_next_call_delivers_it() {
    let (commands, _pump) = mpsc::channel(1);
    let (answers, sources) = mpsc::channel(4);
    let channel = RuntimeKadChannel {
        commands,
        sources: Mutex::new(sources),
    };
    let file_hash = FileHash::from_bytes([0x5B; FileHash::BYTE_LEN]);

    let mut pending = Box::pin(channel.next_sources());
    std::future::poll_fn(|cx| {
        assert!(
            pending.as_mut().poll(cx).is_pending(),
            "nothing sent yet, so the call parks"
        );
        std::task::Poll::Ready(())
    })
    .await;
    answers.send((file_hash, Vec::new())).await.unwrap();
    tokio::select! {
        biased;
        () = std::future::ready(()) => {}
        answer = &mut pending => panic!("the sweep tick is biased to win, got {answer:?}"),
    }
    drop(pending);

    let delivered = tokio::time::timeout(Duration::from_secs(1), channel.next_sources())
        .await
        .expect("the next call does not wait for a second answer");
    assert_eq!(delivered, Some((file_hash, Vec::new())));
}
