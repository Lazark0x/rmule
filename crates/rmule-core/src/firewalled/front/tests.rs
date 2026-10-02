//! The firewalled front over a real loopback buddy link.
//!
//! A firewalled rmule recruits a buddy, dials it, holds the link, and consumes
//! what the buddy relays down it: an ordinary `0x9A` reask re-enters the
//! ADR-0057 reply matrix, an embedded `OP_RENDEZVOUS` reaches the acting path
//! and becomes a punch the NAT-T front is asked to fire, and a `0x99` becomes a
//! dial-back. The counterparty is a fake buddy speaking the real `rmule-peer`
//! codecs over a real TCP socket — the hello it answers and the relays it
//! frames are the wire's, not a mock's.
//!
//! **The requester the fake buddy injects is a public address, on purpose.**
//! `is_public_punch_address` refuses loopback and the self-punch guard refuses
//! our own interfaces (ADR-0091), and neither is weakened here:
//! a rendezvous naming `127.0.0.1` *must* resolve to nothing. So the injected
//! endpoint is `45.55.200.7:5000`, and what these legs assert is the verdict
//! and the command it produced — never that a datagram arrived anywhere.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_peer::natt::{NattConnectOptions, RendezvousBody};
use rmule_peer::{Callback, HelloAnswer, PeerOpcode, ReaskCallbackTcp};
use rmule_primitives::{
    CryptStance, FileHash, Ipv4Endpoint, Packet, PacketProtocol, PeerEndpoint, SourceCryptOptions,
    UserHash,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::firewalled::link::{FirewalledSlot, RecruitedBuddy, SharedFirewalledSlot};
use crate::firewalled::recruit::{AdoptOutcome, FindBuddyRes};

mod buddy_hello;
mod buddy_release;
mod direct_callback;
mod link_and_refusals;
mod relayed_callback;

/// Our Kad ID, and the `~ourKadID` every answer for it echoes.
const OUR_KAD_ID: u8 = 0xAA;
const BUDDY_ID: u8 = 0x55;

/// The buddy's user hash — what the front checks the dialed link's identity
/// against before it holds anything.
fn buddy_hash() -> UserHash {
    UserHash::from_bytes([0xBB; UserHash::BYTE_LEN])
}

/// The requester our fake buddy claims to have observed. Publicly routable, so
/// the ADR-0091 target rule can resolve it; see the module doc.
fn requester() -> Ipv4Endpoint {
    Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 5000)
}

/// What the front's `select!` is driven with, and what the test watches.
struct Harness {
    front: mpsc::Sender<FirewalledCommand>,
    slot: SharedFirewalledSlot,
    natt: mpsc::Receiver<NattCommand>,
    reask: mpsc::Receiver<crate::client_udp::ClientUdpDatagram>,
    /// The strong half of the reask inbox, kept alive so the front's weak
    /// sender upgrades — exactly as the client-UDP front's own does.
    _reask_tx: mpsc::Sender<crate::client_udp::ClientUdpDatagram>,
    diagnostics: crate::diagnostics::DiagnosticsState,
    /// The file-known predicate — empty by default, exactly as
    /// a fresh session shares and downloads nothing.
    file_known: crate::known_files::SharedFileKnown,
    /// Where a dial-back would enter the serve pipeline. Empty unless a leg
    /// calls [`Harness::start_serving`]: a dial-back is then opened and
    /// refused, which is what a node with no serve side should do with one.
    admit: crate::adapters::SharedTunnelAdmit,
    /// **Kad Presence**'s lease, held from construction —
    /// every leg that does not care about it sees "Kad up", the old
    /// `kad_started()`-implied assumption. A leg stops Kad by `drop`ping this
    /// — never by sending a `KadStopped` command, which no longer exists.
    /// `None` only under [`kad_down_harness`]: Kad never ran.
    kad_lease: Option<crate::adapters::KadPresenceLease>,
    /// The Kad family of **Self Reach** the front reads: a leg
    /// opens the TCP verdict here, as the pump would publish it.
    kad: crate::reachability::SharedKadVerdicts,
    /// The Hello Adverts read the front was wired with, which the
    /// admit seam [`Harness::start_serving`] fills is handed too.
    hello: crate::adapters::HelloAdverts,
    /// The core events the front reports.
    events: mpsc::Receiver<crate::CoreEvent>,
    /// The strong half, so the front's weak sender upgrades.
    _events_tx: mpsc::Sender<crate::CoreEvent>,
}

impl Harness {
    /// Give the front a serve pipeline to admit dial-backs into, so an admitted
    /// connection actually speaks — the only way a leg can read the dial-back's
    /// *hello* off the wire rather than just its TCP connect. Both halves are
    /// handed back for the leg to hold: the sender because the admit cell keeps
    /// only a weak one, the receiver because the admitted connection lives in
    /// its buffer and a dropped one would tear the link down mid-hello.
    fn start_serving(
        &self,
    ) -> (
        mpsc::Sender<crate::adapters::AdmittedPeer>,
        mpsc::Receiver<crate::adapters::AdmittedPeer>,
    ) {
        let (accept_tx, accept_rx) = mpsc::channel(4);
        // The pump's own options come from the same Hello Adverts read the
        // front's are, exactly as `Core::builder` weaves them.
        self.admit.install_for_test(
            &accept_tx,
            rmule_testkit::peer_session::serverless_ctx(),
            self.hello.clone(),
        );
        (accept_tx, accept_rx)
    }
}

/// Weave a front with every seam observable: a NAT-T front that only records,
/// an empty admit cell (a dial-back is then refused, which is what a node that
/// is not serving should do), a reask inbox the test drains, and an empty
/// file-known cell a test populates when it wants a `0x99` to prove a file.
fn harness(slot: &SharedFirewalledSlot) -> Harness {
    crypt_harness(slot, None)
}

/// A front whose clock never ticks inside a leg: an hour-long period, first
/// tick one period out. For a leg whose slot must move only on its own
/// events.
fn quiet_harness(slot: &SharedFirewalledSlot) -> Harness {
    ticking_harness(adverts(slot, None), Duration::from_secs(3600), true)
}

/// [`quiet_harness`] on a node whose Kad never started: no lease was ever
/// taken, so Kad Presence has no change for the front to act on and the slot
/// moves only on the commands a leg sends.
fn kad_down_harness(slot: &SharedFirewalledSlot) -> Harness {
    ticking_harness(adverts(slot, None), Duration::from_secs(3600), false)
}

/// The same front under a chosen obfuscation policy — what a `0x95` dial-back
/// reads before it decides whether to dial obfuscated, plaintext or at all.
fn crypt_harness(
    slot: &SharedFirewalledSlot,
    crypt: Option<rmule_net::peer::ObfuscationPolicy>,
) -> Harness {
    ticking_harness(adverts(slot, crypt), TICK, true)
}

/// The same front on a node whose every advert is live: a served
/// reask port, a running Kad node, a Known IPv6, crypt supported.
fn live_harness(slot: &SharedFirewalledSlot) -> Harness {
    ticking_harness(
        crate::adapters::tests::hello_wire::live_adverts(slot.clone()),
        TICK,
        true,
    )
}

/// Hello Adverts that state nothing but `crypt`, over `slot`.
fn adverts(
    slot: &SharedFirewalledSlot,
    crypt: Option<rmule_net::peer::ObfuscationPolicy>,
) -> crate::adapters::HelloAdverts {
    crate::adapters::HelloAdverts {
        firewalled_slot: slot.clone(),
        crypt_policy: crypt,
        ..crate::adapters::HelloAdverts::default()
    }
}

fn ticking_harness(hello: crate::adapters::HelloAdverts, tick: Duration, kad_up: bool) -> Harness {
    let slot = &hello.firewalled_slot.clone();
    let (natt_tx, natt_rx) = mpsc::channel(8);
    let natt = crate::natt::front::SharedNattFront::default();
    natt.install(natt_tx);
    let (reask_tx, reask_rx) = mpsc::channel(8);
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    let file_known = crate::known_files::SharedFileKnown::default();
    let admit = crate::adapters::SharedTunnelAdmit::default();
    let kad_presence = crate::adapters::KadPresenceView::default();
    let kad_lease = kad_up.then(|| {
        kad_presence.lease(rmule_kad::KadId::from_bytes(
            [OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN],
        ))
    });
    let kad = crate::reachability::SharedKadVerdicts::default();
    let (events_tx, events) = mpsc::channel(8);
    let front = super::spawn_ticking(
        FirewalledWiring {
            hello: hello.clone(),
            reach: crate::reachability::SharedSelfReach::new(
                crate::KadReachLevel::published(kad.clone()),
                crate::own_identity::SharedOwnIdentity::default(),
                natt,
            ),
            admit: admit.clone(),
            reask_ping: reask_tx.downgrade(),
            addresses: crate::address_learning::SharedAddressLearning::new(),
            file_known: file_known.clone(),
            diagnostics: diagnostics.clone(),
            kad_presence: kad_presence.clone(),
            events: Some(events_tx.downgrade()),
        },
        tick,
    );
    Harness {
        front,
        slot: slot.clone(),
        natt: natt_rx,
        reask: reask_rx,
        _reask_tx: reask_tx,
        diagnostics,
        file_known,
        admit,
        kad_lease,
        kad,
        hello,
        events,
        _events_tx: events_tx,
    }
}

/// The eD2k identity the front presents when it dials — the Kad pump's
/// serverless dial-back context. Carries only that identity:
/// whether Kad runs is the harness's [`Harness::kad_lease`], held from
/// construction, not anything this command sets.
fn kad_started() -> FirewalledCommand {
    FirewalledCommand::KadStarted(Box::new(crate::server_session::HelloSource::Fixed(
        rmule_testkit::peer_session::serverless_ctx(),
    )))
}

/// One decoded frame off the fake buddy's socket, buffering across reads.
async fn next_packet(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Packet> {
    loop {
        if let Ok((packet, consumed)) = Packet::decode(buf) {
            buf.drain(..consumed);
            return Some(packet);
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// A buddy that accepts one dial, answers the hello with `buddy_hash`, then
/// frames `relays` down the link and stays open. Returns the opcodes it saw
/// after the handshake — the keepalive proof — once the link closes.
fn fake_buddy(listener: TcpListener, relays: Vec<Packet>) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("the front dials");
        let mut buf = Vec::new();
        // The firewalled side dials, so its `OP_HELLO` opens the conversation.
        let hello = next_packet(&mut sock, &mut buf).await.expect("a hello");
        assert_eq!(hello.opcode(), PeerOpcode::Hello.as_u8());
        let answer = HelloAnswer::new(rmule_testkit::peer_session::answer_body(buddy_hash()))
            .encode_packet()
            .encode();
        sock.write_all(&answer).await.expect("the answer is framed");
        for relay in relays {
            sock.write_all(&relay.encode()).await.expect("a relay");
        }
        let mut seen = Vec::new();
        while let Some(packet) = next_packet(&mut sock, &mut buf).await {
            seen.push(packet.opcode());
        }
        seen
    })
}

/// The slot a firewalled node holds once its `0x5A` verified, pointed at
/// `buddy` on loopback.
fn recruited(buddy: SocketAddrV4) -> SharedFirewalledSlot {
    recruited_with_id(buddy, [OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN])
}

/// [`recruited`] with the front's own Kad ID chosen by the caller — an
/// asymmetric one exercises the per-word `TAG_BUDDYHASH` spelling swap
/// Which this module's palindromic `OUR_KAD_ID` constant
/// cannot: word-swapping a repeated byte is a no-op.
fn recruited_with_id(buddy: SocketAddrV4, our_kad_id: [u8; 16]) -> SharedFirewalledSlot {
    let slot: SharedFirewalledSlot = std::sync::Arc::new(FirewalledSlot::new(
        rmule_kad::KadId::from_bytes(our_kad_id),
    ));
    adopt(&slot, buddy, our_kad_id);
    slot
}

/// Fill `slot` with `buddy` exactly as the Kad pump does on a verified `0x5A`,
/// and hand back the buddy it now holds.
fn adopt(slot: &FirewalledSlot, buddy: SocketAddrV4, our_kad_id: [u8; 16]) -> RecruitedBuddy {
    adopt_stating(slot, buddy, our_kad_id, CryptStance::disabled())
}

/// [`adopt`] from a `0x5A` whose connect-options byte stated `crypt`.
fn adopt_stating(
    slot: &FirewalledSlot,
    buddy: SocketAddrV4,
    our_kad_id: [u8; 16],
    crypt: CryptStance,
) -> RecruitedBuddy {
    let udp = Ipv4Endpoint::new(*buddy.ip(), buddy.port());
    let recruited = RecruitedBuddy {
        udp,
        tcp: Ipv4Endpoint::new(*buddy.ip(), buddy.port()),
        hash: buddy_hash(),
        crypt: Some(crypt),
    };
    assert_eq!(
        slot.adopt_buddy(
            &FindBuddyRes {
                // The `0x5A` verify checks this against `inverted(our_kad_id)`
                // (`recruit.rs`'s `adopt_buddy`) — the walk target echoed back,
                // not the buddy's own Kad ID.
                buddy_id: rmule_kad::KadId::from_bytes(addressed_to(our_kad_id)),
                buddy_endpoint: udp,
            },
            recruited,
            CryptStance::disabled(),
        ),
        AdoptOutcome::Adopted
    );
    recruited
}

/// The `0x9A` a buddy frames for an embedded rendezvous: the requester it
/// observed, then the forwarded tail the requester's `0x94` carried.
fn relayed_rendezvous() -> Packet {
    let body = RendezvousBody {
        requester: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
        options: NattConnectOptions::from_byte(0x80),
        file_hash: None,
        claimed_endpoint: None,
        transport_hint: None,
    };
    ReaskCallbackTcp {
        requester: PeerEndpoint::V4(requester()),
        forwarded: body.embed([BUDDY_ID; 16]).forwarded,
    }
    .encode_packet()
}

/// The `0x99` check field addressed to `id`: its bit-inverse — aMule's own
/// `TAG_BUDDYHASH` spelling.
fn addressed_to(id: [u8; 16]) -> [u8; 16] {
    id.map(|b| !b)
}

/// Wait for `poll` to yield, or fail — every leg below is driven by a real
/// socket, so the budget bounds a hang rather than pacing anything.
async fn within<T>(what: &str, poll: impl std::future::Future<Output = Option<T>>) -> T {
    tokio::time::timeout(Duration::from_secs(10), poll)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap_or_else(|| panic!("{what} never arrived"))
}

/// Wait, within [`within`]'s budget, for `holds` to read true — a state the
/// front publishes, polled because the slot and the diagnostics are shared
/// cells, not event streams.
async fn until(what: &str, mut holds: impl FnMut() -> bool) {
    within(what, async {
        for _ in 0..200 {
            if holds() {
                return Some(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    })
    .await;
}

/// The done-when leg: recruit, hold, and act on a rendezvous relayed over the
/// held link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rendezvous_relayed_over_the_held_buddy_link_becomes_a_punch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    let mut h = harness(&slot);
    let peer = fake_buddy(listener, vec![relayed_rendezvous()]);

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");

    // The acting path ruled, and the NAT-T front was asked to punch — with the
    // Responder role, because the requester asked for the introduction and so
    // dials, and with the burst, because nothing has left yet on this path.
    let command = within("the acting punch", h.natt.recv()).await;
    assert!(
        matches!(
            command,
            NattCommand::Introduced {
                target,
                role: rmule_ed2k::HolepunchRole::Responder,
                burst: true,
                ..
            } if target == requester()
        ),
        "unexpected NAT-T command: {command:?}"
    );
    // The punch is counted where a node reports its own traversal — right
    // *after* the command is handed over, since the count records whether the
    // hand-over took; so the command can be here before the count is.
    until("the punch to be counted", || {
        h.diagnostics.snapshot().session.acting_punches_total == 1
    })
    .await;
    assert_eq!(
        h.slot.state().0,
        crate::firewalled::link::BuddyState::Held,
        "the link the relay rode is the one we dialed"
    );

    drop(h.front);
    let seen = within("the buddy link to close", async { peer.await.ok() }).await;
    assert!(
        !seen.contains(&PeerOpcode::Callback.as_u8()),
        "the firewalled side never relays back down its own buddy link"
    );
}

/// The buddy dial sends the one hello every outbound connection
/// sends — our ports, Kad version, IPv6 and crypt support — and no buddy tags
/// while firewalled with a buddy adopted, because the buddy they would name is
/// the one this hello is dialing (aMule links `m_pBuddy` only once
/// the handshake completes). And Secure User Identification: once
/// the Core holds our keypair, this hello lights the SUI nibble as
/// aMule's every hello does (`uSupportSecIdent = 3`, `BaseClient.cpp:1508`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_buddy_dial_s_hello_states_every_advert_and_names_no_buddy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    // Firewalled: Self Reach with no High ID and Kad unproven.
    slot.install_reach(crate::reachability::SharedSelfReach::new(
        crate::KadReachLevel::fixed(false),
        crate::own_identity::SharedOwnIdentity::default(),
        crate::natt::front::SharedNattFront::default(),
    ));
    let mut hello = crate::adapters::tests::hello_wire::live_adverts(slot.clone());
    hello.secure_ident = Some(std::sync::Arc::new(
        rmule_primitives::SecureIdentKey::generate().expect("a SUI keypair"),
    ));
    let h = ticking_harness(hello, TICK, true);

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");

    let (mut sock, _) = within("the buddy dial", async { listener.accept().await.ok() }).await;
    let hello = within("its hello", async {
        Some(crate::adapters::tests::hello_wire::read_hello_body(&mut sock).await)
    })
    .await;
    crate::adapters::tests::hello_wire::assert_states_live_adverts(&hello);
    assert_eq!(
        crate::adapters::tests::held_buddy::BuddyTags::of(&hello),
        crate::adapters::tests::held_buddy::BuddyTags::default(),
    );
    assert_eq!(
        rmule_peer::MiscOptions1::from_tags(&hello.tags)
            .map(rmule_peer::MiscOptions1::secure_identification_version),
        Some(3),
        "MiscOptions1 advertises SUI v1 and v2",
    );
}

/// The buddy dial follows the stance the `0x5A` stated. A buddy
/// whose connect-options byte asks for obfuscation (`0x03`: supports and
/// requests), met by our `Supported` policy, is dialled obfuscated toward the
/// hash the `0x5A` carried — aMule's `RequestBuddy` seats both on the client
/// it dials (`ClientList.cpp:1141-1144`). The buddy's listener *requires* the
/// crypt layer and cuts a plaintext opening, so a held link is the proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_obfuscation_requesting_buddy_is_dialled_obfuscated() {
    use rmule_net::peer::{ConnectOptions, ObfuscationConfig, ObfuscationPolicy, PeerListener};

    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let slot: SharedFirewalledSlot = std::sync::Arc::new(FirewalledSlot::new(
        rmule_kad::KadId::from_bytes([OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN]),
    ));
    adopt_stating(
        &slot,
        buddy,
        [OUR_KAD_ID; rmule_kad::KadId::BYTE_LEN],
        SourceCryptOptions::from_byte(0x03).crypt_stance(),
    );
    let h = live_harness(&slot);
    // The buddy answers under the hash the `0x5A` carried — the key an
    // obfuscated opening toward it is derived from. The accepted link is kept
    // alive until the test ends, so the front's hold is never raced by a close.
    let _buddy_side = tokio::spawn(async move {
        let mut ctx = rmule_testkit::peer_session::serverless_ctx();
        ctx.identity = rmule_primitives::ClientIdentity::new(
            buddy_hash(),
            rmule_primitives::Ed2kText::from_utf8("buddy"),
            buddy.port(),
            0x3C,
        );
        let requires = ConnectOptions {
            obfuscation: Some(ObfuscationConfig {
                policy: ObfuscationPolicy::Required,
            }),
            ..ConnectOptions::default()
        };
        let conn = listener.accept(ctx, requires).await;
        std::future::pending::<()>().await;
        drop(conn);
    });

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");

    until("the obfuscated buddy link to be held", || {
        h.slot.state().0 == crate::firewalled::link::BuddyState::Held
    })
    .await;
}

/// An ordinary relayed reask re-enters the ADR-0057 reply matrix, addressed to
/// the requester the buddy injected — aMule's own
/// `ProcessPacket(..., OP_REASKFILEPING, destip, destport)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ordinary_relayed_reask_re_enters_the_reply_matrix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let buddy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let slot = recruited(buddy);
    let mut h = harness(&slot);
    let file = FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]);
    // The tail a `0x94` carried: a UDPv4 `0x90` body — hash, count-zero
    // status, complete-source count (stock 2.3.3 `DownloadClient.cpp:
    // 1278-1291`) — header stripped by the relay. It is re-entered whole, so
    // the serve side reads its status as it reads a direct ping's.
    let forwarded = [file.as_bytes().as_slice(), &[0x00, 0x00, 0x00, 0x00]].concat();
    let peer = fake_buddy(
        listener,
        vec![
            ReaskCallbackTcp {
                requester: PeerEndpoint::V4(requester()),
                forwarded: forwarded.clone(),
            }
            .encode_packet(),
        ],
    );

    h.front.send(kad_started()).await.expect("front running");
    h.front
        .send(FirewalledCommand::BuddyAdopted)
        .await
        .expect("front running");

    let (to, datagram) = within("the injected reask", h.reask.recv()).await;
    assert_eq!(to, PeerEndpoint::V4(requester()));
    let mut expected = vec![PacketProtocol::Emule.as_byte(), 0x90];
    expected.extend_from_slice(&forwarded);
    assert_eq!(
        datagram, expected,
        "the two-byte peer-UDP header the relay stripped is put back"
    );

    drop(h.front);
    let _ = peer.await;
}
