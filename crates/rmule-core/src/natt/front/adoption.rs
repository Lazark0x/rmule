//! **What this module proves**: a download takes a part's bytes
//! over a **Tunnel** it adopted, across two whole NAT-T fronts on real
//! loopback client-UDP sockets.
//!
//! Nothing between the two nodes is simulated. The requester's front dials a
//! punched path; the uTP Tunnel rises through the same
//! `ClientUdpEngine` → NAT-T inbox → `NattDemux` path a running node uses; the
//! risen Tunnel enters through the production
//! [`SharedTunnelAdmit`](crate::adapters::SharedTunnelAdmit) seam carrying the
//! target hash the punch was aimed at; the production
//! `triage_inbound_connection` reads the peer's hello, finds the claim, and
//! hands back an **Adopted Inbound Worker** — which streams the part off the
//! serving node over that same pinhole.
//!
//! # Where the leg enters, and why not higher
//!
//! At the front's punch-this-endpoint-for-this-target operation, exactly as
//! this module's sibling `live.rs` does and for the same honest reason:
//! `is_public_punch_address` refuses loopback (kno's audit finding F1) and the
//! self-punch guard refuses our own interfaces (amule#1177 correction 4). Both
//! guards are correct, neither is weakened, and neither gets a test-only
//! bypass — a hint naming `127.0.0.1` can never be believed, so hint
//! acceptance is proven in the pure tier against public addresses instead.
//!
//! The twelve seconds of callback silence that *produce* the claim are not
//! waited out here either. The claim is filed through the production
//! registry exactly as `CallbackContext::claim_tunnel` files it, from a
//! decision driven in `download::state::tests::callbacks`; how the registry
//! picks and spends it is proven in `adapters::awaited_inbound`. What this leg
//! adds, and what nothing else can, is that the adopted worker's bytes really
//! crossed a punched UDP path.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rmule_peer::natt::{EndpointHint, NattConnectOptions};
use rmule_peer::{
    ConnectionEvent, EMBLOCKSIZE, PartBitmap, PartRanges, ServerCommand, ServerEvent,
};
use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kText, FileHash, FileHashSummary, Ipv4Endpoint, PeerEndpoint,
    UserHash,
};
use tokio::sync::mpsc;

use crate::adapters::{
    AdmittedPeer, AdoptionBrief, AwaitedInbound, CallbackKey, InboundPeerDeps, PeerWorker,
    PeerWorkerCommand, PeerWorkerEvent, ServeInput, ServeOutput, triage_inbound_connection,
};

use super::live::Node;

/// The content the serving node holds: one sub-part file, so the requester's
/// connect-time negotiation is the plain source-exchange ask and the whole
/// file is part zero.
fn served_bytes() -> Vec<u8> {
    (0..4096u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

fn link(bytes: &[u8]) -> Ed2kFileLink {
    let summary = FileHashSummary::digest_bytes(bytes);
    Ed2kFileLink {
        name: Ed2kText::from_utf8("adopted-over-a-tunnel.bin"),
        size: summary.file_size(),
        file_hash: summary.file_hash(),
        part_hash_set: summary.part_hash_set().cloned(),
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// The callback the claim runs beside — what the adopted worker comes back
/// under, because NAT traversal is an additional attempt on one pending
/// callback and not a second one.
fn callback_key() -> CallbackKey {
    CallbackKey {
        server: None,
        low_id: ClientId::from_u32(7),
        kad_port: None,
    }
}

/// The inbound-path handles a node with no other activity running brings: no
/// upload queue to reach, no Kad node, no buddy, no learned addresses.
fn deps() -> InboundPeerDeps {
    InboundPeerDeps {
        slot_wait_timeout: Duration::from_secs(10),
        dialed_serve_sink: crate::adapters::SharedDialedServeSink::default(),
        kad_bootstrap: crate::adapters::SharedKadBootstrap::default(),
        kad_pump: crate::adapters::SharedKadPump::default(),
        buddy_slot: crate::buddy_link::SharedBuddySlot::default(),
        addresses: crate::address_learning::SharedAddressLearning::new(),
        peer_roster: crate::peer_roster::SharedPeerRoster::default(),
        kad_presence: crate::adapters::KadPresenceView::default(),
        file_known: crate::known_files::SharedFileKnown::default(),
        tunnel_admit: crate::adapters::SharedTunnelAdmit::default(),
        hello_refusals: crate::hello_refusals::SharedHelloRefusals::default(),
        peer_links: crate::adapters::SharedPeerLinks::default(),
    }
}

/// Hand one admitted path to the production inbound router against `awaited`.
/// This is what the serve adapter's `accept()` does per connection; an
/// adoption leaves down the claim's own `adopt_tx`, so nothing comes back
/// here.
fn triage_admitted(admitted: AdmittedPeer, awaited: AwaitedInbound) {
    let (_cmd_tx, cmd_rx) = mpsc::channel(4);
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    // The requesting node serves nothing; draining is what a serve runner
    // would do with the events, and keeps the bridge's sends from filling.
    tokio::spawn(async move { while evt_rx.recv().await.is_some() {} });
    tokio::spawn(triage_inbound_connection(
        admitted.conn,
        admitted.dialed_toward,
        cmd_rx,
        evt_tx,
        awaited,
        deps(),
    ));
}

/// The serving half: drive the admitted Tunnel through the production triage
/// onto the serve road, then answer its pull the way an uploader with a free
/// slot does — grant, then cut each requested range out of the file.
async fn serve_one_file(admitted: AdmittedPeer, file: Ed2kFileLink, bytes: Vec<u8>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (evt_tx, mut evt_rx) = mpsc::channel(32);
    tokio::spawn(triage_inbound_connection(
        admitted.conn,
        admitted.dialed_toward,
        cmd_rx,
        evt_tx,
        AwaitedInbound::default(),
        deps(),
    ));
    while let Some(event) = evt_rx.recv().await {
        let answer = match event {
            ServeInput::Server(ServerEvent::SlotRequested { file_hash }) => {
                ServeOutput::Server(ServerCommand::GrantSlot { file_hash })
            }
            ServeInput::Server(ServerEvent::FileRequested { file_hash, .. }) => {
                ServeOutput::Server(ServerCommand::AnswerFileName {
                    file_hash,
                    file_name: file.name.clone(),
                })
            }
            // The probe pair's second half: a complete uploader answers with
            // every part set, which is what makes the requester ask for a
            // slot rather than write us off as holding nothing.
            ServeInput::Server(ServerEvent::FileBundleRequested {
                file_hash, asks, ..
            }) => {
                for ask in asks {
                    let command = match ask {
                        rmule_peer::BundledAsk::Name { .. } => {
                            ServeOutput::Server(ServerCommand::AnswerFileName {
                                file_hash,
                                file_name: file.name.clone(),
                            })
                        }
                        rmule_peer::BundledAsk::SetReqId => {
                            ServeOutput::Server(ServerCommand::AnswerFileStatus {
                                file_hash,
                                bitmap: complete_bitmap(file.size),
                            })
                        }
                        _ => continue,
                    };
                    if cmd_tx.send(command).await.is_err() {
                        return;
                    }
                }
                continue;
            }
            ServeInput::Server(ServerEvent::FileIdSet { file_hash }) => {
                ServeOutput::Server(ServerCommand::AnswerFileStatus {
                    file_hash,
                    bitmap: complete_bitmap(file.size),
                })
            }
            ServeInput::Server(ServerEvent::PartsRequested { file_hash, ranges }) => {
                send_ranges(&cmd_tx, file_hash, &ranges, &bytes).await;
                continue;
            }
            ServeInput::Connection(ConnectionEvent::Disconnected { .. }) => return,
            _ => continue,
        };
        if cmd_tx.send(answer).await.is_err() {
            return;
        }
    }
}

/// Every part of a file of `size` bytes, held: the bitmap a complete
/// uploader answers `OP_SETREQFILEID` with.
fn complete_bitmap(size: u64) -> PartBitmap {
    let parts = rmule_primitives::part_count(size);
    let bytes = vec![0xFFu8; (parts as usize).div_ceil(8)];
    PartBitmap::decode(parts, &bytes).expect("a full bitmap for the part count it was sized by")
}

/// Cut each live range out of the file and send it in `EMBLOCKSIZE` blocks —
/// the block discipline a real uploader keeps, so the requester's
/// one-block-in-flight loop is exercised rather than short-circuited.
async fn send_ranges(
    cmd_tx: &mpsc::Sender<ServeOutput>,
    file_hash: FileHash,
    ranges: &PartRanges,
    bytes: &[u8],
) {
    for &(start, end) in ranges.as_array() {
        if start == end {
            continue;
        }
        let mut at = start;
        while at < end {
            let stop = (at + EMBLOCKSIZE).min(end);
            let block = bytes[at as usize..stop as usize].to_vec();
            if cmd_tx
                .send(ServeOutput::Server(ServerCommand::SendBlock {
                    file_hash,
                    start: at,
                    end: stop,
                    bytes: block,
                }))
                .await
                .is_err()
            {
                return;
            }
            at = stop;
        }
    }
}

/// Stream one part off `worker` and return what core would have assembled:
/// every block it forwarded, written at the offset it named.
async fn take_part(worker: &mut PeerWorker, file: &Ed2kFileLink) -> Vec<u8> {
    worker
        .send(PeerWorkerCommand::RequestPart {
            plan: crate::PartPlan {
                part_index: 0,
                offset: 0,
                len: file.size,
            },
            resume_offset: 0,
        })
        .await
        .expect("the adopted worker takes commands");
    let mut assembled = vec![0u8; usize::try_from(file.size).expect("a test-sized file")];
    let mut delivered = 0u64;
    loop {
        let event = tokio::time::timeout(Duration::from_secs(20), worker.next_event())
            .await
            .expect("the part streams within 20s")
            .expect("the worker's event stream stayed open");
        match event {
            PeerWorkerEvent::BlockReceived { offset, bytes, .. } => {
                let at = usize::try_from(offset).expect("a test-sized offset");
                assembled[at..at + bytes.len()].copy_from_slice(&bytes);
                delivered += bytes.len() as u64;
            }
            PeerWorkerEvent::PartStreamed { .. } => {
                assert_eq!(delivered, file.size, "the worker delivered its whole range");
                return assembled;
            }
            PeerWorkerEvent::Disconnected | PeerWorkerEvent::SlotTimeout => {
                panic!("the tunnelled worker ended before the part: {event:?}")
            }
            _ => {}
        }
    }
}

/// A download completes a part over a Tunnel it adopted.
///
/// The requester's callback for a Low-ID source has gone silent, so its claim
/// stands in the table, and its front is told a coordinator introduced it to
/// the target. The front dials, the Tunnel rises, the hello inside it names
/// the claimed target, and the triage hands the connection to the download as
/// a worker — which asks for the part and gets every byte of it back over the
/// same pinhole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_download_takes_a_part_over_the_tunnel_it_adopted() {
    let (requester_hash, target_hash) = (
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
    );
    let bytes = served_bytes();
    let file = link(&bytes);

    let requester = Node::start(requester_hash, "rmule-downloader").await;
    let target = Node::start(target_hash, "rmule-uploader").await;

    // The claim the twelve-second fallback leaves behind, filed through the
    // production registry as the runner files it.
    let claims = AwaitedInbound::default();
    let (adopt_tx, mut adopt_rx) = mpsc::channel(4);
    let claim = claims.register(callback_key(), adopt_tx, mpsc::channel(4).0);
    claim.claim_tunnel(
        target_hash,
        AdoptionBrief {
            own_status: rmule_peer::PartBitmap::downloader_empty(0),
            want_sources: true,
            file: file.clone(),
        },
        false,
    );

    // Both sides are told at once, as a coordinator tells them: the side that
    // asked dials, the other records its expectation and accepts.
    target
        .introduced_to(
            requester_hash,
            requester.port,
            rmule_ed2k::HolepunchRole::Responder,
        )
        .await;
    requester
        .introduced_to(
            target_hash,
            target.port,
            rmule_ed2k::HolepunchRole::Initiator,
        )
        .await;
    // Each node's front raises exactly one Tunnel and admits it; the serve
    // adapter's `accept()` is what takes them in production.
    let mut requester = requester;
    let mut target = target;
    let dialed = tokio::time::timeout(Duration::from_secs(20), requester.accepted.recv())
        .await
        .expect("the requester's dialed tunnel was admitted within 20s")
        .expect("the admit channel is open");
    let accepted = tokio::time::timeout(Duration::from_secs(20), target.accepted.recv())
        .await
        .expect("the target's accepted tunnel was admitted within 20s")
        .expect("the admit channel is open");
    assert_eq!(
        dialed.dialed_toward,
        Some(target_hash),
        "the dialed path names the target its punch was aimed at"
    );
    assert_eq!(
        accepted.dialed_toward, None,
        "the accepted path was aimed at us, so no download of ours may claim it"
    );
    triage_admitted(dialed, claims.clone());
    tokio::spawn(serve_one_file(accepted, file.clone(), bytes.clone()));

    let (key, mut worker) = tokio::time::timeout(Duration::from_secs(30), adopt_rx.recv())
        .await
        .expect("the tunnel was adopted within 30s")
        .expect("the claim's adopt channel stayed open");
    assert_eq!(
        key,
        callback_key(),
        "the worker is reported under the callback the punch ran beside"
    );
    assert!(
        matches!(worker.peer(), PeerEndpoint::V4(_)),
        "the adopted worker rides the punched IPv4 path"
    );

    let taken = take_part(&mut worker, &file).await;
    assert_eq!(
        taken, bytes,
        "every byte of the part crossed the punched path"
    );
    assert_eq!(
        FileHashSummary::digest_bytes(&taken).file_hash(),
        file.file_hash,
        "and what crossed it verifies as the file that was asked for"
    );
}

/// Before this was wired, nothing sent `Risen::Identified`, so an
/// adoption inbound triage confirmed through a **Dial-Back Claim** resolved
/// nothing on the front — a peer's own held burst survived its confirmed
/// hello and still fired at its own deadline. `target` begins a real hold
/// toward each of two peers, the same `begin_toward` fixture `live.rs`'s
/// `a_tunnel_adopted_cancels_a_still_pending_hold_toward_the_same_peer` uses,
/// so both holds are real ledger entries, not stand-ins — two peers behind
/// one address, one loopback node standing in for both. `alice`
/// then dials in for real; nothing in `target`'s **Punch Expectation** table
/// ever named her, so her accepted path attributes to nobody and only the
/// **Dial-Back Claim** her hello confirms, through the production triage,
/// can end her attempt. Bob's claim and his hold are never touched: his
/// burst fires at its own deadline exactly as if alice's hello had never
/// arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn triage_reports_a_confirmed_hello_and_ends_only_that_peers_hold() {
    let (target_hash, alice_hash, bob_hash) = (
        UserHash::from_bytes([0x10; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
        UserHash::from_bytes([0xBB; UserHash::BYTE_LEN]),
    );
    let mut target = Node::start(target_hash, "rmule-target").await;
    let alice = Node::start(alice_hash, "rmule-alice").await;

    // Two peers behind one address: `target` itself asked for
    // both introductions, so each holds a real burst on its own ledger,
    // aimed at a fake public address nothing here will ever dial for real.
    let buddy_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a loopback buddy probe binds");
    let buddy_udp = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        buddy_socket.local_addr().expect("bound").port(),
    );
    let buddy_id = [0xCC; rmule_peer::BUDDY_ID_LEN];
    target.begin_toward(alice_hash, buddy_id, buddy_udp).await;
    target.begin_toward(bob_hash, buddy_id, buddy_udp).await;
    // The relay round trip this exchange measures: the holds below arm for
    // half of it, long enough that alice's real Tunnel has every chance to
    // rise and be adopted first.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let fake_public = Ipv4Addr::new(1, 2, 3, 4);
    let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, target.port));
    for (peer, port) in [(alice_hash, 9998u16), (bob_hash, 9999u16)] {
        let hint = EndpointHint {
            target: peer,
            buddy_id,
            file_hash: None,
            target_endpoint: Ipv4Endpoint::new(fake_public, port),
            options: NattConnectOptions::from_byte(0),
        };
        buddy_socket
            .send_to(&hint.encode_udp(), target_addr)
            .await
            .expect("send");
    }

    // Alice's Dial-Back Claim: the one road that can adopt a path nothing in
    // `target`'s Punch Expectation table ever aimed at her.
    let file = link(&served_bytes());
    let (alice_adopt_tx, mut alice_adopt_rx) = mpsc::channel(4);
    let alice_claim = target
        .claims
        .register(callback_key(), alice_adopt_tx, mpsc::channel(4).0);
    alice_claim.claim_tunnel(
        alice_hash,
        AdoptionBrief {
            own_status: rmule_peer::PartBitmap::downloader_empty(0),
            want_sources: true,
            file: file.clone(),
        },
        true,
    );
    // Bob's own claim, standing beside alice's — proof that alice's hello
    // spends only hers.
    let bob_claim = target
        .claims
        .register(callback_key(), mpsc::channel(4).0, mpsc::channel(4).0);
    bob_claim.claim_tunnel(
        bob_hash,
        AdoptionBrief {
            own_status: rmule_peer::PartBitmap::downloader_empty(0),
            want_sources: true,
            file,
        },
        true,
    );

    alice
        .introduced_to(
            target_hash,
            target.port,
            rmule_ed2k::HolepunchRole::Initiator,
        )
        .await;

    let accepted = tokio::time::timeout(Duration::from_secs(20), target.accepted.recv())
        .await
        .expect("alice's real Tunnel was admitted within 20s")
        .expect("the admit channel is open");
    assert_eq!(
        accepted.dialed_toward, None,
        "target never dialed; nothing here named a target for this accepted path"
    );

    triage_admitted(accepted, target.claims.clone());

    let (_, worker) = tokio::time::timeout(Duration::from_secs(20), alice_adopt_rx.recv())
        .await
        .expect("alice's hello confirmed the Dial-Back Claim within 20s")
        .expect("the claim's adopt channel stayed open");
    assert!(
        matches!(worker.peer(), PeerEndpoint::V4(_)),
        "the adopted worker rides the path alice's hello confirmed"
    );

    // Past both holds' own deadline: if alice's survived, its burst fired at
    // the fake address and a second dial toward it spawned. Bob's hold was
    // never named by any hello, so his fires unconditionally.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let after = target.diagnostics.snapshot().session;
    assert_eq!(
        after.natt_dials_total, 1,
        "alice's hold died with her confirmed hello; only bob's fired at its own deadline"
    );
}
