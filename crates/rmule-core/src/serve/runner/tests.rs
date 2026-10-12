//! The reask reply matrix wired live end to end (ADR-0057): a
//! real [`ClientUdpEngine`](crate::client_udp::ClientUdpEngine) over a
//! test transport, its demuxed `0x90` inbox handed to a real [`ServeTask`],
//! and the task's `client_udp` send half asserted on. The sans-I/O
//! [`ServeState`] reask tests prove the *decision*; this proves the whole
//! async span the live pcap exercises — socket → engine demux → `reask_rx`
//! → serve task → `on_reask_ping` → `client_udp_tx` — never bypassed.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rmule_ed2k::OfferedFile;
use rmule_peer::peer_udp::crypt::PeerUdpCryptTarget;
use rmule_peer::{ReaskAck, ReaskFilePing, ServerCommand, ServerEvent};
use rmule_primitives::{
    ClientId, CryptStance, FileHash, Ipv4Endpoint, PeerEndpoint, PeerSource, UserHash,
};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::timeout;

use super::ServeTask;
use crate::CoreError;
use crate::adapters::{ServeConnection, ServeInput, ServeOutput, ServeRuntimeService};
use crate::client_udp::{
    ClientUdpDatagram, ClientUdpEngine, ClientUdpSend, ClientUdpTransport, PeerUdpCrypt,
    encrypt_client_udp_send, os_datagram_nonce,
};
use crate::credit::SharedCreditStore;
use crate::hello_facts::HelloFacts;
use crate::own_identity::SharedOwnIdentity;
use crate::registry::{ShareSource, SharedFileEntry, SharedFileRegistry};
use crate::service::{CoreEvent, ServeEvent, ServeStopReason};
use crate::store::credit::DurableCreditStore;
use crate::store::registry::DurableSharedFileRegistry;
use crate::upload_queue::UploadSlotQueue;

/// A [`ClientUdpTransport`] fed one datagram at a time on cue: `recv`
/// parks on the channel, so the engine stays alive between the scripted
/// steps (mirrors the live socket's blocking receive).
struct ChannelTransport {
    inbound: Mutex<mpsc::Receiver<ClientUdpDatagram>>,
}

impl ClientUdpTransport for ChannelTransport {
    async fn recv(&self) -> Option<ClientUdpDatagram> {
        self.inbound.lock().await.recv().await
    }
}

/// A serve runtime that binds to a fixed address, yields scripted accepted
/// connections, then parks (never `None`, which would wind the serve loop
/// down). `announce` is a no-op — no server session in the harness.
struct FakeServeRuntime {
    bound: SocketAddrV4,
    accepts: mpsc::Receiver<ServeConnection>,
}

impl ServeRuntimeService for FakeServeRuntime {
    async fn start(
        &mut self,
        _identity: rmule_primitives::ClientIdentity,
        _listen_addr: SocketAddrV4,
    ) -> Result<SocketAddrV4, CoreError> {
        Ok(self.bound)
    }

    async fn accept(&mut self) -> Option<ServeConnection> {
        match self.accepts.recv().await {
            Some(conn) => Some(conn),
            // The scripted senders are still held; an empty channel means
            // "no more accepts yet", so park instead of closing the loop.
            None => std::future::pending().await,
        }
    }

    async fn announce(
        &mut self,
        files: Vec<OfferedFile>,
    ) -> Result<crate::AnnounceOutcome, CoreError> {
        Ok(crate::AnnounceOutcome::Announced {
            file_count: files.len(),
        })
    }
}

fn peer_at(ip: [u8; 4], tcp_port: u16) -> PeerEndpoint {
    PeerSource::new(ClientId::from_u32(u32::from_le_bytes(ip)), tcp_port)
        .as_peer_endpoint()
        .unwrap()
}

async fn next_serve_event(
    rx: &mut mpsc::Receiver<CoreEvent>,
    want: impl Fn(&ServeEvent) -> bool,
) -> ServeEvent {
    timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await.expect("core event stream stays open") {
                CoreEvent::Serve(serve) if want(&serve) => return serve,
                _ => {}
            }
        }
    })
    .await
    .expect("the awaited serve event arrived within 5s")
}

/// The end-to-end proof for the ADR-0057 reask reply matrix: an inbound
/// `OP_REASKFILEPING` from a genuinely queued waiter, delivered through the
/// *real* `ClientUdpEngine` demux and the *real* `ServeTask` select loop,
/// egresses an `OP_REASKACK` on the client-UDP send half — the whole async
/// span (`socket → engine → reask_rx → serve task → on_reask_ping →
/// client_udp_tx`) the sans-I/O `ServeState` tests bypass. The waiter
/// advertises its client-UDP contact (as the serve adapter now threads,
/// ADR-0057), so the reask matches by exact IP + port and the ack carries
/// our part status. This green established that the live consume leg's
/// missing egress was *not* a wiring hole — the live reasker had been
/// promoted out of the waiting list into a pending dial-back grant (covered
/// by the `ServeState` dial-back-grant reask test).
#[tokio::test]
async fn a_queued_waiters_live_reask_egresses_a_reask_ack_through_the_real_client_udp_path() {
    reask_loopback(None, WaiterPing::WithStatus).await;
}

/// The same live span with the ADR-0046 crypt layer armed on both ends —
/// the pinned capture direction, deterministically: a crypt-capable waiter
/// sends an **obfuscated** `0x90` (keyed on our user hash + its own sender
/// IP), the real engine dual-path decrypts it, the reply matrix answers, and
/// the real socket-boundary gate obfuscates the `0x91` back — which only the
/// waiter's key recovers. Nothing here is a hand-built datagram: both
/// directions run the production transforms.
#[tokio::test]
async fn an_armed_front_decrypts_a_live_reask_and_obfuscates_the_ack_back() {
    reask_loopback(
        Some(rmule_net::peer::ObfuscationPolicy::Requested),
        WaiterPing::WithStatus,
    )
    .await;
}

/// The same live span, but the UDPv4 waiter — whose hello also
/// claimed extended requests — pings with the file hash alone. aMule's
/// reader throws on that (stock 2.3.3 `UploadClient.cpp:408-412`) and its
/// dispatcher only logs (`ClientUDPSocket.cpp:131-132`), so no `0x91` leaves;
/// rmule's only trace is the event and the counter the runner folds it into.
#[tokio::test]
async fn a_hash_only_reask_from_a_udpv4_waiter_draws_silence_and_a_counter() {
    reask_loopback(None, WaiterPing::HashOnly).await;
}

/// The `0x90` body the queued waiter sends in [`reask_loopback`].
#[derive(Clone, Copy)]
enum WaiterPing {
    /// What aMule's writer puts in a ping to a UDPv4 peer: the hash, its part
    /// status, its complete-source count (stock 2.3.3 `DownloadClient.cpp:1280-1291`).
    WithStatus,
    /// The file hash alone — malformed for a UDPv4, extended-requests sender.
    HashOnly,
}

/// The live reask loopback, plaintext or crypt-armed (`crypt`). With a
/// policy the waiter obfuscates its ping and the ack must come back
/// obfuscated; without one both directions stay plaintext. A
/// [`WaiterPing::HashOnly`] ping must draw no reply at all.
async fn reask_loopback(crypt: Option<rmule_net::peer::ObfuscationPolicy>, shape: WaiterPing) {
    let policy = crate::obfuscation_policy::SharedObfuscationPolicy::new(crypt);
    let file = FileHash::from_bytes([0x11; FileHash::BYTE_LEN]);
    // One store for both seams, exactly as a front-end opens it (ADR-0083).
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .share(SharedFileEntry {
            file_hash: file,
            file_size: 4096,
            path: "/shared/served.bin".into(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    // Our own wire self-facts, as a High-ID login would publish them: the
    // crypt layer keys receive on the hash and send on the public IP.
    let our_hash = UserHash::from_bytes([0x42; UserHash::BYTE_LEN]);
    let our_public_ip = Ipv4Addr::new(203, 0, 113, 9);
    let own = SharedOwnIdentity::default();
    own.set_user_hash(our_hash);
    own.addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            our_public_ip,
        ));

    // The real client-UDP front over a transport we feed on cue.
    let (inbound_tx, inbound_rx) = mpsc::channel::<ClientUdpDatagram>(4);
    let (engine, inboxes) = ClientUdpEngine::new(
        ChannelTransport {
            inbound: Mutex::new(inbound_rx),
        },
        PeerUdpCrypt::new(own.clone(), policy.clone()),
        crate::buddy_link::SharedBuddySlot::default(),
        crate::firewalled::front::SharedFirewalledFront::default(),
        crate::diagnostics::DiagnosticsState::default(),
        tokio::sync::mpsc::channel(4).0,
        crate::client_udp::SharedKadInlet::default(),
    );
    tokio::spawn(engine.run());

    // The serve task's client-UDP reply half, drained through the same
    // send gate the live socket drain applies (`client_udp_tx` →
    // `encrypt_client_udp_send` → `socket.send_to`).
    let (client_udp_tx, mut client_udp_reply_rx) = mpsc::channel::<ClientUdpSend>(4);
    let diagnostics = crate::diagnostics::DiagnosticsState::new();

    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(4);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (_share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let credit: SharedCreditStore = Arc::new(DurableCreditStore::new(store));

    let task = ServeTask {
        registry: Arc::new(registry),
        serve_runtime: FakeServeRuntime {
            bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
            accepts: accept_rx,
        },
        queue: UploadSlotQueue::new(1, 200),
        own_identity: None,
        evt_tx,
        stop_rx,
        share_changed_rx,
        dialed_serve_rx: None,
        credit,
        // Long enough that neither timer fires mid-test (no rerank/purge
        // racing the reask arm).
        rerank_interval: Duration::from_secs(3600),
        reask_rx: Some(inboxes.reask_ping),
        client_udp_tx: Some(client_udp_tx),
        purge_interval: Duration::from_secs(3600),
        purge_after: Duration::from_secs(3600),
        diagnostics: diagnostics.clone(),
        peer_roster: crate::peer_roster::SharedPeerRoster::default(),
        withheld: crate::registry_check::WithheldRows::default(),
        read_failed_tx: None,
    };
    let serve = tokio::spawn(task.run());

    // The task's own first act is the opening announce (the actor emits
    // `ServingStarted` at the bind, before this task exists), so this is the
    // barrier that says the share set is loaded.
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;

    // A holder grabs the sole slot, so the next requester must queue.
    let holder = peer_at([10, 0, 0, 1], 4000);
    let (holder_cmd_tx, _holder_cmd_rx) = mpsc::channel(16);
    let (holder_evt_tx, holder_evt_rx) = mpsc::channel(16);
    accept_tx
        .send(ServeConnection::new(holder, holder_cmd_tx, holder_evt_rx))
        .await
        .unwrap();
    holder_evt_tx
        .send(ServeInput::Server(ServerEvent::SlotRequested {
            file_hash: file,
        }))
        .await
        .unwrap();
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::UploadSlotGranted { .. })
    })
    .await;

    // The waiter identifies advertising its client-UDP reask contact (port
    // + UDP version 4, as the serve adapter now threads from the hello) and
    // queues at rank 1 behind the holder.
    let waiter = peer_at([198, 51, 100, 2], 4000);
    let waiter_udp_port = 6000u16;
    let waiter_hash = UserHash::from_bytes([0x0A; UserHash::BYTE_LEN]);
    let (waiter_cmd_tx, _waiter_cmd_rx) = mpsc::channel(16);
    let (waiter_evt_tx, waiter_evt_rx) = mpsc::channel(16);
    accept_tx
        .send(ServeConnection::new(waiter, waiter_cmd_tx, waiter_evt_rx))
        .await
        .unwrap();
    waiter_evt_tx
        .send(
            HelloFacts {
                tcp_port: 4000,
                udp_port: waiter_udp_port,
                udp_version: 4,
                // The hello's crypt advert: it decides whether the ack may be
                // obfuscated at all (ADR-0046).
                crypt: rmule_net::peer::ObfuscationPolicy::stance_of(crypt),
                ..HelloFacts::of(waiter_hash)
            }
            .identified(),
        )
        .await
        .unwrap();
    waiter_evt_tx
        .send(ServeInput::Server(ServerEvent::SlotRequested {
            file_hash: file,
        }))
        .await
        .unwrap();
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::PeerQueued { rank: 1, .. })
    })
    .await;

    // The live condition: the waiter's `0xC5 0x90` reask arrives from its UDP
    // endpoint. It walks the real engine demux and the real serve task; a
    // well-formed ping must draw a `0x91 OP_REASKACK` addressed back to it.
    let reask_src = rmule_primitives::PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::from([198, 51, 100, 2]),
        waiter_udp_port,
    ));
    let plain_ping = match shape {
        WaiterPing::WithStatus => ReaskFilePing {
            file_hash: file,
            part_status: Some(rmule_peer::PartBitmap::downloader_empty(4096)),
            complete_sources: Some(0),
        },
        WaiterPing::HashOnly => ReaskFilePing {
            file_hash: file,
            part_status: None,
            complete_sources: None,
        },
    }
    .encode_udp();
    // The waiter's own crypt layer, keyed on its sender IP — it obfuscates
    // *for us* (our hash) exactly as aMule does.
    let waiter_own = SharedOwnIdentity::default();
    waiter_own.set_user_hash(waiter_hash);
    // A routable address: the key mixes in the sender's *external* address,
    // and Address Learning refuses a private one as anybody's External
    // Endpoint (ADR-0084), so a LAN fixture would leave the waiter plaintext.
    waiter_own
        .addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            Ipv4Addr::from([198, 51, 100, 2]),
        ));
    let waiter_crypt = PeerUdpCrypt::new(waiter_own, policy.clone());
    let ping = match crypt.map(rmule_net::peer::ObfuscationPolicy::crypt_stance) {
        Some(stance) => {
            let (_, obfuscated) = encrypt_client_udp_send(
                &waiter_crypt,
                ClientUdpSend::to_peer(
                    reask_src,
                    plain_ping.clone(),
                    Some(PeerUdpCryptTarget::new(our_hash, stance)),
                ),
                os_datagram_nonce,
            );
            assert_ne!(obfuscated, plain_ping, "the waiter obfuscated its 0x90");
            obfuscated
        }
        _ => plain_ping,
    };
    inbound_tx.send((reask_src, ping)).await.unwrap();

    if let WaiterPing::HashOnly = shape {
        // The event is the enactment's last act for this ping, after the
        // counter; any reply would already sit on the send half.
        let malformed = next_serve_event(&mut evt_rx, |e| {
            matches!(e, ServeEvent::ReaskPingMalformed { .. })
        })
        .await;
        assert_eq!(malformed, ServeEvent::ReaskPingMalformed { peer: waiter });
        assert!(
            client_udp_reply_rx.try_recv().is_err(),
            "a malformed ping is answered with nothing",
        );
        assert_eq!(
            diagnostics.snapshot().session.malformed_reask_pings_total,
            1
        );
        let _ = stop_tx.send(true);
        let _ = serve.await;
        return;
    }

    let send = timeout(Duration::from_secs(5), client_udp_reply_rx.recv())
        .await
        .expect("a reask reply egressed within 5s")
        .expect("the client-UDP send half stays open");
    // The live socket drain's transform, applied here exactly as `run_actor`
    // applies it before `socket.send_to`.
    let (to, datagram) = encrypt_client_udp_send(
        &PeerUdpCrypt::new(own.clone(), policy.clone()),
        send,
        os_datagram_nonce,
    );
    assert_eq!(
        to, reask_src,
        "the ReaskAck is addressed back to the reasker's UDP endpoint",
    );
    // Crypt-armed: the egress is obfuscated on the wire and only the
    // waiter's key — our public IP as the sender — recovers the `0x91`.
    let datagram = match crypt {
        Some(_) => {
            assert_ne!(
                &datagram[..2],
                &[0xC5, 0x91],
                "an armed ack must not leave in the clear",
            );
            let recovered = waiter_crypt.receive(
                rmule_primitives::DatagramSenderAddress::V4(our_public_ip.octets()),
                datagram.clone(),
            );
            assert_ne!(recovered, datagram, "the waiter's key recovered the ack");
            recovered
        }
        None => datagram,
    };
    assert_eq!(
        &datagram[..2],
        &[0xC5, 0x91],
        "the egress is an OP_EMULEPROT OP_REASKACK",
    );
    // The waiter advertised UDP version 4, so our part status rides ahead of
    // the rank (aMule gates it on the *waiter's* version).
    let ack = ReaskAck::decode_udp(&datagram, 4).expect("egress decodes as a 0x91 ReaskAck");
    assert_eq!(ack.rank, 1, "the queued waiter is confirmed at rank 1");
    assert!(
        ack.part_status.is_some(),
        "a UDPv4 waiter's ReaskAck carries our part status",
    );

    let _ = stop_tx.send(true);
    let _ = serve.await;
}

/// A **dropped** stop sender ends the serve task, exactly as a
/// signalled stop does.
///
/// The actor never sends `true` on its own way out — it drops the whole
/// `ServeActivity`, stop sender and all — and a dropped `watch::Sender` makes
/// `changed()` answer `Err` *immediately, forever*. Read as a spurious wakeup
/// that leaves the loop spinning at full speed, holding the `CoreEvent` sender
/// `Core::shutdown` waits to see dropped. A closed channel is the owner being
/// gone, which is stronger than "stop", so the task leaves — handing its
/// adapter back under the same reason a signalled stop gives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_stop_sender_ends_the_serve_task() {
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let (_accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(1);
    let (evt_tx, _evt_rx) = mpsc::channel::<CoreEvent>(16);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let credit: SharedCreditStore = Arc::new(DurableCreditStore::new(store));

    let serve = tokio::spawn(
        ServeTask {
            registry: Arc::new(registry),
            serve_runtime: FakeServeRuntime {
                bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
                accepts: accept_rx,
            },
            queue: UploadSlotQueue::new(1, 200),
            own_identity: None,
            evt_tx,
            stop_rx,
            share_changed_rx,
            dialed_serve_rx: None,
            credit,
            rerank_interval: Duration::from_secs(3600),
            reask_rx: None,
            client_udp_tx: None,
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: crate::diagnostics::DiagnosticsState::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            withheld: crate::registry_check::WithheldRows::default(),
            read_failed_tx: None,
        }
        .run(),
    );
    // The actor's way out: the activity drops whole, nothing is ever sent.
    drop(stop_tx);
    drop(share_changed_tx);

    let outcome = timeout(Duration::from_secs(5), serve)
        .await
        .expect("the serve task ends when its owner drops")
        .expect("the serve task did not panic");
    assert_eq!(
        outcome.reason,
        ServeStopReason::Requested,
        "an owner that dropped asked for this as surely as a signalled stop did",
    );
}

/// The per-address queue cap live on the serve task (ADR-0088):
/// five peers at **one** address ask for a slot on five real accepted
/// connections. One is served, three wait, and the fifth gets **nothing on
/// its connection** — the reference frames no packet for this refusal
/// (eMule `srchybrid/UploadQueue.cpp:608-613`, aMule
/// `src/UploadQueue.cpp:510-516`), so the only trace it leaves is the
/// diagnostics counter the runner folds the event into.
///
/// Driven through the real `ServeTask` rather than `ServeState` because
/// silence is what is being asserted: only the live task can show that the
/// command half stayed empty while the neighbouring three were written to.
#[tokio::test]
async fn the_fifth_asker_from_one_address_is_served_silence_and_a_counter() {
    let file = FileHash::from_bytes([0x11; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .share(SharedFileEntry {
            file_hash: file,
            file_size: 4096,
            path: "/shared/served.bin".into(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(8);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (_share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let credit: SharedCreditStore = Arc::new(DurableCreditStore::new(store));
    let diagnostics = crate::diagnostics::DiagnosticsState::new();

    let serve = tokio::spawn(
        ServeTask {
            registry: Arc::new(registry),
            serve_runtime: FakeServeRuntime {
                bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
                accepts: accept_rx,
            },
            // One slot and a wide wait list: the only limit that can bite
            // here is the per-address one.
            queue: UploadSlotQueue::new(1, 200),
            own_identity: None,
            evt_tx,
            stop_rx,
            share_changed_rx,
            dialed_serve_rx: None,
            credit,
            rerank_interval: Duration::from_secs(3600),
            reask_rx: None,
            client_udp_tx: None,
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: diagnostics.clone(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            withheld: crate::registry_check::WithheldRows::default(),
            read_failed_tx: None,
        }
        .run(),
    );

    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;

    // Five peers behind one address — different TCP ports, as five clients
    // behind one NAT present themselves.
    let mut command_halves = Vec::new();
    let mut event_halves = Vec::new();
    for port in 4000..4005u16 {
        let peer = peer_at([203, 0, 113, 7], port);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_evt_tx, conn_evt_rx) = mpsc::channel(16);
        accept_tx
            .send(ServeConnection::new(peer, cmd_tx, conn_evt_rx))
            .await
            .unwrap();
        conn_evt_tx
            .send(ServeInput::Server(ServerEvent::SlotRequested {
                file_hash: file,
            }))
            .await
            .unwrap();
        command_halves.push(cmd_rx);
        // Held so the connection's event half stays open for the task.
        event_halves.push(conn_evt_tx);
    }

    // The first takes the slot; the next three queue at ranks 1..3.
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::UploadSlotGranted { .. })
    })
    .await;
    for rank in 1..=3u16 {
        next_serve_event(
            &mut evt_rx,
            |e| matches!(e, ServeEvent::PeerQueued { rank: seen, .. } if *seen == rank),
        )
        .await;
    }

    // The fifth is turned away by the cap, and only the event says so.
    let capped = next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::UploadAddressCapReached { .. })
    })
    .await;
    assert_eq!(
        capped,
        ServeEvent::UploadAddressCapReached {
            peer: peer_at([203, 0, 113, 7], 4004),
        },
    );
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .upload_address_cap_refusals_total,
        1,
        "the silent refusal is counted",
    );

    // The four admitted peers were each written to; the fifth's command half
    // never received a byte of intent — no grant, no rank, and no refusal.
    for (index, half) in command_halves.iter_mut().enumerate() {
        match half.try_recv() {
            Ok(_) if index < 4 => {}
            Ok(command) => panic!("the capped peer was answered with {command:?}"),
            Err(error) => assert!(index == 4, "peer {index} was never answered: {error:?}"),
        }
    }

    let _ = stop_tx.send(true);
    let _ = serve.await;
}

/// A hash-only standalone name ask from a peer whose hello claimed
/// extended requests makes aMule's reader throw and its packet handler drop
/// the client (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:408-412`,
/// `ClientTCPSocket.cpp:2018-2047`). Through the real serve task: the name is
/// never sent, the connection is told to close, and the event reaches the
/// core stream with its counter folded.
#[tokio::test]
async fn a_hash_only_name_ask_from_a_claimant_closes_the_connection_and_is_counted() {
    let file = FileHash::from_bytes([0x11; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .share(SharedFileEntry {
            file_hash: file,
            file_size: 4096,
            path: "/shared/served.bin".into(),
            name: "served.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(4);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (_share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let credit: SharedCreditStore = Arc::new(DurableCreditStore::new(store));
    let diagnostics = crate::diagnostics::DiagnosticsState::new();

    let serve = tokio::spawn(
        ServeTask {
            registry: Arc::new(registry),
            serve_runtime: FakeServeRuntime {
                bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
                accepts: accept_rx,
            },
            queue: UploadSlotQueue::new(1, 200),
            own_identity: None,
            evt_tx,
            stop_rx,
            share_changed_rx,
            dialed_serve_rx: None,
            credit,
            rerank_interval: Duration::from_secs(3600),
            reask_rx: None,
            client_udp_tx: None,
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: diagnostics.clone(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            withheld: crate::registry_check::WithheldRows::default(),
            read_failed_tx: None,
        }
        .run(),
    );
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;

    let asker = peer_at([198, 51, 100, 2], 4000);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (conn_evt_tx, conn_evt_rx) = mpsc::channel(16);
    accept_tx
        .send(ServeConnection::new(asker, cmd_tx, conn_evt_rx))
        .await
        .unwrap();
    conn_evt_tx
        .send(
            HelloFacts {
                tcp_port: 4000,
                udp_version: 4,
                extended_requests_version: 1,
                crypt: CryptStance::disabled(),
                ..HelloFacts::of(UserHash::from_bytes([0x0A; UserHash::BYTE_LEN]))
            }
            .identified(),
        )
        .await
        .unwrap();
    conn_evt_tx
        .send(ServeInput::Server(ServerEvent::FileRequested {
            file_hash: file,
            status: rmule_peer::PartStatusTail::default(),
        }))
        .await
        .unwrap();

    let malformed = next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::NameAskMalformed { .. })
    })
    .await;
    assert_eq!(malformed, ServeEvent::NameAskMalformed { peer: asker });
    assert_eq!(diagnostics.snapshot().session.malformed_name_asks_total, 1);
    loop {
        let command = timeout(Duration::from_secs(5), cmd_rx.recv())
            .await
            .expect("the connection is told to close")
            .expect("the command half stays open");
        match command {
            ServeOutput::Disconnect => break,
            ServeOutput::Server(ServerCommand::AnswerFileName { .. }) => {
                panic!("a malformed ask was answered")
            }
            _ => {}
        }
    }

    let _ = stop_tx.send(true);
    let _ = serve.await;
}

/// `self_position` is what the serve loop's Low-ID abuse guard reads at every
/// connection event; its own accessor already follows a
/// mid-session `OP_IDCHANGE`, so this is the reader-side proof:
/// the next ask must read the re-assigned id, not the login's.
#[test]
fn self_position_follows_a_mid_session_reassignment() {
    use crate::own_identity::ConnectedSession;
    use crate::serve::state::ServeSelfPosition;

    let own = SharedOwnIdentity::default();
    assert_eq!(
        super::self_position(None),
        ServeSelfPosition {
            low_id: false,
            server: None
        },
        "a serve task woven with no identity holds the un-firewalled default"
    );
    assert_eq!(
        super::self_position(Some(&own)),
        ServeSelfPosition {
            low_id: true,
            server: None
        },
        "no session yet: Low ID, no server"
    );

    let server = Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4661);
    own.set_connected_session(Some(ConnectedSession {
        server: Some(server),
        client_id: ClientId::from_u32(0x0000_2A57),
    }));
    assert_eq!(
        super::self_position(Some(&own)),
        ServeSelfPosition {
            low_id: true,
            server: Some(server)
        },
        "logged in Low ID"
    );

    own.reassign_client_id(ClientId::from_u32(0x0100_007F));
    assert_eq!(
        super::self_position(Some(&own)),
        ServeSelfPosition {
            low_id: false,
            server: Some(server)
        },
        "re-assigned High ID mid-session: the next ask reads it at once"
    );
}

mod roster;
