//! Driving one dialed or adopted peer worker to a downloaded part: the block
//! request loop that turns granted slots into bytes, the identity wait the
//! dialer blocks on, and the AICH recovery detour a corrupt part triggers.

use std::collections::VecDeque;
use std::time::Duration;

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{
    EMBLOCKSIZE, FileProbeStatus, PartBitmap, PartRanges, PeerCommand, PeerEvent, PeerIdentity,
    SlotReleaseReason,
};
use rmule_primitives::{AichRootHash, Ed2kFileLink, PeerEndpoint};
use tokio::sync::mpsc;

use crate::PartPlan;
use crate::adapters::dialed_serve::{
    DialedRoute, SharedDialedServeSink, bridge_dialed_serve, route_dialed_connection,
};
use crate::adapters::kad_runtime::SharedKadBootstrap;
use crate::adapters::peer_transfer::{PeerWorkerCommand, PeerWorkerEvent};
use crate::adapters::serve_runtime::ServeConnection;
use crate::service::DialEnd;

/// Drive a peer worker over an established `conn` — the body shared by a dialed
/// worker ([`RuntimePeerTransferService`](crate::RuntimePeerTransferService)'s `start_peer_worker`) and an adopted
/// inbound worker (a called-back Low-ID peer, ADR-0039). `identified` is `None`
/// for a dialed worker (wait for the peer's hello) and `Some(identity)` for an
/// adopted one — the inbound hello already identified it during accept, so the
/// wait is skipped, the worker enters the requester flow directly, and the
/// identity's own hello stance and serving buddy
/// ride through with it.
/// `own_status` is what rmule holds of `file`; the connect-time name ask
/// carries it. `want_sources` is the download's source-ask
/// decision for this connection (ADR-0108).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drive_peer_worker(
    conn: PeerConnection,
    peer: PeerEndpoint,
    file: Ed2kFileLink,
    own_status: PartBitmap,
    want_sources: bool,
    identified: Option<PeerIdentity>,
    mut command_rx: mpsc::Receiver<PeerWorkerCommand>,
    event_tx: mpsc::Sender<PeerWorkerEvent>,
    slot_wait_timeout: Duration,
    dialed_serve_sink: SharedDialedServeSink,
    kad_bootstrap: SharedKadBootstrap,
    addresses: crate::address_learning::SharedAddressLearning,
    hello_refusals: crate::hello_refusals::SharedHelloRefusals,
) {
    // Split the one socket into the two consumers: the router owns the
    // connection, fans events to the download (requester) half and the serve
    // (Server Capability) half, and frames commands from both back onto the
    // socket.
    let (peer_cmd_tx, peer_cmd_rx) = mpsc::channel(16);
    let (requester_tx, mut requester_rx) = mpsc::channel(64);
    // Server Capability events arriving before the serve bridge attaches
    // (below, post-identify) buffer here; the handshake ordering means no
    // serve burst precedes `PeerIdentified`, so this depth is ample.
    let (server_tx, server_rx) = mpsc::channel(16);
    tokio::spawn(route_dialed_connection(
        conn,
        peer_cmd_rx,
        DialedRoute {
            requester_tx,
            server_tx,
            worker_evt_tx: event_tx.clone(),
            adopted_support: identified.as_ref().map(PeerIdentity::source_exchange),
            kad_bootstrap,
            addresses,
        },
    ));

    // A dialed worker waits for the peer's hello; an adopted inbound worker
    // already identified during accept (ADR-0039), so its `user_hash` and
    // crypt stance are supplied and the wait is skipped.
    // An adopted inbound worker (a called-back Low-ID peer) is firewalled with no
    // reachable client-UDP contact, so it never carries a reask endpoint; only a
    // dialed worker learns one from the peer's hello.
    let (identity, udp_contact) = match identified {
        // An adopted inbound worker identified during accept; the accept-side
        // identity's own hello stance rides through adoption, so
        // it seeds `hello_crypts` the same as a dialed worker's — moot for the
        // reask itself: a called-back Low-ID peer advertises no reachable
        // client-UDP contact.
        Some(identity) => (identity, None),
        None => match wait_for_peer_identified(&mut requester_rx, &hello_refusals).await {
            Ok(identity) => {
                let udp_contact = identity.client_udp_reask();
                (identity, udp_contact)
            }
            Err(cause) => {
                super::end_dial(&event_tx, cause).await;
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return; // dropping peer_cmd_tx winds the router (and socket) down
            }
        },
    };
    let user_hash = identity.user_hash();
    if event_tx
        .send(PeerWorkerEvent::Identified {
            user_hash,
            crypt: Some(identity.crypt_stance()),
            software: identity.software().clone(),
        })
        .await
        .is_err()
    {
        return;
    }
    if event_tx.send(PeerWorkerEvent::Connected).await.is_err() {
        return;
    }
    // Surface the peer's client-UDP reask contact right after `Connected`, so the
    // runner can pool this source for UDP reask if it queues us and hangs up
    // (ADR-0057). Absent ⇒ the source is TCP-reask-only.
    if let Some((udp_port, udp_version)) = udp_contact
        && event_tx
            .send(PeerWorkerEvent::UdpContact {
                udp_port,
                udp_version,
            })
            .await
            .is_err()
    {
        return;
    }
    // The peer's serving buddy: kept by the brain so the
    // source's next buddy callback goes straight to it.
    if let Some(buddy) = identity.serving_buddy()
        && event_tx
            .send(PeerWorkerEvent::ServingBuddy {
                buddy_udp: buddy.buddy_udp,
            })
            .await
            .is_err()
    {
        return;
    }

    // Connect-time file negotiation (ADR-0054 emit): fold the name,
    // part-status, and source-exchange asks into one `RequestFile` — the
    // session frames it as a single `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT`
    // bundle when the peer advertised MultiPacket, or as the same standalone
    // packets otherwise (one decision core, session-owned gate), mirroring
    // aMule's `SendFileRequest` toward every new source, one part or many. A
    // one-part file's set is the name and SX asks alone, and its name answer
    // is the whole probe (a complete source, aMule `ProcessFileInfo`) — the
    // bundle keeps the SX2 ask off aMule 2.3.3's standalone `0x83` arm, which
    // disconnects on it. The SX answer arrives on the event stream and is forwarded as `SourcesReceived` while the part
    // download drains events (ADR-0055). The AICH-root ask stays the brain's
    // separate Connected-time decision (ADR-0038) — it owns "still rootless?"
    // dynamically, stopping once a root commits — so `want_aich_root` is not
    // folded from a spawn-time snapshot here.
    let connect_request = PeerCommand::RequestFile {
        file_hash: file.file_hash,
        file_size: file.size,
        want_sources,
        want_aich_root: false,
        own_status,
    };
    // Whether the ask went out is the session's to say (ADR-0108): its
    // `FileRequestSent` reaches the download through the router as
    // `SourceExchange` + `SourcesAsked`.
    let _ = peer_cmd_tx.send(connect_request).await;

    // Same-socket serve: while the serve activity is running, hand the serve
    // half of this connection to it so the peer's pull is admitted to the one
    // cross-connection UploadSlotQueue exactly like an accepted connection. When
    // not serving the sink is empty and the router drops Server Capability
    // requests.
    let serve_sink = dialed_serve_sink.lock().await.clone();
    if let Some(serve_sink) = serve_sink {
        let (serve_cmd_tx, serve_cmd_rx) = mpsc::channel(16);
        let (serve_evt_tx, serve_evt_rx) = mpsc::channel(16);
        tokio::spawn(bridge_dialed_serve(
            server_rx,
            serve_cmd_rx,
            peer_cmd_tx.clone(),
            serve_evt_tx,
        ));
        let _ = serve_sink
            .send(ServeConnection::new(peer, serve_cmd_tx, serve_evt_rx))
            .await;
    } else {
        // Not serving: nobody drains the serve half. Close it now so the
        // router's bounded `server_tx.send(..)` fails fast (the request is
        // dropped) instead of filling at capacity and stalling the socket once
        // a peer sends >16 Server Capability requests.
        drop(server_rx);
    }

    // Set once the download signals a local-reason abandon (ADR-0056): the
    // teardown then emits `OP_CANCELTRANSFER` instead of the silent slot
    // release a normal completion uses.
    let mut cancel = false;
    // Commands the block loop read mid-part but could not act on there (a
    // next part, an AICH detour); served here, in arrival order, before the
    // channel is read again.
    let mut deferred = VecDeque::new();
    loop {
        let command = match deferred.pop_front() {
            Some(command) => command,
            None => match command_rx.recv().await {
                Some(command) => command,
                None => break,
            },
        };
        match command {
            PeerWorkerCommand::RequestPart {
                plan,
                resume_offset,
            } => {
                let streamed = stream_part_download(
                    &mut requester_rx,
                    &peer_cmd_tx,
                    &event_tx,
                    PartCommands {
                        rx: &mut command_rx,
                        deferred: &mut deferred,
                    },
                    &file,
                    plan,
                    resume_offset,
                    slot_wait_timeout,
                )
                .await;
                match streamed {
                    Streamed::Next => {}
                    Streamed::WindDown => break,
                    Streamed::Shutdown { cancel: c } => {
                        cancel = c;
                        break;
                    }
                }
            }
            PeerWorkerCommand::RequestAich { part, root } => {
                if !request_aich_recovery(
                    &mut requester_rx,
                    &peer_cmd_tx,
                    &event_tx,
                    &file,
                    part,
                    root,
                    slot_wait_timeout,
                )
                .await
                {
                    break;
                }
            }
            PeerWorkerCommand::RequestAichFileHash => {
                // Fire-and-forget: the OP_AICHFILEHASHANS answer arrives on the
                // event stream and is forwarded as AichFileHashReceived while a
                // part streams (ADR-0038).
                let _ = peer_cmd_tx
                    .send(PeerCommand::RequestAichFileHash {
                        file_hash: file.file_hash,
                    })
                    .await;
            }
            PeerWorkerCommand::Shutdown { cancel: c } => {
                cancel = c;
                break;
            }
        }
    }
    // A cancel `Shutdown` the runner enqueued while this worker was mid-stream
    // never reached the match above: the streaming/recovery helper broke on its
    // own timeout or the peer's disconnect before returning to read it. Drain
    // the buffer so a pending abandon still commands `OP_CANCELTRANSFER`
    // (ADR-0056 local-reason teardown) rather than a silent release.
    if !cancel {
        while let Ok(command) = command_rx.try_recv() {
            if matches!(command, PeerWorkerCommand::Shutdown { cancel: true }) {
                cancel = true;
                break;
            }
        }
    }
    // Wind the held slot down (a no-op if none): a local-reason abandon emits
    // `OP_CANCELTRANSFER` (the requester-side counterpart to a silent release,
    // ADR-0056), a completion or peer-initiated end releases silently. Then drop
    // `peer_cmd_tx`: if the serve bridge still holds a clone the router keeps
    // serving until the peer disconnects; otherwise the router sees its command
    // channel close and shuts the socket down (ADR-0025 release).
    let teardown = if cancel {
        PeerCommand::CancelTransfer {
            file_hash: file.file_hash,
        }
    } else {
        PeerCommand::ReleaseSlot {
            file_hash: file.file_hash,
        }
    };
    let _ = peer_cmd_tx.send(teardown).await;
    drop(peer_cmd_tx);
}

async fn wait_for_peer_identified(
    events: &mut mpsc::Receiver<PeerEvent>,
    hello_refusals: &crate::hello_refusals::SharedHelloRefusals,
) -> Result<PeerIdentity, DialEnd> {
    while let Some(event) = events.recv().await {
        match event {
            // The peer's user hash keys its credit ledger; its client-UDP reask
            // contact (ADR-0057) rides alongside so a queued-then-hung-up source
            // can be UDP-reasked at its advertised endpoint, and its crypt stance
            // says whether that reask may be obfuscated (ADR-0046).
            PeerEvent::PeerIdentified { identity } => return Ok(identity),
            // The answer was refused by name (ADR-0050); the close follows.
            PeerEvent::HelloRefused { refusal } => hello_refusals.report(refusal).await,
            PeerEvent::Disconnected { reason } => {
                return Err(super::dial_end::closed_before_hello(reason));
            }
            _ => {}
        }
    }
    Err(DialEnd::ClosedBeforeHello)
}

/// Ask the peer for the AICH recovery data of `part` (quoting the trusted
/// master `root`) and forward the answer to core (ADR-0038). The recovery data
/// verifies against the trusted root core-side, so asking any connected peer is
/// safe. On timeout or disconnect, forwards an *empty* answer so the runner
/// resolves the awaiting part via the MD4 retire-all fallback rather than
/// stranding it. Returns `false` (winding the worker down) only on disconnect.
async fn request_aich_recovery(
    events: &mut mpsc::Receiver<PeerEvent>,
    cmd_tx: &mpsc::Sender<PeerCommand>,
    event_tx: &mpsc::Sender<PeerWorkerEvent>,
    file: &Ed2kFileLink,
    part: u16,
    root: AichRootHash,
    timeout: Duration,
) -> bool {
    if cmd_tx
        .send(PeerCommand::RequestAich {
            file_hash: file.file_hash,
            part,
            root,
        })
        .await
        .is_err()
    {
        let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
        return false;
    }
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            // The peer answered: forward it; core verifies + localizes.
            Ok(Some(PeerEvent::AichAnswerReceived {
                part: answered,
                recovery_data,
                ..
            })) if answered == part => {
                return event_tx
                    .send(PeerWorkerEvent::AichAnswerReceived {
                        part,
                        recovery_data,
                    })
                    .await
                    .is_ok();
            }
            // Disconnected: resolve the awaiting part with an empty answer (→
            // retire-all fallback), then wind the worker down.
            Ok(None) | Ok(Some(PeerEvent::Disconnected { .. })) => {
                let _ = event_tx
                    .send(PeerWorkerEvent::AichAnswerReceived {
                        part,
                        recovery_data: Vec::new(),
                    })
                    .await;
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return false;
            }
            // No answer within the budget: empty answer → fallback, keep worker.
            Err(_) => {
                return event_tx
                    .send(PeerWorkerEvent::AichAnswerReceived {
                        part,
                        recovery_data: Vec::new(),
                    })
                    .await
                    .is_ok();
            }
            // Any other event during the wait: ignore and keep waiting.
            Ok(Some(_)) => {}
        }
    }
}

/// Stream one part's bytes from `resume_offset` to the part end in
/// `<= EMBLOCKSIZE` blocks, emitting each block to core via `BlockReceived`.
/// A real peer grants the slot but sends nothing for a request whose range
/// exceeds one block, so the next block is requested only once every byte
/// already requested has arrived. Core (not the worker) owns assembly and
/// completion (ADR-0029): the worker forwards each block as it arrives and
/// reports `PartStreamed` once it has delivered its whole assigned range.
///
/// Every wait is bounded by `slot_wait_timeout` measured from the last
/// sign of data progress: a busy peer may queue us (and rank us)
/// indefinitely, and a peer that grants a slot may then stall delivering
/// nothing. Either way, if no part bytes arrive within the budget the
/// worker gives up and reports `SlotTimeout`. The budget resets on each
/// received block so a healthy slow transfer is not cut off.
#[allow(clippy::too_many_arguments)]
async fn stream_part_download(
    events: &mut mpsc::Receiver<PeerEvent>,
    cmd_tx: &mpsc::Sender<PeerCommand>,
    event_tx: &mpsc::Sender<PeerWorkerEvent>,
    commands: PartCommands<'_>,
    file: &Ed2kFileLink,
    plan: PartPlan,
    resume_offset: u64,
    slot_wait_timeout: Duration,
) -> Streamed {
    let file_hash = file.file_hash;
    let part_end = plan.offset + plan.len;
    let mut requested_until = resume_offset;
    let mut received_until = resume_offset;
    let mut progress_deadline = tokio::time::Instant::now() + slot_wait_timeout;

    loop {
        if received_until >= part_end {
            // Delivered the whole assigned range; core decides completion
            // once the shared per-part prefix reaches the part length.
            return match event_tx
                .send(PeerWorkerEvent::PartStreamed {
                    part_index: plan.part_index,
                })
                .await
            {
                Ok(()) => Streamed::Next,
                Err(_) => Streamed::WindDown,
            };
        }

        if requested_until < part_end && received_until >= requested_until {
            let block_end = (requested_until + EMBLOCKSIZE).min(part_end);
            let ranges = match PartRanges::new([(requested_until, block_end), (0, 0), (0, 0)]) {
                Ok(ranges) => ranges,
                Err(_) => {
                    let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                    return Streamed::WindDown;
                }
            };
            if cmd_tx
                .send(PeerCommand::RequestParts {
                    file_hash,
                    file_size: file.size,
                    ranges,
                })
                .await
                .is_err()
            {
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return Streamed::WindDown;
            }
            requested_until = block_end;
        }

        // Bound every wait by the no-progress budget: a busy peer can
        // queue us forever before a grant, and a peer that grants can then
        // stall sending nothing. The deadline resets whenever a block
        // arrives (below), so a healthy transfer is never cut off.
        //
        // The command channel is read between blocks too: a `Shutdown`
        // mid-part stops the stream at once instead of letting the peer send
        // the rest of a part the download has already let go of (aMule's
        // `CUpDownClient::Disconnected` aborts the transfer on the spot). The
        // bias puts the command first so a shutdown is never starved by a
        // busy block stream.
        let event = tokio::select! {
            biased;
            command = commands.rx.recv() => match command {
                Some(PeerWorkerCommand::Shutdown { cancel }) => {
                    return Streamed::Shutdown { cancel };
                }
                Some(PeerWorkerCommand::RequestAichFileHash) => {
                    let _ = cmd_tx
                        .send(PeerCommand::RequestAichFileHash { file_hash })
                        .await;
                    continue;
                }
                Some(later) => {
                    commands.deferred.push_back(later);
                    continue;
                }
                None => return Streamed::WindDown,
            },
            waited = tokio::time::timeout_at(progress_deadline, events.recv()) => match waited {
                Ok(event) => event,
                Err(_) => {
                    let _ = event_tx.send(PeerWorkerEvent::SlotTimeout).await;
                    return Streamed::WindDown;
                }
            },
        };
        match event {
            Some(PeerEvent::HashSetReceived {
                file_hash: received,
                part_hashes,
            }) if received == file_hash => {
                if event_tx
                    .send(PeerWorkerEvent::HashSetReceived { part_hashes })
                    .await
                    .is_err()
                {
                    return Streamed::WindDown;
                }
            }
            Some(PeerEvent::SlotGranted { file_hash: granted }) if granted == file_hash => {
                if event_tx.send(PeerWorkerEvent::SlotGranted).await.is_err() {
                    return Streamed::WindDown;
                }
            }
            Some(PeerEvent::PartReceived {
                file_hash: received,
                offset,
                bytes,
            }) if received == file_hash => {
                // Data progress: extend the no-progress budget and forward
                // the block to core, which merges it into the shared prefix.
                progress_deadline = tokio::time::Instant::now() + slot_wait_timeout;
                received_until = offset + bytes.len() as u64;
                if event_tx
                    .send(PeerWorkerEvent::BlockReceived {
                        part_index: plan.part_index,
                        offset,
                        bytes,
                    })
                    .await
                    .is_err()
                {
                    return Streamed::WindDown;
                }
            }
            Some(PeerEvent::SourcesReceived {
                file_hash: received,
                sources,
            }) if received == file_hash => {
                // Forward exchanged sources to the runner's candidate pool
                // (ADR-0055); non-terminal — keep streaming this part.
                let _ = event_tx
                    .send(PeerWorkerEvent::SourcesReceived { sources })
                    .await;
            }
            Some(PeerEvent::FileProbed {
                file_hash: probed,
                status,
            }) if probed == file_hash => {
                // The one bit of the peer's part picture the source-ask gate
                // reads (ADR-0108); non-terminal.
                let complete = match &status {
                    FileProbeStatus::Available { complete, .. } => *complete,
                    FileProbeStatus::NotAvailable => false,
                };
                let _ = event_tx
                    .send(PeerWorkerEvent::PartsAdvertised { complete })
                    .await;
            }
            Some(PeerEvent::AichFileHashReceived { root }) => {
                // A trusted-set root proposal (ADR-0038); forward to the
                // runner's vote tally. Non-terminal — keep streaming. No file
                // guard: the 0x9D answer carries no file hash.
                let _ = event_tx
                    .send(PeerWorkerEvent::AichFileHashReceived { root })
                    .await;
            }
            // The peer signals it finished the requested range; the
            // range-done check at the top of the loop emits PartStreamed
            // once the assigned range is delivered, otherwise the next block
            // is requested.
            Some(PeerEvent::SlotReleased {
                file_hash: released,
                reason: SlotReleaseReason::DownloadComplete,
            }) if released == file_hash => {}
            Some(PeerEvent::SlotReleased {
                file_hash: released,
                reason: SlotReleaseReason::QueueRejected,
            }) if released == file_hash => {
                let _ = event_tx.send(PeerWorkerEvent::SlotRejected).await;
                return Streamed::WindDown;
            }
            Some(PeerEvent::SlotReleased {
                file_hash: released,
                ..
            }) if released == file_hash => {
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return Streamed::WindDown;
            }
            // The peer is holding us in its upload queue. Non-terminal:
            // keep the connection open and keep waiting for a slot grant,
            // but forward the position so core/CLI see queue progress.
            Some(PeerEvent::QueueRanked {
                file_hash: ranked,
                rank,
            })
            | Some(PeerEvent::QueueProgress {
                file_hash: ranked,
                new_rank: rank,
                ..
            }) if ranked == file_hash => {
                if event_tx
                    .send(PeerWorkerEvent::Queued { rank })
                    .await
                    .is_err()
                {
                    return Streamed::WindDown;
                }
            }
            Some(PeerEvent::CommandRejected { .. })
            | Some(PeerEvent::Disconnected { .. })
            | None => {
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return Streamed::WindDown;
            }
            _ => {}
        }
    }
}

/// The worker's command side, lent to the block loop so it can hear a
/// `Shutdown` mid-part; anything else it reads there waits in `deferred`.
struct PartCommands<'a> {
    rx: &'a mut mpsc::Receiver<PeerWorkerCommand>,
    deferred: &'a mut VecDeque<PeerWorkerCommand>,
}

/// How one part's stream ended.
enum Streamed {
    /// The assigned range was delivered; read the next command.
    Next,
    /// The peer or the core side went away; wind the worker down.
    WindDown,
    /// The download told this worker to stop mid-part.
    Shutdown { cancel: bool },
}
