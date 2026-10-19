//! Driving one dialed or adopted peer worker: the probe wait its slot ask
//! waits on, the wait between handouts that hears the slot's answers and the
//! link's end, the block request loop that turns handed blocks into bytes
//! (ADR-0117), the identity wait the dialer blocks on, and the AICH recovery
//! detour a corrupt part triggers.

use std::collections::VecDeque;
use std::time::Duration;

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{
    PartBitmap, PartRanges, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent,
};
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, PeerEndpoint};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::adapters::InboundPeerDeps;
use crate::adapters::dialed_serve::{
    DialedRoute, LinkOrigin, bridge_dialed_serve, route_dialed_connection,
};
use crate::adapters::hello_wait::{Opening, await_hello};
use crate::adapters::peer_link::{DownloadHalf, JoinedLink};
use crate::adapters::peer_transfer::{PeerWorkerCommand, PeerWorkerEvent};
use crate::adapters::serve_runtime::{ServeConnection, ServeInput};
use crate::service::DialEnd;

use self::aich::await_aich_answer;
use self::pipeline::{Pipeline, RANGES_PER_REQUEST};
use self::wait::{
    Ended, Idled, SlotNews, await_probe, forward_shared, forward_slot_news, idle_wait, next_event,
};

/// Drive a peer worker over an established `conn` — the body shared by a dialed
/// worker ([`RuntimePeerTransferService`](crate::RuntimePeerTransferService)'s `start_peer_worker`) and an adopted
/// inbound worker (a called-back Low-ID peer, ADR-0039). `origin` is the
/// dial's **Dial in Flight** for a dialed worker (wait for the peer's hello)
/// and the identity for an adopted one — the inbound hello already identified
/// it during accept, so the wait is skipped, the worker enters the requester
/// flow directly, and that identity is what the download keeps.
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
    origin: LinkOrigin,
    command_rx: mpsc::Receiver<PeerWorkerCommand>,
    event_tx: mpsc::Sender<PeerWorkerEvent>,
    deps: InboundPeerDeps,
) {
    let slot_wait_timeout = deps.slot_wait_timeout;
    let hello_refusals = deps.hello_refusals.clone();
    let dialed_serve_sink = deps.dialed_serve_sink.clone();
    // Split the one socket into its consumers: the router owns the
    // connection, fans events to the download riding it (the requester) and
    // the serve half (Server Capability), and frames each one's commands back
    // onto the socket. This download is the link's first rider; once the
    // peer is identified another download of it may wait for the next turn
    // (ADR-0107, "One peer, one link").
    let (peer_cmd_tx, peer_cmd_rx) = mpsc::channel(16);
    let (requester_tx, mut requester_rx) = mpsc::channel(64);
    let (serve_cmd_tx, serve_cmd_rx) = mpsc::channel(16);
    // Server Capability events arriving before the serve bridge attaches
    // (below, post-identify) buffer here; the handshake ordering means no
    // serve burst precedes `Identified`, so this depth is ample.
    let (server_tx, server_rx) = mpsc::channel(16);
    // An adopted inbound worker already identified during accept (ADR-0039):
    // its identity reaches the download before the router starts, so every
    // revision the router forwards follows it. A dialed worker's comes from
    // the router at the peer's hello.
    let adopted = matches!(origin, LinkOrigin::Adopted(_));
    if let LinkOrigin::Adopted(identity) = &origin
        && event_tx
            .send(PeerWorkerEvent::Identity(identity.clone()))
            .await
            .is_err()
    {
        return;
    }
    tokio::spawn(route_dialed_connection(
        conn,
        DialedRoute {
            rider: DownloadHalf {
                requester_tx,
                worker_evt_tx: event_tx.clone(),
                peer_cmd_rx,
            },
            server_tx,
            serve_cmd_rx,
            deps,
            origin,
        },
    ));
    if !adopted
        && let Err(cause) = wait_for_peer_identified(&mut requester_rx, &hello_refusals).await
    {
        super::end_dial(&event_tx, cause).await;
        let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
        return; // dropping both command senders winds the router (and socket) down
    }
    work_the_link(
        WorkerHalves {
            peer_cmd_tx,
            requester_rx,
        },
        Some(ServeHalf {
            peer,
            server_rx,
            serve_cmd_tx,
            sink: dialed_serve_sink,
        }),
        &file,
        own_status,
        want_sources,
        command_rx,
        event_tx,
        slot_wait_timeout,
    )
    .await;
}

/// Drive a download worker over a **Served Link** it joined (ADR-0107, "One
/// peer, one link"): the peer is linked to us already, so nothing is dialed
/// and nothing waits for a hello — the link's identity is the one the
/// download keeps, as an adopted worker's is — and the link's serve half
/// stays where it is, registered since the peer came in.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drive_joined_worker(
    joined: JoinedLink,
    file: Ed2kFileLink,
    own_status: PartBitmap,
    want_sources: bool,
    command_rx: mpsc::Receiver<PeerWorkerCommand>,
    event_tx: mpsc::Sender<PeerWorkerEvent>,
    slot_wait_timeout: Duration,
) {
    let JoinedLink {
        identity,
        peer_cmd_tx,
        requester_rx,
    } = joined;
    if event_tx
        .send(PeerWorkerEvent::Identity(identity))
        .await
        .is_err()
    {
        return;
    }
    work_the_link(
        WorkerHalves {
            peer_cmd_tx,
            requester_rx,
        },
        None,
        &file,
        own_status,
        want_sources,
        command_rx,
        event_tx,
        slot_wait_timeout,
    )
    .await;
}

/// The download's two ends of a link: where its commands are framed and where
/// the link's requester events arrive.
struct WorkerHalves {
    peer_cmd_tx: mpsc::Sender<PeerCommand>,
    requester_rx: mpsc::Receiver<PeerEvent>,
}

/// A dialed or adopted link's serve half, handed to the serve activity once
/// the worker is connected.
struct ServeHalf {
    peer: PeerEndpoint,
    server_rx: mpsc::Receiver<ServeInput>,
    /// Where the serve half's commands are framed onto the link.
    serve_cmd_tx: mpsc::Sender<PeerCommand>,
    sink: crate::adapters::SharedDialedServeSink,
}

/// From a connected link to the worker's end: report the connection, send the
/// connect-time file request, hand the serve half (when the link has one of
/// its own) to the serve activity, then take the download's commands until it
/// winds the worker down.
#[allow(clippy::too_many_arguments)]
async fn work_the_link(
    halves: WorkerHalves,
    serve_half: Option<ServeHalf>,
    file: &Ed2kFileLink,
    own_status: PartBitmap,
    want_sources: bool,
    mut command_rx: mpsc::Receiver<PeerWorkerCommand>,
    event_tx: mpsc::Sender<PeerWorkerEvent>,
    slot_wait_timeout: Duration,
) {
    let WorkerHalves {
        peer_cmd_tx,
        mut requester_rx,
    } = halves;
    if event_tx.send(PeerWorkerEvent::Connected).await.is_err() {
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
    let connect_request = PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash: file.file_hash,
        file_size: file.size,
        want_sources,
        want_aich_root: false,
        own_status,
    });
    // Whether the ask went out is the session's to say (ADR-0108): its
    // `FileRequestSent` reaches the download through the router as
    // `SourceExchange` + `SourcesAsked`.
    let _ = peer_cmd_tx.send(connect_request).await;

    // Same-socket serve: a link of the worker's own hands its serve half to
    // the serve activity, so the peer's pull is admitted to the one
    // cross-connection UploadSlotQueue exactly like an accepted connection; a
    // joined link's serve half never left it.
    if let Some(half) = serve_half {
        hand_over_serve_half(half).await;
    }

    // Set once the download signals a local-reason abandon (ADR-0056): the
    // teardown then emits `OP_CANCELTRANSFER` instead of the silent slot
    // release a normal completion uses.
    let mut cancel = false;
    let mut link = WorkerLink::new(
        &mut requester_rx,
        &peer_cmd_tx,
        &event_tx,
        &mut command_rx,
        slot_wait_timeout,
    );
    // The link's request pipeline, kept across handouts (ADR-0029).
    let mut pipeline = Pipeline::new();
    // The slot ask waits for the probe's answer (ADR-0112): the brain asks
    // on `PartsAdvertised` and hands the part at the grant, so a partial
    // source is never handed a part it lacks.
    let probed = await_probe(&mut link, file.file_hash, slot_wait_timeout).await;
    match probed {
        Streamed::Shutdown { cancel: c } => cancel = c,
        Streamed::Stalled => cancel = pipeline.holds_slot(),
        _ => {}
    }
    if matches!(probed, Streamed::Next) {
        // A slot wait — from the probe's answer, or the flow's return to the
        // queue — is bounded by the slot budget with no part streaming
        // (ADR-0026).
        let mut slot_deadline = tokio::time::Instant::now() + slot_wait_timeout;
        loop {
            // An AICH ask a stream sent is answered before the worker idles:
            // the download holds the part until it is (ADR-0038).
            if link.aich.is_some() && !await_aich_answer(&mut link, file.file_hash).await {
                break;
            }
            let command = match link.deferred.pop_front() {
                Some(command) => command,
                None => {
                    match idle_wait(&mut link, &mut pipeline, file.file_hash, slot_deadline).await {
                        Idled::Command(command) => command,
                        Idled::Requeued => {
                            pipeline.requeued();
                            slot_deadline = tokio::time::Instant::now() + slot_wait_timeout;
                            continue;
                        }
                        Idled::Ended => break,
                        // A granted slot held with nothing asked for the
                        // budget goes back, as a stalled stream's does.
                        Idled::Stalled => {
                            cancel = pipeline.holds_slot();
                            break;
                        }
                    }
                }
            };
            match command {
                PeerWorkerCommand::AskSlot | PeerWorkerCommand::RequestHashSet => {
                    let file_hash = file.file_hash;
                    let ask = match command {
                        PeerWorkerCommand::AskSlot => RequesterCommand::AskSlot { file_hash },
                        _ => RequesterCommand::RequestHashSet { file_hash },
                    };
                    if link.cmd_tx.send(PeerCommand::Requester(ask)).await.is_err() {
                        let _ = link.event_tx.send(PeerWorkerEvent::Disconnected).await;
                        break;
                    }
                }
                PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                    pipeline.hand(&blocks, handout);
                    let streamed =
                        stream_blocks(&mut link, &mut pipeline, file, slot_wait_timeout).await;
                    match streamed {
                        Streamed::Next | Streamed::Handed => {
                            slot_deadline = tokio::time::Instant::now() + slot_wait_timeout;
                        }
                        Streamed::WindDown => break,
                        // No byte for the budget: a granted slot goes back,
                        // as aMule's `DOWNLOADTIMEOUT` cancels
                        // (`DownloadClient.cpp:1188-1196`, ADR-0056).
                        Streamed::Stalled => {
                            cancel = pipeline.holds_slot();
                            break;
                        }
                        Streamed::Shutdown { cancel: c } => {
                            cancel = c;
                            break;
                        }
                    }
                }
                PeerWorkerCommand::RequestAich { part, root } => {
                    if !link.ask_aich(file.file_hash, part, root).await
                        || !await_aich_answer(&mut link, file.file_hash).await
                    {
                        break;
                    }
                }
                PeerWorkerCommand::RequestAichFileHash => {
                    // Fire-and-forget: the OP_AICHFILEHASHANS answer arrives on the
                    // event stream and is forwarded as AichFileHashReceived while a
                    // part streams (ADR-0038).
                    let _ = link
                        .cmd_tx
                        .send(PeerCommand::Requester(
                            RequesterCommand::RequestAichFileHash {
                                file_hash: file.file_hash,
                            },
                        ))
                        .await;
                }
                PeerWorkerCommand::Shutdown { cancel: c } => {
                    cancel = c;
                    break;
                }
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
    // Wind the held slot down (a no-op if none): a local-reason abandon or a
    // granted slot that stalled emits `OP_CANCELTRANSFER` (the requester-side
    // counterpart to a silent release, ADR-0056), a completion or
    // peer-initiated end releases silently. Then drop
    // `peer_cmd_tx`: the link's next waiter takes it, and with none the link
    // stays up only while its serve half holds it (ADR-0025 release).
    let teardown = if cancel {
        PeerCommand::Requester(RequesterCommand::CancelTransfer {
            file_hash: file.file_hash,
        })
    } else {
        PeerCommand::Requester(RequesterCommand::ReleaseSlot {
            file_hash: file.file_hash,
        })
    };
    let _ = peer_cmd_tx.send(teardown).await;
    drop(peer_cmd_tx);
}

/// While the serve activity is running, hand `half` to it so the peer's pull
/// is admitted to the one cross-connection UploadSlotQueue exactly like an
/// accepted connection; its commands are framed onto the link through its own
/// sender. When not serving the sink is empty, the router drops Server
/// Capability requests, and the serve half lets the link go at once.
async fn hand_over_serve_half(half: ServeHalf) {
    let ServeHalf {
        peer,
        server_rx,
        serve_cmd_tx,
        sink,
    } = half;
    if let Some(serve_sink) = sink.sender() {
        let (bridge_cmd_tx, bridge_cmd_rx) = mpsc::channel(16);
        let (serve_evt_tx, serve_evt_rx) = mpsc::channel(16);
        tokio::spawn(bridge_dialed_serve(
            server_rx,
            bridge_cmd_rx,
            serve_cmd_tx,
            serve_evt_tx,
        ));
        let _ = serve_sink
            .send(ServeConnection::new(peer, bridge_cmd_tx, serve_evt_rx))
            .await;
    } else {
        // Not serving: nobody drains the serve half. Close it now so the
        // router's bounded `server_tx.send(..)` fails fast (the request is
        // dropped) instead of filling at capacity and stalling the socket once
        // a peer sends >16 Server Capability requests.
        drop(server_rx);
    }
}

/// Wait for a dialed peer's hello, or learn why the connection ended before
/// it. The identity itself reaches the download from the router.
async fn wait_for_peer_identified(
    events: &mut mpsc::Receiver<PeerEvent>,
    hello_refusals: &crate::hello_refusals::SharedHelloRefusals,
) -> Result<(), DialEnd> {
    match await_hello(events, hello_refusals, |_| {}).await {
        Opening::Identified(_) => Ok(()),
        Opening::Closed(reason) => Err(super::dial_end::closed_before_hello(reason)),
        Opening::Ended => Err(DialEnd::ClosedBeforeHello),
    }
}

/// Ask the blocks `pipeline` was handed and forward their bytes, in
/// `<= EMBLOCKSIZE` steps up to the Request Depth, refilled at every arrival
/// (ADR-0029 "Request pipeline"). Core (not the worker) owns assembly and
/// completion (ADR-0117): the worker forwards each block's bytes as they
/// arrive, tells core the room it has once everything handed is asked
/// (`BlocksWanted`), and serves blocks handed meanwhile behind the rest. A
/// block the session could not inflate is reported lost and freed; the slot is
/// kept. The stream ends when the pipeline has drained, its last
/// `BlocksWanted` saying so.
///
/// Every wait is bounded by `slot_wait_timeout` measured from the last
/// sign of data progress: a peer that grants a slot may stall delivering
/// nothing, and if no part bytes arrive within the budget the worker gives
/// up and reports `SlotTimeout`. The budget resets on each received block so
/// a healthy slow transfer is not cut off.
async fn stream_blocks(
    link: &mut WorkerLink<'_>,
    pipeline: &mut Pipeline,
    file: &Ed2kFileLink,
    slot_wait_timeout: Duration,
) -> Streamed {
    let (cmd_tx, event_tx) = (link.cmd_tx, link.event_tx);
    let file_hash = file.file_hash;
    let mut progress_deadline = tokio::time::Instant::now() + slot_wait_timeout;

    loop {
        while let Some(blocks) = pipeline.next_request(Instant::now().into_std()) {
            let mut padded = [(0, 0); RANGES_PER_REQUEST];
            padded[..blocks.len()].copy_from_slice(&blocks);
            let Ok(ranges) = PartRanges::new(padded) else {
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return Streamed::WindDown;
            };
            if cmd_tx
                .send(PeerCommand::Requester(RequesterCommand::RequestParts {
                    file_hash,
                    file_size: file.size,
                    ranges,
                }))
                .await
                .is_err()
            {
                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                return Streamed::WindDown;
            }
        }
        if let Some((room, drained)) = pipeline.want() {
            let room = u32::try_from(room).unwrap_or(u32::MAX);
            let handout = pipeline.handout();
            if event_tx
                .send(PeerWorkerEvent::BlocksWanted {
                    room,
                    drained,
                    handout,
                })
                .await
                .is_err()
            {
                return Streamed::WindDown;
            }
            if drained {
                return Streamed::Next;
            }
        }

        // Bound every wait by the no-progress budget: a peer that grants can
        // stall sending nothing. The deadline resets whenever a block arrives
        // (below), so a healthy transfer is never cut off.
        let event = match next_event(link, file_hash, progress_deadline).await {
            Ok(event) => event,
            // Blocks handed meanwhile queue behind the rest.
            Err(Streamed::Handed) => {
                hand_deferred(link, pipeline);
                continue;
            }
            Err(end) => return end,
        };
        let event = match forward_shared(event_tx, file_hash, event).await {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(Ended) => return Streamed::WindDown,
        };
        // `OP_OUTOFPARTREQS` on the granted slot: the transfer is over, not
        // the flow. Core frees the worker's blocks, and the worker stays on
        // the link for the next grant (ADR-0057).
        match forward_slot_news(event_tx, pipeline, file_hash, &event).await {
            Ok(None) => {}
            Ok(Some(SlotNews::Noted)) => continue,
            Ok(Some(SlotNews::Requeued)) => {
                pipeline.requeued();
                return Streamed::Next;
            }
            Err(Ended) => return Streamed::WindDown,
        }
        match event {
            PeerEvent::Requester(RequesterEvent::PartReceived {
                file_hash: received,
                offset,
                bytes,
            }) if received == file_hash => {
                // Data progress: extend the no-progress budget and forward
                // the bytes of an asked block to core, which merges them into
                // the part's Arrived Ranges.
                let now = Instant::now();
                progress_deadline = now + slot_wait_timeout;
                let part_index = u32::try_from(offset / ED2K_PART_SIZE).unwrap_or(u32::MAX);
                if pipeline.arrived(now.into_std(), offset, bytes.len() as u64)
                    && event_tx
                        .send(PeerWorkerEvent::BlockReceived {
                            part_index,
                            offset,
                            bytes,
                        })
                        .await
                        .is_err()
                {
                    return Streamed::WindDown;
                }
            }
            // A lost block will not come again on this slot (a stock uploader
            // never sends a block twice in one slot): core frees it for
            // another worker (ADR-0029 "A lost block is freed").
            PeerEvent::Requester(RequesterEvent::CompressedPartSkipped {
                file_hash: received,
                offset,
                ..
            }) if received == file_hash => {
                if let Some((start, end)) = pipeline.lost(offset)
                    && event_tx
                        .send(PeerWorkerEvent::BlockLost { start, end })
                        .await
                        .is_err()
                {
                    return Streamed::WindDown;
                }
            }
            _ => {}
        }
    }
}

/// Queue every `RequestBlocks` a wait set aside behind what `pipeline` holds,
/// in arrival order; the other commands keep their place.
fn hand_deferred(link: &mut WorkerLink<'_>, pipeline: &mut Pipeline) {
    link.deferred.retain(|command| match command {
        PeerWorkerCommand::RequestBlocks { blocks, handout } => {
            pipeline.hand(blocks, *handout);
            false
        }
        _ => true,
    });
}

/// The worker's ends of its channels, lent to every wait on the peer: the
/// peer's events, the commands sent it, the events sent the download, and
/// the download's commands, read so a wait hears a `Shutdown`. A command a
/// wait reads but cannot act on there (a next part, an AICH detour) waits in
/// `deferred`, served in arrival order before the channel is read again.
struct WorkerLink<'a> {
    events: &'a mut mpsc::Receiver<PeerEvent>,
    cmd_tx: &'a mpsc::Sender<PeerCommand>,
    event_tx: &'a mpsc::Sender<PeerWorkerEvent>,
    commands: &'a mut mpsc::Receiver<PeerWorkerCommand>,
    deferred: VecDeque<PeerWorkerCommand>,
    /// The AICH recovery asked and not yet answered: its part, and when an
    /// empty answer stands in for the peer's (ADR-0038).
    aich: Option<(u16, tokio::time::Instant)>,
    /// How long an AICH ask waits for its answer: the slot budget.
    aich_budget: Duration,
}

impl<'a> WorkerLink<'a> {
    fn new(
        events: &'a mut mpsc::Receiver<PeerEvent>,
        cmd_tx: &'a mpsc::Sender<PeerCommand>,
        event_tx: &'a mpsc::Sender<PeerWorkerEvent>,
        commands: &'a mut mpsc::Receiver<PeerWorkerCommand>,
        aich_budget: Duration,
    ) -> Self {
        Self {
            events,
            cmd_tx,
            event_tx,
            commands,
            deferred: VecDeque::new(),
            aich: None,
            aich_budget,
        }
    }
}

/// How a wait on the peer ended: the probe's, or a stream of handed blocks.
enum Streamed {
    /// The probe was answered, or the pipeline drained; read the next
    /// command.
    Next,
    /// The peer or the core side went away; wind the worker down.
    WindDown,
    /// Nothing arrived within the slot budget, reported as `SlotTimeout`;
    /// wind the worker down, giving back a slot it holds (ADR-0056).
    Stalled,
    /// The download told this worker to stop mid-part.
    Shutdown { cancel: bool },
    /// The download handed this worker blocks while it waited: they wait in
    /// `deferred` until the stream takes them.
    Handed,
}

mod aich;
mod pipeline;
#[cfg(test)]
mod tests;
mod wait;
