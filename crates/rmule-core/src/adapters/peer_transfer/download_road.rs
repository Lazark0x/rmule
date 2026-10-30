//! A download worker's road to its peer (ADR-0107, "One peer, one link"): the
//! peer's **Peer Link** it rides or waits on, or — when the look-up finds
//! none — a dial, filed as a **Dial in Flight** in the same step so the next
//! download of the peer waits on it. The IP filter and the ban list come
//! first, as aMule's `TryToConnect` meets them before any socket.
//!
//! Until its socket is up and its hello goes out, the dial yields to the
//! peer's own link filed under one of its names: the connect is dropped, the
//! dial retires nobody, and the download takes its turn on that link with
//! the dial's waiters behind it, as aMule's connecting client carries on over
//! the socket the peer opened (`ClientList.cpp:400-403`,
//! `BaseClient.cpp:1692-1698`, ADR-0107 invariant 7). A dial answered by a far
//! end that stayed on its own link does the same.

use std::time::Instant;

use rmule_net::peer::{
    ConnectOptions, Connection as PeerConnection, ObfuscationPolicy, PeerNetError,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{Ed2kFileLink, PeerEndpoint};
use tokio::sync::mpsc;

use super::worker::{drive_joined_worker, drive_peer_worker};
use super::{PeerWorkerCommand, PeerWorkerEvent, WorkerBrief, WorkerOpening, dial_end, end_dial};
use crate::adapters::InboundPeerDeps;
use crate::adapters::dialed_serve::LinkOrigin;
use crate::adapters::peer_link::{FoundLink, LinkJoin, LinkName, Reach, Turn};
use crate::ban_store::SharedBanStore;
use crate::ip_filter::SharedIpFilter;
use crate::service::DialEnd;

/// Everything one download worker reaches its peer with.
pub(super) struct DownloadRoad {
    pub(super) peer: PeerEndpoint,
    pub(super) ctx: PeerHandshakeContext,
    /// The dial's options: our adverts, and the crypt the source's stance
    /// meets ours with (ADR-0049).
    pub(super) options: ConnectOptions,
    pub(super) file: Ed2kFileLink,
    pub(super) brief: WorkerBrief,
    pub(super) ban_store: SharedBanStore,
    pub(super) ip_filter: SharedIpFilter,
    pub(super) deps: InboundPeerDeps,
}

/// Resolves when the run lets a worker go that has not connected: a
/// `Shutdown`, or the run dropping the worker. Nothing else is asked of it; the
/// brain waits for its `Connected`.
async fn let_go(commands: &mut mpsc::Receiver<PeerWorkerCommand>) {
    loop {
        match commands.recv().await {
            None | Some(PeerWorkerCommand::Shutdown { .. }) => return,
            Some(_) => {}
        }
    }
}

/// Where the look-up left the download: a link to take its turn on, with
/// the waiters of a dial that yielded to it behind.
struct Onto {
    link: FoundLink,
    behind: Option<mpsc::Receiver<LinkJoin>>,
}

impl DownloadRoad {
    /// Reach the peer and work it until the download lets the worker go,
    /// reporting on `event_tx`.
    pub(super) async fn drive(
        self,
        command_rx: mpsc::Receiver<PeerWorkerCommand>,
        event_tx: mpsc::Sender<PeerWorkerEvent>,
    ) {
        let mut command_rx = command_rx;
        let Self {
            peer,
            ctx,
            options,
            file,
            brief,
            ban_store,
            ip_filter,
            deps,
        } = self;
        let WorkerBrief {
            peer_crypt,
            own_status,
            want_sources,
            opening,
        } = brief;
        // The IP filter, aMule `CUpDownClient::TryToConnect` /
        // `SendHelloPacket`: a candidate source whose IP is filtered is never
        // dialed — reported like a connect failure so the runner backfills
        // the slot (the ban gate's exact shape, below). The verdict is bound
        // first so the read guard never crosses an await.
        let ip_filtered = ip_filter
            .read()
            .expect("ip filter lock")
            .is_filtered_peer(peer);
        if ip_filtered {
            end_dial(&event_tx, DialEnd::IpFiltered).await;
            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
            return;
        }
        // ADR-0064, peer-TCP enforcement: a banned candidate source is never
        // dialed at all — reported the same way a real connect failure is, so
        // the runner backfills the slot exactly as it would for any other dead
        // source.
        if ban_store.lock().await.is_banned(peer.ip(), Instant::now()) {
            end_dial(&event_tx, DialEnd::Banned).await;
            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
            return;
        }
        // One peer, one link (ADR-0107): a peer linked to us already is asked
        // over that link, as aMule asks a client over the socket it holds
        // (`BaseClient.cpp:1489-1496`); a second link would make it drop the
        // first (`ClientList.cpp:400-403`). Busy with another download — or
        // still being dialed by one — the link is waited on, not dialed
        // around; finding nothing files this dial in the same step, so the
        // next download finds it.
        let mut names = vec![LinkName::Endpoint(peer)];
        names.extend(peer_crypt.user_hash().map(LinkName::User));
        let ours = ObfuscationPolicy::stance_of(options.obfuscation.map(|config| config.policy));
        let on_a_link = opening == WorkerOpening::ProbeOnLink;
        let mut yielded: Option<Onto> = None;
        loop {
            let onto = match yielded.take() {
                Some(onto) => onto,
                None if on_a_link => {
                    let Some(link) = deps.peer_links.find(&names) else {
                        let _ = event_tx.send(PeerWorkerEvent::HandedBack).await;
                        return;
                    };
                    Onto { link, behind: None }
                }
                None => match deps.peer_links.reach(peer, &names) {
                    Reach::Found(link) => Onto { link, behind: None },
                    Reach::Dial(mut dial) => {
                        // Connect + identify run inside the worker task, off
                        // the runner's critical path (ADR-0030). Until the
                        // hello goes out the peer's own link overtakes the
                        // dial.
                        let opened = tokio::select! {
                            biased;
                            () = let_go(&mut command_rx) => {
                                tracing::debug!(?peer, "the download let the worker go: its dial is called off");
                                return;
                            }
                            opened = PeerConnection::open(peer, options.clone()) => opened,
                            link = dial.overtaken() => {
                                tracing::debug!(
                                    ?peer,
                                    link = ?link.remote,
                                    "the peer's own link overtook the dial before its hello: the download moves onto it"
                                );
                                yielded = Some(Onto { link, behind: Some(dial.yielded()) });
                                continue;
                            }
                        };
                        let opened = match opened {
                            Ok(opened) => opened,
                            // The stances cannot meet: named apart from a
                            // dead source, so the brain retires the source for
                            // that reason rather than as unreachable. No
                            // socket opened, so no dial was in flight: a
                            // download waiting on it meets the rule with what
                            // its own record knows.
                            Err(PeerNetError::CryptIncompatible) => {
                                drop(dial);
                                end_dial(&event_tx, dial_end::crypt_refusal(peer_crypt, ours))
                                    .await;
                                let _ = event_tx.send(PeerWorkerEvent::CryptIncompatible).await;
                                return;
                            }
                            // A connect failure ends this worker and every
                            // download waiting on the dial with its cause, so
                            // the runner backfills a replacement instead of
                            // aborting the whole download.
                            Err(error) => {
                                let cause = dial_end::connect_failure(&error);
                                dial.failed(cause);
                                end_dial(&event_tx, cause).await;
                                let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                                return;
                            }
                        };
                        // Overtaken while the socket came up: the peer never
                        // reads a hello on it.
                        if let Err(link) = dial.claim_hello() {
                            drop(opened);
                            yielded = Some(Onto {
                                link,
                                behind: Some(dial.yielded()),
                            });
                            continue;
                        }
                        let conn = opened.hello(ctx.clone());
                        // A dialed worker has not identified yet, so the drive
                        // body waits for the peer's hello, unless the dial
                        // gives way to the peer's own link first.
                        let gave_way = drive_peer_worker(
                            conn,
                            peer,
                            file.clone(),
                            own_status.clone(),
                            want_sources,
                            LinkOrigin::Dialed(dial),
                            command_rx,
                            event_tx.clone(),
                            deps.clone(),
                        )
                        .await;
                        let Some((gave_way, commands)) = gave_way else {
                            return;
                        };
                        command_rx = commands;
                        yielded = Some(Onto {
                            link: gave_way.link,
                            behind: gave_way.behind,
                        });
                        continue;
                    }
                },
            };
            let Onto { link, behind } = onto;
            match link
                .take_turn_ahead_of(behind, &event_tx, &mut command_rx)
                .await
            {
                Turn::Seated(joined) => {
                    tracing::debug!(?peer, "download rides the peer's link");
                    drive_joined_worker(
                        *joined,
                        file,
                        own_status,
                        want_sources,
                        opening,
                        command_rx,
                        event_tx,
                        deps.slot_wait_timeout,
                    )
                    .await;
                    return;
                }
                Turn::Stopped => return,
                // The dial it waited on failed: the source is gone for this
                // download too, for the same cause.
                Turn::DialEnded(cause) => {
                    end_dial(&event_tx, cause).await;
                    let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
                    return;
                }
                // The link ended before this download's turn: look again.
                Turn::LinkEnded => {}
                // The link it waited on ended: its source stands on the
                // peer's queue, as aMule keeps the client for its other file
                // (`BaseClient.cpp:1283-1284`), and is asked at the reask,
                // never dialed now (ADR-0107 invariant 9).
                Turn::HandedBack => {
                    let _ = event_tx.send(PeerWorkerEvent::HandedBack).await;
                    return;
                }
            }
        }
    }
}
