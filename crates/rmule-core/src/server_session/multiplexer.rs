//! The session **multiplexer**: one spawned task drives every request —
//! source lookups, announce, search, Low-ID callback relay, disconnect — down
//! the one logged-in server link, routes the server's answers back (lookups
//! demuxed by file hash, a search answer by its place on the link, welcome-burst
//! facts and IDCHANGE republishes into their sinks, a relayed peer callback to
//! its dial-back), and on any link close
//! fails every parked request so no activity hangs on a session that will
//! never answer. The link is a trait so the loop is tested sans-I/O over a
//! fake; the cheap-`Clone` handle is what the slot stores and adapters share.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use rmule_ed2k::{
    CommandRejectReason, Ed2kCommand, Ed2kCommandKind, Ed2kEvent, OfferedFile,
    SearchResultSkipReason, ServerCapability, ServerGrants,
};
use rmule_net::ed2k::Connection as Ed2kConnection;
use rmule_primitives::{
    ClientId, FileHash, Informant, SearchQuery, ServerEndpoint, SourceLookupTarget, SourceSighting,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::adapters::SourceLookupOutcome;
use crate::firewalled::server_callback::ServerCallbackConsume;
use crate::own_identity::SharedOwnIdentity;
use crate::reachability::{OwnListenEndpoint, SharedIpv6Probe};
use crate::search::LiveSearches;
use crate::server_list::ServerFacts;
use crate::service::SearchId;
use crate::{CoreError, DownloadFailure};

mod answer_order;
#[cfg(test)]
mod tests;

use answer_order::{AnswerOrder, Ask};

/// Where one source lookup's answer goes.
type LookupReply = oneshot::Sender<Result<Vec<SourceSighting>, DownloadFailure>>;

/// One request the session task fulfils over the shared server link.
enum ServerRequest {
    Holepunch {
        target: ClientId,
        our_udp_port: u16,
    },
    LookupSources {
        target: SourceLookupTarget,
        reply: LookupReply,
    },
    Announce {
        files: Vec<OfferedFile>,
        reply: oneshot::Sender<Result<(), CoreError>>,
    },
    Search {
        search_id: SearchId,
        ask: Ask,
        answer_wait: Duration,
        live: LiveSearches,
        reply: oneshot::Sender<Result<SearchStream, ServerSearchStartError>>,
    },
    /// Ask the connected server to relay a Low-ID callback to `low_id`
    /// (`OP_CALLBACKREQUEST`, ADR-0039). Fire-and-forget: the server sends no
    /// ack, and a delivery failure (`OP_CALLBACK_FAIL`) carries no id, so there
    /// is nothing to reply — the requesting download's per-callback timeout is
    /// the slot-release path.
    CallbackRequest {
        low_id: ClientId,
    },
    /// End this session: the operator picked another server, so
    /// the loop stops, every parked request is failed exactly as a link fault
    /// fails them, and `ack` fires **after** the session has reported itself
    /// gone. That ordering is what lets the switch establish the next session
    /// without a generation counter — a cleared marker always precedes the
    /// next set.
    Disconnect {
        ack: oneshot::Sender<()>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServerSearchEvent {
    /// The answer in this search's place did not decode, or one of its rows
    /// did not stand; sent once per row skipped.
    Skipped {
        reason: SearchResultSkipReason,
    },
    /// The eD2k session refused a related-files search because the server
    /// never granted it: nothing went on the wire. The actor gates on the same
    /// grant first, so this surfaces only when an `OP_IDCHANGE` withdrew the
    /// grant between the gate and the send.
    RelatedSearchNotOffered,
    /// The answer in a **Related-Files Search**'s place arrived while an
    /// earlier request's answer was owed, so it may be that late answer
    /// instead: nothing in it can be shown as this search's.
    RelatedAnswerUnattributable,
    /// The request waits for the search spacing; it goes on the link in
    /// `send_in`.
    WaitingForTurn {
        send_in: std::time::Duration,
    },
    /// The waiting request went on the link.
    SentToServer,
    /// A request for more was not sent: this search's server holds no pages
    /// rmule may still ask for — another search went out since its answer,
    /// its answer said no more, or it has asked as often as it may.
    MoreNotOffered,
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerSearchStartError {
    ServerDisconnected,
}

/// One search's server leg: what befalls its request. It closes once the
/// answer in its place has arrived — the rows went through **Search
/// Attribution**, not down this stream — or its answer wait ran out.
pub(crate) struct SearchStream {
    /// Crate-visible so `search`'s merged-stream tests can stand up a stream
    /// without a live session (the session constructs it the same way).
    pub(crate) event_rx: mpsc::Receiver<ServerSearchEvent>,
}

impl SearchStream {
    pub(crate) async fn next_event(&mut self) -> Option<ServerSearchEvent> {
        self.event_rx.recv().await
    }
}

/// The eD2k server connection the session drives, abstracted so the loop is
/// tested sans-I/O over a fake. The real impl forwards to the `-net`
/// `Connection`; tests push events and observe commands over channels.
pub(crate) trait ServerLink: Send + 'static {
    fn send(&self, command: Ed2kCommand) -> impl Future<Output = Result<(), ()>> + Send;
    fn next_event(&mut self) -> impl Future<Output = Option<Ed2kEvent>> + Send;
}

impl ServerLink for Ed2kConnection {
    async fn send(&self, command: Ed2kCommand) -> Result<(), ()> {
        Ed2kConnection::send(self, command).await.map_err(|_| ())
    }
    async fn next_event(&mut self) -> Option<Ed2kEvent> {
        Ed2kConnection::next_event(self).await
    }
}

/// A session's request half, held **weakly** by the **Server Coordinator**
/// (ADR-0091): what a server introduction is asked through, and whether the
/// session it asks still runs. Weak because the coordinator outlives every
/// session it served — a strong half would keep a session alive that every
/// handle had let go of — and so a session whose task ended without its own
/// exit reads dark here too.
#[derive(Clone, Debug)]
pub(crate) struct SessionLink {
    requests: mpsc::WeakSender<ServerRequest>,
    /// Which session this is. A late exit may clear the cell only while the
    /// cell still holds *its* session, never a newer login's.
    id: u64,
}

impl SessionLink {
    /// Whether `other` is the same session's link.
    pub(crate) const fn is_session(&self, other: &Self) -> bool {
        self.id == other.id
    }

    /// Whether the session's task still runs and a handle still holds it.
    pub(crate) fn is_alive(&self) -> bool {
        self.requests
            .upgrade()
            .is_some_and(|requests| !requests.is_closed())
    }

    /// Ask the server to introduce us to the Low-ID `target`
    /// (`OP_LOWID_HOLEPUNCH_REQUEST`, `0x60`), naming `our_udp_port`,
    /// reporting whether the request was queued. `try_send`, never `send`:
    /// the caller is the NAT-T front's loop, which may not wait on a consumer
    /// it does not drain — a full session inbox costs this introduction. The
    /// answer is an event on the session, or — from a server that does not
    /// speak the punch — nothing at all, which the ledger's timeout turns
    /// into a fallback.
    pub(crate) fn request_holepunch(&self, target: ClientId, our_udp_port: u16) -> bool {
        self.requests.upgrade().is_some_and(|requests| {
            requests
                .try_send(ServerRequest::Holepunch {
                    target,
                    our_udp_port,
                })
                .is_ok()
        })
    }
}

/// A cheap-`Clone` handle to a running session. `client_id` is captured at
/// login, so the High-ID id is a field read, not a round-trip.
#[derive(Clone)]
pub(crate) struct ServerSessionHandle {
    request_tx: mpsc::Sender<ServerRequest>,
    client_id: ClientId,
    /// The server this session is logged in to.
    server: ServerEndpoint,
    /// What the server grants this session, moved by each `OP_IDCHANGE`.
    grants: watch::Receiver<ServerGrants>,
    /// This session's identity among the sessions of one run.
    id: u64,
}

/// The next session identity: one counter for the process, so two sessions
/// never share one.
fn next_session_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl ServerSessionHandle {
    /// A handle that reads alive but whose session is ending: it takes every
    /// request and drops it unanswered, as a loop that ended with the request
    /// still queued does.
    #[cfg(test)]
    pub(crate) fn ending(server: ServerEndpoint) -> Self {
        let (request_tx, mut request_rx) = mpsc::channel(32);
        tokio::spawn(async move { while request_rx.recv().await.is_some() {} });
        Self {
            request_tx,
            client_id: ClientId::from_u32(0x0100_007F),
            server,
            grants: watch::channel(ServerGrants::default()).1,
            id: next_session_id(),
        }
    }

    pub(crate) const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// The server this session is logged in to.
    pub(crate) const fn server(&self) -> &ServerEndpoint {
        &self.server
    }

    /// What the server grants this session as it stands now.
    pub(crate) fn grants(&self) -> ServerGrants {
        *self.grants.borrow()
    }

    /// Whether `other` is a handle on this same session.
    pub(crate) fn same_session(&self, other: &Self) -> bool {
        self.request_tx.same_channel(&other.request_tx)
    }

    /// Whether the session task is still running. False once it has ended
    /// (its receiver dropped); only the operator's next connect replaces it.
    pub(crate) fn is_alive(&self) -> bool {
        !self.request_tx.is_closed()
    }

    /// Resolves when the session task ends.
    pub(crate) async fn closed(&self) {
        self.request_tx.closed().await;
    }

    /// This session's request half as the **Server Coordinator** holds it
    /// (ADR-0091).
    pub(crate) fn coordinator_link(&self) -> SessionLink {
        SessionLink {
            requests: self.request_tx.downgrade(),
            id: self.id,
        }
    }

    pub(crate) async fn lookup_sources(
        &self,
        target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.request_tx
            .send(ServerRequest::LookupSources {
                target,
                reply: reply_tx,
            })
            .await
            .map_err(|_| DownloadFailure::ServerDisconnected)?;
        let sources = reply_rx
            .await
            .map_err(|_| DownloadFailure::ServerDisconnected)??;
        Ok(SourceLookupOutcome {
            client_id: self.client_id,
            sources,
        })
    }

    pub(crate) async fn announce(&self, files: Vec<OfferedFile>) -> Result<(), CoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.request_tx
            .send(ServerRequest::Announce {
                files,
                reply: reply_tx,
            })
            .await
            .map_err(|_| CoreError::Repository("server session closed".into()))?;
        reply_rx
            .await
            .map_err(|_| CoreError::Repository("server session closed".into()))?
    }

    /// Put `search_id`'s request on the link in turn, the search spacing after
    /// the last one at the soonest ([`answer_order`]). Its answer's rows reach `live`'s searches by what
    /// they contain; the stream carries the leg's own news and closes after the
    /// answer in its place, or once `answer_wait` has passed without one.
    pub(crate) async fn start_search(
        &self,
        search_id: SearchId,
        query: SearchQuery,
        answer_wait: Duration,
        live: LiveSearches,
    ) -> Result<SearchStream, ServerSearchStartError> {
        self.ask(search_id, Ask::Search(query), answer_wait, live)
            .await
    }

    /// Ask for the next page of `search_id`'s answer (`OP_QUERY_MORE_RESULT`),
    /// in turn like any request. Its answer is known by its place and reaches
    /// the search as the owner; the leg says [`ServerSearchEvent::MoreNotOffered`]
    /// instead when the search is not the one whose server holds more
    /// ([`answer_order`]).
    pub(crate) async fn more_results(
        &self,
        search_id: SearchId,
        answer_wait: Duration,
        live: LiveSearches,
    ) -> Result<SearchStream, ServerSearchStartError> {
        self.ask(search_id, Ask::More, answer_wait, live).await
    }

    async fn ask(
        &self,
        search_id: SearchId,
        ask: Ask,
        answer_wait: Duration,
        live: LiveSearches,
    ) -> Result<SearchStream, ServerSearchStartError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.request_tx
            .send(ServerRequest::Search {
                search_id,
                ask,
                answer_wait,
                live,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ServerSearchStartError::ServerDisconnected)?;
        reply_rx
            .await
            .map_err(|_| ServerSearchStartError::ServerDisconnected)?
    }

    /// Ask the connected server to relay a Low-ID callback to `low_id`
    /// (ADR-0039), saying whether the session took the request. No ack, no
    /// reply beyond that: a session that has ended takes nothing, and the
    /// caller ends the callback's road at once.
    pub(crate) async fn request_callback(&self, low_id: ClientId) -> bool {
        self.request_tx
            .send(ServerRequest::CallbackRequest { low_id })
            .await
            .is_ok()
    }

    /// End the session and wait until it has reported itself gone.
    /// Returns immediately when the task has already ended: a closed
    /// request channel means the loop returned, and the loop clears the
    /// connected marker before it drops its receiver, so "the send failed" and
    /// "the ack arrived" carry the same guarantee.
    pub(crate) async fn disconnect(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .request_tx
            .send(ServerRequest::Disconnect { ack: ack_tx })
            .await
            .is_ok()
        {
            let _ = ack_rx.await;
        }
    }
}

/// What the login granted, and everything the session task writes to as the
/// server talks: our own
/// self-facts cell (a mid-session `OP_IDCHANGE` republishes the public IP) and
/// the managed list's dynamic half, keyed by the endpoint this session dialed.
///
/// The welcome burst is the *other* place a server states its load and its name
/// (ADR-0080 §Dynamic server facts): the UDP sweep asks every listed server
/// from the outside, and the login is told by the one server we are inside.
/// Both write the same two surfaces through the same seam.
pub(crate) struct SessionSinks {
    pub(crate) own: SharedOwnIdentity,
    pub(crate) server: ServerEndpoint,
    /// The address this session's TCP connection reached, when the dial
    /// resolved one — what a Low-ID `OP_IDCHANGE` report is checked against
    /// (ADR-0084's 2026-09-28 amendment: a server is never us).
    pub(crate) server_ip: Option<std::net::IpAddr>,
    pub(crate) facts: ServerFacts,
    /// Where `ST_IPV6_STATUS` lands, and what this session clears when it ends
    /// (ADR-0084). The tag's reader arrives with the IPv6 dialect; the clear
    /// is here from the start, because a probe verdict outliving its session
    /// would suppress an advert on the strength of a server we left.
    pub(crate) ipv6_probe: SharedIpv6Probe,
    /// Whether this session's TCP connection actually runs over IPv6 — the
    /// gate on `OP_SERVERIDENT`'s `CT_MOD_YOUR_IP` (ADR-0087 §4.3).
    ///
    /// A reflection received over an **IPv4** session says nothing about our
    /// IPv6 connectivity: the server is naming an address it never reached us
    /// at. Only the layer that dialed knows which family it got, so the fact
    /// travels from there rather than being guessed here.
    pub(crate) over_ipv6: bool,
    /// The server coordinator (ADR-0091): where `0x61` and `0x62` land. A
    /// default one holds no send half, so it decides and fires nothing —
    /// which is what every leg that is not about the punch wants.
    pub(crate) punch: crate::natt::server_punch::SharedServerPunch,
    /// The grants the login's `OP_IDCHANGE` carried. The session keeps its own
    /// copy, moved by each later one: a related search goes on the link only
    /// under a grant it holds (ADR-0037).
    pub(crate) grants: ServerGrants,
    /// Self Reach, where an offer reads the Presented Client ID it carries at
    /// the moment it is sent. `None` presents the session's own id.
    pub(crate) reach: Option<crate::reachability::SharedSelfReach>,
    /// Where a server-relayed callback is answered (ADR-0061): a dial-back
    /// into the serve pipeline while this session is Low-ID.
    pub(crate) dial_backs: super::ServerCallbackDialBacks,
    /// The TCP port the login named, as configured: the self-connect guard
    /// reads the port we present from it at each callback.
    pub(crate) tcp_port: u16,
}

/// Namespace for the session spawner. The session itself is the spawned task.
pub(crate) struct ServerSession;

impl ServerSession {
    /// Spawn the multiplexer over an already-logged-in `link`, with the
    /// `client_id` the login returned and the `sinks` the server's own
    /// statements land in. Returns the handle the adapters share.
    pub(crate) fn spawn<L: ServerLink>(
        link: L,
        client_id: ClientId,
        sinks: SessionSinks,
    ) -> ServerSessionHandle {
        // One slot per in-flight request; 32 is far above the actor's
        // realistic concurrency (one download activity at a time).
        let (request_tx, request_rx) = mpsc::channel(32);
        let server = sinks.server.clone();
        let (grants_tx, grants) = watch::channel(sinks.grants);
        let id = next_session_id();
        let own_link = SessionLink {
            requests: request_tx.downgrade(),
            id,
        };
        tokio::spawn(run_session(
            link, client_id, request_rx, sinks, grants_tx, own_link,
        ));
        ServerSessionHandle {
            request_tx,
            client_id,
            server,
            grants,
            id,
        }
    }
}

/// The multiplexer loop: send requests down the one link, route `SourcesFound`
/// back to the matching parked lookup by `FileHash`, and on any link close
/// fail every parked lookup (so no download hangs on a session that will never
/// answer). Ends when the link closes or all handles are dropped.
async fn run_session<L: ServerLink>(
    mut link: L,
    mut session_id: ClientId,
    mut request_rx: mpsc::Receiver<ServerRequest>,
    sinks: SessionSinks,
    grants_tx: watch::Sender<ServerGrants>,
    own_link: SessionLink,
) {
    let SessionSinks {
        own,
        server,
        server_ip,
        facts,
        ipv6_probe,
        over_ipv6,
        punch,
        grants,
        reach,
        dial_backs,
        tcp_port,
    } = sinks;
    // Every waiter on one file's ask, keyed by the hash `OP_FOUNDSOURCES`
    // carries back (ADR-0107): lookups for different files ride the link side
    // by side, and a second lookup for a hash already asked joins that ask.
    let mut pending: HashMap<FileHash, Vec<LookupReply>> = HashMap::new();
    let mut searches = AnswerOrder::new(grants.related_search);
    let mut disconnect_ack: Option<oneshot::Sender<()>> = None;
    // The introduction clock (ADR-0091). It lives on the session
    // for the reason the `0x9F` keepalive's cadence does: the session is an
    // introduction's whole lifetime. A server that does not speak the punch
    // says nothing at all, so this tick is the only thing that can ever turn
    // that silence into a fall-through to the target's buddy.
    let mut introductions = tokio::time::interval(crate::natt::server_punch::INTRODUCTION_POLL);
    introductions.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            // An interval never closes, so this arm cannot end the session;
            // `tick` is cancel-safe, so racing it drops nothing.
            () = answer_wait_expiry(searches.deadline()) => {
                searches.expire(tokio::time::Instant::now());
            }
            // A search whose turn has come after the spacing (ADR-0035).
            () = answer_wait_expiry(searches.next_send()) => {
                if let Some(command) = searches.release(tokio::time::Instant::now())
                    && link.send(command).await.is_err()
                {
                    break;
                }
            }
            _ = introductions.tick() => {
                // The runtime's clock, not the wall's: it is the one a
                // deterministic test can advance, and the two agree
                // everywhere else.
                punch.poll_overdue(tokio::time::Instant::now().into_std());
            }
            request = request_rx.recv() => {
                let Some(request) = request else { break }; // all handles dropped
                match request {
                    ServerRequest::LookupSources { target, reply } => {
                        // One wire ask per hash (ADR-0107 invariant 1): a waiter
                        // still listening means the ask is out and its answer
                        // will name this hash, so the newcomer joins it. An ask
                        // whose every waiter gave up is asked again.
                        let waiters = pending.entry(target.file_hash()).or_default();
                        waiters.retain(|waiter| !waiter.is_closed());
                        let asked = !waiters.is_empty();
                        waiters.push(reply);
                        if !asked
                            && link
                                .send(Ed2kCommand::RequestSources { target })
                                .await
                                .is_err()
                        {
                            break;
                        }
                    }
                    ServerRequest::Announce { files, reply } => {
                        let result = link
                            .send(Ed2kCommand::OfferFiles {
                                files,
                                presented_id: reach
                                    .as_ref()
                                    .map(crate::reachability::SharedSelfReach::presented_client_id),
                            })
                            .await
                            .map_err(|()| CoreError::Repository("announce send failed".into()));
                        let dead = result.is_err();
                        let _ = reply.send(result);
                        if dead { break; }
                    }
                    ServerRequest::Search { search_id, ask, answer_wait, live, reply } => {
                        let (stream, now) = searches.ask(
                            search_id,
                            ask,
                            answer_wait,
                            live,
                            tokio::time::Instant::now(),
                        );
                        if let Some(command) = now
                            && link.send(command).await.is_err()
                        {
                            searches.unsent();
                            let _ = reply.send(Err(ServerSearchStartError::ServerDisconnected));
                            break;
                        }
                        let _ = reply.send(Ok(stream));
                    }
                    ServerRequest::Holepunch {
                        target,
                        our_udp_port,
                    } => {
                        // Recorded only once it is on the link: a request
                        // that never left must not wait out a timeout.
                        if link
                            .send(Ed2kCommand::RequestHolepunch {
                                target,
                                our_udp_port,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                        punch
                            .ledger()
                            .on_request(target, tokio::time::Instant::now().into_std());
                    }
                    ServerRequest::CallbackRequest { low_id } => {
                        // Fire-and-forget (ADR-0039); a dead link ends the
                        // session, failing parked lookups via the drain below
                        // exactly like Announce.
                        if link
                            .send(Ed2kCommand::RequestCallback { low_id })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    // The operator switched servers. Nothing is
                    // sent to the server: aMule's own disconnect drops the
                    // socket, and the eD2k protocol has no goodbye. Every
                    // parked request is failed by the drain below, exactly as
                    // a hang-up fails them.
                    ServerRequest::Disconnect { ack } => {
                        disconnect_ack = Some(ack);
                        break;
                    }
                }
            }
            event = link.next_event() => {
                match event {
                    Some(Ed2kEvent::SourcesFound { file_hash, sources, tail }) => {
                        if tail.is_malformed() {
                            // ADR-0085: the list's IPv6 sources were dropped and
                            // every IPv4 one survived — a diagnostic, never a
                            // reason to fail the lookup this reply answers.
                            tracing::debug!(
                                file_hash = %file_hash.to_hex_upper(),
                                sentinels = tail.sentinels(),
                                "source list carried a malformed Sentinel Source tail"
                            );
                        }
                        // The answer is this server's word, judged against the
                        // address the session reached (ADR-0085). A session
                        // over a stream its caller brought reached no address
                        // of its own, and its answer is rmule's word.
                        let informant = server_ip.map_or(
                            rmule_primitives::Informant::Own,
                            rmule_primitives::Informant::Party,
                        );
                        let sources: Vec<_> = sources
                            .into_iter()
                            .map(|claim| claim.stated_by(informant))
                            .collect();
                        for reply in pending.remove(&file_hash).into_iter().flatten() {
                            let _ = reply.send(Ok(sources.clone()));
                        }
                    }
                    Some(Ed2kEvent::SearchResultsFound { results, skipped, more_available }) => {
                        searches
                            .answered(results, &skipped, more_available, tokio::time::Instant::now())
                            .await;
                    }
                    Some(Ed2kEvent::SearchResultSkipped { reason }) => {
                        searches
                            .skipped(reason, tokio::time::Instant::now())
                            .await;
                    }
                    // A refused related search is the search's fault to report,
                    // not the session's: the link is healthy and nothing was
                    // sent, so it must not fall into the session-ending arm.
                    Some(Ed2kEvent::CommandRejected {
                        command: Ed2kCommandKind::Search,
                        reason: CommandRejectReason::UnsupportedServerCapability {
                            capability: ServerCapability::RelatedSearch,
                        },
                    }) => {
                        // Nothing reached the wire, so it holds no place.
                        searches.related_refused().await;
                    }
                    // A login rejection mid-session, the driver dropping its
                    // send half (None), or the server rejecting a command we
                    // sent (`CommandRejected` carries no file hash to target one
                    // waiter — e.g. RequestSources when not logged in, or a
                    // large-file request an old server can't serve) ends the
                    // session, failing all parked lookups via the drain below
                    // rather than stranding them: a rejected command is a
                    // session-level fault, not one lookup's.
                    Some(Ed2kEvent::Disconnected { .. })
                    | Some(Ed2kEvent::LoginRejected)
                    | Some(Ed2kEvent::CommandRejected { .. })
                    | None => break,
                    // The server could not route a Low-ID callback we requested
                    // (`OP_CALLBACK_FAIL`, ADR-0039). It carries no id, so it
                    // cannot be attributed to a specific pending callback; the
                    // requesting download's timeout is the slot-release path.
                    Some(Ed2kEvent::CallbackFailed) => {
                        tracing::info!("server could not route a Low-ID callback");
                    }
                    // ADR-0091: the server introduced us to a LowID peer —
                    // because we asked, or because *it* did; the server sends
                    // `0x61` to both sides. Decided and, on a punch, fired
                    // from the client-UDP socket in the same call.
                    Some(Ed2kEvent::HolepunchIntroduced { info }) => {
                        let verdict = punch.on_info(
                            &info,
                            |ip| own.addresses().holds_interface(ip),
                            std::time::Instant::now(),
                        );
                        tracing::debug!(peer_udp = %info.peer_udp, ?verdict, "server introduction (ADR-0091)");
                    }
                    Some(Ed2kEvent::HolepunchRefused { fail }) => {
                        let outcome = punch.on_fail(&fail);
                        tracing::debug!(
                            target = fail.target.as_u32(),
                            ?outcome,
                            "server refused an introduction (ADR-0091)"
                        );
                    }
                    // A mid-session id re-assignment re-reports the whole
                    // IDCHANGE extension (ADR-0047), so republish the public IP
                    // it carries — including a drop to LowID, which the
                    // projection reports as `None` and which must disarm the
                    // UDP crypt send paths that key on it (ADR-0046).
                    // The id half follows too: the **Server High ID** level
                    // the Kad pump watches reads the live id.
                    Some(Ed2kEvent::LoginAccepted { client_id, tcp_flags, facts: assigned }) => {
                        let grants = tcp_flags.map(ServerGrants::from).unwrap_or_default();
                        facts.regranted(&server, client_id, tcp_flags, &assigned);
                        grants_tx.send_replace(grants);
                        searches.regranted(grants.related_search).await;
                        let address = own.addresses().observe_server_assigned(
                            client_id,
                            assigned.public_ip,
                            server_ip,
                        );
                        own.reassign_client_id(client_id);
                        session_id = client_id;
                        let assignment = crate::service::IdAssignment { client_id, address, grants };
                        let step = crate::service::LoginStep::Reassigned { assignment };
                        facts.login_step(&server, step).await;
                    }
                    // The welcome burst's `OP_SERVERSTATUS` (ADR-0080): the one
                    // server we are inside states its own load, on its own
                    // cadence — servers re-send it mid-session — so the row's
                    // counts track the connected server without waiting for the
                    // UDP sweep's hours-long re-ask window.
                    Some(Ed2kEvent::ServerStatusReceived { status }) => {
                        facts.reported(&server, status.user_count, status.file_count);
                    }
                    // The welcome burst's `OP_SERVERIDENT` (ADR-0080): the
                    // server names itself. Folded into the list exactly as a
                    // downloaded server.met row is, so a cold start that never
                    // read a mirror still learns the name of the server it
                    // connected to.
                    Some(Ed2kEvent::ServerIdentified { identity }) => {
                        // ADR-0087 §4.3, before the name and description are
                        // moved into the list: only a *stated* verdict writes
                        // the cell. A server sends a second ident in reply to
                        // `OP_GETSERVERLIST` and the tag is normally absent
                        // there, so treating absence as a verdict would
                        // un-suppress an advert the first ident suppressed. The
                        // verdict ends with the session and nowhere else.
                        if let Some(status) = identity.ipv6_status {
                            let verdict = crate::reachability::Ipv6Probe::from(status);
                            tracing::debug!(
                                bits = format_args!("{:#04x}", status.bits()),
                                ?verdict,
                                "server stated an IPv6 probe verdict"
                            );
                            ipv6_probe.set(verdict);
                            let step = crate::service::LoginStep::Ipv6Probe { verdict };
                            facts.login_step(&server, step).await;
                        }
                        // `CT_MOD_SVR_IP_V6` is informational by contract: the
                        // server names its own address and rmule keeps using
                        // the one it dialled. Read id-tolerantly upstream, so
                        // this may be the `0xAE` misuse rather than `0xAF`.
                        if let Some(address) = identity.server_ipv6 {
                            tracing::debug!(%address, "server named its own IPv6");
                        }
                        // `CT_MOD_YOUR_IP`, hash form, is tier 1 of the
                        // address ladder (ADR-0084) — but only from a session
                        // that actually ran over IPv6. The store's
                        // local-interface filter is the second half of the
                        // rule and lives there: a reflection is adopted only
                        // when this host also holds the address, so one server
                        // can never make rmule advertise a foreign one.
                        if let Some(address) = identity.reflected_ipv6 {
                            if over_ipv6 {
                                own.addresses().observe(
                                    crate::address_learning::AddressObservation::server_reflection(
                                        address.into(),
                                    ),
                                );
                            } else {
                                tracing::debug!(
                                    %address,
                                    "ignoring an IPv6 reflection from an IPv4 session"
                                );
                            }
                        }
                        if let Err(error) = facts
                            .identified(&server, identity.name, identity.description)
                            .await
                        {
                            tracing::warn!(%error, "server ident not folded into the list");
                        }
                    }
                    // A peer on the server asking to reach us (`0x35`, or
                    // `0x26` for an IPv6 requester — ADR-0087 §4.5): it wants
                    // to download from us, so a Low-ID session dials it back
                    // into the serve pipeline (ADR-0061). The requester is the
                    // server's word, judged against the address the session
                    // reached (ADR-0085).
                    Some(Ed2kEvent::PeerCallbackRequested { peer, crypt }) => {
                        let verdict = dial_backs.answer(
                            &ServerCallbackConsume { requester: peer, crypt },
                            session_id,
                            server_ip.map_or(Informant::Own, Informant::Party),
                            OwnListenEndpoint::current(
                                &own,
                                super::presented_tcp_port(tcp_port, &own),
                            ),
                        );
                        tracing::debug!(%peer, ?verdict, "server relayed a peer callback");
                    }
                    // Informational server events are not part of any request.
                    Some(_) => {}
                }
            }
        }
    }
    for reply in pending.into_values().flatten() {
        let _ = reply.send(Err(DownloadFailure::ServerDisconnected));
    }
    searches.disconnect_all().await;
    // The session is over however it ended, so the connected marker comes down
    // here and nowhere else. Ordered before the ack — and before
    // this task drops its request receiver, which is what a caller's
    // `is_alive()` reads — so the next session's marker can never be
    // overwritten by this one's.
    facts.disconnected(&server).await;
    // The server's statements about us end with its session (ADR-0084): the
    // IPv6 probe verdict clears outright, while the address it assigned stays
    // readable as a *stale* last-known — a reconnect must not blank the UDP
    // crypt key mid-reask, and only the server contradicting itself (a Low-ID
    // re-assignment) withdraws the address.
    ipv6_probe.clear();
    // And so does its willingness to introduce us (ADR-0091): the keepalive
    // stops with the session, every outstanding `0x60` died with the link,
    // and the route chooser must stop offering a coordinator that is gone.
    punch.go_dark(&own_link);
    // The id it assigned and the server itself are facts *about this session*
    // and nothing else. Unlike the address above they do not survive as a
    // stale last-known: a node with no session is Low-ID and shares its server
    // with nobody, which is exactly what `None` here says.
    own.set_connected_session(None);
    own.addresses().end_server_session();
    if let Some(ack) = disconnect_ack {
        let _ = ack.send(());
    }
}

/// Resolves when the earliest answer wait of the requests out runs out; never
/// while none is out.
async fn answer_wait_expiry(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
