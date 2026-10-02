//! What a front end asks the core to do. One [`CoreCommand`] per ask, grouped
//! by activity (download, serve, search, directory scan, server list), plus the reasons the
//! actor refuses one outright.

use std::net::SocketAddrV4;
use std::path::PathBuf;

use rmule_ed2k::ServerPriority;
use rmule_primitives::{Ed2kFileLink, FileHash, SearchQuery, ServerEndpoint};

use crate::adapters::KadEnableConfig;
use crate::server_list::ManagedServer;

use super::{ClientCredentials, DownloadId, PeerReach, SearchId};

/// The download activity's command vocabulary. Wrapped by
/// [`CoreCommand::Download`]; `ServeCommand` is its serve-side sibling.
#[derive(Clone, Debug)]
pub enum DownloadCommand {
    /// Queue a new download. Answered off the actor with
    /// [`DownloadEvent::DownloadQueued`](crate::DownloadEvent::DownloadQueued),
    /// which carries the id the caller uses for every later command.
    StartDownload {
        /// The ed2k link being fetched: hash, size, and any part hash set or
        /// AICH root it carries.
        file: Ed2kFileLink,
        /// The server the link was found on, stored with the download as a
        /// source hint; `None` when no server is connected or
        /// configured — a Kad-only start. Nothing dials it or asks it:
        /// the run's sources come from the operator's session and Kad.
        source_hint: Option<ServerEndpoint>,
        /// The identity the run's hellos present — core is storage-agnostic
        /// (ADR-0069), so the caller holds it.
        credentials: ClientCredentials,
        /// Where the finished file lands. Partial data is written beside it
        /// until every part verifies.
        output_path: PathBuf,
    },
    /// Stop the run but keep the verified parts and the store row, so a resume
    /// picks up where it left off.
    PauseDownload {
        /// The download to stop.
        download_id: DownloadId,
    },
    /// Start a fresh run for a paused, recovered or failed download.
    ///
    /// For a failed one this is **Restart** (ADR-0094): rmule continues from
    /// what is on disk when it can, dropping and re-fetching damaged parts,
    /// and starts over from nothing when the part file is gone or no recorded
    /// part matches it — its part file removed, its identity and place kept.
    /// [`DownloadEvent::DownloadRestarted`](crate::DownloadEvent::DownloadRestarted)
    /// says which it did and what that cost.
    ResumeDownload {
        /// The download to restart.
        download_id: DownloadId,
        /// The identity the new run's hellos present.
        credentials: ClientCredentials,
    },
    /// Stop the run and drop the store row. Terminal — the partial data is no
    /// longer tracked.
    CancelDownload {
        /// The download to abandon.
        download_id: DownloadId,
    },
    /// Forget one completed download (ADR-0093, "Clearing a completed
    /// download"): its record and its row leave; the file, its **Shared File
    /// Registry** entry and its share totals stay. Refused with
    /// [`CoreCommandRejectReason::DownloadNotCompleted`] for any other.
    ClearDownload {
        /// The completed download to forget.
        download_id: DownloadId,
    },
    /// Forget every completed download at once — aMule's "Clear completed".
    ClearCompletedDownloads,
}

/// The serve activity's command vocabulary. Wrapped by
/// [`CoreCommand::Serve`]: the share-set verbs and the upload-queue / grant
/// verbs share this one enum.
#[derive(Clone, Debug)]
pub enum ServeCommand {
    /// Stop serving the file with this content identity.
    UnshareFile {
        /// The content identity to withdraw; the file on disk is untouched.
        file_hash: FileHash,
    },
    /// Start the serve activity: bind the inbound listener on `listen_addr`
    /// and accept peer connections into the **Upload Slot Queue** (ADR-0031).
    /// It dials no server: the share set is announced to the live session and
    /// to each one the operator's connect makes after it (ADR-0095). At most
    /// one serve activity is live; a core built with credentials starts it at
    /// attach.
    StartServing {
        /// Where to bind the inbound listener. This is the port rmule then
        /// advertises, so it must be the one peers can actually reach.
        listen_addr: SocketAddrV4,
        /// The identity the listener's hellos present.
        credentials: ClientCredentials,
    },
    /// Stop the serve activity: close the listener, drop queued/granted
    /// peers, and end announcing. Shares stay in the registry.
    StopServing,
}

/// The search activity's command vocabulary. Wrapped by
/// [`CoreCommand::Search`]; any number of searches run side by side (ADR-0034).
#[derive(Clone, Debug)]
pub enum SearchCommand {
    /// Submit a query on the shared server session, under the id the caller
    /// chose. Answered with
    /// [`SearchEvent::SearchStarted`](crate::SearchEvent::SearchStarted),
    /// [`SearchEvent::SearchFailed`](crate::SearchEvent::SearchFailed) when no
    /// session could be had, or
    /// [`SearchEvent::SearchRefused`](crate::SearchEvent::SearchRefused) when a
    /// Related-Files Search cannot be asked — every one naming `search_id`, so
    /// a front end ties each outcome to what it sent by id, never by order.
    StartSearch {
        /// The id every later event and the cancel use. Take it from
        /// [`SearchId::mint`]; one a running search already holds is rejected
        /// ([`CoreCommandRejectReason::SearchIdInUse`]).
        search_id: SearchId,
        /// The query, by kind. A keyword query rides the connected server,
        /// the Global Search Sweep and Kad; a related-files query rides the
        /// connected server alone and is refused unless that server is
        /// connected and grants it — it never dials one.
        query: SearchQuery,
    },
    /// Close one running search. Its accumulated set is dropped and late
    /// batches are ignored; the others run on.
    CancelSearch {
        /// The search to close.
        search_id: SearchId,
    },
    /// Ask the connected server for the next page of `search_id`'s answer
    /// (`OP_QUERY_MORE_RESULT`, ADR-0036) — only ever on the
    /// operator's word, as eMule's *More* button; rmule never asks on its own.
    /// Offered while
    /// [`DiagnosticsSnapshot::search_more_results`](crate::diagnostics::DiagnosticsSnapshot::search_more_results)
    /// names the search with asks left. Answered with
    /// [`SearchEvent::SearchMoreRequested`](crate::SearchEvent::SearchMoreRequested),
    /// the page's rows joining the search's set, or
    /// [`SearchEvent::SearchMoreRefused`](crate::SearchEvent::SearchMoreRefused)
    /// with nothing sent.
    MoreResults {
        /// The search whose next page is asked for.
        search_id: SearchId,
    },
}

/// The **Shared Directory List**'s command vocabulary (ADR-0101): the
/// download directory, the disclosure guard's answer, and the directories the
/// operator adds and removes. Wrapped by [`CoreCommand::Scan`]; one scan runs
/// per scanned directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanCommand {
    /// Scan `dir`, the download directory, and share what lies under it. A
    /// start for the directory already being scanned is a no-op; one for
    /// another directory stops the running scan first. A directory never
    /// asked about that already holds files raises
    /// [`ScanEvent::ConsentRequested`](crate::ScanEvent::ConsentRequested)
    /// and waits for [`Answer`](Self::Answer); one declined before is not
    /// scanned.
    Start {
        /// The directory to scan, as the download-directory preference
        /// holds it.
        dir: PathBuf,
    },
    /// The operator's answer to the disclosure guard for `dir`, recorded
    /// durably. Releases a scan waiting on it; sent before a `Start` (the
    /// Settings warning), it spares the operator a second question.
    Answer {
        /// The directory the answer is for.
        dir: PathBuf,
        /// `true` to offer what lies under it to the network.
        share: bool,
    },
    /// Add `path` to the list (ADR-0101, "Shared Directories"). Guarded
    /// first: a refusal is [`ScanEvent::DirectoryRefused`](crate::ScanEvent::DirectoryRefused).
    /// Otherwise its scan walks it and asks, whatever it would read, with
    /// [`ScanEvent::ConsentRequested`](crate::ScanEvent::ConsentRequested):
    /// the count and size, and the entries it would replace. The
    /// [`Answer`](Self::Answer) for its canonical path stores it, or drops it.
    AddSharedDirectory {
        /// The directory, as the operator typed it.
        path: PathBuf,
    },
    /// Remove `path` from the list: its scan stops and every file under it
    /// is unshared at once and set aside, so adding it again reads nothing.
    /// Answered by [`ScanEvent::DirectoryRemoved`](crate::ScanEvent::DirectoryRemoved)
    /// with the count, or a refusal.
    RemoveSharedDirectory {
        /// The directory, as the list names it.
        path: PathBuf,
    },
}

/// Top-level command to the core actor: a per-activity command, or a
/// cross-activity control command. Thin wrapper so serve commands are a
/// new arm, not a widening of the download vocabulary.
#[derive(Clone, Debug)]
// CoreCommand is sent over a low-frequency mpsc channel (one message per
// user action), so the size imbalance between Download(DownloadCommand) and
// the zero-size DumpDiagnostics is intentional; boxing would add indirection
// for no measurable gain.
#[allow(clippy::large_enum_variant)]
pub enum CoreCommand {
    /// Download activity commands (ADR-0030).
    Download(DownloadCommand),
    /// Serve-side share-set commands (ADR-0031). Cross-activity vocabulary
    /// kept separate from `Download` so serve never carries a `DownloadId`.
    Serve(ServeCommand),
    /// Connected-server eD2k search commands (ADR-0034). Search is a sibling
    /// activity that rides the shared persistent server session.
    Search(SearchCommand),
    /// **Download Directory Scan** commands (ADR-0100).
    Scan(ScanCommand),
    /// Managed server list commands (ADR-0080): the CRUD an operator performs
    /// on the list of servers rmule knows, plus the on-demand server.met
    /// re-fetch. Core owns the list, so these mutate it and republish the
    /// level; nothing here touches the *connected* session — that is
    /// [`ConnectToServer`](Self::ConnectToServer).
    ServerList(ServerListCommand),
    /// Connect to a **listed** server and make it the one every later activity
    /// rides (ADR-0080 amendment) — aMule's "connect to the
    /// selected server".
    ///
    /// Deliberately *not* a [`ServerListCommand`]: the list is a config fact
    /// and the connection a session fact, and no list command reaches the
    /// session slot. It carries credentials for the same reason every other
    /// session-establishing command does (`StartSearch`, `StartDownload`,
    /// `StartServing`) — core is storage-agnostic (ADR-0069) and the identity
    /// is the front-end's to hold.
    ///
    /// Answered off the actor: the reply is the
    /// [`ServerConnectionEvent`](crate::ServerConnectionEvent) trail (`Connecting` → `Connected` /
    /// `ConnectFailed`, preceded by `Disconnected` when a live session was
    /// switched out), so a multi-second dial never blocks the command channel.
    /// Rejected outright with [`CoreCommandRejectReason::UnknownServer`] when
    /// the endpoint is not listed and
    /// [`CoreCommandRejectReason::ServerConnectInFlight`] when one connect is
    /// already running.
    ConnectToServer {
        /// The listed server to make the session's server.
        server: ServerEndpoint,
        /// The identity to log in with.
        credentials: ClientCredentials,
    },
    /// End the operator's intent to stay connected (ADR-0093, "A lost
    /// session is re-made"): the live session is hung up, a pending
    /// reconnect is dropped (`ReconnectEnded { OperatorDisconnected }`), and
    /// nothing is dialed until the operator connects again. A no-op with
    /// neither.
    DisconnectFromServer,
    /// Take up the operator's **Server Policy** live (ADR-0052): the rows'
    /// health and the swept list follow it at once. The front end keeps the
    /// preferences it came from; core read them at its start.
    SetServerPolicy(crate::ServerPolicy),
    /// Take up the operator's `Remember peers` live (ADR-0107, "Source
    /// Seeds"): the next seed write keeps that many peers per download.
    SetRememberPeers(crate::RememberPeers),
    /// Start the Kad node and its source-discovery task (ADR-0043). The
    /// front-end owns config (ADR-0069): it reads the persisted Kad identity
    /// from `AppConfigStore` and pushes it here. Never sent ⇒ no Kad task
    /// spawns and nothing else changes; a duplicate is ignored; a failed
    /// start rejects with [`CoreCommandRejectReason::KadUnavailable`].
    EnableKad(KadEnableConfig),
    /// Reach a peer that a plain TCP dial may not reach (ADR-0061): ask the one
    /// **callback route chooser** which of the four routes gets to it, and enact
    /// that verdict. The chosen route is reported as
    /// [`CoreEvent::PeerReachRouted`](crate::CoreEvent::PeerReachRouted).
    ///
    /// The caller supplies the counterparty facts it learned — from a source
    /// row, a peer hello, or an operator — and never the route: our own half of
    /// the decision (the ADR-0058 reachability verdict, whether the client-UDP
    /// surface is bound, whether Kad is running) is core's to know.
    ReachPeer(PeerReach),
    /// Re-run **both** halves of "can anyone reach me" (ADR-0086): re-race the
    /// port-mapping backends, and start a Kad firewall self-check now rather
    /// than at its next hourly slot.
    ///
    /// One command rather than two because to an operator they are one
    /// question. A stale port mapping is the usual reason a firewall recheck
    /// keeps coming back negative, so rechecking Kad alone would re-confirm the
    /// same stale mapping, and re-racing the mappers alone would leave the Kad
    /// verdict wrong for up to an hour.
    ///
    /// Answered by the trail it causes — the diagnostics snapshot's mapping
    /// rows and the Kad firewall verdict — not by an event of its own: a
    /// recheck is a request to *find out*, and the finding out takes seconds to
    /// minutes. Both halves are individually rate-limited and both are no-ops
    /// when their subsystem is off.
    RecheckReachability,
    /// Ask the orchestrator to echo a [`DiagnosticsSnapshot`](crate::diagnostics::DiagnosticsSnapshot) via
    /// [`CoreEvent::DiagnosticsSnapshot`](crate::CoreEvent::DiagnosticsSnapshot) (ADR-0028). Cross-activity; cheap
    /// lock-and-clone, schedules no work.
    DumpDiagnostics,
    /// Ask for the **File History** — the Shared File Registry's entries and
    /// the cancelled downloads — answered by [`CoreEvent::FileHistory`]
    /// (ADR-0100). A read of the store, scheduling no work; a front end asks
    /// again when a share, unshare, completion or cancel tells it the
    /// history moved.
    ///
    /// [`CoreEvent::FileHistory`]: crate::CoreEvent::FileHistory
    DumpFileHistory,
    /// Stop a running Kad activity: the discovery pump, the
    /// publisher and the ed2k→Kad handoff forwarder `EnableKad` spawned are
    /// all stopped and joined, then the same reaper a pump's own death goes
    /// through (ADR-0093) takes the activity out of the ledger, clears the
    /// `CT_EMULE_UDPPORTS` advert's Kad half and reports
    /// [`CoreEvent::KadStopped`](crate::CoreEvent::KadStopped). Never sent ⇒
    /// nothing changes; sent while Kad is already off is a no-op; a later
    /// `EnableKad` restarts clean. The activity's own lever is always
    /// the one wired into the pump, so this reaches it even when
    /// a caller also holds a lever of its own (the raw `KadShutdownHandle` path).
    DisableKad,
}

/// What an operator does to the **managed server list** (ADR-0080).
///
/// Every variant names its subject by [`ServerEndpoint`] — the list's key —
/// and every one of them is answered with a [`ServerListEvent`](crate::ServerListEvent) or, when the
/// row is not there or the capability is missing, a
/// [`CoreEvent::CommandRejected`](crate::CoreEvent::CommandRejected).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerListCommand {
    /// List a server, or fold onto the row already holding its endpoint. The
    /// caller supplies the whole row, so a front-end's add form can carry a
    /// name and a priority; a re-add of a known endpoint keeps the installed
    /// priority, static pin and failure tally (aMule's own duplicate rule —
    /// `ManagedServer::fold`), so those are changed with the two `Set`
    /// commands below, never by re-adding.
    AddServer {
        /// The whole row to list or fold.
        server: ManagedServer,
    },
    /// Drop a server from the list. **Never disconnects**: aMule's
    /// `RemoveServer` deletes the list entry and leaves a live session alone,
    /// and so does this — the connection is a session fact, the list is a
    /// config fact, and one does not own the other.
    RemoveServer {
        /// The endpoint whose row goes away.
        server: ServerEndpoint,
    },
    /// Set one row's priority (aMule's `ST_PREFERENCE`).
    SetServerPriority {
        /// The listed endpoint to re-prioritize.
        server: ServerEndpoint,
        /// The priority to install.
        priority: ServerPriority,
    },
    /// Pin or unpin one row (aMule's static-server flag).
    SetServerStatic {
        /// The listed endpoint to pin or unpin.
        server: ServerEndpoint,
        /// `true` pins the row against list updates and the failure-tally drop.
        is_static: bool,
    },
    /// Re-fetch `url` and merge it into the list — aMule's "update server.met
    /// from URL", the Join Sequence's first-run acquisition (ADR-0067) run
    /// on demand instead of on a cold start.
    ///
    /// Answered immediately with [`ServerListEvent::ServerListUpdateStarted`](crate::ServerListEvent::ServerListUpdateStarted);
    /// the fetch itself runs off the actor, so the list stays editable while
    /// it is in flight, and lands as
    /// [`ServerListEvent::ServerListUpdated`](crate::ServerListEvent::ServerListUpdated) or
    /// [`ServerListEvent::ServerListUpdateFailed`](crate::ServerListEvent::ServerListUpdateFailed). Rejected outright when no
    /// fetch capability was injected, or when one update is already running.
    UpdateServerList {
        /// The server.met URL to fetch and merge.
        url: String,
    },
}
/// Why the actor refused a [`CoreCommand`] outright, reported as
/// [`CoreEvent::CommandRejected`](crate::CoreEvent::CommandRejected)(crate::CoreEvent::CommandRejected). A refusal
/// means nothing was started and no state moved — it is not a failed run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoreCommandRejectReason {
    /// A resume named a download that already has a live run in the
    /// **Download Set**.
    DownloadAlreadyActive,
    /// A start named a file (hash and size) a live download already holds.
    /// One file is one download: its source discovery, file-known entry and
    /// `.part` are keyed by the file, so a second copy is refused rather
    /// than raced.
    DuplicateDownload,
    /// A start named an output path that already exists on disk, or whose
    /// `.part` another download already writes.
    DownloadPathConflict,
    /// The download store refused to mint, or to forget, the row for a
    /// reason of its own — a storage fault, traced at `warn` where it happened.
    DownloadStoreFailed,
    /// The command named a download id core does not hold, so there was
    /// nothing to act on.
    UnknownDownload,
    /// A clear named a download that has not completed, or whose completion
    /// core has not finished sharing. Only a completed download's record is
    /// forgotten: any other still holds its file's place, and a cancel is what
    /// drops it.
    DownloadNotCompleted,
    /// The command named a search id core does not hold — usually one that
    /// already completed or was cancelled.
    UnknownSearch,
    /// A `StartSearch` named an id a running search already holds; nothing
    /// was started and the running search was left alone. Ids from
    /// [`SearchId::mint`] never collide.
    SearchIdInUse,
    /// The Kad node could not start. Downloads still work through the
    /// connected server and global discovery. Carries why: the
    /// unified UDP socket never bound, or the Kad factory itself refused for
    /// a reason of its own.
    KadUnavailable(KadUnavailableReason),
    /// A server-list command named an endpoint the list does not hold
    /// (ADR-0080).
    UnknownServer,
    /// The server-list store refused the write; the list is unchanged. The
    /// store's own reason is traced at `warn` — it is a storage fault, not a
    /// caller mistake, so it is not modelled as a command vocabulary.
    ServerListStoreFailed,
    /// [`ServerListCommand::UpdateServerList`] was sent to a core built with
    /// no fetch capability (no [`CoreBuilder::server_list_fetcher`](crate::CoreBuilder::server_list_fetcher)). Honest
    /// Capability Advertisement: core does not link an HTTP client, so
    /// without an injected fetcher there is nothing to fetch with.
    ServerListFetchUnavailable,
    /// An update is already in flight. aMule's own one-at-a-time posture: a
    /// second fetch would race the first into the same list for no gain.
    ServerListUpdateInFlight,
    /// A [`CoreCommand::ConnectToServer`] arrived while one is already
    /// dialing. Refused rather than queued: the second connect
    /// would tear down a session the first is still establishing, and the
    /// operator would read a trail that interleaves two servers.
    ServerConnectInFlight,
}

/// Why [`CoreCommandRejectReason::KadUnavailable`] refused an `EnableKad`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadUnavailableReason {
    /// The one client-UDP socket (ADR-0057) never bound at core start, so
    /// there is no socket for Kad to ride. The same two facts
    /// [`CoreEvent::ClientUdpBindFailed`](crate::CoreEvent::ClientUdpBindFailed)
    /// reported at start. Permanent for the session: there is no retry
    /// (ADR-0057 amendment, "stay down until restart"), so every `EnableKad`
    /// sent after the first is refused with the same reason until a restart.
    UdpUnbound {
        /// The port core asked the OS for.
        port: u16,
        /// The OS's reason the bind gave.
        kind: std::io::ErrorKind,
    },
    /// The one client-UDP socket bound, but **without the family Kad rides**
    /// Kad is IPv4-only (ADR-0087) and it
    /// shares the client-UDP Family Pair, so a pair that came up on `::`
    /// alone is a Kad node with no transport — even though ADR-0085 rightly
    /// let the pair come up. Permanent for the session, like
    /// [`Self::UdpUnbound`]: there is no re-bind.
    UdpFamilyMissing {
        /// The family that refused — IPv4 whenever this refuses an
        /// `EnableKad`, since no other family carries Kad.
        family: rmule_primitives::AddressFamily,
        /// The OS's reason that family's bind gave.
        kind: std::io::ErrorKind,
    },
    /// The socket bound, but the Kad factory itself refused to start — a
    /// reason of its own, already logged at `warn` where it happened.
    StartFailed,
}
