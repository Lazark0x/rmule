//! What a front end asks the core to do. One [`CoreCommand`] per ask, grouped
//! by activity (download, serve, search, directory scan, server list), plus the reasons the
//! actor refuses one outright.

use std::net::SocketAddrV4;
use std::path::PathBuf;

use rmule_ed2k::ServerPriority;
use rmule_primitives::{Ed2kFileLink, FileHash, SafeFileName, SearchQuery, ServerEndpoint};

use crate::adapters::KadEnableConfig;
use crate::server_list::ManagedServer;

use super::{DownloadId, PeerReach, SearchId};

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
        /// The name the finished file takes. Core places it in the download
        /// directory its Core Settings name, once the share guards pass that
        /// directory; partial data is written beside it until every part
        /// verifies. No command names a folder.
        name: SafeFileName,
        /// What the start does when `name` is taken there.
        if_taken: NameTaken,
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

/// What a [`DownloadCommand::StartDownload`] does when the name it gives is
/// taken in the download directory: a file or a `.part` already there
/// (ADR-0100, "Adding a marked file").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameTaken {
    /// Refuse the start as [`CoreCommandRejectReason::DownloadPathConflict`]:
    /// a fresh add never lands on a file it did not make.
    Refuse,
    /// Take the first `stem (n).ext` free beside it: the confirmed re-add of
    /// a file the operator has, had or cancelled.
    Number,
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
    /// one serve activity is live; a core built to
    /// [`restore_at_attach`](crate::CoreBuilder::restore_at_attach) starts it
    /// at attach. Its hellos present the Core Settings' credentials.
    StartServing {
        /// Where to bind the inbound listener; port `0` takes one the OS
        /// assigns. rmule advertises the Core Settings' TCP port, so the two
        /// must agree for peers to reach it — or the settings' be `0`,
        /// which advertises the port bound.
        listen_addr: SocketAddrV4,
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
/// disclosure guard's answer, and the directories the operator adds and
/// removes. Wrapped by [`CoreCommand::Scan`]; one scan runs per scanned
/// directory. No command scans a directory of its own choosing: core scans
/// the download directory the Core Settings name, at attach and when
/// [`Setting::DownloadDir`](crate::Setting::DownloadDir) moves it, and every
/// other directory only once an add is guarded and confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanCommand {
    /// The operator's answer to the disclosure guard for `dir`, recorded
    /// durably. Releases a scan waiting on it; recorded before the download
    /// directory moves to `dir` (the Settings warning), it spares the operator
    /// a second question.
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
    /// session slot. The login presents the Core Settings' credentials
    /// (ADR-0069), as every other wire-touching command does; no command
    /// carries them.
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
    },
    /// End the operator's intent to stay connected (ADR-0093, "A lost
    /// session is re-made"): the live session is hung up, a pending
    /// reconnect is dropped (`ReconnectEnded { OperatorDisconnected }`), and
    /// nothing is dialed until the operator connects again. A no-op with
    /// neither.
    DisconnectFromServer,
    /// Start the Kad node and its source-discovery task (ADR-0043). The node
    /// is core's own: its Kad ID and Kad UDP Key come from core's store, and
    /// its dials present the Core Settings' credentials (ADR-0069); the
    /// command carries only how to start it — seeds, the persisted routing
    /// table, the bench knobs. Never sent ⇒ no Kad task spawns and nothing
    /// else changes; a duplicate is ignored; a failed start rejects with
    /// [`CoreCommandRejectReason::KadUnavailable`].
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
// One message per operator action over a low-frequency channel: the whole
// `ManagedServer` row in `AddServer` outweighs the endpoint-only variants, and
// boxing it would put an indirection in every front end's construction for no
// measurable gain.
#[allow(clippy::large_enum_variant)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CoreCommandRejectReason {
    /// A resume named a download that already has a live run in the
    /// **Download Set**.
    DownloadAlreadyActive,
    /// A Pause or a Cancel named a download whose finished file is already
    /// in place: its completion move ends on its own (ADR-0115).
    DownloadCompleting,
    /// A start named a file (hash and size) a live download already holds.
    /// One file is one download: its source discovery, file-known entry and
    /// `.part` are keyed by the file, so a second copy is refused rather
    /// than raced.
    DuplicateDownload,
    /// A start named a file that already exists in the download directory,
    /// or whose `.part` another download already writes there.
    DownloadPathConflict,
    /// A start found no download directory in the Core Settings: there is
    /// nowhere to put the file.
    NoDownloadDir,
    /// A start found a download directory the share guards refuse, for this
    /// reason: a file finished there would be shared from a place the
    /// operator never chose to share (ADR-0101).
    DownloadDirRefused(crate::DirectoryRefusal),
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
    /// The Core Settings' TCP port is `0` — the OS's choice — and the eD2k
    /// listener the start brought up first did not bind, so the node would
    /// present port `0` in every firewall check it asks for and every source
    /// it publishes, for its whole life. The listener's own failure was said
    /// as `ServingFailed`. An operator's store never holds `0`, so only a
    /// test's or a tool's injected settings meet this.
    TcpPortUnbound,
}
