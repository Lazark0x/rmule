//! The **serve connection** vocabulary: the two channel-borne halves core and
//! one accepted peer speak through, and the handle that owns them.
//!
//! No socket, no listener, no task — a [`ServeConnection`] is a pair of
//! channel ends already wired to whatever drives the wire, which is why core's
//! serve queue can be exercised end to end without the peer wire types (the
//! `PeerWorkerEvent` posture on the download side). The adapter beside it owns
//! the listener that produces these handles.

use std::net::Ipv6Addr;

use rmule_peer::{
    BundleCut, BundledAsk, PartBitmap, PartRanges, PartStatusTail, ServedSourcesVersion,
};
use rmule_primitives::{
    AichRootHash, ClientId, CryptStance, Ed2kText, ExchangedSource, FileHash, Ipv4Endpoint,
    PartHash, PeerEndpoint, UserHash,
};
use tokio::sync::mpsc;

use crate::CoreError;

/// Server Capability events surfaced to core for one accepted connection,
/// projected from the peer session's serve-side `PeerEvent`s. The narrow
/// core-facing mirror of the serve subset of `rmule_peer::PeerEvent`, so the
/// serve queue is tested without the peer wire types (cf. `PeerWorkerEvent`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeConnEvent {
    /// A standalone `OP_REQUESTFILENAME`: the peer asked for the file's name.
    FileRequested {
        /// The file whose name the peer asked for.
        file_hash: FileHash,
        /// The bytes after the hash, unread until the file is known — the
        /// input to the source-exchange answer's needed-part filter (ADR-0055
        /// §Serving).
        status: PartStatusTail,
    },
    /// `OP_MULTIPACKET` / `OP_MULTIPACKET_EXT`: several asks about one file in
    /// one bundle (ADR-0054), gated on the file as a whole.
    FileBundleRequested {
        /// The file every ask is about.
        file_hash: FileHash,
        /// The size an `OP_MULTIPACKET_EXT` names.
        file_size: Option<u64>,
        /// The asks, in wire order, up to where the walk stopped.
        asks: Vec<BundledAsk>,
        /// Where the walk ran out of bytes inside a sub-ask.
        cut: Option<BundleCut>,
    },
    /// `OP_SETREQFILEID`: the peer set the current file; answer its bitmap.
    FileIdSet {
        /// The file the rest of this connection's asks refer to.
        file_hash: FileHash,
    },
    /// `OP_HASHSETREQUEST`: the peer asked for the part hash set.
    HashSetRequested {
        /// The file whose part hashes the peer asked for.
        file_hash: FileHash,
    },
    /// `OP_STARTUPLOADREQ`: the peer asked for an upload slot.
    SlotRequested {
        /// The file the peer wants to pull once it holds a slot.
        file_hash: FileHash,
    },
    /// `OP_REQUESTPARTS` on a granted slot: ranges to serve.
    PartsRequested {
        /// The file the ranges are in.
        file_hash: FileHash,
        /// Up to three byte ranges, half-open `[start, end)` in file offsets.
        ranges: PartRanges,
    },
    /// `OP_REQUESTSOURCES` / `OP_REQUESTSOURCES2` (or a bundled `Sources`(2)
    /// sub): the peer asked us for more sources of `file_hash` (ADR-0055 slice
    /// 3). `version` is the aMule-exact serve wire form the peer session
    /// already picked from the requester's advertised SX capability — core
    /// applies its pools / filters / per-peer throttle and echoes it back on
    /// the `AnswerSources` command.
    SourcesRequested {
        /// The file the peer wants more sources of.
        file_hash: FileHash,
        /// The wire form to answer in, already picked from the requester's
        /// advertised SX capability; core echoes it back on `AnswerSources`.
        version: ServedSourcesVersion,
    },
    /// `OP_AICHREQUEST`: the peer asked for a part's AICH recovery data
    /// (ADR-0038). Core builds the file's tree and answers with `AnswerAich`.
    AichRequested {
        /// The file the part belongs to.
        file_hash: FileHash,
        /// The zero-based part index whose recovery data is wanted.
        part: u16,
        /// The AICH master root the peer believes the file has; an answer is
        /// only built when it matches ours.
        root: AichRootHash,
    },
    /// `OP_AICHFILEHASHREQ`: the peer asked for the file's AICH master hash
    /// (ADR-0038). Core answers with `AnswerAichFileHash` from the file's tree.
    AichFileHashRequested {
        /// The file whose AICH master root the peer asked for.
        file_hash: FileHash,
    },
    /// `OP_CANCELTRANSFER` (ADR-0056): the peer canceled its held upload
    /// slot. Core runs the same release/promote batch as `Disconnected`
    /// minus teardown — the connection is left registered.
    TransferCancelled {
        /// The file whose transfer the peer abandoned.
        file_hash: FileHash,
    },
    /// The connection closed (any reason); core frees the peer's slot.
    Disconnected,
    /// The peer identified itself; `user_hash` keys its credit ledger.
    /// Emitted once, before any serve-capability events on this connection.
    /// `client_id` + `connected_server` are the Low-ID callback correlation key
    /// (ADR-0039): an inbound peer whose `(connected_server, client_id)` matches
    /// a pending callback is adopted as a download worker, not served.
    Identified {
        /// The peer's claimed identity, and the key of its credit ledger row.
        /// Unproven until an `IdentityVerified` follows.
        user_hash: UserHash,
        /// Its server-assigned id — the Low-ID half of the callback key.
        client_id: ClientId,
        /// The server it says it is logged in to, or `None` when its hello
        /// encoded `0.0.0.0:0` (a DNS-named server). The other half of the
        /// callback key.
        connected_server: Option<Ipv4Endpoint>,
        /// The peer's advertised eD2k TCP listen port (from its hello). Paired
        /// with `client_id` it is the peer's own source coordinate — a HighID
        /// serve client rmule may hand to another peer as a source-exchange
        /// entry (ADR-0055 §Serving), which needs the *listen* port, not the
        /// ephemeral inbound socket port `PeerEndpoint` carries.
        tcp_port: u16,
        /// The peer's advertised client UDP port (`0` = none) and UDP version,
        /// from its hello — the uploader reask match key (ADR-0057). Threaded
        /// truthfully once the live client-UDP front binds (the hello's
        /// `CT_EMULE_UDPPORTS` + `MiscOptions1` UDP-version parse lands with
        /// the socket and its capture); `0`/`0` until then, so no reask matches
        /// before rmule actually serves peer-UDP.
        udp_port: u16,
        /// The UDP protocol version behind `udp_port`; `4` or above is what
        /// earns a part-status payload in the reask answer.
        udp_version: u8,
        /// The extended-requests version the peer's hello claimed
        /// (`MiscOptions1` bits [8..12), aMule `m_byExtendedRequestsVer`). A
        /// `0` claimant's part status is discarded on the name-ask and reask
        /// paths alike, as aMule's `ProcessExtendedInfo` does (ADR-0055 §Serving).
        extended_requests_version: u8,
        /// The peer's advertised obfuscation stance (`MiscOptions2` crypt bits).
        /// The reask reply matrix pairs it with `user_hash` into the peer-UDP
        /// crypt target an obfuscated `0x91`/`0x92` is keyed on (ADR-0046).
        crypt: CryptStance,
        /// The peer's own reachable IPv6 from its hello's `CT_MOD_IP_V6`,
        /// already refused when it is no usable tag identity (ADR-0087). A
        /// Low-ID peer that named one is still a source — over IPv6, in an
        /// ExtSX record only.
        ipv6: Option<Ipv6Addr>,
        /// Which client the peer runs, read off the same hello.
        software: rmule_peer::ClientSoftware,
    },
    /// Secure User Identification proved this inbound peer owns `user_hash`
    /// (ADR-0041): the serve task binds `public_key` as its
    /// **Secured Identity** so upload-queue credit cannot be claimed by a
    /// spoofed hash. Arrives after `Identified`, before or between serve
    /// requests.
    IdentityVerified {
        /// The hash the proof was for.
        user_hash: UserHash,
        /// The DER SPKI public key now bound to it. A later exchange under a
        /// different key is a mismatch, never an overwrite.
        public_key: Vec<u8>,
    },
    /// The peer's `OP_EMULEINFO` named its software after `Identified` — the
    /// only version a pre-0.42 mule sends. Replaces what `Identified`
    /// carried for this peer.
    SoftwareRevised {
        /// Which client the peer runs, hello and block read together.
        software: rmule_peer::ClientSoftware,
    },
    /// The peer's `OP_EMULEINFO` named a client-UDP reask contact its hello
    /// did not: kept as `Identified`'s `udp_port`/`udp_version` are.
    ReaskContactRevised {
        /// Its client-UDP port.
        udp_port: u16,
        /// Its peer-UDP protocol version.
        udp_version: u8,
    },
    /// The accept-router matched this inbound peer's `(connected_server,
    /// client_id)` to a pending callback and adopted it as a download worker
    /// (ADR-0039). It never served, so `ServeTask` just drops it from the serve
    /// set — distinct from `Disconnected`, which would imply it had been serving
    /// and release a slot it never held.
    Readopted,
}

/// Server Capability answers core pushes back down one connection. The narrow
/// mirror of the serve subset of `rmule_peer::PeerCommand`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeConnCommand {
    /// Answer an `OP_REQUESTFILENAME`: we share the file, and this is what we
    /// call it.
    AnswerFileName {
        /// The file being named.
        file_hash: FileHash,
        /// Our name for it, in the eD2k string encoding the wire uses.
        file_name: Ed2kText,
    },
    /// Answer an `OP_REQUESTFILENAME` for a file we do not share, which ends
    /// the peer's interest in it.
    AnswerFileNotFound {
        /// The file we do not have.
        file_hash: FileHash,
    },
    /// Answer an `OP_SETREQFILEID` with which parts of the file we hold.
    AnswerFileStatus {
        /// The file the bitmap describes.
        file_hash: FileHash,
        /// One bit per part, set where we can serve.
        bitmap: PartBitmap,
    },
    /// Answer an `OP_HASHSETREQUEST` with the file's part hashes.
    AnswerHashSet {
        /// The file the hashes are for.
        file_hash: FileHash,
        /// The part hashes in part order — the peer verifies against these.
        part_hashes: Vec<PartHash>,
    },
    /// Grant the peer an upload slot (`OP_ACCEPTUPLOADREQ`); it may now ask for
    /// parts.
    GrantSlot {
        /// The file the slot is for.
        file_hash: FileHash,
    },
    /// Tell a waiting peer its current queue position (`OP_QUEUERANKING`).
    SetQueueRank {
        /// Its position in our upload queue.
        rank: u16,
    },
    /// Serve one block of file data to a peer holding a slot.
    SendBlock {
        /// The file the bytes come from.
        file_hash: FileHash,
        /// The block's first byte offset in the file.
        start: u64,
        /// The offset one past its last byte — `end - start` is `bytes.len()`.
        end: u64,
        /// The block's contents.
        bytes: Vec<u8>,
    },
    /// Answer an `OP_AICHREQUEST` with a part's recovery data (ADR-0038).
    AnswerAich {
        /// The file the part belongs to.
        file_hash: FileHash,
        /// The zero-based part index the recovery data is for.
        part: u16,
        /// Our AICH master root, which the peer checks the data against.
        root: AichRootHash,
        /// The serialized recovery hash set for that part.
        recovery_data: Vec<u8>,
    },
    /// Answer an `OP_AICHFILEHASHREQ` with our AICH master root (ADR-0038).
    AnswerAichFileHash {
        /// Our AICH master root for the file.
        root: AichRootHash,
    },
    /// Answer a source-exchange request with the filtered, capped `sources`
    /// (ADR-0055 §Serving). `version` (echoed from the request) tells the peer
    /// session whether to frame `OP_ANSWERSOURCES` (`0x82`) or
    /// `OP_ANSWERSOURCES2` (`0x84`), and it pack-attempts the answer above the
    /// 354-byte threshold (ADR-0053).
    AnswerSources {
        /// The file the sources are for.
        file_hash: FileHash,
        /// The selected sources, already filtered and capped.
        sources: Vec<ExchangedSource>,
        /// Echoed from the request; picks the `0x82` or `0x84` framing.
        version: ServedSourcesVersion,
    },
    /// Close the connection (queue eviction or shutdown).
    Disconnect,
}

/// Core's handle to one accepted, identified serve connection. Mirrors
/// [`PeerWorker`](crate::PeerWorker): commands go down `command_tx`, events arrive on `event_rx`.
pub struct ServeConnection {
    peer: PeerEndpoint,
    command_tx: mpsc::Sender<ServeConnCommand>,
    event_rx: mpsc::Receiver<ServeConnEvent>,
}

impl ServeConnection {
    /// Wrap an already-accepted connection's two channel halves. The caller
    /// owns the task that drives the socket behind them.
    #[must_use]
    pub fn new(
        peer: PeerEndpoint,
        command_tx: mpsc::Sender<ServeConnCommand>,
        event_rx: mpsc::Receiver<ServeConnEvent>,
    ) -> Self {
        Self {
            peer,
            command_tx,
            event_rx,
        }
    }

    /// The remote address this connection came in on. It is the *inbound
    /// socket*'s endpoint, so its port is ephemeral — the peer's advertised
    /// listen port arrives on [`ServeConnEvent::Identified`] instead.
    #[must_use]
    pub const fn peer(&self) -> PeerEndpoint {
        self.peer
    }

    /// Push one answer down the connection. Fails once the peer's task is
    /// gone, which is not an error worth retrying — the connection is over.
    pub async fn send(&self, command: ServeConnCommand) -> Result<(), CoreError> {
        self.command_tx
            .send(command)
            .await
            .map_err(|_| CoreError::Repository("serve connection closed".into()))
    }

    /// The next serve event, or `None` once the connection is gone. A `None`
    /// is the terminal signal — equivalent to a `ServeConnEvent::Disconnected`
    /// — so the consumer must free the peer's queue slot on either.
    pub async fn next_event(&mut self) -> Option<ServeConnEvent> {
        self.event_rx.recv().await
    }
}
