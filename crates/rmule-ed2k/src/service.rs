//! The command vocabulary a consumer queues against a live eD2k session, and
//! the facts and events it gets back.
//!
//! Connecting is deliberately absent: the endpoint and identity are
//! construction-time inputs the driver owns, and a `Connect` command here
//! would fork the connect path in two.

use std::fmt;
use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientId, Ed2kText, ExchangedSource, FileHash, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint,
    SearchQuery, SearchResult, ServerEndpoint, ServerIdentity, ServerStatusReport, SourceListTail,
    SourceLookupTarget,
};

use crate::{
    CloseReason, CompressedFrameSkipReason, HolepunchFail, HolepunchInfo, IdChange, OfferedFile,
    PeerCallbackCrypt, SearchResultSkipReason, ServerPacket, ServerTcpFlags,
};

/// Service-layer commands a consumer can queue against an active eD2k
/// session. The connection-establishment step is *not* in this enum —
/// `rmule_net::ed2k::Connection::connect_with_options` owns it because the
/// endpoint and identity are construction-time inputs, not in-flight
/// commands. Adding `Connect { .. }` here would create two parallel
/// connect paths with one as a silent no-op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ed2kCommand {
    /// Ask the server for more servers (`OP_GETSERVERLIST`) — how a client's
    /// list grows without an out-of-band source.
    RequestServerList,
    /// Ask the connected server for the next page of the last search this
    /// link sent (`OP_QUERY_MORE_RESULT`). The request names no search: the
    /// caller asks only after an answer said more, and before sending any
    /// other search.
    QueryMoreResults,
    /// Run a search against the connected server.
    Search {
        /// The query, by kind: a phrase with its constraints, or a file whose
        /// related files are asked for (refused unless the server granted
        /// [`ServerCapability::RelatedSearch`]).
        query: SearchQuery,
    },
    /// Ask the server which of its logged-in clients hold a file.
    RequestSources {
        /// The file to find sources for, hash and size.
        target: SourceLookupTarget,
    },
    /// Ask the connected server to relay an invitation to a Low-ID **source**
    /// (`OP_CALLBACKREQUEST`) so it dials us back (ADR-0039). `low_id` is the
    /// source's server-assigned id.
    RequestCallback {
        /// The source's server-assigned id.
        low_id: ClientId,
    },
    /// Ask the connected server to introduce us to a LowID client for a punch
    /// (`OP_LOWID_HOLEPUNCH_REQUEST`, ADR-0091). The answer is a
    /// [`HolepunchIntroduced`](Ed2kEvent::HolepunchIntroduced) — sent to the
    /// target too — or a [`HolepunchRefused`](Ed2kEvent::HolepunchRefused).
    /// A server that does not speak this ignores the opcode and answers
    /// nothing, so the caller's own timeout is the only failure signal there.
    RequestHolepunch {
        /// The target's server-assigned Low-ID.
        target: ClientId,
        /// Our bound client-UDP port — the server's fallback when it has
        /// observed no keepalive from us.
        our_udp_port: u16,
    },
    /// Publish our shared files to the server, so its searches can return them
    /// and its source lookups can name us.
    OfferFiles {
        /// The files to offer, with the metadata the server indexes them by.
        files: Vec<OfferedFile>,
    },
    /// Leave the server: send the goodbye and close.
    Disconnect,
}

/// Compact tag identifying which command was rejected. Mirrors
/// [`Ed2kCommand`] variants without dragging their payloads through the
/// event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ed2kCommandKind {
    /// [`Ed2kCommand::RequestServerList`].
    RequestServerList,
    /// [`Ed2kCommand::Search`].
    Search,
    /// [`Ed2kCommand::QueryMoreResults`].
    QueryMoreResults,
    /// [`Ed2kCommand::RequestSources`].
    RequestSources,
    /// [`Ed2kCommand::RequestCallback`].
    RequestCallback,
    /// [`Ed2kCommand::RequestHolepunch`].
    RequestHolepunch,
    /// [`Ed2kCommand::OfferFiles`].
    OfferFiles,
}

/// A server capability a command depends on — advertised at login, so a
/// command needing one can be refused locally rather than sent and ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServerCapability {
    /// Files past 4 GiB: without it a large file's size has no encoding the
    /// server would read correctly.
    LargeFiles,
    /// `SRV_TCPFLG_RELATEDSEARCH`: without it the server was never offered a
    /// `related::` search — eMule greys the item out
    /// (`SearchResultsWnd.cpp:1658-1663`) and aMule refuses
    /// (`SearchListCtrl.cpp:999-1016`).
    RelatedSearch,
}

/// Why the session refused a command instead of putting it on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandRejectReason {
    /// The command arrived before login completed.
    NotLoggedIn,
    /// The server never advertised a capability the command needs.
    UnsupportedServerCapability {
        /// The capability that is missing.
        capability: ServerCapability,
    },
}

/// Typed facts the server asserted in its `OP_IDCHANGE` extension
/// (ADR-0047) — the session's projection of the codec's wire-faithful
/// `u32`s, applying aMule's consume rules (`ServerSocket.cpp`): a
/// LowID-valued reported IP is discarded, a zero obfuscation port means
/// "not offered", and ports narrow to `u16` as aMule's setters do. The
/// public IP is load-bearing beyond login: direct callback, the Kad
/// firewall self-check, buddy, and ADR-0042's crypt-ping all read it
/// (aMule applies it globally only while LowID — that gate belongs to
/// those consumers, not to this projection).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ServerAssignedFacts {
    /// Our own public IPv4 as this login establishes it — from the assigned id
    /// when it is High, from the server's reported address when it is Low.
    pub public_ip: Option<Ipv4Addr>,
    /// The server's standard TCP port, sent when login came through an
    /// auxiliary port.
    pub standard_tcp_port: Option<u16>,
    /// The server's obfuscated TCP listener (feeds ADR-0042's crypt dial
    /// together with the `TCPOBFUSCATION` grant).
    pub obfuscation_tcp_port: Option<u16>,
}

impl ServerAssignedFacts {
    /// Project one decoded `OP_IDCHANGE` onto session facts.
    #[must_use]
    pub fn project(id: &IdChange) -> Self {
        // aMule takes our address from two different places depending on the
        // id it was given, and the High-ID case never consults the extension:
        //   High-ID — `CServerConnect::SetClientID` calls `SetPublicIP(new_id)`,
        //             because a High id *is* the address the server reached.
        //   Low-ID  — `ServerSocket.cpp:414` calls
        //             `SetPublicIP(dwServerReportedIP)` from the extension.
        // Reading only the extension leaves a High-ID login with no address at
        // all against any server that sends the short `OP_IDCHANGE`, which
        // silently disarms every UDP crypt send gate.
        let public_ip = if id.client_id.is_high_id() {
            Some(Ipv4Addr::from(id.client_id.as_u32().to_le_bytes()))
        } else {
            id.public_ip
                .filter(|raw| *raw >= ClientId::LOW_ID_THRESHOLD)
                .map(|raw| Ipv4Addr::from(raw.to_le_bytes()))
        };
        Self {
            public_ip,
            // aMule narrows the wire u32 into its u16 port setter
            // unconditionally once the threshold is cleared.
            standard_tcp_port: id.standard_tcp_port.map(|raw| raw as u16),
            obfuscation_tcp_port: id
                .obfuscation_tcp_port
                .filter(|raw| *raw != 0)
                .map(|raw| raw as u16),
        }
    }
}

/// What the session reports as a conversation with a server unfolds.
///
/// Events are summary signals, not the wire: a consumer follows the session's
/// state from these without decoding a packet, and anything unmodelled still
/// surfaces (as [`Self::UnknownServerPacket`]) rather than vanishing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ed2kEvent {
    /// The login handshake went out.
    LoginRequested {
        /// The server being logged in to.
        endpoint: ServerEndpoint,
    },
    /// The server assigned us an id: we are logged in.
    LoginAccepted {
        /// Our assigned id — High means peers can dial us, Low means they
        /// cannot.
        client_id: ClientId,
        /// The server's advertised capability flags, when it sent them.
        tcp_flags: Option<ServerTcpFlags>,
        /// The IDCHANGE-extension projection (ADR-0047). Re-emitted whole on
        /// a mid-session re-assignment.
        facts: ServerAssignedFacts,
    },
    /// The server refused the login; the session is over.
    LoginRejected,
    /// The server sent a free-text message — a banner, a rule, or a notice.
    ServerMessageReceived {
        /// The message, byte-faithful: server banners are routinely not UTF-8.
        text: Ed2kText,
    },
    /// The server reported its load.
    ServerStatusReceived {
        /// Its user and file counts, as it claims them.
        status: ServerStatusReport,
    },
    /// The server described itself.
    ServerIdentified {
        /// What it said about itself — name, description, hash and any
        /// untyped tags.
        identity: ServerIdentity,
    },
    /// The server handed over other servers it knows.
    ServerListReceived {
        /// The endpoints it offered.
        servers: Vec<Ipv4Endpoint>,
        /// The IPv6 endpoints its optional trailing block offered (ADR-0087
        /// §4.6). Empty for a legacy server, which sends no block at all.
        ipv6_servers: Vec<Ipv6Endpoint>,
    },
    /// Sources for `file_hash`, as candidates carrying the optional
    /// `(user_hash, crypt_options)` provenance the obfuscation-aware `0x44`
    /// reply delivers (ADR-0046). A plain `0x42` reply projects each source
    /// as [`ExchangedSource::plain`] — no crypt material, dialed plaintext.
    SourcesFound {
        /// The file the sources are for.
        file_hash: FileHash,
        /// The sources, each carrying whatever crypt provenance the reply
        /// form delivered.
        sources: Vec<ExchangedSource>,
        /// How the list's records measured (ADR-0085). A
        /// [`SourceListTail::Malformed`] list cost the records from its first
        /// **Sentinel Source** on and nothing before it — a counted
        /// diagnostic, not a failure.
        tail: SourceListTail,
    },
    /// A batch of search results arrived.
    SearchResultsFound {
        /// The rows, already projected to typed results.
        results: Vec<SearchResult>,
        /// Why each row the batch did not yield was skipped, in the order the
        /// server sent them.
        skipped: Vec<SearchResultSkipReason>,
        /// The server holds more rows for the link's last search, which
        /// [`Ed2kCommand::QueryMoreResults`] asks for.
        more_available: bool,
    },
    /// A search answer was not a result batch at all, so none of its rows
    /// were surfaced.
    SearchResultSkipped {
        /// Why it was unusable.
        reason: SearchResultSkipReason,
    },
    /// A firewalled peer asked us, through the server, to dial it back.
    PeerCallbackRequested {
        /// Where to dial.
        peer: PeerEndpoint,
        /// The `0x35` crypt extension when the server relayed the `>= 23`-byte
        /// form (ADR-0061): the requester's crypt stance + user hash,
        /// threaded so the firewalled-node dial-back can obfuscate the
        /// connect-back. `None` for a legacy 6-byte callback.
        crypt: Option<PeerCallbackCrypt>,
    },
    /// `OP_CALLBACK_FAIL`: the server could not route a callback we requested
    /// (ADR-0039). Carries no id — the wire payload is empty — so it cannot be
    /// attributed to a specific pending callback; a diagnostic signal only, the
    /// per-callback timeout drives slot release.
    CallbackFailed,
    /// `OP_LOWID_HOLEPUNCH_INFO`: the server introduced us to a LowID peer
    /// (ADR-0091). It arrives whether we asked (`0x60`) or the peer did — the
    /// server sends it to both sides — and may repeat about 1.2 s and 3 s
    /// later, so a consumer treats a repeat as the same introduction.
    HolepunchIntroduced {
        /// The peer's coordinates, as the **server observed** them.
        info: HolepunchInfo,
    },
    /// `OP_LOWID_HOLEPUNCH_FAIL`: the server would not introduce us. Unlike
    /// [`CallbackFailed`](Self::CallbackFailed) it names its target, so it is
    /// attributable to one attempt.
    HolepunchRefused {
        /// Which target, and why.
        fail: HolepunchFail,
    },
    /// A queued command was refused locally and never sent.
    CommandRejected {
        /// Which command it was.
        command: Ed2kCommandKind,
        /// Why it was refused.
        reason: CommandRejectReason,
    },
    /// A well-formed packet whose opcode this build has no model for. Its
    /// bytes were kept, not the session dropped (ADR-0018).
    UnknownServerPacket {
        /// The unmodelled opcode.
        opcode: u8,
        /// How large its payload was.
        payload_len: usize,
    },
    /// A compressed frame was left undecoded.
    CompressedFrameSkipped {
        /// The frame's opcode.
        opcode: u8,
        /// Its compressed payload length.
        compressed_len: usize,
        /// Why it was skipped.
        reason: CompressedFrameSkipReason,
    },
    /// The session ended.
    Disconnected {
        /// What ended it — our own goodbye, the server's, or a failure.
        reason: CloseReason,
    },
}

impl Ed2kEvent {
    /// Project a decoded server packet onto its lifecycle event. Lossy by
    /// design — events are summary signals for the service layer; the raw
    /// packet stays available for diagnostics or replay.
    #[must_use]
    pub fn from_server_packet(packet: &ServerPacket) -> Self {
        match packet {
            ServerPacket::IdChange(id) => Self::LoginAccepted {
                client_id: id.client_id,
                tcp_flags: id.tcp_flags,
                facts: ServerAssignedFacts::project(id),
            },
            ServerPacket::Reject(_) => Self::LoginRejected,
            ServerPacket::ServerMessage(msg) => Self::ServerMessageReceived {
                text: msg.text().clone(),
            },
            ServerPacket::ServerStatus(status) => Self::ServerStatusReceived {
                status: *status.report(),
            },
            ServerPacket::ServerIdent(ident) => Self::ServerIdentified {
                identity: ident.identity(),
            },
            ServerPacket::ServerList(list) => Self::ServerListReceived {
                servers: list.servers().to_vec(),
                ipv6_servers: list.ipv6_servers().to_vec(),
            },
            ServerPacket::FoundSources(found) => Self::SourcesFound {
                file_hash: found.file_hash(),
                // A plain `0x42` source has no crypt provenance — plaintext-dial only.
                sources: found
                    .sources()
                    .iter()
                    .copied()
                    .map(ExchangedSource::plain)
                    .collect(),
                tail: found.tail(),
            },
            ServerPacket::FoundSourcesObfu(found) => Self::SourcesFound {
                file_hash: found.file_hash(),
                sources: found.sources().to_vec(),
                tail: found.tail(),
            },
            ServerPacket::SearchResults(results) => Self::SearchResultsFound {
                results: results.results().to_vec(),
                skipped: results.skipped().to_vec(),
                more_available: results.more_available(),
            },
            ServerPacket::PeerCallback(cb) => Self::PeerCallbackRequested {
                // `0x35` names a 32-bit requester; the event speaks in peers.
                peer: PeerEndpoint::V4(cb.peer),
                crypt: cb.crypt,
            },
            // `0x26` is the same request one family over (ADR-0087 §4.5), so
            // it projects onto the same event: a consumer dials the peer it
            // is handed and never asks which family produced it. No crypt
            // provenance exists on this opcode, so the dial-back is plaintext.
            ServerPacket::PeerCallbackIpv6(cb) => Self::PeerCallbackRequested {
                peer: PeerEndpoint::V6(cb.peer),
                crypt: None,
            },
            ServerPacket::CallbackFailed(_) => Self::CallbackFailed,
            ServerPacket::HolepunchInfo(info) => Self::HolepunchIntroduced { info: *info },
            ServerPacket::HolepunchFail(fail) => Self::HolepunchRefused { fail: *fail },
            ServerPacket::Unknown { opcode, payload } => Self::UnknownServerPacket {
                opcode: *opcode,
                payload_len: payload.len(),
            },
        }
    }
}

/// Compact one-line diagnostic summary of a server-connection event — the
/// co-located projection `rmule-tools` prints (the `s2c` prefix marks a
/// server→client fact; `CommandRejected` and `Disconnected` are local/terminal,
/// so they carry no direction). Exhaustive by design: a new [`Ed2kEvent`]
/// variant fails to compile until its projection lands here, keeping the label
/// in the enum's own crate rather than re-walked by every consumer.
impl fmt::Display for Ed2kEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ed2kEvent::LoginRequested { endpoint } => write!(
                f,
                "s2c connection_started {}:{}",
                endpoint.host(),
                endpoint.port()
            ),
            Ed2kEvent::LoginAccepted { client_id, .. } => {
                write!(f, "s2c login_accepted client_id={}", client_id.as_u32())
            }
            Ed2kEvent::LoginRejected => write!(f, "s2c login_rejected"),
            Ed2kEvent::ServerMessageReceived { text } => {
                write!(f, "s2c server_message text_len={}", text.as_bytes().len())
            }
            Ed2kEvent::ServerStatusReceived { status } => write!(
                f,
                "s2c server_status user={} file={}",
                status.user_count, status.file_count
            ),
            Ed2kEvent::ServerIdentified { .. } => write!(f, "s2c server_ident"),
            Ed2kEvent::ServerListReceived {
                servers,
                ipv6_servers,
            } => {
                write!(
                    f,
                    "s2c server_list count={} ipv6_count={}",
                    servers.len(),
                    ipv6_servers.len()
                )
            }
            Ed2kEvent::SourcesFound {
                file_hash,
                sources,
                tail,
            } => write!(
                f,
                "s2c sources_found file_hash={} count={} malformed_tail={}",
                file_hash.to_hex_upper(),
                sources.len(),
                tail.is_malformed()
            ),
            Ed2kEvent::SearchResultsFound {
                results,
                skipped,
                more_available,
            } => write!(
                f,
                "s2c search_results count={} skipped={} more={more_available}",
                results.len(),
                skipped.len()
            ),
            Ed2kEvent::SearchResultSkipped { reason } => {
                write!(f, "s2c search_result_skipped reason={reason:?}")
            }
            Ed2kEvent::PeerCallbackRequested { peer, crypt } => {
                write!(
                    f,
                    "s2c peer_callback_requested peer={peer} crypt={}",
                    crypt.is_some()
                )
            }
            Ed2kEvent::CommandRejected { command, reason } => {
                write!(f, "command_rejected command={command:?} reason={reason:?}")
            }
            Ed2kEvent::UnknownServerPacket {
                opcode,
                payload_len,
            } => write!(
                f,
                "s2c unknown opcode=0x{opcode:02X} payload_len={payload_len}"
            ),
            Ed2kEvent::CompressedFrameSkipped {
                opcode,
                compressed_len,
                reason,
            } => write!(
                f,
                "s2c compressed_frame_skipped opcode=0x{opcode:02X} compressed_len={compressed_len} reason={reason:?}"
            ),
            Ed2kEvent::CallbackFailed => write!(f, "s2c callback_failed"),
            Ed2kEvent::HolepunchIntroduced { info } => write!(
                f,
                "s2c holepunch_info peer_udp={} role={:?}",
                info.peer_udp, info.role
            ),
            Ed2kEvent::HolepunchRefused { fail } => write!(
                f,
                "s2c holepunch_fail target={} reason={:?}",
                fail.target.as_u32(),
                fail.reason
            ),
            Ed2kEvent::Disconnected { reason } => {
                write!(f, "disconnected reason={}", reason.label())
            }
        }
    }
}
