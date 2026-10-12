//! What a peer session reports to its driver: the [`PeerEvent`] vocabulary,
//! grouped by the side of the conversation each fact belongs to, and the
//! opcode-to-event mapping capture tooling reads. Each group lives in its own
//! submodule; the human-readable rendering the TUI and harness log lines
//! share lives in `display`.

mod connection;
mod display;
mod notice;
mod requester;
mod server;
mod side;

pub use self::connection::{ConnectionEvent, IdentityChange};
pub use self::notice::NoticeEvent;
pub use self::requester::RequesterEvent;
pub use self::server::ServerEvent;
pub use self::side::SideEvent;

use rmule_primitives::Ed2kText;

use crate::file::PartBitmap;
use crate::packet::PeerPacket;

/// What a session reports to its owner, on one ordered stream. Every
/// variant is a fact already established — nothing here asks a question,
/// and the owner is free to act on it or not.
///
/// Facts are grouped by the side of the conversation aMule's handler for
/// them serves (ADR-0031), so an owner routes a whole group at once and a
/// new fact reaches the compiler inside its group. The stream stays one
/// stream because its order is load-bearing: `Connection(Identified)`
/// precedes every `Server` request it keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// The link itself: the opening, the peer's identity and its revisions,
    /// and the close.
    Connection(ConnectionEvent),
    /// Our pull from the peer: the Requester Capability (ADR-0025).
    Requester(RequesterEvent),
    /// The peer's pull from us: the Server Capability (ADR-0031).
    Server(ServerEvent),
    /// Node-wide services riding the link: Kad firewall checks, the buddy
    /// relay and the public-IP ask.
    Side(SideEvent),
    /// What the session counted or dropped that no capability acts on.
    Notice(NoticeEvent),
}

impl PeerEvent {
    /// Project the *state-independent* peer packets onto their event.
    ///
    /// Returns `None` for packets whose emitted event depends on session
    /// state (handshake, probe accumulation, slot/queue progress) — those
    /// stay in `PeerSession::dispatch`. Lossy by design, mirroring
    /// `rmule_ed2k::Ed2kEvent::from_server_packet` (plain reference, not an
    /// intra-doc link — `rmule-peer` does not depend on `rmule-ed2k`); the
    /// raw packet stays available for diagnostics or replay. `AnswerSources`
    /// is state-*dependent* (its sanity filter, Low-ID
    /// routing, and per-file cap all read session context) and is handled in
    /// `PeerSession::dispatch` instead of here.
    #[must_use]
    pub fn from_peer_packet(packet: &PeerPacket) -> Option<Self> {
        let event = match packet {
            PeerPacket::SendingPart(sp) => Self::Requester(RequesterEvent::PartReceived {
                file_hash: sp.file_hash,
                offset: sp.start,
                bytes: sp.data.clone(),
            }),
            PeerPacket::AichAnswer(a) => Self::Requester(RequesterEvent::AichAnswerReceived {
                file_hash: a.file_hash,
                part: a.part,
                root: a.root,
                recovery_data: a.recovery_data.clone(),
            }),
            PeerPacket::AichFileHashAns(a) => {
                Self::Requester(RequesterEvent::AichFileHashReceived { root: a.root })
            }
            PeerPacket::HashSetAnswer(a) => Self::Requester(RequesterEvent::HashSetReceived {
                file_hash: a.file_hash,
                part_hashes: a.part_hashes.clone(),
            }),
            PeerPacket::FileReqAnsNoFil(n) => Self::Requester(RequesterEvent::FileProbed {
                file_hash: n.file_hash,
                status: FileProbeStatus::NotAvailable,
            }),
            PeerPacket::KadFirewallAck => Self::Side(SideEvent::KadFirewallCheckAck),
            PeerPacket::KadUdpFirewallRequest(request) => {
                Self::Side(SideEvent::KadUdpFirewallCheckRequested {
                    request: request.clone(),
                })
            }
            PeerPacket::BuddyPing => Self::Side(SideEvent::BuddyPingReceived),
            PeerPacket::BuddyCallback(c) => Self::Side(SideEvent::BuddyCallbackReceived {
                callback: c.clone(),
            }),
            PeerPacket::BuddyReaskCallback(r) => {
                Self::Side(SideEvent::BuddyReaskCallbackReceived { relay: r.clone() })
            }
            PeerPacket::Unknown {
                protocol,
                opcode,
                payload,
            } => Self::Notice(NoticeEvent::UnknownPacket {
                protocol: *protocol,
                opcode: *opcode,
                payload_len: payload.len(),
            }),
            _ => return None,
        };
        Some(event)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// What a file probe established about the peer's copy.
pub enum FileProbeStatus {
    /// The peer has the file.
    Available {
        /// The name it calls the file by.
        file_name: Ed2kText,
        /// Which parts of it the peer holds — aMule's part-count-0 sentinel
        /// already expanded to every part.
        bitmap: PartBitmap,
        /// Whether the peer said it holds the whole file (aMule
        /// `m_bCompleteSource`, ADR-0108): the part-count-0 sentinel, or the
        /// name answer for a one-part file. A spelled-out bitmap with every
        /// part set is not complete — a part file whose last part arrived.
        complete: bool,
    },
    /// The peer does not have it.
    NotAvailable,
}

/// Terminal transitions out of an active slot context per ADR-0025.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlotReleaseReason {
    /// All requested parts arrived and verified.
    DownloadComplete,
    /// Peer refused the slot (`OP_OUTOFPARTREQS` or queue terminal).
    QueueRejected,
    /// Peer closed the connection mid-slot.
    PeerClosed,
    /// Wire-level protocol violation forced session into terminal
    /// slot state.
    ProtocolViolation,
    /// Driver-owned slot-stale timeout fired (`signal_slot_stale`).
    Stale,
    /// Local-reason teardown sent `OP_CANCELTRANSFER` before releasing
    /// (`CancelTransfer`, ADR-0056): `CancelDownload`, `PauseDownload`, or
    /// complete-overshoot while the slot was held.
    Cancelled,
}
