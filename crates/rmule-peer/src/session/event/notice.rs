//! The **Notice** group of [`PeerEvent`](super::PeerEvent): what the session
//! counted or dropped that no capability acts on — unknown and unsolicited
//! frames, inflate failures below a part, rejected commands, and the human
//! layer rmule answers by parity or drops (ADR-0068).

use rmule_primitives::{Ed2kText, FileHash, PacketProtocol};

use crate::compressed_frame::CompressedFrameSkipReason;
use crate::session::PeerError;

/// A diagnostic fact about the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoticeEvent {
    /// A well-formed frame this crate does not model. Reported as shape
    /// only; the bytes stay with the packet, which is kept rather than
    /// ending the conversation (ADR-0018).
    UnknownPacket {
        /// Which framing byte carried it.
        protocol: PacketProtocol,
        /// The opcode nothing claimed.
        opcode: u8,
        /// Payload size, so a diagnostic can say how much went unread.
        payload_len: usize,
    },
    /// A bundled `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT`/`OP_MULTIPACKETANSWER`
    /// (ADR-0054) walk met a sub-opcode it does not model and stopped; the
    /// already-decoded prefix still fanned in normally. Non-terminal — the
    /// session stays open, mirroring [`Self::UnknownPacket`] but scoped to
    /// one sub-item inside the bundle rather than a whole wire frame.
    MultiPacketUnknownSub {
        /// The file the bundle was about.
        file_hash: FileHash,
        /// The sub-opcode the walk stopped at.
        opcode: u8,
        /// Bytes left unwalked behind it.
        remaining: usize,
    },
    /// An inbound packed (`0xD4`) frame's payload could not be inflated
    /// (corrupt zlib or over the [`crate::PEER_COMPRESSED_FRAME_LIMIT`]
    /// ceiling). Non-terminal: the session stays open, mirroring
    /// `rmule-ed2k`'s `CompressedFrameSkipped` (ADR-0053). Distinct from
    /// `CompressedPartSkipped`: this is the frame-level `0xD4` codec: any
    /// packed opcode, not only `OP_COMPRESSEDPART` transfer blocks.
    CompressedFrameSkipped {
        /// The inner opcode, which framing established before the payload
        /// was lost.
        opcode: u8,
        /// Compressed size as framed.
        compressed_len: usize,
        /// Why inflation failed.
        reason: CompressedFrameSkipReason,
    },
    /// Session refused to act on an application command (e.g. a second
    /// `RequestParts` while a slot context is active). Carries the
    /// typed `PeerError` per ADR-0010.
    CommandRejected {
        /// Why the session refused.
        reason: PeerError,
    },
    /// Respond-by-parity (ADR-0068): a browse request
    /// (`OP_ASKSHAREDFILES`/`OP_ASKSHAREDDIRS`/`OP_ASKSHAREDFILESDIR`) was
    /// answered `OP_ASKSHAREDDENIEDANS` — the classification counter for the
    /// `browse-denied` gate. rmule has no browse feature; every browse
    /// request gets this same unconditional refusal.
    BrowseDenied,
    /// Drop-with-counter (ADR-0068): an unsolicited browse answer arrived
    /// (`OP_ASKSHAREDFILESANSWER`/`OP_ASKSHAREDDIRSANS`/
    /// `OP_ASKSHAREDFILESDIRANS`/a denied answer rmule never asked for) —
    /// rmule never browses, so any of these is unsolicited. Parsed, counted,
    /// dropped.
    UnsolicitedBrowseAnswerDropped,
    /// Drop-with-counter (ADR-0068): an unsolicited `OP_PUBLICIP_ANSWER`
    /// arrived (rmule never asks — the server's IDCHANGE serves that need,
    /// ADR-0047). Parsed, counted, dropped.
    UnsolicitedPublicIpAnswerDropped,
    /// Surface-as-event (ADR-0068): inbound chat text (`OP_MESSAGE`),
    /// already capped to aMule's 450-char limit. No reply, no state, no spam
    /// gate — rmule has no chat feature.
    ChatMessageReceived {
        /// The message, already capped at aMule's 450 characters.
        text: Ed2kText,
    },
    /// Drop-with-counter (ADR-0068): an inbound chat-captcha challenge or
    /// answer (`OP_CHATCAPTCHAREQ`/`RES`). Rides on outbound chat, which
    /// rmule never sends, so any inbound instance is unsolicited. Parsed,
    /// counted, dropped.
    ChatCaptchaDropped,
}
