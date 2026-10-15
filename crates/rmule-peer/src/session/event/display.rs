//! The one-line rendering of a [`PeerEvent`] that the TUI and harness log
//! lines share.

use std::fmt;

use super::PeerEvent;
use crate::{ConnectionEvent, IdentityChange, NoticeEvent, RequesterEvent, ServerEvent, SideEvent};

/// Compact one-line diagnostic summary of a peer-conversation event — the
/// co-located projection `rmule-tools` prints (every line carries the `peer`
/// prefix). Exhaustive by design: a new [`PeerEvent`] variant fails to compile
/// until its projection lands here, keeping the label in the enum's own crate
/// rather than re-walked by every consumer.
impl fmt::Display for PeerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerEvent::Connection(event) => event.fmt(f),
            PeerEvent::Requester(event) => event.fmt(f),
            PeerEvent::Server(event) => event.fmt(f),
            PeerEvent::Side(event) => event.fmt(f),
            PeerEvent::Notice(event) => event.fmt(f),
        }
    }
}

impl fmt::Display for ConnectionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionEvent::HelloSent => write!(f, "peer hello_sent"),
            ConnectionEvent::Identified { identity } => write!(
                f,
                "peer identified user_hash={} client_id={}",
                identity.user_hash().to_hex_upper(),
                identity.client_id().as_u32()
            ),
            ConnectionEvent::IdentityRevised { identity, what } => {
                write!(f, "peer identity_revised ")?;
                match what {
                    IdentityChange::Software => {
                        write!(f, "software={:?}", identity.software())
                    }
                    IdentityChange::ReaskContact => {
                        let (udp_port, udp_version) =
                            identity.client_udp_reask().unwrap_or_default();
                        write!(f, "udp_port={udp_port} udp_version={udp_version}")
                    }
                    IdentityChange::SourceExchange => {
                        write!(f, "{}", SupportLine(identity.source_exchange()))
                    }
                    IdentityChange::Ipv6 => match identity.peer_ipv6() {
                        Some(address) => write!(f, "ipv6={address}"),
                        None => write!(f, "ipv6=none"),
                    },
                    IdentityChange::ClientId => {
                        write!(f, "client_id={}", identity.client_id().as_u32())
                    }
                }
            }
            ConnectionEvent::HelloRefused { refusal } => match refusal.code {
                crate::HelloRefusalCode::TagCountShort { declared, written } => write!(
                    f,
                    "peer hello_refused code=tag_count_short declared={declared} written={written}"
                ),
            },
            ConnectionEvent::Disconnected { reason } => {
                write!(f, "peer disconnected reason={}", reason.label())
            }
            ConnectionEvent::IdentityVerified {
                user_hash,
                public_key,
            } => write!(
                f,
                "peer identity_verified user_hash={} public_key_len={}",
                user_hash.to_hex_upper(),
                public_key.len()
            ),
            ConnectionEvent::SecureIdentFailed { reason } => {
                write!(f, "peer secure_ident_failed reason={reason:?}")
            }
            ConnectionEvent::ClientIdOffered { client_id, server } => write!(
                f,
                "peer client_id_offered client_id={} server={server}",
                client_id.as_u32()
            ),
        }
    }
}

impl fmt::Display for RequesterEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequesterEvent::FileRequestSent {
                file_hash,
                sources_asked,
            } => write!(
                f,
                "peer file_request_sent file_hash={} sources_asked={sources_asked}",
                file_hash.to_hex_upper(),
            ),
            RequesterEvent::FileProbed { file_hash, status } => write!(
                f,
                "peer file_probed file_hash={} status={status:?}",
                file_hash.to_hex_upper()
            ),
            RequesterEvent::HashSetReceived {
                file_hash,
                part_hashes,
            } => write!(
                f,
                "peer hash_set_received file_hash={} part_hash_count={}",
                file_hash.to_hex_upper(),
                part_hashes.len()
            ),
            RequesterEvent::QueueRanked { file_hash, rank } => write!(
                f,
                "peer queue_ranked file_hash={} rank={rank}",
                file_hash.to_hex_upper()
            ),
            RequesterEvent::QueueProgress {
                file_hash,
                previous_rank,
                new_rank,
            } => write!(
                f,
                "peer queue_progress file_hash={} previous_rank={previous_rank} new_rank={new_rank}",
                file_hash.to_hex_upper()
            ),
            RequesterEvent::SlotAsked { file_hash } => {
                write!(f, "peer slot_asked file_hash={}", file_hash.to_hex_upper())
            }
            RequesterEvent::Requeued { file_hash } => {
                write!(f, "peer requeued file_hash={}", file_hash.to_hex_upper())
            }
            RequesterEvent::SlotGranted { file_hash } => {
                write!(
                    f,
                    "peer slot_granted file_hash={}",
                    file_hash.to_hex_upper()
                )
            }
            RequesterEvent::PartReceived {
                file_hash,
                offset,
                bytes,
            } => write!(
                f,
                "peer part_received file_hash={} offset={offset} data_len={}",
                file_hash.to_hex_upper(),
                bytes.len()
            ),
            RequesterEvent::SourcesReceived { file_hash, sources } => write!(
                f,
                "peer sources_received file_hash={} source_count={}",
                file_hash.to_hex_upper(),
                sources.len()
            ),
            RequesterEvent::SourceExchangeAnswerSkipped { reason } => {
                write!(f, "peer source_exchange_answer_skipped reason={reason}")
            }
            RequesterEvent::AichAnswerReceived {
                file_hash,
                part,
                recovery_data,
                ..
            } => write!(
                f,
                "peer aich_answer_received file_hash={} part={part} recovery_len={}",
                file_hash.to_hex_upper(),
                recovery_data.len()
            ),
            RequesterEvent::AichFileHashReceived { root } => {
                write!(
                    f,
                    "peer aich_file_hash_received root={}",
                    root.to_base32_upper()
                )
            }
            RequesterEvent::CompressedPartSkipped {
                file_hash,
                offset,
                reason,
            } => write!(
                f,
                "peer compressed_part_skipped file_hash={} offset={offset} reason={reason}",
                file_hash.to_hex_upper()
            ),
            RequesterEvent::SlotReleased { file_hash, reason } => write!(
                f,
                "peer slot_released file_hash={} reason={reason:?}",
                file_hash.to_hex_upper()
            ),
            RequesterEvent::FileCommentReceived { rating, comment } => write!(
                f,
                "peer file_comment_received rating={rating} comment_len={}",
                comment.as_bytes().len()
            ),
        }
    }
}

impl fmt::Display for ServerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerEvent::FileRequested { file_hash, status } => write!(
                f,
                "peer file_requested file_hash={} part_status={}B",
                file_hash.to_hex_upper(),
                status.as_bytes().len(),
            ),
            ServerEvent::FileBundleRequested {
                file_hash,
                file_size,
                asks,
                cut,
            } => write!(
                f,
                "peer file_bundle_requested file_hash={} file_size={} asks={} cut={}",
                file_hash.to_hex_upper(),
                file_size.map_or_else(|| "none".to_owned(), |s| s.to_string()),
                asks.len(),
                cut.is_some(),
            ),
            ServerEvent::FileIdSet { file_hash } => {
                write!(f, "peer file_id_set file_hash={}", file_hash.to_hex_upper())
            }
            ServerEvent::HashSetRequested { file_hash } => write!(
                f,
                "peer hash_set_requested file_hash={}",
                file_hash.to_hex_upper()
            ),
            ServerEvent::SlotRequested { file_hash } => write!(
                f,
                "peer slot_requested file_hash={}",
                file_hash.to_hex_upper()
            ),
            ServerEvent::PartsRequested { file_hash, ranges } => {
                let (start, end) = ranges.as_array()[0];
                write!(
                    f,
                    "peer parts_requested file_hash={} start={start} end={end}",
                    file_hash.to_hex_upper()
                )
            }
            ServerEvent::PartsWithoutSlot { file_hash } => write!(
                f,
                "peer parts_without_slot file_hash={}",
                file_hash.to_hex_upper()
            ),
            ServerEvent::TransferCancelled { file_hash } => write!(
                f,
                "peer transfer_cancelled file_hash={}",
                file_hash.to_hex_upper()
            ),
            ServerEvent::SourcesRequested { file_hash } => write!(
                f,
                "peer sources_requested file_hash={}",
                file_hash.to_hex_upper()
            ),
            ServerEvent::SourcesAnswered { file_hash, count } => write!(
                f,
                "peer sources_answered file_hash={} count={count}",
                file_hash.to_hex_upper()
            ),
            ServerEvent::AichRequested {
                file_hash, part, ..
            } => write!(
                f,
                "peer aich_requested file_hash={} part={part}",
                file_hash.to_hex_upper()
            ),
            ServerEvent::AichFileHashRequested { file_hash } => write!(
                f,
                "peer aich_file_hash_requested file_hash={}",
                file_hash.to_hex_upper()
            ),
        }
    }
}

impl fmt::Display for SideEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SideEvent::KadFirewallCheckAck => write!(f, "peer kad_fwtcpcheck_ack"),
            SideEvent::KadUdpFirewallCheckRequested { request } => {
                write!(f, "peer kad_fwcheckudpreq len={}", request.len())
            }
            SideEvent::BuddyPingReceived => write!(f, "peer buddy_ping"),
            SideEvent::BuddyCallbackReceived { callback } => write!(
                f,
                "peer buddy_callback file_hash={} requester={}",
                callback.file_hash.to_hex_upper(),
                callback.requester
            ),
            SideEvent::BuddyReaskCallbackReceived { relay } => write!(
                f,
                "peer buddy_reask_callback requester={} forwarded={}",
                relay.requester,
                relay.forwarded.len()
            ),
            SideEvent::PublicIpAnswered => write!(f, "peer publicip_answered"),
            SideEvent::PublicIpRequestUnanswerable => {
                write!(f, "peer publicip_request_unanswerable")
            }
        }
    }
}

impl fmt::Display for NoticeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoticeEvent::CompressedFrameSkipped {
                opcode,
                compressed_len,
                reason,
            } => write!(
                f,
                "peer compressed_frame_skipped opcode=0x{opcode:02X} compressed_len={compressed_len} reason={reason:?}"
            ),
            NoticeEvent::CommandRejected { reason } => {
                write!(f, "peer command_rejected reason={reason}")
            }
            NoticeEvent::UnknownPacket {
                protocol,
                opcode,
                payload_len,
            } => write!(
                f,
                "peer unknown protocol={} opcode=0x{opcode:02X} payload_len={payload_len}",
                protocol.name()
            ),
            NoticeEvent::MultiPacketUnknownSub {
                file_hash,
                opcode,
                remaining,
            } => write!(
                f,
                "peer multipacket_unknown_sub file_hash={} opcode=0x{opcode:02X} remaining={remaining}",
                file_hash.to_hex_upper()
            ),
            NoticeEvent::BrowseDenied => write!(f, "peer browse_denied"),
            NoticeEvent::UnsolicitedBrowseAnswerDropped => {
                write!(f, "peer unsolicited_browse_answer_dropped")
            }
            NoticeEvent::UnsolicitedPublicIpAnswerDropped => {
                write!(f, "peer unsolicited_publicip_answer_dropped")
            }
            NoticeEvent::ChatMessageReceived { text } => write!(
                f,
                "peer chat_message_received len={}",
                text.as_bytes().len()
            ),
            NoticeEvent::ChatCaptchaDropped => write!(f, "peer chat_captcha_dropped"),
        }
    }
}

/// A peer's source-exchange facts as `key=value` fields.
struct SupportLine(crate::SourceExchangeSupport);

impl fmt::Display for SupportLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ext_protocol={} sx1_version={} sx2={}",
            self.0.ext_protocol(),
            self.0.sx1_version(),
            self.0.supports_sx2()
        )
    }
}
