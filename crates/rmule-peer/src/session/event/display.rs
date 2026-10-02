//! The one-line rendering of a [`PeerEvent`] that the TUI and harness log
//! lines share.

use std::fmt;

use super::PeerEvent;

/// Compact one-line diagnostic summary of a peer-conversation event — the
/// co-located projection `rmule-tools` prints (every line carries the `peer`
/// prefix). Exhaustive by design: a new [`PeerEvent`] variant fails to compile
/// until its projection lands here, keeping the label in the enum's own crate
/// rather than re-walked by every consumer.
impl fmt::Display for PeerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerEvent::PeerHelloSent => write!(f, "peer hello_sent"),
            PeerEvent::PeerIdentified { identity } => write!(
                f,
                "peer identified user_hash={} client_id={}",
                identity.user_hash().to_hex_upper(),
                identity.client_id().as_u32()
            ),
            PeerEvent::PeerSoftwareRevised { software } => {
                write!(f, "peer software_revised software={software:?}")
            }
            PeerEvent::PeerSourceExchangeRevised { support } => {
                write!(f, "peer source_exchange_revised {}", SupportLine(*support))
            }
            PeerEvent::FileRequestSent {
                file_hash,
                support,
                sources_asked,
            } => write!(
                f,
                "peer file_request_sent file_hash={} {} sources_asked={sources_asked}",
                file_hash.to_hex_upper(),
                SupportLine(*support)
            ),
            PeerEvent::PeerReaskContactRevised {
                udp_port,
                udp_version,
            } => write!(
                f,
                "peer reask_contact_revised udp_port={udp_port} udp_version={udp_version}"
            ),
            PeerEvent::FileProbed { file_hash, status } => write!(
                f,
                "peer file_probed file_hash={} status={status:?}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::HashSetReceived {
                file_hash,
                part_hashes,
            } => write!(
                f,
                "peer hash_set_received file_hash={} part_hash_count={}",
                file_hash.to_hex_upper(),
                part_hashes.len()
            ),
            PeerEvent::QueueRanked { file_hash, rank } => write!(
                f,
                "peer queue_ranked file_hash={} rank={rank}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::QueueProgress {
                file_hash,
                previous_rank,
                new_rank,
            } => write!(
                f,
                "peer queue_progress file_hash={} previous_rank={previous_rank} new_rank={new_rank}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::QueueRejected { file_hash } => write!(
                f,
                "peer queue_rejected file_hash={}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::SlotGranted { file_hash } => {
                write!(
                    f,
                    "peer slot_granted file_hash={}",
                    file_hash.to_hex_upper()
                )
            }
            PeerEvent::PartReceived {
                file_hash,
                offset,
                bytes,
            } => write!(
                f,
                "peer part_received file_hash={} offset={offset} data_len={}",
                file_hash.to_hex_upper(),
                bytes.len()
            ),
            PeerEvent::SourcesReceived { file_hash, sources } => write!(
                f,
                "peer sources_received file_hash={} source_count={}",
                file_hash.to_hex_upper(),
                sources.len()
            ),
            PeerEvent::SourceExchangeAnswerSkipped { reason } => {
                write!(f, "peer source_exchange_answer_skipped reason={reason}")
            }
            PeerEvent::AichAnswerReceived {
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
            PeerEvent::AichFileHashReceived { root } => {
                write!(
                    f,
                    "peer aich_file_hash_received root={}",
                    root.to_base32_upper()
                )
            }
            PeerEvent::CompressedPartSkipped {
                file_hash,
                offset,
                reason,
            } => write!(
                f,
                "peer compressed_part_skipped file_hash={} offset={offset} reason={reason}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::CompressedFrameSkipped {
                opcode,
                compressed_len,
                reason,
            } => write!(
                f,
                "peer compressed_frame_skipped opcode=0x{opcode:02X} compressed_len={compressed_len} reason={reason:?}"
            ),
            PeerEvent::SlotReleased { file_hash, reason } => write!(
                f,
                "peer slot_released file_hash={} reason={reason:?}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::CommandRejected { reason } => {
                write!(f, "peer command_rejected reason={reason}")
            }
            PeerEvent::UnknownPeerPacket {
                protocol,
                opcode,
                payload_len,
            } => write!(
                f,
                "peer unknown protocol={} opcode=0x{opcode:02X} payload_len={payload_len}",
                protocol.name()
            ),
            PeerEvent::MultiPacketUnknownSub {
                file_hash,
                opcode,
                remaining,
            } => write!(
                f,
                "peer multipacket_unknown_sub file_hash={} opcode=0x{opcode:02X} remaining={remaining}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::KadFirewallCheckAck => write!(f, "peer kad_fwtcpcheck_ack"),
            PeerEvent::KadUdpFirewallCheckRequested { request } => {
                write!(f, "peer kad_fwcheckudpreq len={}", request.len())
            }
            PeerEvent::PeerIpv6Changed { address } => {
                write!(f, "peer ipv6_changed address={address}")
            }
            PeerEvent::BuddyPingReceived => write!(f, "peer buddy_ping"),
            PeerEvent::BuddyCallbackReceived { callback } => write!(
                f,
                "peer buddy_callback file_hash={} requester={}",
                callback.file_hash.to_hex_upper(),
                callback.requester
            ),
            PeerEvent::BuddyReaskCallbackReceived { relay } => write!(
                f,
                "peer buddy_reask_callback requester={} forwarded={}",
                relay.requester,
                relay.forwarded.len()
            ),
            PeerEvent::HelloRefused { refusal } => match refusal.code {
                crate::HelloRefusalCode::TagCountShort { declared, written } => write!(
                    f,
                    "peer hello_refused code=tag_count_short declared={declared} written={written}"
                ),
            },
            PeerEvent::Disconnected { reason } => {
                write!(f, "peer disconnected reason={}", reason.label())
            }
            PeerEvent::FileRequested { file_hash, status } => write!(
                f,
                "peer file_requested file_hash={} part_status={}B",
                file_hash.to_hex_upper(),
                status.as_bytes().len(),
            ),
            PeerEvent::FileBundleRequested {
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
            PeerEvent::FileIdSet { file_hash } => {
                write!(f, "peer file_id_set file_hash={}", file_hash.to_hex_upper())
            }
            PeerEvent::HashSetRequested { file_hash } => write!(
                f,
                "peer hash_set_requested file_hash={}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::SlotRequested { file_hash } => write!(
                f,
                "peer slot_requested file_hash={}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::PartsRequested { file_hash, ranges } => {
                let (start, end) = ranges.as_array()[0];
                write!(
                    f,
                    "peer parts_requested file_hash={} start={start} end={end}",
                    file_hash.to_hex_upper()
                )
            }
            PeerEvent::ServePartsWithoutSlot { file_hash } => write!(
                f,
                "peer parts_without_slot file_hash={}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::TransferCancelled { file_hash } => write!(
                f,
                "peer transfer_cancelled file_hash={}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::SourcesRequested { file_hash, version } => write!(
                f,
                "peer sources_requested file_hash={} version={version:?}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::AichRequested {
                file_hash, part, ..
            } => write!(
                f,
                "peer aich_requested file_hash={} part={part}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::AichFileHashRequested { file_hash } => write!(
                f,
                "peer aich_file_hash_requested file_hash={}",
                file_hash.to_hex_upper()
            ),
            PeerEvent::PeerIdentityVerified {
                user_hash,
                public_key,
            } => write!(
                f,
                "peer identity_verified user_hash={} public_key_len={}",
                user_hash.to_hex_upper(),
                public_key.len()
            ),
            PeerEvent::PeerSecureIdentFailed { reason } => {
                write!(f, "peer secure_ident_failed reason={reason:?}")
            }
            PeerEvent::BrowseDenied => write!(f, "peer browse_denied"),
            PeerEvent::UnsolicitedBrowseAnswerDropped => {
                write!(f, "peer unsolicited_browse_answer_dropped")
            }
            PeerEvent::PublicIpAnswered => write!(f, "peer publicip_answered"),
            PeerEvent::PublicIpRequestUnanswerable => {
                write!(f, "peer publicip_request_unanswerable")
            }
            PeerEvent::UnsolicitedPublicIpAnswerDropped => {
                write!(f, "peer unsolicited_publicip_answer_dropped")
            }
            PeerEvent::ChatMessageReceived { text } => write!(
                f,
                "peer chat_message_received len={}",
                text.as_bytes().len()
            ),
            PeerEvent::FileCommentReceived { rating, comment } => write!(
                f,
                "peer file_comment_received rating={rating} comment_len={}",
                comment.as_bytes().len()
            ),
            PeerEvent::ClientIdChanged {
                new_id,
                new_server_ip,
            } => write!(
                f,
                "peer client_id_changed new_id={} new_server_ip={new_server_ip}",
                new_id.as_u32()
            ),
            PeerEvent::ChatCaptchaDropped => write!(f, "peer chat_captcha_dropped"),
        }
    }
}

/// A peer's source-exchange facts as `key=value` fields.
struct SupportLine(super::SourceExchangeSupport);

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
