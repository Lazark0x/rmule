//! The one reading of a [`PeerEvent`] for tools, as an [`EventRow`]. The
//! `peer …` line `rmule-tools` prints and the row a capture's `events.toml`
//! keeps are both rendered from it.

use std::fmt;

use rmule_primitives::{EventRow, PacketProtocol};

use super::{PeerEvent, SlotReleaseReason};
use crate::{
    ConnectionEvent, FileProbeStatus, HelloRefusalCode, IdentityChange, NoticeEvent,
    RequesterEvent, ServerEvent, SideEvent,
};

impl PeerEvent {
    /// This event as tools read it. Exhaustive by design: a new variant fails
    /// to compile until it says what it reports.
    #[must_use]
    pub fn row(&self) -> EventRow {
        match self {
            Self::Connection(event) => connection_row(event),
            Self::Requester(event) => requester_row(event),
            Self::Server(event) => server_row(event),
            Self::Side(event) => side_row(event),
            Self::Notice(event) => notice_row(event),
        }
        .under("peer")
    }
}

impl fmt::Display for PeerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.row().fmt(f)
    }
}

fn connection_row(event: &ConnectionEvent) -> EventRow {
    match event {
        ConnectionEvent::HelloSent => EventRow::new("hello_sent", "PeerHelloSent"),
        ConnectionEvent::Identified { identity } => EventRow::new("identified", "PeerIdentified")
            .text("user_hash", identity.user_hash().to_hex_upper())
            .plain("client_id", identity.client_id().as_u32())
            .capture_plain("tcp_port", identity.tcp_port())
            .capture_text(
                "nickname",
                identity
                    .nickname()
                    .map(|name| name.to_display_string())
                    .unwrap_or_default(),
            ),
        ConnectionEvent::IdentityRevised { identity, what } => match what {
            IdentityChange::Software => EventRow::new("identity_revised", "PeerSoftwareRevised")
                .text("software", format!("{:?}", identity.software())),
            IdentityChange::ReaskContact => {
                let (udp_port, udp_version) = identity.client_udp_reask().unwrap_or_default();
                EventRow::new("identity_revised", "PeerReaskContactRevised")
                    .plain("udp_port", udp_port)
                    .plain("udp_version", udp_version)
            }
            IdentityChange::SourceExchange => {
                let support = identity.source_exchange();
                EventRow::new("identity_revised", "PeerSourceExchangeRevised")
                    .plain("ext_protocol", support.ext_protocol())
                    .plain("sx1_version", support.sx1_version())
                    .plain("sx2", support.supports_sx2())
            }
            IdentityChange::Ipv6 => {
                let address = identity.peer_ipv6().map(|address| address.to_string());
                EventRow::new("identity_revised", "PeerIpv6Changed")
                    .line_only("ipv6", address.as_deref().unwrap_or("none"))
                    .capture_text("address", address.as_deref().unwrap_or_default())
            }
            IdentityChange::ClientId => EventRow::new("identity_revised", "PeerClientIdChanged")
                .plain("client_id", identity.client_id().as_u32()),
        },
        ConnectionEvent::HelloRefused { refusal } => {
            let HelloRefusalCode::TagCountShort { declared, written } = refusal.code;
            let said = |text: &Option<rmule_primitives::Ed2kText>| {
                text.as_ref()
                    .map(|text| text.to_display_string())
                    .unwrap_or_default()
            };
            EventRow::new("hello_refused", "HelloRefused")
                .text("code", "tag_count_short")
                .plain("declared", declared)
                .plain("written", written)
                .capture_text("name", said(&refusal.name))
                .capture_text("client_mod", said(&refusal.client_mod))
        }
        ConnectionEvent::Disconnected { reason } => {
            EventRow::new("disconnected", "Disconnected").text("reason", reason.label())
        }
        ConnectionEvent::IdentityVerified {
            user_hash,
            public_key,
        } => EventRow::new("identity_verified", "PeerIdentityVerified")
            .text("user_hash", user_hash.to_hex_upper())
            .plain("public_key_len", public_key.len()),
        ConnectionEvent::SecureIdentFailed { reason } => {
            EventRow::new("secure_ident_failed", "PeerSecureIdentFailed")
                .text("reason", format!("{reason:?}"))
        }
        ConnectionEvent::ClientIdOffered { client_id, server } => {
            EventRow::new("client_id_offered", "PeerClientIdOffered")
                .plain("client_id", client_id.as_u32())
                .text("server", server)
        }
    }
}

fn requester_row(event: &RequesterEvent) -> EventRow {
    match event {
        RequesterEvent::FileRequestSent {
            file_hash,
            sources_asked,
        } => EventRow::new("file_request_sent", "FileRequestSent")
            .file(*file_hash)
            .plain("sources_asked", sources_asked),
        RequesterEvent::FileProbed { file_hash, status } => {
            let row = EventRow::new("file_probed", "FileProbed")
                .file(*file_hash)
                .line_only("status", format!("{status:?}"));
            match status {
                FileProbeStatus::Available {
                    file_name, bitmap, ..
                } => row
                    .capture_text("status", "Available")
                    .capture_text("file_name", file_name.to_display_string())
                    .capture_plain("part_count", bitmap.part_count()),
                FileProbeStatus::NotAvailable => row.capture_text("status", "NotAvailable"),
            }
        }
        RequesterEvent::HashSetReceived {
            file_hash,
            part_hashes,
        } => EventRow::new("hash_set_received", "HashSetReceived")
            .file(*file_hash)
            .plain("part_hash_count", part_hashes.len()),
        RequesterEvent::QueueRanked { file_hash, rank } => {
            EventRow::new("queue_ranked", "QueueRanked")
                .file(*file_hash)
                .plain("rank", rank)
        }
        RequesterEvent::QueueProgress {
            file_hash,
            previous_rank,
            new_rank,
        } => EventRow::new("queue_progress", "QueueProgress")
            .file(*file_hash)
            .plain("previous_rank", previous_rank)
            .plain("new_rank", new_rank),
        RequesterEvent::SlotAsked { file_hash } => {
            EventRow::new("slot_asked", "SlotAsked").file(*file_hash)
        }
        RequesterEvent::Requeued { file_hash } => {
            EventRow::new("requeued", "Requeued").file(*file_hash)
        }
        RequesterEvent::SlotOffered => EventRow::new("slot_offered", "SlotOffered"),
        RequesterEvent::SlotGranted { file_hash, .. } => {
            EventRow::new("slot_granted", "SlotGranted").file(*file_hash)
        }
        RequesterEvent::PartReceived {
            file_hash,
            offset,
            bytes,
        } => EventRow::new("part_received", "PartReceived")
            .file(*file_hash)
            .plain("offset", offset)
            .plain("data_len", bytes.len()),
        RequesterEvent::SourcesReceived { file_hash, sources } => {
            EventRow::new("sources_received", "SourcesReceived")
                .file(*file_hash)
                .plain("source_count", sources.len())
        }
        RequesterEvent::SourceExchangeAnswerSkipped { reason } => EventRow::new(
            "source_exchange_answer_skipped",
            "SourceExchangeAnswerSkipped",
        )
        .text("reason", reason),
        RequesterEvent::AichAnswerReceived {
            file_hash,
            part,
            recovery_data,
            ..
        } => EventRow::new("aich_answer_received", "AichAnswerReceived")
            .file(*file_hash)
            .plain("part", part)
            .plain("recovery_len", recovery_data.len()),
        RequesterEvent::AichRefused {
            file_hash: Some(file_hash),
        } => EventRow::new("aich_refused", "AichRefused").file(*file_hash),
        RequesterEvent::AichRefused { file_hash: None } => {
            EventRow::new("aich_refused", "AichRefused")
        }
        RequesterEvent::AichFileHashReceived { file_hash, root } => {
            EventRow::new("aich_file_hash_received", "AichFileHashReceived")
                .file(*file_hash)
                .text("root", root.to_base32_upper())
        }
        RequesterEvent::CompressedPartSkipped {
            file_hash,
            offset,
            reason,
        } => EventRow::new("compressed_part_skipped", "CompressedPartSkipped")
            .file(*file_hash)
            .plain("offset", offset)
            .text("reason", reason),
        RequesterEvent::SlotReleased { file_hash, reason } => {
            EventRow::new("slot_released", "SlotReleased")
                .file(*file_hash)
                .text("reason", slot_release_label(*reason))
        }
        RequesterEvent::FileCommentReceived { rating, comment } => {
            EventRow::new("file_comment_received", "FileCommentReceived")
                .plain("rating", rating)
                .line_only("comment_len", comment.as_bytes().len())
                .capture_text("comment", comment.to_display_string())
        }
    }
}

fn server_row(event: &ServerEvent) -> EventRow {
    match event {
        ServerEvent::FileRequested { file_hash, status } => {
            let status_bytes = status.as_bytes().len();
            EventRow::new("file_requested", "FileRequested")
                .file(*file_hash)
                .line_only("part_status", format!("{status_bytes}B"))
                .capture_plain("status_bytes", status_bytes)
        }
        ServerEvent::FileBundleRequested {
            file_hash,
            file_size,
            asks,
            cut,
        } => {
            let row =
                EventRow::new("file_bundle_requested", "FileBundleRequested").file(*file_hash);
            match file_size {
                Some(size) => row.plain("file_size", size),
                None => row.line_only("file_size", "none"),
            }
            .plain("asks", asks.len())
            .plain("cut", cut.is_some())
        }
        ServerEvent::FileIdSet { file_hash } => {
            EventRow::new("file_id_set", "FileIdSet").file(*file_hash)
        }
        ServerEvent::HashSetRequested { file_hash } => {
            EventRow::new("hash_set_requested", "HashSetRequested").file(*file_hash)
        }
        ServerEvent::MalformedSlotAsk => EventRow::new("malformed_slot_ask", "MalformedSlotAsk"),
        ServerEvent::SlotRequested { file_hash } => {
            EventRow::new("slot_requested", "SlotRequested").file(*file_hash)
        }
        ServerEvent::PartsRequested { file_hash, ranges } => {
            let (start, end) = ranges.as_array()[0];
            EventRow::new("parts_requested", "PartsRequested")
                .file(*file_hash)
                .plain("start", start)
                .plain("end", end)
        }
        ServerEvent::PartsWithoutSlot { file_hash } => {
            EventRow::new("parts_without_slot", "ServePartsWithoutSlot").file(*file_hash)
        }
        ServerEvent::TransferCancelled { file_hash } => {
            EventRow::new("transfer_cancelled", "TransferCancelled").file(*file_hash)
        }
        ServerEvent::SourcesRequested { file_hash, .. } => {
            EventRow::new("sources_requested", "SourcesRequested").file(*file_hash)
        }
        ServerEvent::SourcesAnswered { file_hash, count } => {
            EventRow::new("sources_answered", "SourcesAnswered")
                .file(*file_hash)
                .plain("count", count)
        }
        ServerEvent::BlockLeft {
            file_hash,
            start,
            end,
        } => EventRow::new("block_left", "BlockLeft")
            .file(*file_hash)
            .plain("start", start)
            .plain("end", end),
        ServerEvent::AichRequested {
            file_hash, part, ..
        } => EventRow::new("aich_requested", "AichRequested")
            .file(*file_hash)
            .plain("part", part),
        ServerEvent::AichFileHashRequested { file_hash } => {
            EventRow::new("aich_file_hash_requested", "AichFileHashRequested").file(*file_hash)
        }
    }
}

fn side_row(event: &SideEvent) -> EventRow {
    match event {
        SideEvent::KadFirewallCheckAck => {
            EventRow::new("kad_fwtcpcheck_ack", "KadFirewallCheckAck")
        }
        SideEvent::KadUdpFirewallCheckRequested { request } => {
            EventRow::new("kad_fwcheckudpreq", "KadUdpFirewallCheckRequested")
                .line_only("len", request.len())
                .capture_plain("request_len", request.len())
        }
        SideEvent::BuddyPingReceived => EventRow::new("buddy_ping", "BuddyPingReceived"),
        SideEvent::BuddyCallbackReceived { callback } => {
            EventRow::new("buddy_callback", "BuddyCallbackReceived")
                .file(callback.file_hash)
                .text("requester", callback.requester)
        }
        SideEvent::BuddyReaskCallbackReceived { relay } => {
            EventRow::new("buddy_reask_callback", "BuddyReaskCallbackReceived")
                .text("requester", relay.requester)
                .line_only("forwarded", relay.forwarded.len())
                .capture_plain("forwarded_len", relay.forwarded.len())
        }
        SideEvent::PublicIpAnswered => EventRow::new("publicip_answered", "PublicIpAnswered"),
        SideEvent::PublicIpRequestUnanswerable => EventRow::new(
            "publicip_request_unanswerable",
            "PublicIpRequestUnanswerable",
        ),
    }
}

fn notice_row(event: &NoticeEvent) -> EventRow {
    match event {
        NoticeEvent::UnknownPacket {
            protocol,
            opcode,
            payload_len,
        } => EventRow::new("unknown", "UnknownPeerPacket")
            .line_only("protocol", protocol.name())
            .capture_text("protocol", protocol_label(*protocol))
            .opcode("opcode", *opcode)
            .plain("payload_len", payload_len),
        NoticeEvent::MultiPacketUnknownSub {
            file_hash,
            opcode,
            remaining,
        } => EventRow::new("multipacket_unknown_sub", "MultiPacketUnknownSub")
            .file(*file_hash)
            .opcode("opcode", *opcode)
            .plain("remaining", remaining),
        NoticeEvent::CompressedFrameSkipped {
            opcode,
            compressed_len,
            reason,
        } => EventRow::new("compressed_frame_skipped", "CompressedFrameSkipped")
            .opcode("opcode", *opcode)
            .plain("compressed_len", compressed_len)
            .text("reason", format!("{reason:?}")),
        NoticeEvent::CommandRejected { reason } => {
            EventRow::new("command_rejected", "CommandRejected").text("reason", reason)
        }
        NoticeEvent::BrowseDenied => EventRow::new("browse_denied", "BrowseDenied"),
        NoticeEvent::UnsolicitedBrowseAnswerDropped => EventRow::new(
            "unsolicited_browse_answer_dropped",
            "UnsolicitedBrowseAnswerDropped",
        ),
        NoticeEvent::UnsolicitedPublicIpAnswerDropped => EventRow::new(
            "unsolicited_publicip_answer_dropped",
            "UnsolicitedPublicIpAnswerDropped",
        ),
        NoticeEvent::ChatMessageReceived { text } => {
            EventRow::new("chat_message_received", "ChatMessageReceived")
                .line_only("len", text.as_bytes().len())
                .capture_text("text", text.to_display_string())
        }
        NoticeEvent::ChatCaptchaDropped => {
            EventRow::new("chat_captcha_dropped", "ChatCaptchaDropped")
        }
    }
}

const fn slot_release_label(reason: SlotReleaseReason) -> &'static str {
    match reason {
        SlotReleaseReason::DownloadComplete => "DownloadComplete",
        SlotReleaseReason::PeerClosed => "PeerClosed",
        SlotReleaseReason::ProtocolViolation => "ProtocolViolation",
        SlotReleaseReason::FileNotFound => "FileNotFound",
        SlotReleaseReason::Cancelled => "Cancelled",
    }
}

const fn protocol_label(protocol: PacketProtocol) -> &'static str {
    match protocol {
        PacketProtocol::Edonkey => "Edonkey",
        PacketProtocol::Emule => "Emule",
        PacketProtocol::PackedEd2k => "PackedEd2k",
    }
}
