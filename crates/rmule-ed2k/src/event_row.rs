//! The one reading of an [`Ed2kEvent`] for tools, as an [`EventRow`]: the
//! compact line `rmule-tools` prints and the row a capture's `events.toml`
//! keeps are both rendered from it, so a new event states its facts once. The
//! `s2c` prefix marks a server-to-client fact; `CommandRejected` is local and
//! `Disconnected` terminal, so they carry no direction.

use std::fmt;

use rmule_primitives::EventRow;

use crate::{
    CommandRejectReason, CompressedFrameSkipReason, Ed2kCommandKind, Ed2kEvent, ServerCapability,
};

impl Ed2kEvent {
    /// This event as tools read it. Exhaustive by design: a new variant fails
    /// to compile until it says what it reports.
    #[must_use]
    pub fn row(&self) -> EventRow {
        let row = event_row(self);
        match self {
            Self::CommandRejected { .. } | Self::Disconnected { .. } => row,
            _ => row.under("s2c"),
        }
    }
}

fn event_row(event: &Ed2kEvent) -> EventRow {
    match event {
        Ed2kEvent::CommandRejected { command, reason } => {
            EventRow::new("command_rejected", "CommandRejected")
                .line_only("command", format_args!("{command:?}"))
                .capture_text("command", command_kind_label(command))
                .line_only("reason", format_args!("{reason:?}"))
                .capture_text("reason", command_reject_reason_label(reason))
        }
        Ed2kEvent::Disconnected { reason } => {
            EventRow::new("disconnected", "Disconnected").text("reason", reason.label())
        }
        Ed2kEvent::LoginRequested { endpoint } => {
            let address = format!("{}:{}", endpoint.host(), endpoint.port());
            EventRow::new("connection_started", "LoginRequested")
                .line_word(&address)
                .capture_text("endpoint", address)
        }
        Ed2kEvent::LoginAccepted {
            client_id,
            tcp_flags,
            facts,
        } => {
            let mut row = EventRow::new("login_accepted", "LoginAccepted")
                .plain("client_id", client_id.as_u32());
            if let Some(flags) = tcp_flags {
                row = row.capture_plain("tcp_flags", flags.bits());
            }
            // The IDCHANGE-extension facts (ADR-0047): live captures pin the
            // extended payload's projection when a server sends one.
            if let Some(ip) = facts.public_ip {
                row = row.capture_text("public_ip", ip);
            }
            if let Some(port) = facts.standard_tcp_port {
                row = row.capture_plain("standard_tcp_port", port);
            }
            if let Some(port) = facts.obfuscation_tcp_port {
                row = row.capture_plain("obfuscation_tcp_port", port);
            }
            row
        }
        Ed2kEvent::LoginRejected => EventRow::new("login_rejected", "LoginRejected"),
        Ed2kEvent::ServerRejectedCommand => {
            EventRow::new("server_rejected_command", "ServerRejectedCommand")
        }
        Ed2kEvent::FoundSourcesSkipped { opcode, reason } => {
            EventRow::new("found_sources_skipped", "FoundSourcesSkipped")
                .line_only("opcode", format_args!("{opcode:#04x}"))
                .capture_plain("opcode", opcode)
                .text("reason", reason)
        }
        Ed2kEvent::ServerMessageReceived { text } => {
            EventRow::new("server_message", "ServerMessageReceived")
                .plain("text_len", text.as_bytes().len())
        }
        Ed2kEvent::ServerStatusReceived { status } => {
            EventRow::new("server_status", "ServerStatusReceived")
                .line_only("user", status.user_count)
                .capture_plain("user_count", status.user_count)
                .line_only("file", status.file_count)
                .capture_plain("file_count", status.file_count)
        }
        Ed2kEvent::ServerIdentified { .. } => EventRow::new("server_ident", "ServerIdentified"),
        Ed2kEvent::ServerListReceived {
            servers,
            ipv6_servers,
        } => EventRow::new("server_list", "ServerListReceived")
            .line_only("count", servers.len())
            .capture_plain("server_count", servers.len())
            .line_only("ipv6_count", ipv6_servers.len())
            .capture_plain("ipv6_server_count", ipv6_servers.len()),
        Ed2kEvent::SourcesFound {
            file_hash,
            sources,
            tail,
        } => EventRow::new("sources_found", "SourcesFound")
            .file(*file_hash)
            .line_only("count", sources.len())
            .capture_plain("source_count", sources.len())
            .plain("malformed_tail", tail.is_malformed()),
        Ed2kEvent::SearchResultsFound {
            results,
            skipped,
            more_available,
        } => EventRow::new("search_results", "SearchResultsFound")
            .line_only("count", results.len())
            .capture_plain("result_count", results.len())
            .line_only("skipped", skipped.len())
            .line_only("more", more_available),
        Ed2kEvent::SearchResultSkipped { reason } => {
            EventRow::new("search_result_skipped", "SearchResultSkipped")
                .line_only("reason", format_args!("{reason:?}"))
                .capture_text("reason", reason.as_static_str())
        }
        Ed2kEvent::PeerCallbackRequested { peer, crypt } => {
            let mut row = EventRow::new("peer_callback_requested", "PeerCallbackRequested")
                .line_only("peer", peer)
                .capture_text("peer_ip", peer.ip())
                .capture_plain("peer_port", peer.port())
                .plain("crypt", crypt.is_some());
            // The 0x35 crypt extension (ADR-0061) pinned in the capture: the
            // requester's crypt-stance byte + user hash, the dial provenance.
            if let Some(crypt) = crypt {
                row = row
                    .capture_plain("crypt_options", crypt.connect_options.as_byte())
                    .capture_text("crypt_user_hash", crypt.user_hash.to_hex_upper());
            }
            row
        }
        Ed2kEvent::UnknownServerPacket {
            opcode,
            payload_len,
        } => EventRow::new("unknown", "UnknownServerPacket")
            .opcode("opcode", *opcode)
            .plain("payload_len", payload_len),
        Ed2kEvent::CompressedFrameSkipped {
            opcode,
            compressed_len,
            reason,
        } => {
            let row = EventRow::new("compressed_frame_skipped", "CompressedFrameSkipped")
                .opcode("opcode", *opcode)
                .plain("compressed_len", compressed_len)
                .line_only("reason", format_args!("{reason:?}"))
                .capture_text("reason", compressed_frame_skip_reason_label(reason));
            match reason {
                CompressedFrameSkipReason::DecompressedSizeLimitExceeded { limit } => {
                    row.capture_plain("limit", limit)
                }
                _ => row,
            }
        }
        Ed2kEvent::CallbackFailed => EventRow::new("callback_failed", "CallbackFailed"),
        Ed2kEvent::HolepunchIntroduced { info } => {
            EventRow::new("holepunch_info", "HolepunchIntroduced")
                .text("peer_udp", info.peer_udp)
                .capture_plain("peer_tcp_port", info.peer_tcp_port)
                .text("role", format_args!("{:?}", info.role))
        }
        Ed2kEvent::HolepunchRefused { fail } => EventRow::new("holepunch_fail", "HolepunchRefused")
            .plain("target", fail.target.as_u32())
            .text("reason", format_args!("{:?}", fail.reason)),
    }
}

impl fmt::Display for Ed2kEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.row().fmt(f)
    }
}

/// Discriminant label for a [`CompressedFrameSkipReason`]. Stable across
/// compression-backend swaps because it's a rmule-owned tag, not a
/// reflected zlib error.
fn compressed_frame_skip_reason_label(reason: &CompressedFrameSkipReason) -> &'static str {
    match reason {
        CompressedFrameSkipReason::InflateFailed => "InflateFailed",
        CompressedFrameSkipReason::DecompressedSizeLimitExceeded { .. } => {
            "DecompressedSizeLimitExceeded"
        }
        // `CompressedFrameSkipReason` is `#[non_exhaustive]`; new
        // variants land as `"Other"` until this match learns about them.
        _ => "Other",
    }
}

fn command_kind_label(kind: &Ed2kCommandKind) -> &'static str {
    match kind {
        Ed2kCommandKind::RequestServerList => "RequestServerList",
        Ed2kCommandKind::Search => "Search",
        Ed2kCommandKind::QueryMoreResults => "QueryMoreResults",
        Ed2kCommandKind::RequestSources { .. } => "RequestSources",
        Ed2kCommandKind::RequestCallback => "RequestCallback",
        Ed2kCommandKind::RequestHolepunch => "RequestHolepunch",
        Ed2kCommandKind::UpdateIpv6 => "UpdateIpv6",
        Ed2kCommandKind::OfferFiles => "OfferFiles",
    }
}

fn command_reject_reason_label(reason: &CommandRejectReason) -> &'static str {
    match reason {
        CommandRejectReason::NotLoggedIn => "NotLoggedIn",
        CommandRejectReason::UnsupportedServerCapability {
            capability: ServerCapability::LargeFiles,
        } => "UnsupportedServerCapability:LargeFiles",
        CommandRejectReason::UnsupportedServerCapability {
            capability: ServerCapability::RelatedSearch,
        } => "UnsupportedServerCapability:RelatedSearch",
        CommandRejectReason::UnsupportedServerCapability {
            capability: ServerCapability::LowIdHolepunch,
        } => "UnsupportedServerCapability:LowIdHolepunch",
        CommandRejectReason::UnsupportedServerCapability {
            capability: ServerCapability::Ipv6Update,
        } => "UnsupportedServerCapability:Ipv6Update",
    }
}
