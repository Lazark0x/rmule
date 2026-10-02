//! eD2k capture format: file layout and TOML row encoding only. The
//! writer body — `.partial` staging and rename-on-clean-finalize, the
//! ordered drain-then-finalize shutdown, row collection, and the meta
//! write — is the shared capture engine, [`crate::driver::run_capture`].

use crate::driver::{
    CaptureFormat, FinalizeVerdict, FrameWrite, RowsFile, StreamTap, toml_basic_string,
};
use rmule_ed2k::{
    CommandRejectReason, CompressedFrameSkipReason, Ed2kCommandKind, Ed2kEvent, ServerCapability,
};

/// The eD2k session capture layout: raw stream bytes split by direction
/// into `s2c.bin` / `c2s.bin`, the decoded event sequence as `events.toml`
/// rows, and session facts in `meta.toml`. Byte-identical to the layout
/// the promoted Compatibility Fixtures and the `rmule-tools` slicing
/// command were built against.
///
/// Holds the session context the sans-I/O session can't observe (endpoint,
/// identity summary) so the engine's finalize needs only the harness's
/// [`FinalizeVerdict`] to complete `meta.toml`.
pub(crate) struct Ed2kCaptureFormat {
    pub endpoint: String,
    pub identity_summary: String,
}

impl CaptureFormat for Ed2kCaptureFormat {
    type Frame = StreamTap;
    type Meta = FinalizeVerdict;

    fn files(&self) -> &'static [&'static str] {
        &["s2c.bin", "c2s.bin"]
    }

    fn encode_frame(&mut self, tap: StreamTap) -> FrameWrite {
        // Reads (server→client) are `s2c.bin` (index 0); writes
        // (client→server) are `c2s.bin` (index 1).
        FrameWrite {
            file_index: usize::from(tap.outbound),
            bytes: tap.bytes,
            row: None,
        }
    }

    fn rows_file(&self) -> Option<RowsFile> {
        Some(RowsFile {
            file: "events.toml",
            header: "# Decoded event sequence for one captured eD2k welcome burst.\n\
                     # Source of truth: s2c.bin (server-to-client wire bytes).\n\n",
            table: "event",
        })
    }

    fn meta_toml(&self, verdict: FinalizeVerdict) -> String {
        format!(
            "# Session-level metadata for the capture in this directory.\n\n\
             endpoint = {endpoint}\n\
             started_unix_secs = {started}\n\
             duration_ms = {duration}\n\
             identity_summary = {identity}\n\
             close_reason = {reason}\n",
            endpoint = toml_basic_string(&self.endpoint),
            started = verdict.started_unix_secs,
            duration = verdict.duration_ms,
            identity = toml_basic_string(&self.identity_summary),
            reason = toml_basic_string(verdict.close_label),
        )
    }
}

pub(crate) fn event_to_toml(event: &Ed2kEvent) -> String {
    match event {
        Ed2kEvent::LoginRequested { endpoint } => format!(
            "type = \"LoginRequested\"\nendpoint = {}\n",
            toml_basic_string(&format!("{}:{}", endpoint.host(), endpoint.port()))
        ),
        Ed2kEvent::LoginAccepted {
            client_id,
            tcp_flags,
            facts,
        } => {
            let mut s = format!(
                "type = \"LoginAccepted\"\nclient_id = {}\n",
                client_id.as_u32()
            );
            if let Some(flags) = tcp_flags {
                s.push_str(&format!("tcp_flags = {}\n", flags.bits()));
            }
            // The IDCHANGE-extension facts (ADR-0047): live captures pin the
            // extended payload's projection when a server sends one.
            if let Some(ip) = facts.public_ip {
                s.push_str(&format!("public_ip = \"{ip}\"\n"));
            }
            if let Some(port) = facts.standard_tcp_port {
                s.push_str(&format!("standard_tcp_port = {port}\n"));
            }
            if let Some(port) = facts.obfuscation_tcp_port {
                s.push_str(&format!("obfuscation_tcp_port = {port}\n"));
            }
            s
        }
        Ed2kEvent::LoginRejected => "type = \"LoginRejected\"\n".to_owned(),
        Ed2kEvent::ServerMessageReceived { text } => format!(
            "type = \"ServerMessageReceived\"\ntext_len = {}\n",
            text.as_bytes().len()
        ),
        Ed2kEvent::ServerStatusReceived { status } => format!(
            "type = \"ServerStatusReceived\"\nuser_count = {}\nfile_count = {}\n",
            status.user_count, status.file_count
        ),
        Ed2kEvent::ServerIdentified { .. } => "type = \"ServerIdentified\"\n".to_owned(),
        Ed2kEvent::ServerListReceived {
            servers,
            ipv6_servers,
        } => format!(
            "type = \"ServerListReceived\"\nserver_count = {}\nipv6_server_count = {}\n",
            servers.len(),
            ipv6_servers.len()
        ),
        Ed2kEvent::SourcesFound {
            file_hash,
            sources,
            tail,
        } => format!(
            "type = \"SourcesFound\"\nfile_hash = \"{}\"\nsource_count = {}\nmalformed_tail = {}\n",
            file_hash.to_hex_upper(),
            sources.len(),
            tail.is_malformed()
        ),
        Ed2kEvent::SearchResultsFound { results, .. } => format!(
            "type = \"SearchResultsFound\"\nresult_count = {}\n",
            results.len()
        ),
        Ed2kEvent::SearchResultSkipped { reason } => format!(
            "type = \"SearchResultSkipped\"\nreason = \"{}\"\n",
            reason.as_static_str()
        ),
        Ed2kEvent::PeerCallbackRequested { peer, crypt } => {
            let mut out = format!(
                "type = \"PeerCallbackRequested\"\npeer_ip = \"{}\"\npeer_port = {}\ncrypt = {}\n",
                peer.ip(),
                peer.port(),
                crypt.is_some()
            );
            // The 0x35 crypt extension (ADR-0061) pinned in the capture:
            // the requester's crypt-stance byte + user hash, the dial provenance.
            if let Some(crypt) = crypt {
                out.push_str(&format!(
                    "crypt_options = {}\ncrypt_user_hash = \"{}\"\n",
                    crypt.connect_options.as_byte(),
                    crypt.user_hash.to_hex_upper()
                ));
            }
            out
        }
        Ed2kEvent::CommandRejected { command, reason } => format!(
            "type = \"CommandRejected\"\ncommand = \"{}\"\nreason = \"{}\"\n",
            command_kind_label(command),
            command_reject_reason_label(reason),
        ),
        Ed2kEvent::UnknownServerPacket {
            opcode,
            payload_len,
        } => format!(
            "type = \"UnknownServerPacket\"\nopcode = {opcode}\npayload_len = {payload_len}\n"
        ),
        Ed2kEvent::CompressedFrameSkipped {
            opcode,
            compressed_len,
            reason,
        } => {
            let mut s = format!(
                "type = \"CompressedFrameSkipped\"\nopcode = {opcode}\ncompressed_len = {compressed_len}\nreason = \"{}\"\n",
                compressed_frame_skip_reason_label(reason),
            );
            if let CompressedFrameSkipReason::DecompressedSizeLimitExceeded { limit } = reason {
                s.push_str(&format!("limit = {limit}\n"));
            }
            s
        }
        Ed2kEvent::CallbackFailed => "type = \"CallbackFailed\"\n".to_string(),
        Ed2kEvent::HolepunchIntroduced { info } => format!(
            "type = \"HolepunchIntroduced\"\npeer_udp = \"{}\"\npeer_tcp_port = {}\nrole = \"{:?}\"\n",
            info.peer_udp, info.peer_tcp_port, info.role
        ),
        Ed2kEvent::HolepunchRefused { fail } => format!(
            "type = \"HolepunchRefused\"\ntarget = {}\nreason = \"{:?}\"\n",
            fail.target.as_u32(),
            fail.reason
        ),
        Ed2kEvent::Disconnected { reason } => {
            format!("type = \"Disconnected\"\nreason = \"{}\"\n", reason.label())
        }
    }
}

/// Discriminant label for a [`CompressedFrameSkipReason`]. Stable across
/// compression-backend swaps because it's a rmule-owned tag, not a
/// reflected zlib error.
pub(crate) fn compressed_frame_skip_reason_label(
    reason: &CompressedFrameSkipReason,
) -> &'static str {
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

pub(crate) fn command_kind_label(kind: &Ed2kCommandKind) -> &'static str {
    match kind {
        Ed2kCommandKind::RequestServerList => "RequestServerList",
        Ed2kCommandKind::Search => "Search",
        Ed2kCommandKind::QueryMoreResults => "QueryMoreResults",
        Ed2kCommandKind::RequestSources => "RequestSources",
        Ed2kCommandKind::RequestCallback => "RequestCallback",
        Ed2kCommandKind::RequestHolepunch => "RequestHolepunch",
        Ed2kCommandKind::OfferFiles => "OfferFiles",
    }
}

pub(crate) fn command_reject_reason_label(reason: &CommandRejectReason) -> &'static str {
    match reason {
        CommandRejectReason::NotLoggedIn => "NotLoggedIn",
        CommandRejectReason::UnsupportedServerCapability {
            capability: ServerCapability::LargeFiles,
        } => "UnsupportedServerCapability:LargeFiles",
        CommandRejectReason::UnsupportedServerCapability {
            capability: ServerCapability::RelatedSearch,
        } => "UnsupportedServerCapability:RelatedSearch",
    }
}
