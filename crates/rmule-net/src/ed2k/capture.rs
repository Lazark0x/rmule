//! eD2k capture format: file layout and TOML row encoding only. The
//! writer body — `.partial` staging and rename-on-clean-finalize, the
//! ordered drain-then-finalize shutdown, row collection, and the meta
//! write — is the shared capture engine, [`crate::driver::run_capture`].

use crate::driver::{
    CaptureFormat, FinalizeVerdict, FrameWrite, RowsFile, StreamTap, row_to_toml, toml_basic_string,
};
use rmule_ed2k::Ed2kEvent;

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

/// One event as the TOML table a capture's `events.toml` carries.
pub(crate) fn event_to_toml(event: &Ed2kEvent) -> String {
    row_to_toml(&event.row())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rmule_ed2k::{
        CloseReason, CommandRejectReason, CompressedFrameSkipReason, Ed2kCommandKind,
        ServerAssignedFacts,
    };
    use rmule_primitives::{ClientId, ServerEndpoint};
    use std::net::Ipv4Addr;

    /// One event, two formats from one row: the line tools print and the table
    /// archived captures hold. Where the two words or notations differ, each
    /// keeps its own.
    #[test]
    fn an_event_keeps_the_line_and_the_table_tools_read() {
        let cases = [
            (
                Ed2kEvent::LoginRequested {
                    endpoint: ServerEndpoint::new("server.example", 4661).expect("endpoint"),
                },
                "s2c connection_started server.example:4661",
                "type = \"LoginRequested\"\nendpoint = \"server.example:4661\"\n",
            ),
            (
                Ed2kEvent::LoginAccepted {
                    client_id: ClientId::from_u32(7),
                    tcp_flags: None,
                    facts: ServerAssignedFacts {
                        public_ip: Some(Ipv4Addr::new(1, 2, 3, 4)),
                        standard_tcp_port: Some(4661),
                        obfuscation_tcp_port: None,
                    },
                },
                "s2c login_accepted client_id=7",
                "type = \"LoginAccepted\"\nclient_id = 7\npublic_ip = \"1.2.3.4\"\n\
                 standard_tcp_port = 4661\n",
            ),
            (
                Ed2kEvent::FoundSourcesSkipped {
                    opcode: 0x42,
                    reason: "cut short",
                },
                "s2c found_sources_skipped opcode=0x42 reason=cut short",
                "type = \"FoundSourcesSkipped\"\nopcode = 66\nreason = \"cut short\"\n",
            ),
            (
                Ed2kEvent::UnknownServerPacket {
                    opcode: 0x7A,
                    payload_len: 3,
                },
                "s2c unknown opcode=0x7A payload_len=3",
                "type = \"UnknownServerPacket\"\nopcode = 122\npayload_len = 3\n",
            ),
            (
                Ed2kEvent::CompressedFrameSkipped {
                    opcode: 0x7A,
                    compressed_len: 9,
                    reason: CompressedFrameSkipReason::DecompressedSizeLimitExceeded { limit: 5 },
                },
                "s2c compressed_frame_skipped opcode=0x7A compressed_len=9 \
                 reason=DecompressedSizeLimitExceeded { limit: 5 }",
                "type = \"CompressedFrameSkipped\"\nopcode = 122\ncompressed_len = 9\n\
                 reason = \"DecompressedSizeLimitExceeded\"\nlimit = 5\n",
            ),
            (
                Ed2kEvent::CommandRejected {
                    command: Ed2kCommandKind::Search,
                    reason: CommandRejectReason::NotLoggedIn,
                },
                "command_rejected command=Search reason=NotLoggedIn",
                "type = \"CommandRejected\"\ncommand = \"Search\"\nreason = \"NotLoggedIn\"\n",
            ),
            (
                Ed2kEvent::Disconnected {
                    reason: CloseReason::Local,
                },
                "disconnected reason=Local",
                "type = \"Disconnected\"\nreason = \"Local\"\n",
            ),
        ];
        for (event, line, table) in cases {
            assert_eq!(event.to_string(), line);
            assert_eq!(event_to_toml(&event), table);
        }
    }
}
