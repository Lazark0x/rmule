//! The peer session's capture layout: raw stream bytes split by direction, the
//! decoded event rows, and the session facts written beside them. The part-data
//! elision of ADR-0024 lives here because it needs the whole buffered stream in
//! hand before a frame's payload can be replaced with the marker.

use std::sync::Arc;

use crate::driver::{
    CaptureFormat, FinalizeVerdict, FrameWrite, RowsFile, StreamTap, toml_basic_string,
};
use rmule_peer::{
    ConnectionEvent, FileProbeStatus, IdentityChange, NoticeEvent, PeerEvent, RequesterEvent,
    ServerEvent, SideEvent, SlotReleaseReason,
};
use rmule_primitives::PacketProtocol;

use crate::peer::options::CaptureMode;

/// Fixed byte pattern that replaces the data portion of an elided
/// `OP_SENDINGPART` / `OP_SENDINGPART_I64` frame under `ProtocolOnly`.
/// Replay tooling identifies elided payloads by looking for this
/// marker at the start of the elided region. Exported at the crate root
/// so capture-mode tests and replay tooling share one definition.
pub const ELISION_MARKER: &[u8] = b"RMULE-ELIDED-PART-PAYLOAD";

const ED2K_PROTOCOL_BYTE: u8 = 0xE3;
const EMULE_PROTOCOL_BYTE: u8 = 0xC5;
const OP_SENDINGPART: u8 = 0x46;
const OP_SENDINGPART_I64: u8 = 0xA2;
const FILE_HASH_LEN: usize = 16;

/// The peer session capture layout: raw stream bytes split by direction
/// into `inbound.bin` / `outbound.bin`, the decoded event sequence as
/// `events.toml` rows, and session facts in `meta.toml`.
///
/// The `OP_SENDINGPART` elision (ADR-0024) needs the whole stream in hand,
/// so `encode_frame` *buffers* both directions and
/// [`finish`](CaptureFormat::finish) emits the elided result into the
/// engine's `.partial` files. The context the peer session can't observe
/// (peer label, capture mode) lives here, so the engine's finalize needs
/// only the harness's [`FinalizeVerdict`] to complete `meta.toml`.
pub(crate) struct PeerCaptureFormat {
    peer_label: String,
    capture_mode: CaptureMode,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
    bytes_elided_inbound: u64,
    bytes_elided_outbound: u64,
}

impl PeerCaptureFormat {
    pub(crate) fn new(peer_label: String, capture_mode: CaptureMode) -> Self {
        Self {
            peer_label,
            capture_mode,
            inbound: Vec::new(),
            outbound: Vec::new(),
            bytes_elided_inbound: 0,
            bytes_elided_outbound: 0,
        }
    }
}

impl CaptureFormat for PeerCaptureFormat {
    type Frame = StreamTap;
    type Meta = FinalizeVerdict;

    fn files(&self) -> &'static [&'static str] {
        &["inbound.bin", "outbound.bin"]
    }

    fn encode_frame(&mut self, tap: StreamTap) -> FrameWrite {
        // Buffer the whole stream — the elision scan runs at `finish`, which
        // emits the finished bytes. The stream write here is empty.
        if tap.outbound {
            self.outbound.extend_from_slice(&tap.bytes);
        } else {
            self.inbound.extend_from_slice(&tap.bytes);
        }
        FrameWrite {
            file_index: usize::from(tap.outbound),
            bytes: Arc::from(&b""[..]),
            row: None,
        }
    }

    fn finish(&mut self) -> Vec<FrameWrite> {
        // Elide `OP_SENDINGPART` payloads across the buffered streams (or
        // leave them literal under `Full`), recording the counts for
        // `meta.toml`, then hand both finished buffers to the engine.
        (self.bytes_elided_inbound, self.bytes_elided_outbound) = match self.capture_mode {
            CaptureMode::Full => (0, 0),
            CaptureMode::ProtocolOnly => (
                elide_sending_part_payloads(&mut self.inbound),
                elide_sending_part_payloads(&mut self.outbound),
            ),
        };
        vec![
            FrameWrite {
                file_index: 0,
                bytes: Arc::from(std::mem::take(&mut self.inbound)),
                row: None,
            },
            FrameWrite {
                file_index: 1,
                bytes: Arc::from(std::mem::take(&mut self.outbound)),
                row: None,
            },
        ]
    }

    fn rows_file(&self) -> Option<RowsFile> {
        Some(RowsFile {
            file: "events.toml",
            header: "",
            table: "event",
        })
    }

    fn meta_toml(&self, verdict: FinalizeVerdict) -> String {
        format!(
            "peer = {}\nstarted_unix_secs = {}\nduration_ms = {}\nclose_reason = {}\ncapture_mode = \"{}\"\nbytes_elided_inbound = {}\nbytes_elided_outbound = {}\n",
            toml_basic_string(&self.peer_label),
            verdict.started_unix_secs,
            verdict.duration_ms,
            toml_basic_string(verdict.close_label),
            capture_mode_label(self.capture_mode),
            self.bytes_elided_inbound,
            self.bytes_elided_outbound,
        )
    }
}

pub(crate) const fn capture_mode_label(mode: CaptureMode) -> &'static str {
    match mode {
        CaptureMode::ProtocolOnly => "protocol_only",
        CaptureMode::Full => "full",
    }
}

/// Replace data bytes of every `OP_SENDINGPART` / `OP_SENDINGPART_I64`
/// frame in `buf` with the `ELISION_MARKER` followed by nul padding.
/// Frame header, opcode, file_hash and the start/end offsets are kept
/// verbatim so byte-offset bookkeeping for the captured stream stays
/// exact per ADR-0024. Returns the number of data bytes elided.
fn elide_sending_part_payloads(buf: &mut [u8]) -> u64 {
    let mut total = 0u64;
    let mut pos = 0usize;
    while pos + 6 <= buf.len() {
        let protocol = buf[pos];
        let length =
            u32::from_le_bytes([buf[pos + 1], buf[pos + 2], buf[pos + 3], buf[pos + 4]]) as usize;
        if length == 0 {
            break;
        }
        let frame_end = pos.saturating_add(5).saturating_add(length);
        if frame_end > buf.len() {
            break;
        }
        let opcode = buf[pos + 5];
        let offset_size = match (protocol, opcode) {
            (ED2K_PROTOCOL_BYTE, OP_SENDINGPART) => Some(4usize),
            (EMULE_PROTOCOL_BYTE, OP_SENDINGPART_I64) => Some(8usize),
            _ => None,
        };
        if let Some(offset_size) = offset_size {
            let payload_header_len = FILE_HASH_LEN + 2 * offset_size;
            let data_start = pos + 6 + payload_header_len;
            if data_start <= frame_end {
                let data_len = frame_end - data_start;
                if data_len > 0 {
                    let marker_len = ELISION_MARKER.len().min(data_len);
                    buf[data_start..data_start + marker_len]
                        .copy_from_slice(&ELISION_MARKER[..marker_len]);
                    for b in &mut buf[data_start + marker_len..frame_end] {
                        *b = 0;
                    }
                    total = total.saturating_add(data_len as u64);
                }
            }
        }
        pos = frame_end;
    }
    total
}

/// A peer's source-exchange facts as TOML lines.
fn support_toml(support: rmule_peer::SourceExchangeSupport) -> String {
    format!(
        "ext_protocol = {}\nsx1_version = {}\nsx2 = {}\n",
        support.ext_protocol(),
        support.sx1_version(),
        support.supports_sx2()
    )
}

/// One event as the TOML table a capture's `events.toml` carries. Each group
/// renders on its own; the `type` labels are the capture format's and stay put
/// when a variant is renamed.
pub(crate) fn event_to_toml(event: &PeerEvent) -> String {
    match event {
        PeerEvent::Connection(event) => connection_toml(event),
        PeerEvent::Requester(event) => requester_toml(event),
        PeerEvent::Server(event) => server_toml(event),
        PeerEvent::Side(event) => side_toml(event),
        PeerEvent::Notice(event) => notice_toml(event),
    }
}

fn connection_toml(event: &ConnectionEvent) -> String {
    match event {
        ConnectionEvent::HelloSent => "type = \"PeerHelloSent\"\n".to_owned(),
        ConnectionEvent::Identified { identity } => {
            format!(
                "type = \"PeerIdentified\"\nuser_hash = \"{}\"\nclient_id = {}\ntcp_port = {}\nnickname = {}\n",
                identity.user_hash().to_hex_upper(),
                identity.client_id().as_u32(),
                identity.tcp_port(),
                toml_basic_string(
                    &identity
                        .nickname()
                        .map(|n| n.to_display_string())
                        .unwrap_or_default()
                )
            )
        }
        // One label per change, the capture format's from before the
        // revisions were one event, each with the facts that change moved.
        ConnectionEvent::IdentityRevised { identity, what } => match what {
            IdentityChange::ReaskContact => {
                let (udp_port, udp_version) = identity.client_udp_reask().unwrap_or_default();
                format!(
                    "type = \"PeerReaskContactRevised\"\nudp_port = {udp_port}\nudp_version = {udp_version}\n"
                )
            }
            IdentityChange::SourceExchange => format!(
                "type = \"PeerSourceExchangeRevised\"\n{}",
                support_toml(identity.source_exchange())
            ),
            IdentityChange::Software => format!(
                "type = \"PeerSoftwareRevised\"\nsoftware = {}\n",
                toml_basic_string(&format!("{:?}", identity.software()))
            ),
            IdentityChange::Ipv6 => format!(
                "type = \"PeerIpv6Changed\"\naddress = \"{}\"\n",
                identity
                    .peer_ipv6()
                    .map(|address| address.to_string())
                    .unwrap_or_default()
            ),
            IdentityChange::ClientId => format!(
                "type = \"PeerClientIdChanged\"\nclient_id = {}\n",
                identity.client_id().as_u32()
            ),
        },
        ConnectionEvent::HelloRefused { refusal } => {
            let rmule_peer::HelloRefusalCode::TagCountShort { declared, written } = refusal.code;
            format!(
                "type = \"HelloRefused\"\ncode = \"tag_count_short\"\ndeclared = {declared}\nwritten = {written}\nname = {}\nclient_mod = {}\n",
                toml_basic_string(
                    &refusal
                        .name
                        .as_ref()
                        .map(|n| n.to_display_string())
                        .unwrap_or_default()
                ),
                toml_basic_string(
                    &refusal
                        .client_mod
                        .as_ref()
                        .map(|n| n.to_display_string())
                        .unwrap_or_default()
                ),
            )
        }
        ConnectionEvent::Disconnected { reason } => {
            format!("type = \"Disconnected\"\nreason = \"{}\"\n", reason.label())
        }
        ConnectionEvent::IdentityVerified {
            user_hash,
            public_key,
        } => format!(
            "type = \"PeerIdentityVerified\"\nuser_hash = \"{}\"\npublic_key_len = {}\n",
            user_hash.to_hex_upper(),
            public_key.len(),
        ),
        ConnectionEvent::SecureIdentFailed { reason } => {
            format!("type = \"PeerSecureIdentFailed\"\nreason = \"{reason:?}\"\n")
        }
    }
}

fn requester_toml(event: &RequesterEvent) -> String {
    match event {
        RequesterEvent::FileRequestSent {
            file_hash,
            sources_asked,
        } => format!(
            "type = \"FileRequestSent\"\nfile_hash = \"{}\"\nsources_asked = {sources_asked}\n",
            file_hash.to_hex_upper(),
        ),
        RequesterEvent::FileProbed { file_hash, status } => {
            let status_label = match status {
                FileProbeStatus::Available {
                    file_name, bitmap, ..
                } => format!(
                    "Available\"\nfile_name = {}\npart_count = {}",
                    toml_basic_string(&file_name.to_display_string()),
                    bitmap.part_count(),
                ),
                FileProbeStatus::NotAvailable => "NotAvailable\"".to_owned(),
            };
            format!(
                "type = \"FileProbed\"\nfile_hash = \"{}\"\nstatus = \"{status_label}\n",
                file_hash.to_hex_upper(),
            )
        }
        RequesterEvent::HashSetReceived {
            file_hash,
            part_hashes,
        } => format!(
            "type = \"HashSetReceived\"\nfile_hash = \"{}\"\npart_hash_count = {}\n",
            file_hash.to_hex_upper(),
            part_hashes.len(),
        ),
        RequesterEvent::QueueRanked { file_hash, rank } => format!(
            "type = \"QueueRanked\"\nfile_hash = \"{}\"\nrank = {rank}\n",
            file_hash.to_hex_upper(),
        ),
        RequesterEvent::QueueProgress {
            file_hash,
            previous_rank,
            new_rank,
        } => format!(
            "type = \"QueueProgress\"\nfile_hash = \"{}\"\nprevious_rank = {previous_rank}\nnew_rank = {new_rank}\n",
            file_hash.to_hex_upper(),
        ),
        RequesterEvent::QueueRejected { file_hash } => format!(
            "type = \"QueueRejected\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        RequesterEvent::SlotGranted { file_hash } => format!(
            "type = \"SlotGranted\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        RequesterEvent::PartReceived {
            file_hash,
            offset,
            bytes,
        } => format!(
            "type = \"PartReceived\"\nfile_hash = \"{}\"\noffset = {offset}\ndata_len = {}\n",
            file_hash.to_hex_upper(),
            bytes.len(),
        ),
        RequesterEvent::SourcesReceived { file_hash, sources } => format!(
            "type = \"SourcesReceived\"\nfile_hash = \"{}\"\nsource_count = {}\n",
            file_hash.to_hex_upper(),
            sources.len(),
        ),
        RequesterEvent::SourceExchangeAnswerSkipped { reason } => {
            format!("type = \"SourceExchangeAnswerSkipped\"\nreason = \"{reason}\"\n")
        }
        RequesterEvent::AichAnswerReceived {
            file_hash,
            part,
            recovery_data,
            ..
        } => format!(
            "type = \"AichAnswerReceived\"\nfile_hash = \"{}\"\npart = {part}\nrecovery_len = {}\n",
            file_hash.to_hex_upper(),
            recovery_data.len(),
        ),
        RequesterEvent::AichFileHashReceived { root } => {
            format!(
                "type = \"AichFileHashReceived\"\nroot = \"{}\"\n",
                root.to_base32_upper()
            )
        }
        RequesterEvent::CompressedPartSkipped {
            file_hash,
            offset,
            reason,
        } => format!(
            "type = \"CompressedPartSkipped\"\nfile_hash = \"{}\"\noffset = {offset}\nreason = \"{reason}\"\n",
            file_hash.to_hex_upper(),
        ),
        RequesterEvent::SlotReleased { file_hash, reason } => format!(
            "type = \"SlotReleased\"\nfile_hash = \"{}\"\nreason = \"{}\"\n",
            file_hash.to_hex_upper(),
            slot_release_reason_label(*reason),
        ),
        RequesterEvent::FileCommentReceived { rating, comment } => format!(
            "type = \"FileCommentReceived\"\nrating = {rating}\ncomment = {}\n",
            toml_basic_string(&comment.to_display_string()),
        ),
    }
}

fn server_toml(event: &ServerEvent) -> String {
    match event {
        ServerEvent::FileRequested { file_hash, status } => format!(
            "type = \"FileRequested\"\nfile_hash = \"{}\"\nstatus_bytes = {}\n",
            file_hash.to_hex_upper(),
            status.as_bytes().len(),
        ),
        ServerEvent::FileBundleRequested {
            file_hash,
            file_size,
            asks,
            cut,
        } => format!(
            "type = \"FileBundleRequested\"\nfile_hash = \"{}\"\n{}asks = {}\ncut = {}\n",
            file_hash.to_hex_upper(),
            file_size.map_or_else(String::new, |s| format!("file_size = {s}\n")),
            asks.len(),
            cut.is_some(),
        ),
        ServerEvent::FileIdSet { file_hash } => format!(
            "type = \"FileIdSet\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::HashSetRequested { file_hash } => format!(
            "type = \"HashSetRequested\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::SlotRequested { file_hash } => format!(
            "type = \"SlotRequested\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::PartsRequested { file_hash, ranges } => {
            let (start, end) = ranges.as_array()[0];
            format!(
                "type = \"PartsRequested\"\nfile_hash = \"{}\"\nstart = {start}\nend = {end}\n",
                file_hash.to_hex_upper(),
            )
        }
        ServerEvent::PartsWithoutSlot { file_hash } => format!(
            "type = \"ServePartsWithoutSlot\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::TransferCancelled { file_hash } => format!(
            "type = \"TransferCancelled\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::SourcesRequested { file_hash } => format!(
            "type = \"SourcesRequested\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::SourcesAnswered { file_hash, count } => format!(
            "type = \"SourcesAnswered\"\nfile_hash = \"{}\"\ncount = {count}\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::AichRequested {
            file_hash, part, ..
        } => format!(
            "type = \"AichRequested\"\nfile_hash = \"{}\"\npart = {part}\n",
            file_hash.to_hex_upper(),
        ),
        ServerEvent::AichFileHashRequested { file_hash } => format!(
            "type = \"AichFileHashRequested\"\nfile_hash = \"{}\"\n",
            file_hash.to_hex_upper(),
        ),
    }
}

fn side_toml(event: &SideEvent) -> String {
    match event {
        SideEvent::KadFirewallCheckAck => "type = \"KadFirewallCheckAck\"\n".to_owned(),
        SideEvent::KadUdpFirewallCheckRequested { request } => format!(
            "type = \"KadUdpFirewallCheckRequested\"\nrequest_len = {}\n",
            request.len()
        ),
        SideEvent::BuddyPingReceived => "type = \"BuddyPingReceived\"\n".to_owned(),
        SideEvent::BuddyCallbackReceived { callback } => format!(
            "type = \"BuddyCallbackReceived\"\nfile_hash = \"{}\"\nrequester = \"{}\"\n",
            callback.file_hash.to_hex_upper(),
            callback.requester
        ),
        SideEvent::BuddyReaskCallbackReceived { relay } => format!(
            "type = \"BuddyReaskCallbackReceived\"\nrequester = \"{}\"\nforwarded_len = {}\n",
            relay.requester,
            relay.forwarded.len()
        ),
        SideEvent::PublicIpAnswered => "type = \"PublicIpAnswered\"\n".to_owned(),
        SideEvent::PublicIpRequestUnanswerable => {
            "type = \"PublicIpRequestUnanswerable\"\n".to_owned()
        }
    }
}

fn notice_toml(event: &NoticeEvent) -> String {
    match event {
        NoticeEvent::UnknownPacket {
            protocol,
            opcode,
            payload_len,
        } => format!(
            "type = \"UnknownPeerPacket\"\nprotocol = \"{}\"\nopcode = {opcode}\npayload_len = {payload_len}\n",
            packet_protocol_label(*protocol),
        ),
        NoticeEvent::MultiPacketUnknownSub {
            file_hash,
            opcode,
            remaining,
        } => format!(
            "type = \"MultiPacketUnknownSub\"\nfile_hash = \"{}\"\nopcode = {opcode}\nremaining = {remaining}\n",
            file_hash.to_hex_upper(),
        ),
        NoticeEvent::CompressedFrameSkipped {
            opcode,
            compressed_len,
            reason,
        } => format!(
            "type = \"CompressedFrameSkipped\"\nopcode = {opcode}\ncompressed_len = {compressed_len}\nreason = \"{reason:?}\"\n",
        ),
        NoticeEvent::CommandRejected { reason } => format!(
            "type = \"CommandRejected\"\nreason = {}\n",
            toml_basic_string(&reason.to_string()),
        ),
        NoticeEvent::BrowseDenied => "type = \"BrowseDenied\"\n".to_owned(),
        NoticeEvent::UnsolicitedBrowseAnswerDropped => {
            "type = \"UnsolicitedBrowseAnswerDropped\"\n".to_owned()
        }
        NoticeEvent::UnsolicitedPublicIpAnswerDropped => {
            "type = \"UnsolicitedPublicIpAnswerDropped\"\n".to_owned()
        }
        NoticeEvent::ChatMessageReceived { text } => format!(
            "type = \"ChatMessageReceived\"\ntext = {}\n",
            toml_basic_string(&text.to_display_string()),
        ),
        NoticeEvent::ChatCaptchaDropped => "type = \"ChatCaptchaDropped\"\n".to_owned(),
    }
}

pub(crate) const fn slot_release_reason_label(reason: SlotReleaseReason) -> &'static str {
    match reason {
        SlotReleaseReason::DownloadComplete => "DownloadComplete",
        SlotReleaseReason::QueueRejected => "QueueRejected",
        SlotReleaseReason::PeerClosed => "PeerClosed",
        SlotReleaseReason::ProtocolViolation => "ProtocolViolation",
        SlotReleaseReason::FileNotFound => "FileNotFound",
        SlotReleaseReason::Stale => "Stale",
        SlotReleaseReason::Cancelled => "Cancelled",
    }
}

pub(crate) const fn packet_protocol_label(protocol: PacketProtocol) -> &'static str {
    match protocol {
        PacketProtocol::Edonkey => "Edonkey",
        PacketProtocol::Emule => "Emule",
        PacketProtocol::PackedEd2k => "PackedEd2k",
    }
}

// Elision offsets, meta counts, and clean-path byte content are exercised
// end-to-end in tests/net/capture_modes.rs; these pin the on-disk staging
// contract at the writer seam instead. `.partial` → rename belongs to the
// shared engine, so the only way to reach the crash path from here is to
// drive `PeerCaptureFormat` through `spawn_capture` and drop the handle.
#[cfg(test)]
mod tests {
    use super::*;

    use crate::driver::{OverflowPolicy, spawn_capture};

    const FINAL_FILES: [&str; 4] = ["inbound.bin", "outbound.bin", "events.toml", "meta.toml"];

    #[tokio::test]
    async fn dropped_finalize_leaves_only_partial_files() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, writer) = spawn_capture(
            dir.path().to_path_buf(),
            PeerCaptureFormat::new(String::new(), CaptureMode::ProtocolOnly),
            OverflowPolicy::Backpressure,
            16,
        );

        handle
            .record_frame(StreamTap {
                outbound: false,
                bytes: Arc::from(&b"peer-hello-bytes"[..]),
            })
            .await;
        handle
            .record_row("type = \"PeerHelloSent\"\n".to_owned())
            .await;

        // Driver abort: the handle drops without a finalize verdict.
        drop(handle);
        writer.await.unwrap().unwrap();

        // Never a bare authoritative file — and no `meta.toml` at all on an
        // aborted run, so a crashed capture is obviously non-authoritative.
        for name in FINAL_FILES {
            assert!(
                !dir.path().join(name).exists(),
                "bare {name} after an unclean exit"
            );
        }
        // The buffered stream is staged as `.partial` (flushed by `finish`).
        let staged = std::fs::read(dir.path().join("inbound.bin.partial")).unwrap();
        assert_eq!(staged, b"peer-hello-bytes");
    }

    #[tokio::test]
    async fn clean_finalize_renames_every_partial() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, writer) = spawn_capture(
            dir.path().to_path_buf(),
            PeerCaptureFormat::new("127.0.0.1:4662".to_owned(), CaptureMode::Full),
            OverflowPolicy::Backpressure,
            16,
        );

        handle
            .record_frame(StreamTap {
                outbound: true,
                bytes: Arc::from(&b"client-hello"[..]),
            })
            .await;
        handle.finalize(FinalizeVerdict {
            close_label: "Local",
            started_unix_secs: 1,
            duration_ms: 2,
        });
        writer.await.unwrap().unwrap();

        for name in FINAL_FILES {
            assert!(
                dir.path().join(name).exists(),
                "{name} missing after clean finalize"
            );
            assert!(
                !dir.path().join(format!("{name}.partial")).exists(),
                "{name}.partial left behind after clean finalize"
            );
        }
        let outbound = std::fs::read(dir.path().join("outbound.bin")).unwrap();
        assert_eq!(outbound, b"client-hello");
        let meta = std::fs::read_to_string(dir.path().join("meta.toml")).unwrap();
        assert!(meta.contains("capture_mode = \"full\""), "{meta}");
    }
}
