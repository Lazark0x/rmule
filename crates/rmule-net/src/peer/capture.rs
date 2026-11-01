//! The peer session's capture layout: raw stream bytes split by direction, the
//! decoded event rows, and the session facts written beside them. The part-data
//! elision of ADR-0024 lives here because it needs the whole buffered stream in
//! hand before a frame's payload can be replaced with the marker.

use std::sync::Arc;

use crate::driver::{
    CaptureFormat, FinalizeVerdict, FrameWrite, RowsFile, StreamTap, row_to_toml, toml_basic_string,
};
use rmule_peer::PeerEvent;

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

/// One event as the TOML table a capture's `events.toml` carries.
pub(crate) fn event_to_toml(event: &PeerEvent) -> String {
    row_to_toml(&event.row())
}

// Elision offsets, meta counts, and clean-path byte content are exercised
// end-to-end in tests/net/capture_modes.rs; these pin the on-disk staging
// contract at the writer seam instead. `.partial` → rename belongs to the
// shared engine, so the only way to reach the crash path from here is to
// drive `PeerCaptureFormat` through `spawn_capture` and drop the handle.
#[cfg(test)]
mod tests {
    use super::*;

    use rmule_peer::{ConnectionEvent, NoticeEvent, ServerEvent};
    use rmule_primitives::{Ed2kText, FileHash, PacketProtocol, UserHash};

    use crate::driver::{OverflowPolicy, spawn_capture};

    const FINAL_FILES: [&str; 4] = ["inbound.bin", "outbound.bin", "events.toml", "meta.toml"];

    /// One event, two formats from one row: the `peer …` line harness parsers
    /// read, and the table archived captures hold. Where the two words or
    /// notations differ, each keeps its own.
    #[test]
    fn an_event_keeps_the_line_and_the_table_tools_read() {
        let file_hash = FileHash::from_bytes([0xAB; 16]);
        let hex = file_hash.to_hex_upper();
        let cases = [
            (
                PeerEvent::Connection(ConnectionEvent::IdentityVerified {
                    user_hash: UserHash::from_bytes([0xCD; 16]),
                    public_key: vec![0; 3],
                }),
                "peer identity_verified user_hash=CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD public_key_len=3"
                    .to_owned(),
                "type = \"PeerIdentityVerified\"\n\
                 user_hash = \"CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD\"\n\
                 public_key_len = 3\n"
                    .to_owned(),
            ),
            (
                PeerEvent::Notice(NoticeEvent::UnknownPacket {
                    protocol: PacketProtocol::Edonkey,
                    opcode: 0x7A,
                    payload_len: 3,
                }),
                "peer unknown protocol=edonkey opcode=0x7A payload_len=3".to_owned(),
                "type = \"UnknownPeerPacket\"\nprotocol = \"Edonkey\"\nopcode = 122\npayload_len = 3\n"
                    .to_owned(),
            ),
            (
                PeerEvent::Server(ServerEvent::FileBundleRequested {
                    file_hash,
                    file_size: None,
                    asks: Vec::new(),
                    cut: None,
                }),
                format!("peer file_bundle_requested file_hash={hex} file_size=none asks=0 cut=false"),
                format!(
                    "type = \"FileBundleRequested\"\nfile_hash = \"{hex}\"\nasks = 0\ncut = false\n"
                ),
            ),
            (
                PeerEvent::Notice(NoticeEvent::ChatMessageReceived {
                    text: Ed2kText::from_utf8("a \"b\""),
                }),
                "peer chat_message_received len=5".to_owned(),
                "type = \"ChatMessageReceived\"\ntext = \"a \\\"b\\\"\"\n".to_owned(),
            ),
        ];
        for (event, line, table) in cases {
            assert_eq!(event.to_string(), line);
            assert_eq!(event_to_toml(&event), table);
        }
    }

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
