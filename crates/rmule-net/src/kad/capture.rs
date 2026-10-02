//! Datagram-level capture tap.
//!
//! While the driver runs, raw datagrams stream into `datagrams.bin.partial`
//! (`[u32 LE length][bytes]` frames, arrival order) and per-frame meta rows
//! accumulate. On clean shutdown the shared capture engine
//! ([`crate::driver::run_capture`]) writes `datagrams.toml` (seq, at_ms,
//! direction, remote, protocol, opcode, len per frame) and `meta.toml`, then
//! renames the `.partial` file — a crashed run leaves `.partial` behind so it
//! is obviously non-authoritative (the same contract as the eD2k stream
//! capture). Capture never back-pressures traffic: the tap uses
//! [`OverflowPolicy::Drop`], shedding frame records rather than stalling the
//! driver.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::driver::{
    CaptureFormat, CaptureHandle, FrameWrite, OverflowPolicy, RowsFile, spawn_capture,
};
use tokio::task::JoinHandle;

/// Which way a datagram crossed the socket.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    const fn label(self) -> &'static str {
        match self {
            Self::Inbound => "in",
            Self::Outbound => "out",
        }
    }
}

/// One datagram observed by the driver.
#[derive(Debug)]
pub(crate) struct DatagramFrame {
    pub at_ms: u64,
    pub direction: Direction,
    pub remote: SocketAddr,
    pub bytes: Vec<u8>,
}

/// Driver-side facts folded into `meta.toml` at finalize time.
#[derive(Debug)]
pub(crate) struct CaptureMeta {
    pub bind: SocketAddr,
    pub node_id_hex: String,
    pub started_unix_secs: u64,
    pub duration_ms: u64,
    pub datagrams_in: u64,
    pub datagrams_out: u64,
    pub non_ipv4_dropped: u64,
}

/// The Kad datagram capture layout: length-prefixed raw frames in
/// `datagrams.bin`, one decoded meta row per frame in `datagrams.toml`, and
/// run facts in `meta.toml`. `encode_frame` is stateful — it stamps each row
/// with a monotonic `seq` and does the length-prefix framing inline.
#[derive(Default)]
pub(crate) struct KadCaptureFormat {
    seq: usize,
}

impl CaptureFormat for KadCaptureFormat {
    type Frame = DatagramFrame;
    type Meta = CaptureMeta;

    fn files(&self) -> &'static [&'static str] {
        &["datagrams.bin"]
    }

    fn encode_frame(&mut self, frame: DatagramFrame) -> FrameWrite {
        let len = u32::try_from(frame.bytes.len()).unwrap_or(u32::MAX);
        let mut bytes = Vec::with_capacity(4 + frame.bytes.len());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&frame.bytes);

        let (protocol, opcode) = match frame.bytes.as_slice() {
            [protocol, opcode, ..] => (i64::from(*protocol), i64::from(*opcode)),
            // A truncated datagram has no opcode to decode; -1 keeps the row
            // honest without inventing a byte.
            _ => (-1, -1),
        };
        let row = format!(
            "seq = {seq}\nat_ms = {at}\ndirection = \"{direction}\"\nremote = \"{remote}\"\nprotocol = {protocol}\nopcode = {opcode}\nlen = {len}\n",
            seq = self.seq,
            at = frame.at_ms,
            direction = frame.direction.label(),
            remote = frame.remote,
            len = frame.bytes.len(),
        );
        self.seq += 1;
        FrameWrite {
            file_index: 0,
            bytes: Arc::from(bytes),
            row: Some(row),
        }
    }

    fn rows_file(&self) -> Option<RowsFile> {
        Some(RowsFile {
            file: "datagrams.toml",
            header: "# One row per datagram, in arrival order. Raw bytes live in\n\
                     # datagrams.bin as [u32 LE length][bytes] frames, same order.\n\n",
            table: "frame",
        })
    }

    fn meta_toml(&self, meta: CaptureMeta) -> String {
        format!(
            "# Run-level metadata for the Kad datagram capture in this directory.\n\n\
             bind = \"{bind}\"\n\
             node_id = \"{id}\"\n\
             started_unix_secs = {started}\n\
             duration_ms = {duration}\n\
             datagrams_in = {datagrams_in}\n\
             datagrams_out = {datagrams_out}\n\
             non_ipv4_dropped = {non_ipv4}\n",
            bind = meta.bind,
            id = meta.node_id_hex,
            started = meta.started_unix_secs,
            duration = meta.duration_ms,
            datagrams_in = meta.datagrams_in,
            datagrams_out = meta.datagrams_out,
            non_ipv4 = meta.non_ipv4_dropped,
        )
    }
}

/// Frame-channel depth. Datagram taps never stall the driver —
/// [`OverflowPolicy::Drop`] sheds records past this depth.
const CAPTURE_CHANNEL_CAP: usize = 1024;

/// The driver's handle to the capture writer task: the engine's
/// [`CaptureHandle`] plus the writer join handle awaited at finalize.
pub(crate) struct CaptureTap {
    handle: CaptureHandle<KadCaptureFormat>,
    writer: JoinHandle<std::io::Result<()>>,
}

impl CaptureTap {
    /// Create the capture directory and start the writer task.
    pub(crate) async fn start(dir: PathBuf) -> std::io::Result<Self> {
        // Surface a bad capture dir at spawn time rather than only at
        // finalize; the engine's `run_capture` also `create_dir_all`s it
        // (idempotent).
        tokio::fs::create_dir_all(&dir).await?;
        let (handle, writer) = spawn_capture(
            dir,
            KadCaptureFormat::default(),
            OverflowPolicy::Drop,
            CAPTURE_CHANNEL_CAP,
        );
        Ok(Self { handle, writer })
    }

    /// Record one datagram. A full or closed writer drops the frame rather
    /// than stalling the driver: capture must never back-pressure traffic.
    /// The `Drop` policy makes this await return immediately.
    pub(crate) async fn record(&self, frame: DatagramFrame) {
        if !self.handle.record_frame(frame).await {
            tracing::warn!("kad capture writer lagging or gone; dropping a frame record");
        }
    }

    /// Send the finalize verdict, release the frame channel, and await the
    /// writer — after which `datagrams.bin` / `datagrams.toml` / `meta.toml`
    /// are in place (or the `.partial` file remains on a write error).
    pub(crate) async fn finalize(self, meta: CaptureMeta) {
        self.handle.finalize(meta);
        if let Err(error) = self
            .writer
            .await
            .map_err(std::io::Error::other)
            .and_then(|r| r)
        {
            tracing::warn!(%error, "kad capture finalize failed; .partial files remain");
        }
    }
}
