//! The capture engine: the one session-capture writer task every runtime
//! module in this crate shares.
//!
//! The engine owns the invariants every capture must uphold; a
//! [`CaptureFormat`] adapter owns only what differs per protocol — the
//! file layout and the frame/row/meta encoding.
//!
//! - **`.partial` staging.** Every file in [`CaptureFormat::files`]
//!   streams to `<name>.partial` and is renamed to `<name>` only on a
//!   clean finalize, so a crashed or aborted session leaves obviously
//!   non-authoritative artifacts.
//! - **Ordered drain-then-finalize.** Frames and rows are drained until
//!   both channels close; only then is the finalize verdict read. See the
//!   comment in [`run_capture`].
//! - **Row collection and the meta write.** Rows (pre-encoded TOML blocks)
//!   arrive from the row channel or from [`CaptureFormat::encode_frame`]
//!   and are written to the format's [`RowsFile`] at finalize, followed by
//!   `meta.toml`.
//! - **[`OverflowPolicy`].** Stream captures await channel capacity
//!   (backpressure); datagram taps drop on full — capture never stalls a
//!   driver.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// What [`CaptureHandle::record_frame`] and
/// [`record_row`](CaptureHandle::record_row) do when the writer task falls
/// behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Await channel capacity: every frame is captured and the producer
    /// slows to the writer. For stream captures, whose tap sits on the
    /// driver's own read/write path.
    Backpressure,
    /// Shed the frame when the channel is full: capture never stalls the
    /// producer. For datagram taps.
    Drop,
}

/// One frame's disk effect, returned by [`CaptureFormat::encode_frame`].
#[derive(Debug)]
pub struct FrameWrite {
    /// Index into [`CaptureFormat::files`] selecting the stream to append
    /// to. Out of range is a format bug: it panics the writer task, which
    /// leaves the `.partial` files behind.
    pub file_index: usize,
    /// Encoded bytes to append. `Arc<[u8]>` so a pass-through format moves
    /// the driver's fanned-out buffer without a byte-copy.
    pub bytes: Arc<[u8]>,
    /// Row collected for the finalize-time [`RowsFile`], if this frame
    /// contributes one.
    pub row: Option<String>,
}

/// Layout of the finalize-time rows file (`events.toml` /
/// `datagrams.toml` style): `header` verbatim, then every collected row as
/// a `[[table]]` block followed by a blank line.
#[derive(Clone, Copy, Debug)]
pub struct RowsFile {
    /// File name, e.g. `"events.toml"`.
    pub file: &'static str,
    /// Written verbatim before the first row — comment lines plus their
    /// trailing blank line, or `""` for none.
    pub header: &'static str,
    /// TOML array-of-tables name, e.g. `"event"`.
    pub table: &'static str,
}

/// The per-protocol half of a capture: file layout and row encoding. The
/// engine ([`run_capture`]) owns everything else — `.partial` staging and
/// rename-on-finalize, drain ordering, row collection, and the meta write.
///
/// `encode_frame` takes `&mut self` so a format can keep state across
/// frames (sequence numbers, or a scanner that rewrites payload bytes);
/// `meta_toml` takes `&self` so that state can fold into the meta record.
pub trait CaptureFormat: Send + 'static {
    /// What one capture write starts from: a [`StreamTap`](crate::driver::StreamTap)
    /// chunk for the connection runtimes, a whole datagram for Kad.
    type Frame: Send + 'static;
    /// What the finalize side hands `meta_toml` — the driver harness supplies
    /// [`FinalizeVerdict`](crate::driver::FinalizeVerdict); a runtime that
    /// finalizes itself (Kad) passes its own richer record.
    type Meta: Send + 'static;

    /// File names this capture streams, e.g. `["s2c.bin", "c2s.bin"]`.
    /// Each is staged as `<name>.partial` and renamed on clean finalize.
    fn files(&self) -> &'static [&'static str];
    /// Map one frame onto its disk effect.
    fn encode_frame(&mut self, frame: Self::Frame) -> FrameWrite;
    /// Stream writes emitted once at finalize, after the last live frame
    /// and before the rows/meta write. Default: none. A format that
    /// *buffers* its streams to post-process them flushes the finished
    /// bytes here — peer capture elides `OP_SENDINGPART` payloads, which
    /// needs the whole stream in hand, so its `encode_frame` accumulates
    /// and this emits the elided result. The writes land in the `.partial`
    /// files like any other stream write, so an unclean exit still leaves
    /// them non-authoritative.
    fn finish(&mut self) -> Vec<FrameWrite> {
        Vec::new()
    }
    /// Layout of the rows file written at finalize, or `None` to discard
    /// collected rows.
    fn rows_file(&self) -> Option<RowsFile>;
    /// Full `meta.toml` contents for the finalize meta.
    fn meta_toml(&self, meta: Self::Meta) -> String;
}

/// Producer half of an engine-owned capture, created by [`spawn_capture`]:
/// policy-aware frame/row senders plus the finalize sender. Dropping the
/// handle without [`finalize`](Self::finalize) is the unclean exit — the
/// writer keeps the `.partial` files.
pub struct CaptureHandle<F: CaptureFormat> {
    frames: mpsc::Sender<F::Frame>,
    rows: mpsc::Sender<String>,
    finalize: oneshot::Sender<F::Meta>,
    policy: OverflowPolicy,
}

impl<F: CaptureFormat> CaptureHandle<F> {
    /// Record one frame. Returns `false` when the frame was not captured —
    /// the writer is gone, or the channel is full under
    /// [`OverflowPolicy::Drop`]. Never waits under `Drop`.
    pub async fn record_frame(&self, frame: F::Frame) -> bool {
        match self.policy {
            OverflowPolicy::Backpressure => self.frames.send(frame).await.is_ok(),
            OverflowPolicy::Drop => self.frames.try_send(frame).is_ok(),
        }
    }

    /// Record one pre-encoded row for the finalize-time rows file. Same
    /// policy behaviour as [`record_frame`](Self::record_frame).
    pub async fn record_row(&self, row: String) -> bool {
        match self.policy {
            OverflowPolicy::Backpressure => self.rows.send(row).await.is_ok(),
            OverflowPolicy::Drop => self.rows.try_send(row).is_ok(),
        }
    }

    /// Clean shutdown: send the finalize meta, then release the channels —
    /// in that order, which [`run_capture`]'s clean-shutdown contract
    /// relies on. Await the writer task returned by [`spawn_capture`] to
    /// observe the renamed artifacts.
    pub fn finalize(self, meta: F::Meta) {
        let _ = self.finalize.send(meta);
    }
}

/// Spawn an engine-owned capture: creates the frame/row/finalize channels
/// with `capacity`, spawns [`run_capture`] over `format`, and returns the
/// producer [`CaptureHandle`] plus the writer task handle. Callers whose
/// channels are created elsewhere (the harness's
/// [`SpawnCapture`](crate::driver::SpawnCapture) sink factory) call [`run_capture`]
/// directly instead.
pub fn spawn_capture<F: CaptureFormat>(
    dir: PathBuf,
    format: F,
    policy: OverflowPolicy,
    capacity: usize,
) -> (CaptureHandle<F>, JoinHandle<std::io::Result<()>>) {
    let (frame_tx, frame_rx) = mpsc::channel(capacity);
    let (row_tx, row_rx) = mpsc::channel(capacity);
    let (finalize_tx, finalize_rx) = oneshot::channel();
    let writer = tokio::spawn(run_capture(dir, format, frame_rx, row_rx, finalize_rx));
    (
        CaptureHandle {
            frames: frame_tx,
            rows: row_tx,
            finalize: finalize_tx,
            policy,
        },
        writer,
    )
}

/// Run the capture writer for one session: stream frames into `.partial`
/// files, collect rows, and on a clean finalize write the rows file and
/// `meta.toml`, then rename every `.partial` into place.
///
/// Clean-shutdown contract: the producer sends the finalize meta *first*
/// and drops its frame/row senders *after* — both [`CaptureHandle::finalize`]
/// and the driver harness's finalize uphold this order. If the channels
/// close without a buffered meta the exit is unclean and the `.partial`
/// files stay behind, obviously non-authoritative.
pub async fn run_capture<F: CaptureFormat>(
    dir: PathBuf,
    mut format: F,
    mut frame_rx: mpsc::Receiver<F::Frame>,
    mut row_rx: mpsc::Receiver<String>,
    finalize_rx: oneshot::Receiver<F::Meta>,
) -> std::io::Result<()> {
    tokio::fs::create_dir_all(&dir).await?;
    let files = format.files();
    let mut partial_paths = Vec::with_capacity(files.len());
    let mut streams = Vec::with_capacity(files.len());
    for name in files {
        let path = dir.join(format!("{name}.partial"));
        let stream = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        partial_paths.push(path);
        streams.push(stream);
    }

    let mut rows: Vec<String> = Vec::new();
    let mut frames_closed = false;
    let mut rows_closed = false;
    // No select against `finalize_rx` here, deliberately: producers send
    // the finalize meta *before* dropping their senders, and racing the
    // channels once made a clean shutdown land on a closed-frames arm
    // first and return without renaming — a run-dependent lost capture.
    // The sequence is inherently ordered: drain every frame and row until
    // both channels close, then read the finalize verdict.
    while !(frames_closed && rows_closed) {
        tokio::select! {
            frame = frame_rx.recv(), if !frames_closed => match frame {
                Some(frame) => {
                    let FrameWrite { file_index, bytes, row } = format.encode_frame(frame);
                    streams[file_index].write_all(&bytes).await?;
                    if let Some(row) = row {
                        rows.push(row);
                    }
                }
                None => frames_closed = true,
            },
            row = row_rx.recv(), if !rows_closed => match row {
                Some(row) => rows.push(row),
                None => rows_closed = true,
            },
        }
    }
    // Let a buffering format (peer elision) emit its finished streams now,
    // into the same `.partial` files — before the finalize verdict, so an
    // unclean exit still leaves them behind as the honest artifact.
    for FrameWrite {
        file_index,
        bytes,
        row,
    } in format.finish()
    {
        streams[file_index].write_all(&bytes).await?;
        if let Some(row) = row {
            rows.push(row);
        }
    }
    for stream in &mut streams {
        stream.flush().await?;
    }
    drop(streams);

    match finalize_rx.await {
        Ok(meta) => {
            if let Some(spec) = format.rows_file() {
                tokio::fs::write(dir.join(spec.file), render_rows(&spec, &rows)).await?;
            }
            tokio::fs::write(dir.join("meta.toml"), format.meta_toml(meta)).await?;
            for (name, partial) in files.iter().zip(&partial_paths) {
                tokio::fs::rename(partial, dir.join(name)).await?;
            }
            Ok(())
        }
        // A dropped finalize sender is an unclean producer exit: keep the
        // `.partial` files as the honest artifact.
        Err(_) => Ok(()),
    }
}

fn render_rows(spec: &RowsFile, rows: &[String]) -> String {
    let mut out = String::new();
    out.push_str(spec.header);
    for row in rows {
        out.push_str("[[");
        out.push_str(spec.table);
        out.push_str("]]\n");
        out.push_str(row);
        out.push('\n');
    }
    out
}

/// Encode `s` as a TOML basic string with proper escaping. Used by the
/// format adapters wherever they hand-emit `meta.toml` / row TOML rather
/// than going through serde — a quote, backslash, or control character in
/// a nickname or endpoint would otherwise produce invalid TOML that the
/// round-trip tests would only catch by surprise.
#[must_use]
pub fn toml_basic_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
