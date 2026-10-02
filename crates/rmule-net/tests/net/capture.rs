//! The capture writer task on its own, against a fake format: what a clean
//! finalize leaves on disk (renamed streams, rows, meta) versus what an abort
//! leaves behind, and the two overflow policies — block until the writer
//! catches up, or shed frames rather than stall the driver.

use std::fs;
use std::sync::Arc;

use rmule_net::driver::{CaptureFormat, FrameWrite, OverflowPolicy, RowsFile, spawn_capture};
use tempfile::tempdir;

/// Two-stream format covering both row sources: ed2k-shaped (rows arrive
/// pre-encoded on the row channel) with `row_per_frame: false`, kad-shaped
/// (each frame contributes a row) with `row_per_frame: true`. `seq`
/// exercises `encode_frame`'s statefulness.
struct FakeFormat {
    row_per_frame: bool,
    seq: usize,
}

impl CaptureFormat for FakeFormat {
    type Frame = (usize, Vec<u8>);
    type Meta = &'static str;

    fn files(&self) -> &'static [&'static str] {
        &["a.bin", "b.bin"]
    }
    fn encode_frame(&mut self, (file_index, payload): (usize, Vec<u8>)) -> FrameWrite {
        let row = self
            .row_per_frame
            .then(|| format!("seq = {}\nlen = {}\n", self.seq, payload.len()));
        self.seq += 1;
        FrameWrite {
            file_index,
            bytes: Arc::from(payload),
            row,
        }
    }
    fn rows_file(&self) -> Option<RowsFile> {
        Some(RowsFile {
            file: "rows.toml",
            header: "# fake rows\n\n",
            table: "row",
        })
    }
    fn meta_toml(&self, meta: &'static str) -> String {
        format!("close = \"{meta}\"\n")
    }
}

fn channel_rows_format() -> FakeFormat {
    FakeFormat {
        row_per_frame: false,
        seq: 0,
    }
}

fn frame_rows_format() -> FakeFormat {
    FakeFormat {
        row_per_frame: true,
        seq: 0,
    }
}

#[tokio::test]
async fn clean_finalize_renames_streams_and_writes_rows_and_meta() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let (handle, writer) = spawn_capture(
        root.clone(),
        channel_rows_format(),
        OverflowPolicy::Backpressure,
        8,
    );

    handle.record_frame((0, b"one".to_vec())).await;
    handle.record_frame((1, b"two".to_vec())).await;
    handle.record_frame((0, b"three".to_vec())).await;
    handle.record_row("type = \"Hello\"\n".to_owned()).await;
    handle.record_row("type = \"Bye\"\n".to_owned()).await;
    handle.finalize("Done");
    writer.await.unwrap().unwrap();

    assert_eq!(fs::read(root.join("a.bin")).unwrap(), b"onethree");
    assert_eq!(fs::read(root.join("b.bin")).unwrap(), b"two");
    assert_eq!(
        fs::read_to_string(root.join("rows.toml")).unwrap(),
        "# fake rows\n\n[[row]]\ntype = \"Hello\"\n\n[[row]]\ntype = \"Bye\"\n\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("meta.toml")).unwrap(),
        "close = \"Done\"\n"
    );
    assert!(!root.join("a.bin.partial").exists());
    assert!(!root.join("b.bin.partial").exists());
}

#[tokio::test]
async fn abort_before_finalize_leaves_only_partial_files() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let (handle, writer) = spawn_capture(
        root.clone(),
        frame_rows_format(),
        OverflowPolicy::Backpressure,
        8,
    );

    handle.record_frame((0, b"abc".to_vec())).await;
    drop(handle); // channels close with no finalize meta: unclean exit
    writer.await.unwrap().unwrap();

    assert_eq!(fs::read(root.join("a.bin.partial")).unwrap(), b"abc");
    assert!(root.join("b.bin.partial").exists());
    assert!(!root.join("a.bin").exists());
    assert!(!root.join("b.bin").exists());
    assert!(!root.join("rows.toml").exists());
    assert!(!root.join("meta.toml").exists());
}

#[tokio::test]
async fn backpressure_captures_every_frame_in_order() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    // Capacity far below the frame count: only awaited sends keep this
    // lossless.
    let (handle, writer) = spawn_capture(
        root.clone(),
        frame_rows_format(),
        OverflowPolicy::Backpressure,
        4,
    );

    let mut expected_a = Vec::new();
    let mut expected_b = Vec::new();
    let mut expected_rows = String::from("# fake rows\n\n");
    for i in 0..100u8 {
        let payload = vec![i; 3];
        let file_index = usize::from(i % 2);
        if file_index == 0 {
            expected_a.extend_from_slice(&payload);
        } else {
            expected_b.extend_from_slice(&payload);
        }
        expected_rows.push_str(&format!("[[row]]\nseq = {i}\nlen = 3\n\n"));
        assert!(handle.record_frame((file_index, payload)).await);
    }
    handle.finalize("Done");
    writer.await.unwrap().unwrap();

    assert_eq!(fs::read(root.join("a.bin")).unwrap(), expected_a);
    assert_eq!(fs::read(root.join("b.bin")).unwrap(), expected_b);
    assert_eq!(
        fs::read_to_string(root.join("rows.toml")).unwrap(),
        expected_rows
    );
}

#[tokio::test]
async fn drop_policy_sheds_overflow_without_stalling() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let (handle, writer) =
        spawn_capture(root.clone(), channel_rows_format(), OverflowPolicy::Drop, 4);

    // Flood without ever yielding: on this current-thread test runtime the
    // writer task cannot run between sends, so the channel fills to its
    // capacity and every further frame must be shed immediately rather
    // than awaited.
    let mut captured = 0;
    for i in 0..12u8 {
        if handle.record_frame((0, vec![i])).await {
            captured += 1;
        }
    }
    assert_eq!(captured, 4, "channel capacity got through, the rest shed");

    handle.finalize("Done");
    writer.await.unwrap().unwrap();

    assert_eq!(
        fs::read(root.join("a.bin")).unwrap(),
        vec![0, 1, 2, 3],
        "exactly the first `capacity` frames reach disk"
    );
    assert!(!root.join("a.bin.partial").exists());
}
