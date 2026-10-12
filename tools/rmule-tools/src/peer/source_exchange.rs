//! The source-exchange leg of a transfer capture: ask an established peer for
//! the sources it knows for a file and slice the `OP_ANSWERSOURCES` frame out
//! of the recorded stream, packed or plain.

use std::time::Duration;

use anyhow::{Context, Result};
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, Connection as PeerConnection};
use rmule_peer::{
    ConnectionEvent, PartBitmap, PeerCommand, PeerEvent, PeerHandshakeContext, RequesterCommand,
    RequesterEvent,
};

use crate::peer::transfer::PeerTransferCaptureArgs;

/// Source-exchange capture (ADR-0053 / ADR-0055): dial the
/// peer, complete the hello + file probe, ask it for sources, and hold the
/// connection until it answers `OP_ANSWERSOURCES`. When the peer knows enough
/// sources for the file (≥12 for a v3 answer), the reply arrives zlib-packed
/// above the 354-byte threshold — the inbound-inflate golden. The raw answer
/// frame, exactly as the counterparty sent it, is sliced out of the captured
/// `inbound.bin` into `sx_answer_raw.bin`; the full exchange stays in the
/// capture artifacts. Prints a `sx_capture:` fact line (found / packed / bytes /
/// source_count) the harness parses into its verdict.
///
/// `--multipacket` folds the source ask into the `OP_MULTIPACKET_EXT` (`0xA4`)
/// bundle instead of emitting the standalone `OP_REQUESTSOURCES2` (`0x83`).
/// That is not a style choice — it is the only shape aMule 2.3.3 can answer:
/// its standalone `0x83` handler
/// (`src/ClientTCPSocket.cpp:1448`) reads the 3 SX2 prefix bytes and then
/// tests `size != 16` against the *whole* 19-byte payload, so every standalone
/// SX2 request throws and drops the connection, while the bundled sub-item
/// handler (`:1143`) has no such test and answers normally. aMule's own
/// emitter (`src/DownloadClient.cpp:249`) prefers the bundle against any
/// MultiPacket peer, so this is also what a real aMule sends.
pub(super) async fn source_exchange_capture(
    args: PeerTransferCaptureArgs,
    peer: rmule_primitives::PeerEndpoint,
    ctx: PeerHandshakeContext,
    options: PeerConnectOptions,
    file: rmule_primitives::Ed2kFileLink,
) -> Result<()> {
    let mut conn = PeerConnection::connect(peer, ctx, options).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.max_seconds);
    let mut sent_probe = false;
    let mut sent_request = false;
    let mut source_count: Option<usize> = None;
    let mut answer_skipped: Option<String> = None;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                println!("max_seconds reached, shutting down");
                break;
            }
            event = conn.next_event() => match event {
                Some(event @ PeerEvent::Connection(ConnectionEvent::Identified { .. })) => {
                    println!("{event}");
                    if !sent_probe {
                        if args.multipacket {
                            // One 0xA4 bundle carrying name + status + the SX
                            // ask, aMule's own connect-time shape.
                            let _ = conn.send(PeerCommand::Requester(RequesterCommand::RequestFile {
                                file_hash: file.file_hash,
                                file_size: file.size,
                                own_status: PartBitmap::downloader_empty(file.size),
                                want_sources: true,
                                want_aich_root: false,
                            })).await;
                            sent_request = true;
                        } else {
                            let _ = conn
                                .send(PeerCommand::Requester(RequesterCommand::ProbeFile {
                                    file_hash: file.file_hash,
                                    file_size: file.size,
                                    own_status: PartBitmap::downloader_empty(file.size),
                                }))
                                .await;
                        }
                        sent_probe = true;
                    }
                }
                Some(PeerEvent::Requester(RequesterEvent::FileProbed { status, .. })) => {
                    println!("file_probed: {status:?}");
                    if !sent_request {
                        let _ = conn.send(PeerCommand::Requester(RequesterCommand::RequestSources { file_hash: file.file_hash })).await;
                        sent_request = true;
                    }
                }
                Some(PeerEvent::Requester(RequesterEvent::SourcesReceived { sources, .. })) => {
                    source_count = Some(sources.len());
                    println!("sources_received: {}", sources.len());
                    break;
                }
                Some(PeerEvent::Requester(RequesterEvent::SourceExchangeAnswerSkipped { reason })) => {
                    answer_skipped = Some(reason.to_string());
                    println!("source_exchange_answer_skipped: {reason}");
                    break;
                }
                Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                    println!("disconnected: {reason:?}");
                    break;
                }
                Some(event) => println!("{event}"),
                None => break,
            }
        }
    }
    // Give the writer a moment to flush, then finalize the capture so
    // `inbound.bin` is authoritative before we slice it.
    let _ = conn.shutdown().await;

    let inbound_path = args.output_dir.join("inbound.bin");
    let inbound =
        std::fs::read(&inbound_path).with_context(|| format!("read {}", inbound_path.display()))?;
    match extract_answer_sources_frame(&inbound) {
        Some(frame) => {
            let packed = frame.first() == Some(&PACKED_PROTOCOL);
            let out = args.output_dir.join("sx_answer_raw.bin");
            std::fs::write(&out, &frame).with_context(|| format!("write {}", out.display()))?;
            println!(
                "sx_capture: found=true packed={packed} frame_bytes={} source_count={} raw={}",
                frame.len(),
                source_count
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unknown".to_owned()),
                out.display(),
            );
        }
        None => {
            println!(
                "sx_capture: found=false packed=false frame_bytes=0 source_count={} skipped={}",
                source_count
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "0".to_owned()),
                answer_skipped.unwrap_or_else(|| "none".to_owned()),
            );
        }
    }
    Ok(())
}

/// Client-to-client protocol bytes for framing.
const EMULE_PROTOCOL: u8 = 0xC5;
const PACKED_PROTOCOL: u8 = 0xD4;
/// `OP_ANSWERSOURCES` (SX1) opcode — the byte after the length word in both the
/// plain (`0xC5`) and packed (`0xD4`) framings.
const OP_ANSWERSOURCES: u8 = 0x82;
/// `OP_ANSWERSOURCES2` (SX2) opcode. aMule answers at this opcode whenever the
/// request carried an SX2 version byte (`CPartFile::CreateSrcInfoPacket` sets
/// `bIsSX2Packet`), so a v4 answer is a `0x84` — the same packed framing.
const OP_ANSWERSOURCES2: u8 = 0x84;

/// Walk the raw inbound peer stream frame by frame and return the first
/// `OP_ANSWERSOURCES`/`OP_ANSWERSOURCES2` frame verbatim (plain `0xC5` or
/// packed `0xD4`). The packed form keeps its opcode byte uncompressed right
/// after the length word, so one opcode test finds either. Returns the exact
/// counterparty bytes (protocol + length + opcode + body) — the golden, never
/// re-encoded.
fn extract_answer_sources_frame(stream: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    while offset + 6 <= stream.len() {
        let protocol = stream[offset];
        let length = u32::from_le_bytes([
            stream[offset + 1],
            stream[offset + 2],
            stream[offset + 3],
            stream[offset + 4],
        ]) as usize;
        if length == 0 {
            break;
        }
        let frame_end = offset.checked_add(5)?.checked_add(length)?;
        if frame_end > stream.len() {
            break;
        }
        let opcode = stream[offset + 5];
        if matches!(protocol, EMULE_PROTOCOL | PACKED_PROTOCOL)
            && matches!(opcode, OP_ANSWERSOURCES | OP_ANSWERSOURCES2)
        {
            return Some(stream[offset..frame_end].to_vec());
        }
        offset = frame_end;
    }
    None
}
