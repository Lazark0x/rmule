//! The `peer reask-capture` command: put a source-reask query on a live peer's
//! UDP port and record what comes back, including the flood-offender behaviour
//! a deliberately over-eager reask provokes.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;

use crate::capture::{hex_lower, write_new};
use crate::operand::parse_hex16;

/// `ed2k peer reask-capture` (ADR-0057): fire bare `OP_REASKFILEPING 0x90`
/// datagrams at a live counterparty's client-UDP socket and capture its raw
/// error-branch replies as fixture files — the operator-run capture shape of
/// `ed2k server udp-capture` for the peer-UDP surface.
///
/// Two stimuli, each drawing a documented `ClientUDPSocket.cpp` branch:
///
/// - a hash the target does **not** share → `OP_FILENOTFOUND 0x92`
///   (unconditional, answered even to an unknown sender);
/// - a hash the target **shares**, asked by an unknown sender →
///   `OP_QUEUEFULL 0x93` iff `(waiting + 50) > QueueSizePref*100`, so the
///   counterparty runs `QueueSizePref=0` (a legal preference) for the branch
///   to open on a quiet bench.
#[derive(Debug, Args)]
pub(crate) struct PeerReaskCaptureArgs {
    /// Target `ipv4:port` — the counterparty's client-UDP socket (aMule muxes
    /// client-UDP and Kad on one port, default 4672).
    pub(crate) target: String,
    /// A file hash (32 hex) the target does NOT share: the `0x92` stimulus.
    #[arg(long, default_value = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")]
    missing_hash: String,
    /// A file hash (32 hex) the target SHARES: the `0x93` stimulus. Omitted,
    /// the queue-full leg is skipped.
    #[arg(long)]
    shared_hash: Option<String>,
    /// Directory to write the captured raw reply datagrams into.
    #[arg(long)]
    out: std::path::PathBuf,
    /// Per-reply timeout, seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

pub(crate) async fn reask_capture(args: PeerReaskCaptureArgs) -> Result<()> {
    use rmule_peer::{file_not_found_datagram, queue_full_datagram};
    use rmule_primitives::FileHash;

    let target: std::net::SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse target {}", args.target))?;
    std::fs::create_dir_all(&args.out).with_context(|| format!("create {}", args.out.display()))?;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind probe UDP socket")?;
    let window = Duration::from_secs(args.timeout);

    // Leg 1: the unshared hash → 0x92 (unconditional, even for an unknown
    // sender — `if (!reqfile)` answers before any sender lookup).
    let missing = FileHash::from_bytes(parse_hex16("--missing-hash", &args.missing_hash)?);
    let reply = probe_reask(&socket, target, missing, window)
        .await?
        .context("no reply to the unshared-hash reask within the window")?;
    if reply != file_not_found_datagram() {
        // A reply that does NOT match rmule's own encoder is the falsifying
        // case this tool exists to find, so keep the bytes before failing —
        // an operator-run session cannot re-draw them at will.
        let path = args.out.join("unexpected_reply_0x92_leg.bin");
        write_new(&path, &reply)?;
        anyhow::bail!(
            "unshared-hash reask drew an unexpected reply (wanted the empty-body 0x92): {} \
             (written to {})",
            hex_lower(&reply),
            path.display()
        );
    }
    let path = args.out.join("filenotfound_0x92.bin");
    write_new(&path, &reply)?;
    println!(
        "reask-capture filenotfound_0x92=captured bytes={} file={}",
        reply.len(),
        path.display()
    );

    // Leg 2: the shared hash from an unknown sender → 0x93 under
    // QueueSizePref=0.
    if let Some(shared) = &args.shared_hash {
        let shared = FileHash::from_bytes(parse_hex16("--shared-hash", shared)?);
        let reply = probe_reask(&socket, target, shared, window)
            .await?
            .context(
                "no reply to the shared-hash reask within the window (is the counterparty sharing \
             the file and running QueueSizePref=0?)",
            )?;
        if reply != queue_full_datagram() {
            // As above: the non-canonical answer is the evidence, so it is
            // written before the bail rather than surviving only as hex.
            let path = args.out.join("unexpected_reply_0x93_leg.bin");
            write_new(&path, &reply)?;
            anyhow::bail!(
                "shared-hash reask drew an unexpected reply (wanted the empty-body 0x93): {} \
                 (written to {})",
                hex_lower(&reply),
                path.display()
            );
        }
        let path = args.out.join("queuefull_0x93.bin");
        write_new(&path, &reply)?;
        println!(
            "reask-capture queuefull_0x93=captured bytes={} file={}",
            reply.len(),
            path.display()
        );
    } else {
        println!("reask-capture queuefull_0x93=skipped (no --shared-hash)");
    }
    Ok(())
}

/// Send one bare `0x90` (`[0xC5][0x90][hash16]` — the handler reads the hash
/// before any version-gated tail) and wait for the first `0xC5` datagram back
/// from the target. Non-peer datagrams (e.g. Kad chatter on the muxed socket)
/// are logged and skipped; `None` on the deadline.
async fn probe_reask(
    socket: &tokio::net::UdpSocket,
    target: std::net::SocketAddr,
    file_hash: rmule_primitives::FileHash,
    window: Duration,
) -> Result<Option<Vec<u8>>> {
    let ping = rmule_peer::ReaskFilePing {
        file_hash,
        part_status: None,
        complete_sources: None,
    };
    socket
        .send_to(&ping.encode_udp(), target)
        .await
        .context("send OP_REASKFILEPING")?;
    println!(
        "reask-capture sent_0x90 hash={} target={target}",
        file_hash.to_hex_upper()
    );
    let deadline = tokio::time::Instant::now() + window;
    let mut buf = [0u8; 2048];
    loop {
        let received = tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            received = socket.recv_from(&mut buf) => received.context("recv reply")?,
        };
        let (len, from) = received;
        let datagram = &buf[..len];
        if from != target {
            println!(
                "reask-capture ignored datagram from {from} ({} bytes)",
                datagram.len()
            );
            continue;
        }
        if datagram.first() != Some(&0xC5) {
            println!(
                "reask-capture ignored non-peer datagram from {from}: {}",
                hex_lower(datagram)
            );
            continue;
        }
        return Ok(Some(datagram.to_vec()));
    }
}
