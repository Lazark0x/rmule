//! Download one verified eD2k part from a live peer.
//!
//! Reads `RMULE_LIVE_TRANSFER_PEER` (ipv4:port) and
//! `RMULE_LIVE_TRANSFER_FILE` (ed2k file link) from the environment,
//! opens a `rmule_net::peer::Connection`, issues `RequestParts` for
//! part 0, accumulates bytes, verifies the `Md4` (`ed2k::Ed2kBlue`)
//! part hash against `HashSetReceived.part_hashes[0]`, writes the
//! verified bytes to a tempfile, and prints a summary.
//!
//! Deliberately one part, and deliberately below the orchestrator: this is
//! the peer wire on its own. Accumulating every part across a swarm and
//! reassembling the file is `rmule_core::Core`'s job, driven by
//! `rmule-tools ed2k download start` (see `src/download.rs`).

use std::env;
use std::io::Write;
use std::time::Duration;

use anyhow::{Context, Result};
use ed2k::digest::Digest;
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{
    ConnectionEvent, PartRanges, PeerCommand, PeerEvent, PeerHandshakeContext, RequesterCommand,
    RequesterEvent, SlotReleaseReason,
};
use rmule_primitives::{
    ClientId, ClientIdentity, ED2K_PART_SIZE, Ed2kLink, Ed2kText, PartHash, PeerEndpoint, UserHash,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let peer_str = env::var("RMULE_LIVE_TRANSFER_PEER")
        .context("set RMULE_LIVE_TRANSFER_PEER=<ipv4>:<port>")?;
    let link_str = env::var("RMULE_LIVE_TRANSFER_FILE")
        .context("set RMULE_LIVE_TRANSFER_FILE=ed2k://|file|...")?;
    let peer = parse_peer(&peer_str)?;
    let link = Ed2kLink::parse(&link_str)?;
    let file = match link {
        Ed2kLink::File(f) => f,
        _ => anyhow::bail!("RMULE_LIVE_TRANSFER_FILE must be an ed2k file link"),
    };
    let part0_len = std::cmp::min(file.size, ED2K_PART_SIZE);

    let identity = ClientIdentity::new(
        UserHash::from_bytes([0x42; 16]),
        Ed2kText::from_utf8("rmule-download-one-part"),
        4662,
        60,
    );
    let ctx = PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(0x10000001),
        ed2k_client_id: ClientId::from_u32(0x10000001),
        public_ip: None,
        connected_server: None,
    };
    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(15),
        hello_timeout: Duration::from_secs(20),
        ..Default::default()
    };
    let mut conn = Connection::connect(peer, ctx, options).await?;
    let ranges = PartRanges::new([(0, part0_len), (0, 0), (0, 0)])?;

    let mut accumulated: Vec<u8> = Vec::new();
    let mut part_hashes: Option<Vec<PartHash>> = None;
    let mut released = false;
    let mut released_reason: Option<SlotReleaseReason> = None;

    while let Some(event) = conn.next_event().await {
        match event {
            PeerEvent::Connection(ConnectionEvent::Identified { .. }) => {
                conn.send(PeerCommand::Requester(RequesterCommand::RequestParts {
                    file_hash: file.file_hash,
                    file_size: file.size,
                    ranges,
                }))
                .await
                .ok();
            }
            PeerEvent::Requester(RequesterEvent::HashSetReceived {
                part_hashes: hashes,
                ..
            }) => {
                part_hashes = Some(hashes);
            }
            PeerEvent::Requester(RequesterEvent::PartReceived { bytes, .. }) => {
                accumulated.extend_from_slice(&bytes);
                // Held slot (ADR-0025, amended): the session does not
                // auto-release per request, so the consumer releases
                // explicitly once the whole requested part has arrived.
                if accumulated.len() as u64 >= part0_len {
                    conn.send(PeerCommand::Requester(RequesterCommand::ReleaseSlot {
                        file_hash: file.file_hash,
                    }))
                    .await
                    .ok();
                }
            }
            PeerEvent::Requester(RequesterEvent::SlotReleased { reason, .. }) => {
                released = true;
                released_reason = Some(reason);
                break;
            }
            PeerEvent::Connection(ConnectionEvent::Disconnected { reason }) => {
                anyhow::bail!("peer disconnected before download complete: {reason:?}");
            }
            _ => {}
        }
    }
    let _ = conn.shutdown().await;

    if !released {
        anyhow::bail!("event stream ended before SlotReleased");
    }
    if !matches!(released_reason, Some(SlotReleaseReason::DownloadComplete)) {
        anyhow::bail!("slot released non-complete: {released_reason:?}");
    }
    let part_hashes = part_hashes.context("no HashSetReceived observed")?;
    let expected = *part_hashes.first().context("hash set empty")?;
    let computed = PartHash::from_bytes(ed2k::Ed2kBlue::digest(&accumulated).into());
    if computed != expected {
        anyhow::bail!("part hash mismatch: computed {computed:?} vs expected {expected:?}");
    }

    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(&accumulated)?;
    let (_, path) = tmp.keep()?;
    println!(
        "verified {} bytes of part 0 from {} (hash {:?}); wrote to {}",
        accumulated.len(),
        peer_str,
        expected,
        path.display()
    );
    Ok(())
}

/// `a.b.c.d:port` or `[addr]:port` — whichever family the operator typed.
fn parse_peer(input: &str) -> Result<PeerEndpoint> {
    input.parse().context("parse peer addr")
}
