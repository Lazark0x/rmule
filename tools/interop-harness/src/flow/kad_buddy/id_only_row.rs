//! `kad-core-buddy --amule-requester`'s **ID-only row**: the type-3 row the stock aMule
//! requester reads names its buddy by `TAG_BUDDYHASH` alone, with no
//! `TAG_SERVERIP`/`TAG_SERVERPORT`, so the requester cannot address the buddy
//! and takes aMule's `FINDSOURCE` road instead (`BaseClient.cpp:2159-2175`,
//! kno `ab483654`): a Kad walk toward the buddy ID, and the `0x52` sent to
//! whoever answers inside `SEARCHTOLERANCE` (`Search.cpp:1081-1122`).
//!
//! **Who publishes it, and why that is admissible (ADR-0045).** No stock aMule
//! writes this row — its publisher always holds the buddy's endpoint
//! (`Search.cpp:840-855`) — and a patched aMule is not admissible. So the
//! publisher is rmule: a `kad join-node` whose source publish names the flow's
//! rmule buddy by ID alone (`--publish-buddy-id`, rmule-kad's own
//! `SetPublishPosture` writer with no endpoint). The firewalled aMule shares
//! nothing under this variant, so its own endpoint-carrying row never exists
//! and the requester's `FILE` search can read only this one. The requester —
//! the body whose bytes are the evidence — stays stock.
//!
//! The publisher waits for the rmule buddy's `buddy link attached`: the row
//! then names a node that really is somebody's buddy, and the `0x52` the walk
//! delivers finds a held link to relay over.
//!
//! **Carried to a transfer.** A requester builds a type-3 source
//! from the row's source ID alone — client ID 1, the row's IP unused
//! (`DownloadQueue.cpp:1762-1777`) — and matches the body that later dials it
//! back by user hash. So under `--findsource-transfer` the firewalled aMule
//! shares the file under [`FIREWALLED_USER_HASH`] and the publisher writes the
//! row under that same hash. aMule has no setting that shares a file without
//! publishing it (`CSharedFileList::Publish` publishes every shared file once
//! the node is connected, or firewalled with a buddy, `SharedFileList.cpp:
//! 1735-1737`), so its own endpoint row reaches the storer too: the publisher
//! waits for it to be indexed first. The rmule storer serves a key's rows
//! newest first (`source_store.rs` `lookup`), and aMule's requester keeps the
//! first row per user hash and drops the rest (`CheckAndAddSource`,
//! `DownloadQueue.cpp:702-724`), so the ID-only row is the one it adopts.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{KadMeshNames, KadResources, run_checked};
use crate::flow::gate::{wait_for_host_file, wait_for_kad_trail};
use crate::flow::identity::hex_lower;
use crate::flow::kad_member::PlacedMember;

/// The publisher's Kad ID: far from the buddy ID and the file key, so it is
/// neither the walk's answer nor a storer.
const PUBLISHER_KAD_ID: [u8; 16] = [0x5C; 16];
/// The publisher's Kad UDP bind.
const PUBLISHER_UDP_PORT: u16 = 4672;
/// The TCP port the row states. Nothing listens there: no requester ever
/// reaches the publisher, only the buddy the row names.
const PUBLISHER_TCP_PORT: u16 = 4662;
/// How long the publisher lives: its publish is acked in seconds, and the
/// storer keeps the row long after it leaves.
const PUBLISHER_RUN_SECS: u64 = 180;
/// The firewalled aMule's user hash under `--findsource-transfer`, pinned in
/// its `preferences.dat` and written into the ID-only row. Pre-stamped:
/// aMule overwrites byte 5 with `0x0E` and byte 14 with `0x6F` after loading
/// the pin (`Preferences.cpp:1081-1082`, kno `ab483654`), so a
/// pin that already carries both is the hash its hello sends.
pub(crate) const FIREWALLED_USER_HASH: &str = "4a4a4a4a4a0e4a4a4a4a4a4a4a4a6f4a";

/// What the publisher is told.
pub(crate) struct IdOnlyRowPlan<'a> {
    pub(crate) image: &'a str,
    pub(crate) address_v4: String,
    /// The placed storer's Kad endpoint, `ip:port` — the publisher's bootstrap
    /// and, at distance 0 from the file key, the publish's destination.
    pub(crate) storer_kad: String,
    /// The buddy ID the row names, wire order: the rmule buddy's own Kad ID.
    pub(crate) buddy_id: [u8; 16],
    /// Publish under [`FIREWALLED_USER_HASH`], once the storer has indexed the
    /// firewalled aMule's own row.
    pub(crate) after_firewalled_row: bool,
}

/// Wait for the rmule buddy to hold its link (and, under
/// [`IdOnlyRowPlan::after_firewalled_row`], for `storer_events` to show the
/// firewalled aMule's own row), then publish the ID-only row. Returns whether
/// the link was held before the publish went out.
///
/// # Errors
/// If the link cannot be read or the publisher cannot be started.
pub(crate) fn publish(
    docker: &Docker,
    layout: &RunLayout,
    names: &KadMeshNames,
    resources: &mut KadResources<'_>,
    plan: &IdOnlyRowPlan<'_>,
    storer_events: &Path,
    window: Duration,
) -> Result<bool> {
    let held = wait_for_kad_trail(
        docker,
        layout,
        "rmule",
        &names.rmule,
        "buddy link attached",
        window,
    )?;
    println!("kad-id-only-row: rmule buddy link held before the publish = {held}");
    if plan.after_firewalled_row {
        let indexed = wait_for_host_file(storer_events, "SourceIndexed", window)?;
        println!("kad-id-only-row: the firewalled aMule's own row indexed first = {indexed}");
    }
    let link =
        fs::read_to_string(layout.synthetic_ed2k_file()).context("read the synthetic ed2k link")?;
    let mut fields = link.trim().split('|');
    let (Some(size), Some(hash)) = (fields.nth(3), fields.next()) else {
        anyhow::bail!("ed2k link has no size/hash fields: {link}");
    };
    let dir = layout.kad_dir().join("publisher");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let kad_id = hex_lower(&PUBLISHER_KAD_ID);
    let mut container = PlacedMember {
        image: plan.image,
        container: &names.publisher,
        network: &names.network_name,
        address_v4: &plan.address_v4,
        udp_port: PUBLISHER_UDP_PORT,
        tcp_port: PUBLISHER_TCP_PORT,
        kad_id: &kad_id,
        bootstrap: Some(&plan.storer_kad),
        host_dir: &dir,
        run_secs: PUBLISHER_RUN_SECS,
    }
    .container_spec()
    .arg("--publish-file-hash")
    .arg(hash.to_ascii_lowercase())
    .arg("--publish-file-size")
    .arg(size)
    .arg("--publish-buddy-id")
    .arg(hex_lower(&plan.buddy_id));
    if plan.after_firewalled_row {
        container = container.arg("--user-hash-hex").arg(FIREWALLED_USER_HASH);
    }
    run_checked(
        docker.run_container(container),
        "run the ID-only row publisher",
    )?;
    resources.track_started("publisher", names.publisher.clone());
    Ok(held)
}
