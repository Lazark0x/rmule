//! v2-nodes-dat-harvest (flow H leg 3): author the aMule-written v2
//! nodes.dat golden. An eD2k-only aMule runs no Kad, so CRoutingZone::WriteFile
//! never fires; this boots ONE aMule in kad-node mode seeded with a routing-zone
//! nodes.dat spanning many distinct non-reserved /24s (kad_seed's
//! build_v2_harvest_seed_nodes_dat), so aMule loads >= 25 contacts into its live
//! tree and re-authors them as a genuine v2 nodes.dat on a clean Shutdown.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::bootstrap::AMULE_CONFIG_DIR;
use crate::flow::evidence::{flush_golden_files, read_flushed_golden};

/// The aMule Kad role the harvest node runs as (a lone routing seed idles once
/// Kad has started — no live counterparty is needed to fill the seeded table).
const V2_HARVEST_KAD_ROLE: &str = "routing";
/// Minimum contacts a genuine v2 harvest must carry — aMule's own
/// `CRoutingZone::WriteFile` gate (`if (numContacts < 25) ... return;`).
const V2_HARVEST_MIN_CONTACTS: u32 = 25;

/// Options for [`run_v2_nodes_dat_harvest`] (flow H leg 3).
pub struct V2NodesDatHarvestOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The aMule image.
    pub amule_image: &'a str,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Extra environment for the harvest aMule (`KEY=VALUE`).
    pub amule_env: &'a [String],
}

/// Harvest a genuine **v2 nodes.dat** golden from a seeded aMule Kad routing
/// table (flow H leg 3).
///
/// Boots one aMule in kad-node mode seeded (via `AMULE_KAD_NODES_DAT`) with the
/// [`crate::kad_seed::build_v2_harvest_seed_nodes_dat`] routing-zone file, waits
/// for Kad to start (the contacts are already loaded into the live tree by then),
/// then does a clean `amulecmd Shutdown` (+ `docker wait`) so
/// `CRoutingZone::WriteFile` persists the table as a v2 nodes.dat, and copies it
/// out. Success = the harvested file is a real v2 nodes.dat (`[0][2]` header)
/// carrying >= 25 contacts (aMule's own write threshold). The bytes are aMule's
/// WriteFile output; the seed is a bootstrap INPUT (seeded-then-persisted
/// provenance, ADR-0045) — never hand-crafted golden bytes.
pub fn run_v2_nodes_dat_harvest(options: V2NodesDatHarvestOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
    }

    // Write the routing-zone seed the aMule loads at Kad start.
    let seed_dir = options.layout.kad_node_seed_dir(V2_HARVEST_KAD_ROLE);
    fs::create_dir_all(&seed_dir)
        .with_context(|| format!("create seed dir {}", seed_dir.display()))?;
    let seed_path = seed_dir.join("nodes.dat");
    fs::write(
        &seed_path,
        crate::kad_seed::build_v2_harvest_seed_nodes_dat(),
    )
    .with_context(|| format!("write seed {}", seed_path.display()))?;

    let harvest_dir = options.layout.root().join("v2-nodes-dat-harvest");

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, None)?;

        let amule = RunContainer::new(options.amule_image.to_owned())
            .detach()
            .name(bench.names.amule_container_name.clone())
            .network(bench.names.network_name.clone())
            .volume(seed_dir.clone(), "/seed")
            .env("AMULE_SCENARIO_MODE", "kad-node")
            .env("AMULE_KAD_ROLE", V2_HARVEST_KAD_ROLE)
            .env("AMULE_KAD_NODES_DAT", "/seed/nodes.dat")
            // The 45.55.x seed /24s are non-reserved and non-LAN, so keep the node
            // off LAN mode — IsGoodIP admits them on the normal paths.
            .env("AMULE_KAD_FILTER_LAN_IPS", "1")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            "rmule-kad-routing-ready",
            Duration::from_secs(options.timeout_secs),
        )?;

        // Golden flush: clean Shutdown -> CRoutingZone::WriteFile -> docker cp.
        let copied = flush_golden_files(
            &bench.docker,
            &bench.names.amule_container_name,
            AMULE_CONFIG_DIR,
            &harvest_dir,
        )?;

        let nodes_dat = harvest_dir.join("nodes.dat");
        let harvested = copied.iter().any(|p| p == &nodes_dat);
        let bytes = read_flushed_golden(&nodes_dat)?;
        let (version, count) = parse_nodes_dat_header(&bytes);
        write_v2_harvest_report(
            options.layout,
            harvested,
            bytes.len() as u64,
            version,
            count,
        )?;

        if !harvested || version != 2 {
            bail!(
                "flow H leg 3: aMule did not write a v2 nodes.dat (harvested={harvested}, \
                 version={version}); see {}",
                harvest_dir.display()
            );
        }
        if count < V2_HARVEST_MIN_CONTACTS {
            bail!(
                "flow H leg 3: harvested v2 nodes.dat carries {count} contacts, below aMule's own \
                 {V2_HARVEST_MIN_CONTACTS}-contact WriteFile threshold — not a usable golden"
            );
        }
        Ok(())
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

/// Read a nodes.dat header: `[u32 0][u32 version][u32 count]`. Returns
/// `(version, count)`, or `(0, 0)` if the bytes are too short.
fn parse_nodes_dat_header(bytes: &[u8]) -> (u32, u32) {
    if bytes.len() < 12 {
        return (0, 0);
    }
    let word = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    // A v2 file leads with a zero marker; the version and count follow.
    (word(4), word(8))
}

fn write_v2_harvest_report(
    layout: &RunLayout,
    harvested: bool,
    nodes_dat_bytes: u64,
    version: u32,
    contact_count: u32,
) -> Result<()> {
    let text = format!(
        "scenario = \"v2-nodes-dat-harvest\"\n\
         nodes_dat_harvested = {harvested}\n\
         nodes_dat_bytes = {nodes_dat_bytes}\n\
         nodes_dat_version = {version}\n\
         contact_count = {contact_count}\n\
         # A genuine v2 nodes.dat from CRoutingZone::WriteFile: the aMule was seeded with a\n\
         # routing-zone (v1) nodes.dat spanning {seed} distinct non-reserved /24s so its live Kad\n\
         # tree held >= 25 contacts, then re-authored them as v2 on a clean Shutdown. The bytes\n\
         # are aMule's WriteFile output (seeded-then-persisted, ADR-0045), never hand-crafted.\n\
         verdict = \"{verdict}\"\n",
        seed = crate::kad_seed::V2_HARVEST_SEED_CONTACTS,
        verdict = if harvested && version == 2 && contact_count >= V2_HARVEST_MIN_CONTACTS {
            "GOLDEN-v2-authored"
        } else {
            "FAIL"
        },
    );
    let path = layout.root().join("v2-nodes-dat-harvest-report.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    Ok(())
}
