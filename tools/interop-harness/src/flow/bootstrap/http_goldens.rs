//! http-bootstrap-goldens (flow H): author the aMule-written server.met
//! golden and assemble the local HTTP-fixture payload for the cold-start
//! bootstrap pipeline. The full flow — a fresh rmule fetching server.met +
//! nodes.dat over HTTP and then joining — additionally needs an rmule
//! bootstrap-fetch runner that does not exist yet; this flow delivers the
//! runnable, capture-faithful half (aMule-authored goldens) and reports the
//! consumption gap + the v2-nodes.dat hole precisely (an input to the
//! server.met bootstrap pipeline).

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::flow::bench::{Bench, Eserver};
use crate::flow::bootstrap::AMULE_CONFIG_DIR;
use crate::flow::evidence::{flush_golden_files, read_flushed_golden};
use crate::flow::mesh::KAD_CONTACT_VERSION;

/// Options for [`run_http_bootstrap_goldens`] (flow H).
pub struct HttpBootstrapGoldensOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Build the project-owned images before starting anything.
    pub build_images: bool,
    /// The eserver image.
    pub server_image: &'a str,
    /// The aMule image.
    pub amule_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Host TCP port the eserver's port is published on (the readiness probe target).
    pub server_host_port: u16,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// Extra `KEY=VALUE` environment for the aMule container(s).
    pub amule_env: &'a [String],
    /// Log substring that marks the aMule container ready.
    pub amule_ready_log_pattern: &'a str,
}

/// Author the HTTP-bootstrap goldens (flow H).
///
/// Boots the eserver + one aMule that connects to it (so its server list is
/// populated), then does a clean `amulecmd Shutdown` and harvests the
/// aMule-authored `server.met` (`SaveServerMet`) into the run dir's
/// `bootstrap-fixture/`. That golden is **never hand-crafted** — it is exactly
/// what a pinned aMule persists. The Kad leg's `nodes.dat` is seeded from the
/// `kad_seed` builders (a documentation-range contact), since a genuine **v2**
/// `nodes.dat` cannot be harvested from an eD2k-only aMule (it never runs Kad,
/// so it writes none) and harvesting one needs a ≥25-contact swarm spanning ≥3
/// `/24`s. The v2 hole and the missing rmule HTTP-consumption
/// runner are recorded in `http-bootstrap-goldens-report.toml`.
///
/// Success here = the aMule-authored `server.met` golden exists and the fixture
/// payload is assembled. The full cold-start (fresh rmule fetches both over
/// HTTP → connects → Kad-joins) is gated on a bootstrap-fetch runner — reported,
/// not faked.
pub fn run_http_bootstrap_goldens(options: HttpBootstrapGoldensOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
    }
    let timeout = Duration::from_secs(options.timeout_secs);
    let fixture_dir = options.layout.root().join("bootstrap-fixture");

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, None)?;
        bench.start_eserver(
            options.layout,
            &Eserver {
                image: options.server_image,
                host_port: options.server_host_port,
                env: options.server_env,
                timeout,
            },
        )?;

        // The aMule connects to the server and populates its server list, so the
        // SaveServerMet flush writes a meaningful server.met.
        let amule = bench
            .amule_role_container(options.amule_image)
            .env("AMULE_SHARED_DIR", "/incoming")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            options.amule_ready_log_pattern,
            timeout,
        )?;

        // Golden flush: clean Shutdown → SaveServerMet, then docker cp out. The
        // aMule container is then a stopped container; cleanup removes it
        // (`docker rm -f` on a stopped container is fine — no double-removal).
        let copied = flush_golden_files(
            &bench.docker,
            &bench.names.amule_container_name,
            AMULE_CONFIG_DIR,
            &fixture_dir,
        )?;

        let server_met = fixture_dir.join("server.met");
        let server_met_data = read_flushed_golden(&server_met)?;
        let server_met_bytes = server_met_data.len() as u64;
        let server_met_authored = server_met_bytes > 0;
        let server_met_first_byte = server_met_data
            .first()
            .map(|b| format!("0x{b:02x}"))
            .unwrap_or_else(|| "none".to_owned());
        // aMule's server.met is [u8 magic 0xE0][u32 LE count][entries…]. A usable
        // golden needs count ≥ 1; the eD2k-server entrypoint (Serverlist=0,
        // AddServerListFrom*=0) connects but does NOT persist the server, so the
        // harvested file is aMule-authored yet empty (count 0). The harvest
        // MECHANISM is proven; a populated golden needs a server-list-persisting
        // aMule variant (reported, not faked).
        let server_met_server_count = if server_met_data.len() >= 5 {
            u32::from_le_bytes([
                server_met_data[1],
                server_met_data[2],
                server_met_data[3],
                server_met_data[4],
            ])
        } else {
            0
        };
        // A v2 nodes.dat cannot come from an eD2k-only aMule (no Kad → no write).
        let nodes_dat = fixture_dir.join("nodes.dat");
        let v2_nodes_dat_harvested =
            copied.contains(&nodes_dat) && !read_flushed_golden(&nodes_dat)?.is_empty();

        // Seed the Kad-leg nodes.dat from the kad_seed builders (a
        // documentation-range contact) so the fixture payload is complete for
        // the day an rmule bootstrap-fetch runner consumes it. This is a
        // harness-built seed, explicitly NOT a v2 golden.
        let seed_contact = crate::kad_seed::KadContact {
            kad_id: [0x5E; 16],
            ipv4: [203, 0, 113, 2],
            udp_port: 4672,
            tcp_port: 4662,
            version: KAD_CONTACT_VERSION,
        };
        let seed_nodes_dat = crate::kad_seed::build_bootstrap_nodes_dat(&[seed_contact]);
        let seed_path = fixture_dir.join("nodes.dat.seed");
        fs::write(&seed_path, &seed_nodes_dat)
            .with_context(|| format!("write {}", seed_path.display()))?;

        write_http_bootstrap_report(
            options.layout,
            server_met_authored,
            server_met_bytes,
            &server_met_first_byte,
            server_met_server_count,
            v2_nodes_dat_harvested,
        )?;

        if !server_met_authored {
            bail!(
                "flow H: aMule wrote no server.met (SaveServerMet flush produced an empty/absent \
                 file) — the golden-author leg failed; see {}",
                fixture_dir.display()
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

fn write_http_bootstrap_report(
    layout: &RunLayout,
    server_met_authored: bool,
    server_met_bytes: u64,
    server_met_first_byte: &str,
    server_met_server_count: u32,
    v2_nodes_dat_harvested: bool,
) -> Result<()> {
    let server_met_populated = server_met_server_count > 0;
    let text = format!(
        "scenario = \"http-bootstrap-goldens\"\n\
         server_met_authored = {server_met_authored}\n\
         server_met_bytes = {server_met_bytes}\n\
         server_met_first_byte = \"{server_met_first_byte}\"\n\
         server_met_server_count = {server_met_server_count}\n\
         server_met_populated = {server_met_populated}\n\
         # RESOLVED (persisted server.met golden): pass AMULE_PERSIST_SERVERLIST=1 to seed the eserver into\n\
         # m_servers before amuled starts, so a clean Shutdown re-authors a populated server.met\n\
         # (amulecmd `Add ed2k://|server|` routes to the download queue, not the server list, so\n\
         # without the seed SaveServerMet writes 0 servers). flush_golden_files now `docker\n\
         # wait`s so the write_safe rename lands before docker cp.\n\
         v2_nodes_dat_harvested = {v2_nodes_dat_harvested}\n\
         # RESOLVED (v2 nodes.dat harvest): a genuine v2 nodes.dat comes from the separate\n\
         # `v2-nodes-dat-harvest` subcommand (a seeded routing-zone table > 25 contacts). It is\n\
         # NOT harvested here (eD2k-only aMule runs no Kad, so CRoutingZone::WriteFile never\n\
         # fires); the nodes.dat.seed below is a harness kad_seed builder output, not a v2 golden.\n\
         # RESOLVED (bootstrap-fetch runner): `rmule-tools ed2k bootstrap-fetch` fetches server.met +\n\
         # nodes.dat over HTTP, connects, and Kad-joins; the full cold start runs green via the\n\
         # `http-bootstrap-cold-start` subcommand (flow H). This subcommand authors the goldens\n\
         # half; the cold-start subcommand runs the consumption half end to end.\n\
         verdict = \"{}\"\n",
        match (server_met_authored, server_met_populated) {
            (true, true) => "PARTIAL-golden-populated",
            (true, false) => "PARTIAL-golden-authored-empty",
            (false, _) => "FAIL",
        },
    );
    let path = layout.root().join("http-bootstrap-goldens-report.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("{text}");
    println!(
        "http-bootstrap-goldens report written to {}",
        path.display()
    );
    Ok(())
}
