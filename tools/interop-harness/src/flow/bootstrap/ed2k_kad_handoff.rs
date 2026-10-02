//! ed2k-kad-handoff (flow G): the ADR-0067 handoff (peer-tag
//! consume -> Kad dial), now driven end to end by the `rmule-tools ed2k
//! kad-handoff` integrated runner. Topology: an eserver, a counterparty aMule
//! that is BOTH server-connected and Kad-running (its hello carries a live
//! CT_EMULE_UDPPORTS Kad port), a stand-alone rmule Kad seed that bootstraps the
//! aMule to "Kad: Connected" (a third party, so the runner's own node stays
//! uncontacted until the handoff dial), and the runner. On a fake-public /24 so
//! the aMule accepts the seed's Kad datagrams (Config A).

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_amule_kad_connected;
use crate::flow::identity::hex_lower;
use crate::flow::logs::retain_artifact;
use crate::flow::mesh::KAD_TCP_PORT;
use crate::rmule::RmuleClientContainer;

/// The aMule's Kad UDP port (entrypoint `UDP_PORT` default) — the port its
/// hello advertises and the seed / runner dial.
pub(crate) const HANDOFF_AMULE_KAD_UDP_PORT: u16 = 4672;
/// The Kad-seed node's UDP bind port and pinned Kad ID.
pub(crate) const HANDOFF_SEED_UDP_PORT: u16 = 4679;
pub(crate) const HANDOFF_SEED_KAD_ID: [u8; 16] = [0x5E; 16];

/// Options for [`run_ed2k_kad_handoff`] (flow G).
pub struct Ed2kKadHandoffOptions<'a> {
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
    /// The rmule Kad-seed image (the `rmule-tools kad join-node` runner; built from the repo
    /// root like flow F's stimulus node).
    pub seed_image: &'a str,
    /// Build context for the eserver image.
    pub server_build_context: &'a Path,
    /// Build context for the aMule image.
    pub amule_build_context: &'a Path,
    /// Dockerfile for the Kad-seed image.
    pub seed_dockerfile: &'a Path,
    /// Build context for the Kad-seed image (the repo root).
    pub seed_build_context: &'a Path,
    /// The runner container (`cargo run -p rmule-tools -- ed2k kad-handoff`).
    pub rmule_client_container: &'a RmuleClientContainer,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// Budget for the counterparty aMule to reach "Kad: Connected" after the
    /// seed bootstraps it.
    pub kad_connect_deadline_secs: u64,
    /// Seconds the runner waits for the node to reach contact after the handoff.
    pub handoff_window_secs: u64,
    /// Extra environment for the counterparty aMule (`KEY=VALUE`).
    pub amule_env: &'a [String],
}

/// Drive the ed2k→Kad handoff end to end (flow G).
///
/// The runner is at once eD2k-connected to the counterparty aMule and running a
/// Kad node: it consumes the aMule hello's `CT_EMULE_UDPPORTS` Kad port +
/// `CT_EMULE_MISCOPTIONS2` Kad version and brokers a `BootstrapFromPeer` dial,
/// reaching Kad contact. The verdict is read from the runner's own stdout
/// (`kad-handoff result=joined`) plus the observed `CT_EMULE_UDPPORTS` layout —
/// the capture fact the ed2k→Kad handoff and the client-UDP socket rely on.
/// Every leg from the counterparty is genuine: the aMule advertises the port
/// only once it is truly Kad-Connected (via the seed), and it answers the
/// runner's real `BOOTSTRAP_REQ`.
pub fn run_ed2k_kad_handoff(options: Ed2kKadHandoffOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let seed_name = format!("{}-kadseed", bench.names.amule_container_name);

    if options.build_images {
        bench.build_image("server", options.server_image, options.server_build_context)?;
        bench.build_image("aMule", options.amule_image, options.amule_build_context)?;
        run_checked(
            bench.docker.build_image_with_dockerfile(
                options.seed_image,
                options.seed_dockerfile.as_os_str(),
                options.seed_build_context.as_os_str(),
            ),
            "build rmule Kad-seed image",
        )?;
    }
    fs::create_dir_all(options.layout.synthetic_dir())
        .context("create synthetic dir for the aMule share mount")?;

    // Fake-public plan (Config A): a documentation-range /24 so the aMule accepts
    // the seed's Kad datagrams and reaches "Kad: Connected" — the gate on
    // emitting a live CT_EMULE_UDPPORTS Kad port (RFC1918 would be rejected by
    // IsGoodIPPort). eserver .2, aMule .3, seed .4; the runner auto-allocates.
    let server_addr = crate::fake_public::fake_public_address(0)?;
    let amule_addr = crate::fake_public::fake_public_address(1)?;
    let seed_addr = crate::fake_public::fake_public_address(2)?;
    let subnet = server_addr.subnet.clone();
    let amule_ip = amule_addr.ip.clone();
    let timeout = Duration::from_secs(options.timeout_secs);

    let result = (|| -> Result<()> {
        bench.create_network(options.layout, Some(&subnet))?;

        // 1. eserver, on its static address.
        let server = RunContainer::new(options.server_image.to_owned())
            .detach()
            .name(bench.names.server_container_name.clone())
            .network(bench.names.network_name.clone())
            .ip(server_addr.ip.clone());
        bench.start_server_container(options.layout, server)?;

        // 2. Counterparty aMule: server-connected AND Kad-running.
        let amule = bench
            .amule_role_container(options.amule_image)
            .ip(amule_ip.clone())
            .volume(options.layout.synthetic_dir(), "/incoming")
            .env("AMULE_SCENARIO_MODE", "ed2k-server-kad")
            .env("AMULE_KAD_FILTER_LAN_IPS", "1")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            "rmule-amule-server-kad-ready",
            timeout,
        )?;

        // 3. Kad seed: a stand-alone rmule Kad node whose bootstrap makes the
        //    aMule "Kad: Connected" — a THIRD party, so the runner's node stays
        //    uncontacted until it dials via the handoff (a clean-room join).
        let seed_dir = options.layout.docker_dir().join("kad-seed");
        fs::create_dir_all(&seed_dir).with_context(|| format!("create {}", seed_dir.display()))?;
        let seed = RunContainer::new(options.seed_image.to_owned())
            .detach()
            .name(seed_name.clone())
            .network(bench.names.network_name.clone())
            .ip(seed_addr.ip.clone())
            .volume(seed_dir.clone(), "/artifacts")
            .arg("--bind")
            .arg(format!("0.0.0.0:{HANDOFF_SEED_UDP_PORT}"))
            .arg("--id-hex")
            .arg(hex_lower(&HANDOFF_SEED_KAD_ID))
            .arg("--tcp-port")
            .arg(KAD_TCP_PORT.to_string())
            .arg("--bootstrap")
            .arg(format!("{amule_ip}:{HANDOFF_AMULE_KAD_UDP_PORT}"))
            .arg("--capture-dir")
            .arg("/artifacts/tap")
            .arg("--events-file")
            .arg("/artifacts/events.log")
            .arg("--run-secs")
            .arg(
                (options.handoff_window_secs + options.kad_connect_deadline_secs + 60).to_string(),
            );
        bench.start_extra(&seed_name, seed, "run rmule Kad seed")?;

        // 4. Wait for the aMule to reach "Kad: Connected" (the seed's bootstrap).
        if !wait_for_amule_kad_connected(
            &bench.docker,
            &bench.names.amule_container_name,
            options.kad_connect_deadline_secs,
        )? {
            bail!(
                "counterparty aMule did not reach 'Kad: Connected' within {}s (the seed bootstrap \
                 did not take, so no live CT_EMULE_UDPPORTS Kad port would be emitted)",
                options.kad_connect_deadline_secs
            );
        }

        // 5. Run the handoff runner in-network: dial the aMule, consume the tag,
        //    broker the Kad bootstrap, reach contact.
        let peer_endpoint = format!("{amule_ip}:{KAD_TCP_PORT}");
        let output = options
            .rmule_client_container
            .kad_handoff_command(
                bench.staging(options.layout),
                &bench.names.server_endpoint(),
                &peer_endpoint,
                options.handoff_window_secs,
            )
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("run ed2k kad-handoff runner")?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        retain_artifact(
            &options.layout.root().join("kad-handoff-stdout.log"),
            stdout.as_bytes(),
        );
        retain_artifact(
            &options.layout.root().join("kad-handoff-stderr.log"),
            stderr.as_bytes(),
        );

        let observed = stdout
            .lines()
            .find(|line| line.contains("observed CT_EMULE_UDPPORTS"))
            .unwrap_or("(CT_EMULE_UDPPORTS not observed)")
            .trim();
        let joined = output.status.success() && stdout.contains("kad-handoff result=joined");
        let verdict = format!(
            "scenario = \"ed2k-kad-handoff\"\nverdict = {}\njoined = {joined}\n\
             observed = \"{}\"\n",
            if joined { "\"PASS\"" } else { "\"FAIL\"" },
            observed.replace('"', "'")
        );
        fs::write(
            options.layout.root().join("ed2k-kad-handoff-verdict.toml"),
            &verdict,
        )
        .context("write ed2k-kad-handoff verdict")?;
        println!("{observed}");
        println!("ed2k-kad-handoff joined={joined}");

        if !joined {
            bail!(
                "flow G: the ed2k→Kad handoff did not reach joined.\n{observed}\n\
                 --- runner stdout ---\n{stdout}\n--- runner stderr ---\n{stderr}"
            );
        }
        Ok(())
    })();

    bench.cleanup_best_effort();
    result
}
