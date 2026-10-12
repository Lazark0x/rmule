//! The sx1-gate leg: a source that states source-exchange version 1 is never
//! asked for sources; one that states version 3 is.
//!
//! **Fake-backed, not interop proof.** No stock body the bench holds states
//! SX1 version 1 (aMule 2.3.3 says 3 and SourceExchange2), so this one row of
//! ADR-0108's source-ask gate is staged against `fake_source.py`, a scripted
//! eMule-family source. Per leg the fake logs in to Lugdunum High ID and
//! offers a file of its own; a downloading rmule finds it there, dials it and
//! is queued; the fake counts the `0xC5/0x81` and `0xC5/0x83` rmule sends.
//! Version 3 is the control that shows the ask would have been visible. The
//! summaries land in `sx1-gate/verdict.txt`.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::ed2k_server::search_wire::SUBNET;

/// The fake, written into the run dir and mounted.
const FAKE_SOURCE: &str = include_str!("sx1_gate/fake_source.py");
/// Per leg: the SX1 version the fake states, its file hash, rmule's user
/// hash (all asymmetric), and the fake's static address on the bench network,
/// the one its listener binds.
const LEGS: [(u8, &str, &str, &str); 2] = [
    (
        1,
        "4B6E1A2C93D0578FE6A1B2C3D4E5F607",
        "2A7F4C91E03B58D6A1C4E7F0923B5D61",
        "203.0.113.81",
    ),
    (
        3,
        "9C2D7E4B1A0F58C3D6E9B2A57F4C1D83",
        "2A7F4C91E03B58D6A1C4E7F0923B5D63",
        "203.0.113.83",
    ),
];
/// How long the fake stays up; rmule's download runs inside it.
const FAKE_SECS: u64 = 70;
const DOWNLOAD_SECS: u64 = 50;

/// Options for the sx1-gate leg.
pub struct Sx1GateOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The Lugdunum eserver image.
    pub server_image: &'a str,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// The `rmule-tools` image, built from the tip under test.
    pub rmule_tools_image: &'a str,
    /// An image carrying `python3`, the fake's interpreter.
    pub probe_image: &'a str,
}

/// Run both legs side by side and write the verdict.
pub fn run_sx1_gate(options: Sx1GateOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("sx1-gate");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    fs::write(root.join("fake_source.py"), FAKE_SOURCE).context("write fake_source.py")?;

    let result = (|| -> Result<Vec<String>> {
        bench.create_network(options.layout, Some(SUBNET))?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        let server = bench.names.server_endpoint();
        let prefix = bench.names.server_container_name.clone();
        let network = bench.names.network_name.clone();
        let mut fakes = Vec::new();
        for (version, file_hash, _, address) in LEGS {
            let fake = format!("{prefix}-sx1fake{version}");
            let container = RunContainer::new(options.probe_image.to_owned())
                .detach()
                .name(&fake)
                .network(network.clone())
                .ip(address)
                .volume(&root, "/w")
                .entrypoint("python3")
                .arg("/w/fake_source.py")
                .arg(version.to_string())
                .arg(FAKE_SECS.to_string())
                .arg(&server)
                .arg(file_hash)
                .arg(address);
            bench.start_extra(&fake, container, "run the fake source")?;
            fakes.push((version, fake));
        }
        // The fakes' offers reach the server before rmule asks it.
        std::thread::sleep(Duration::from_secs(5));
        for (version, file_hash, user_hash, _) in LEGS {
            let rmule = format!("{prefix}-sx1rmule{version}");
            let link = format!("ed2k://|file|sx1-gate.bin|9728000|{file_hash}|/");
            let args = [
                "ed2k",
                "download",
                "start",
                "--data-dir",
                &format!("/w/data-{version}"),
                "--server",
                &server,
                "--file",
                &link,
                "--out",
                &format!("/w/dl/out-{version}.bin"),
                "--user-hash",
                user_hash,
                "--max-seconds",
                &DOWNLOAD_SECS.to_string(),
            ];
            let container = args.into_iter().fold(
                RunContainer::new(options.rmule_tools_image.to_owned())
                    .detach()
                    .name(&rmule)
                    .network(network.clone())
                    .env("RMULE_LOG", "info")
                    .volume(&root, "/w"),
                RunContainer::arg,
            );
            bench.start_extra(&rmule, container, "run the downloading rmule")?;
        }
        let mut summaries = Vec::new();
        for (version, fake) in fakes {
            run_checked(bench.docker.wait(fake.clone()), "wait for the fake")?;
            let log = run_checked(bench.docker.logs(fake.clone()), "fake logs")?;
            fs::write(
                root.join(format!("fake-sx1-{version}.jsonl")),
                format!("{log}\n"),
            )
            .context("write the fake's log")?;
            let rmule = format!("{prefix}-sx1rmule{version}");
            let rmule_log = run_checked(bench.docker.logs(rmule.clone()), "rmule logs")?;
            fs::write(
                root.join(format!("rmule-sx1-{version}.log")),
                format!("{rmule_log}\n"),
            )
            .context("write rmule's log")?;
            let Some(summary) = log.lines().find(|l| l.starts_with("sx1-gate-summary")) else {
                bail!("the SX1 {version} fake printed no summary");
            };
            summaries.push(summary.to_owned());
        }
        Ok(summaries)
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let summaries = result?;
    let asked = |line: &str| !line.contains("requestsources=0 requestsources2=0");
    let dialled = |line: &str| !line.contains("connections=0");
    let pass = summaries.len() == 2
        && dialled(&summaries[0])
        && !asked(&summaries[0])
        && dialled(&summaries[1])
        && asked(&summaries[1]);
    let verdict = format!(
        "verdict={} (fake-backed)\n{}\n",
        if pass { "PASS" } else { "FAIL" },
        summaries.join("\n")
    );
    fs::write(root.join("verdict.txt"), &verdict).context("write verdict")?;
    print!("{verdict}");
    Ok(())
}
