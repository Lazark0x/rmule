//! The late-port-test leg: stock Lugdunum's port test reaches a serving rmule
//! under `--peer-crypt required` only after the login was answered.
//!
//! Lugdunum answers a login only once its port test ends: a connect it cannot
//! complete gives up after about 8.7 s, a connected test whose `OP_HELLO`
//! draws no answer after about 10.6 s (both measured on this bench), and then
//! it hands out a Low ID. A **network condition** on Lugdunum's own attachment
//! — `tc netem` holding every segment it sends to port 4662 with PSH set, so
//! the handshake completes at once and the test's `OP_HELLO` lands late —
//! stretches the test past that answer without touching either program (the
//! same knob class as `AMULE_FORCE_LOW_ID`'s inbound DROP). rmule's own
//! `server.login … step=port_test_late … admission=refused` record, written
//! when the plaintext opener arrives after the window closed, is the verdict;
//! Lugdunum's Low-ID answer before it is the counterparty's part.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;

/// Lugdunum's no-answer give-up, measured, plus margin: the delay must beat it.
pub const DEFAULT_HELLO_DELAY_MS: u64 = 14_000;
/// The shared file's size (any file; the login announces it).
const SHARE_BYTES: usize = 400_003;
/// The line rmule writes for a test that arrives after the window.
const LATE_STEP: &str = "step=port_test_late";

/// Options for the late-port-test leg.
pub struct LatePortTestOptions<'a> {
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
    /// The `rmule-tools` image, built from the tip under test; it also
    /// carries the `tc` the network condition is applied with.
    pub rmule_tools_image: &'a str,
    /// How long Lugdunum's PSH segments to port 4662 are held.
    pub hello_delay_ms: u64,
}

/// Run the leg and write `late-port-test/verdict.txt`.
pub fn run_late_port_test(options: LatePortTestOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("late-port-test");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let share: Vec<u8> = (0..SHARE_BYTES)
        .map(|index| (index.wrapping_mul(131) ^ (index >> 7)) as u8)
        .collect();
    fs::write(root.join("late-port-test.bin"), share).context("write the shared file")?;

    let result = (|| -> Result<String> {
        bench.create_network(options.layout, None)?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        let server = bench.names.server_container_name.clone();
        let condition = format!(
            "tc qdisc add dev eth0 root handle 1: prio \
             && tc qdisc add dev eth0 parent 1:3 handle 30: netem delay {}ms \
             && tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 \
                match ip dport 4662 0xffff match u8 0x08 0x08 at 33 flowid 1:3 \
             && tc qdisc show dev eth0",
            options.hello_delay_ms
        );
        let applied = run_checked(
            bench.docker.run_container(
                RunContainer::new(options.rmule_tools_image.to_owned())
                    .network(format!("container:{server}"))
                    .cap_add("NET_ADMIN")
                    .entrypoint("sh")
                    .arg("-c")
                    .arg(condition)
                    .remove_after_exit(),
            ),
            "hold Lugdunum's segments to port 4662",
        )?;
        fs::write(root.join("tc.txt"), format!("{applied}\n")).context("write tc.txt")?;

        let rmule = format!("{server}-late-rmule");
        let endpoint = bench.names.server_endpoint();
        let serve = [
            "ed2k",
            "serve",
            "start",
            "--file",
            "/w/late-port-test.bin",
            "--server",
            &endpoint,
            "--peer-crypt",
            "required",
            "--listen",
            "0.0.0.0:4662",
            "--tcp-port",
            "4662",
            "--user-hash",
            "5E2A9C71B40D3F8862A1C7E0D93B4F16",
            "--nickname",
            "late-port-test",
            "--max-seconds",
            "90",
        ];
        let container = serve.into_iter().fold(
            RunContainer::new(options.rmule_tools_image.to_owned())
                .detach()
                .name(&rmule)
                .network(bench.names.network_name.clone())
                .env("RMULE_LOG", "info")
                .volume(&root, "/w"),
            RunContainer::arg,
        );
        bench.start_extra(&rmule, container, "run the serving rmule")?;
        let waited = wait_for_container_log(
            &bench.docker,
            &rmule,
            LATE_STEP,
            timeout.max(Duration::from_millis(options.hello_delay_ms) * 3),
        );
        let log = run_checked(bench.docker.logs(rmule.clone()), "rmule logs")?;
        fs::write(root.join("rmule.log"), format!("{log}\n")).context("write rmule.log")?;
        waited?;
        verdict(&log)
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let verdict = result?;
    fs::write(root.join("verdict.txt"), format!("{verdict}\n")).context("write verdict")?;
    println!("{verdict}");
    Ok(())
}

/// PASS when the login was answered with the window closed and no test, and
/// the late test was then refused.
fn verdict(log: &str) -> Result<String> {
    let answered_without = log
        .lines()
        .any(|line| line.contains("step=port_test_window_closed arrived=no"));
    let Some(late) = log.lines().find(|line| line.contains(LATE_STEP)) else {
        bail!("rmule wrote no {LATE_STEP} line");
    };
    let refused = late.contains("admission=refused");
    let outcome = if answered_without && refused {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(format!(
        "verdict={outcome} window_closed_without_test={answered_without} late_refused={refused} line=\"{}\"",
        late.trim()
    ))
}
