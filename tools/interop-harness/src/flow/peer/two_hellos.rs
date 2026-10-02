//! The two-hellos leg: does a second connection's hello from a known client
//! make stock aMule delete the first connection's socket?
//!
//! Two downloads of one core from one High-ID aMule open two peer-TCP
//! connections to it, each saying the same user hash and listen port. Stock
//! aMule 2.3.3's `CClientList::AttachToAlreadyKnown` (ClientList.cpp:386-403,
//! reached from ClientTCPSocket.cpp:391) deletes the known client's socket
//! when the new hello matches it by IP and port, and refuses the new hello
//! instead when the port differs. `hello_twice.py` asks both from two
//! addresses (the `same-port` leg and the `other-port` control): what it sends
//! is Stimulus; whether aMule closed each socket, and aMule's own debug log
//! (`amule/diagnostics`), are the evidence. One `leg=… first_socket_closed=…`
//! line per leg lands in `two-hellos/verdict.txt`.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::ed2k_server::search_wire::SUBNET;
use crate::flow::logs::collect_amule_diagnostics;

/// The probe, written into the run dir and mounted.
const HELLO_TWICE: &str = include_str!("two_hellos/hello_twice.py");
/// The legs, each from a static address of its own: the runtime hands a
/// removed container's address to the next one, and aMule bans an address
/// that says a second user hash.
const LEGS: [(&str, &str); 2] = [
    ("same-port", "203.0.113.61"),
    ("other-port", "203.0.113.62"),
];

/// Options for the two-hellos leg.
pub struct TwoHellosOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The Lugdunum eserver image (aMule's High ID comes from its login).
    pub server_image: &'a str,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// The aMule image; a debug build also logs the peer-protocol trail.
    pub amule_image: &'a str,
    /// Extra `KEY=VALUE` environment for the aMule container.
    pub amule_env: &'a [String],
    /// Log substring that marks the aMule container ready.
    pub amule_ready_log_pattern: &'a str,
    /// An image carrying `python3`, the probe's interpreter.
    pub probe_image: &'a str,
}

/// Run both legs against one High-ID aMule.
pub fn run_two_hellos(options: TwoHellosOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("two-hellos");
    let share = root.join("share");
    fs::create_dir_all(&share).with_context(|| format!("create {}", share.display()))?;
    fs::write(root.join("hello_twice.py"), HELLO_TWICE).context("write hello_twice.py")?;
    // aMule logs in with something to share, as a download's source would.
    fs::write(
        share.join("two-hellos-a.bin"),
        [0x5a_u8, 0x17, 0xc3, 0x08].repeat(65_536),
    )
    .context("write the shared file")?;

    let result = (|| -> Result<Vec<String>> {
        bench.create_network(options.layout, Some(SUBNET))?;
        bench.start_eserver_in_network(
            options.layout,
            options.server_image,
            options.server_env,
            timeout,
        )?;
        let amule = bench
            .amule_role_container(options.amule_image)
            .volume(&share, "/incoming")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("AMULE_VERBOSE", "1")
            .env("AMULE_DEBUG_PEER_CATEGORIES", "1")
            .env_assignments(options.amule_env);
        bench.start_amule(
            options.layout,
            amule,
            options.amule_ready_log_pattern,
            timeout,
        )?;
        let target = format!("{}:4662", bench.names.amule_container_name);
        let mut verdicts = Vec::new();
        for (leg, address) in LEGS {
            let probe = RunContainer::new(options.probe_image.to_owned())
                .name(format!("{}-{leg}", bench.names.amule_container_name))
                .network(bench.names.network_name.clone())
                .ip(address)
                .volume(&root, "/w")
                .entrypoint("python3")
                .arg("/w/hello_twice.py")
                .arg(&target)
                .arg(leg)
                .remove_after_exit();
            let out = run_checked(bench.docker.run_container(probe), "run hello_twice")?;
            fs::write(root.join(format!("{leg}.jsonl")), format!("{out}\n"))
                .with_context(|| format!("write {leg}.jsonl"))?;
            verdicts.push(verdict_line(leg, &out)?);
        }
        collect_amule_diagnostics(
            &bench.docker,
            options.layout,
            &bench.names.amule_container_name,
        )?;
        Ok(verdicts)
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let verdicts = result?;
    fs::write(root.join("verdict.txt"), verdicts.join("\n") + "\n").context("write verdict")?;
    for line in &verdicts {
        println!("{line}");
    }
    Ok(())
}

/// The leg's verdict line, refused when the first hello drew no answer (the
/// leg then measured nothing).
fn verdict_line(leg: &str, out: &str) -> Result<String> {
    let first_answered = out.lines().any(|line| {
        line.contains("\"conn\": 1, \"event\": \"hello\"") && line.contains("0xe3/0x4c")
    });
    if !first_answered {
        bail!("{leg}: aMule never answered the first hello");
    }
    let Some(verdict) = out
        .lines()
        .find(|line| line.contains("\"event\": \"verdict\""))
    else {
        bail!("{leg}: the probe printed no verdict");
    };
    let closed = verdict.contains("\"first_socket_closed\": true");
    let answered = verdict.contains("\"second_answered\": true");
    Ok(format!(
        "leg={leg} first_socket_closed={closed} second_hello_answered={answered}"
    ))
}
