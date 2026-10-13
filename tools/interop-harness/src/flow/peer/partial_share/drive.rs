//! The partial-share flow's steps once rmule runs: each link added, each
//! gate written and each stimulus run at the moment its claim wants, read
//! off rmule's own stamped trail as it grows.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use super::legs::{self, RUN_MOUNT, STIMULUS_USER_HASH};
use super::marks::{self, Trail};
use super::verdict::{Action, DURING_CHECK, PRE_PART, ROOT_DIR, STRADDLE, Stimulus, TopologyFile};
use super::{DOWNLOADER, PROBER, PartialShareOptions, QUEUED, WHOLE_PROBER};
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{Bench, amulecmd_command, run_checked};
use crate::flow::peer::streaming_window::seed::SeedHolding;
use crate::rmule::RMULE_SERVE_TCP_PORT;

/// A stimulus's whole run: its asks, then the link held open.
const STIMULUS_SECS: u64 = 40;
/// How long a stimulus range waits for its bytes before the next one goes.
const STIMULUS_RANGE_WAIT_SECS: u64 = 10;
/// The `sh -c` script a held stimulus runs: wait for the file its `$0`
/// names, then exec the rest of its arguments untouched (a link's `|`
/// included).
const HOLD_UNTIL_GATE: &str = r#"while [ ! -e "$0" ]; do sleep 0.1; done; exec "$@""#;
/// The `rmule-tools` image's own entrypoint.
const IMAGE_ENTRYPOINT: &str = "/entrypoint.sh";

/// The steps after rmule starts, and what they need.
pub(super) struct Drive<'a> {
    pub(super) options: &'a PartialShareOptions<'a>,
    pub(super) root: &'a Path,
    pub(super) rmule: &'a str,
    pub(super) suffix: &'a str,
    pub(super) timeout: Duration,
    /// The stream file's link for a downloader: rmule its only source, no
    /// hash set.
    pub(super) peer_link: String,
    /// The whole file's link, rmule its source.
    pub(super) whole_link: Option<String>,
}

impl Drive<'_> {
    pub(super) fn run(&self, bench: &mut Bench, topology: &mut TopologyFile) -> Result<()> {
        let options = self.options;
        let docker = bench.docker.clone();
        let docker = &docker;
        // The download's row queued is what makes it a Served Download: a
        // probe before it is answered no-file, and aMule drops the source.
        self.wait(docker, "rmule serving its queued download", |trail| {
            trail.first_at("serve.serving_started").is_some()
                && trail.first_at("download.queued").is_some()
        })?;
        if options.prober {
            self.add_link(docker, topology, PROBER, &self.peer_link)?;
        }
        if let Some(whole_link) = &self.whole_link
            && topology
                .downloaders
                .iter()
                .any(|body| body.role == WHOLE_PROBER)
        {
            self.add_link(docker, topology, WHOLE_PROBER, whole_link)?;
        }
        // The stimulus's slot ask follows its hash-set ask, so it waits for
        // rmule to hold the set: a no-file answer would end its ask there.
        if options.straddle && options.prober {
            // The first line is the link's own, holding no part hash.
            self.wait(docker, "rmule's hash set", |trail| {
                trail
                    .named("download.hash_set_received")
                    .any(|mark| mark.field("part_count").is_some_and(|count| count != "0"))
            })?;
            let stimulus = self.stimulus(bench, topology, PRE_PART, &[(0, 4_096)], true)?;
            topology.stimuli.push(stimulus);
        }
        let wanted = options.ask_after_verified;
        let trail = self.wait(
            docker,
            "rmule's first verified parts and its offer",
            |trail| {
                trail.first_at("serve.partial_offered").is_some()
                    && trail
                        .last_parts()
                        .and_then(marks::Mark::verified)
                        .is_some_and(|parts| parts.len() >= wanted)
            },
        )?;
        self.add_link(docker, topology, DOWNLOADER, &self.peer_link)?;
        // With one slot the downloader holds it: a straddle stimulus would
        // only queue, and take the queued downloader's rank.
        if options.straddle && !options.queued {
            let parts = trail
                .last_parts()
                .and_then(|mark| mark.field("parts"))
                .unwrap_or_default()
                .to_owned();
            match legs::straddle(&parts, options.file_size) {
                Some((across, inside)) => {
                    let stimulus =
                        self.stimulus(bench, topology, STRADDLE, &[across, inside], false)?;
                    topology.stimuli.push(stimulus);
                }
                None => act(
                    topology,
                    format!("straddle skipped: no verified part beside a missing one in {parts}"),
                ),
            }
        }
        let downloader = body_ip(topology, DOWNLOADER)?;
        let slot = self.wait(docker, "the downloader's slot", |trail| {
            trail
                .first_at_for("serve.upload_slot_granted", downloader)
                .is_some()
        })?;
        if options.queued {
            self.add_link(docker, topology, QUEUED, &self.peer_link)?;
            let queued = body_ip(topology, QUEUED)?;
            self.wait(docker, "the second downloader queued", |trail| {
                trail.first_at_for("serve.peer_queued", queued).is_some()
            })?;
        }
        if options.pause {
            let granted = slot
                .first_at_for("serve.upload_slot_granted", downloader)
                .unwrap_or_else(now);
            sleep_until(granted + options.pause_after_secs as f64);
            fs::write(self.root.join(legs::PAUSE_GATE), b"").context("write the pause gate")?;
            act(topology, "pause gate written");
            self.wait(docker, "rmule's pause", |trail| {
                trail.first_at("download paused_at_gate").is_some()
            })?;
        }
        if options.queued {
            let queued = body_ip(topology, QUEUED)?;
            let at = self
                .trail(docker)?
                .first_at_for("serve.peer_queued", queued)
                .unwrap_or_else(now);
            act(
                topology,
                format!("waiting {} s for the queued reask", options.reask_wait_secs),
            );
            sleep_until(at + options.reask_wait_secs as f64);
        }
        if options
            .seeds
            .iter()
            .any(|seed| matches!(seed, SeedHolding::Complete))
            && !options.pause
        {
            let done = self.wait(docker, "the download's completion", |trail| {
                trail.first_at("download.completed").is_some()
            })?;
            let completed = done.first_at("download.completed").unwrap_or_else(now);
            sleep_until(completed + options.linger_secs as f64);
            if options.reopen_after_completion {
                fs::write(self.root.join(legs::STOP_GATE), b"").context("write the stop gate")?;
                act(
                    topology,
                    "stop gate written: rmule reopens over the finished file",
                );
                self.wait(
                    docker,
                    "the reopened node's download-directory pass",
                    |trail| {
                        trail.named("scan.finished").any(|mark| {
                            mark.leg == 2
                                && mark
                                    .field("dir")
                                    .is_some_and(|dir| dir.ends_with(legs::INCOMING_DIR))
                        })
                    },
                )?;
            }
        }
        if options.restart {
            fs::write(self.root.join(legs::STOP_GATE), b"").context("write the stop gate")?;
            act(topology, "stop gate written: rmule restarts");
            self.wait(docker, "rmule's reopen", |trail| {
                trail.first_at(marks::REOPENED).is_some()
            })?;
            if options.straddle {
                let stimulus =
                    self.stimulus(bench, topology, DURING_CHECK, &[(0, 4_096)], false)?;
                topology.stimuli.push(stimulus);
            }
            let reoffered = self.wait(docker, "the reopened download's offer", |trail| {
                trail.first_at("download reoffered").is_some()
            })?;
            let at = reoffered.first_at("download reoffered").unwrap_or_else(now);
            let asked_again =
                self.wait_until(docker, Duration::from_secs(options.reopen_secs), |trail| {
                    trail
                        .named("serve.upload_slot_granted")
                        .any(|mark| mark.leg == 2 && mark.at.is_some_and(|granted| granted > at))
                })?;
            act(
                topology,
                if asked_again {
                    "a downloader was granted a slot after the reopen"
                } else {
                    "no downloader was granted a slot inside the second leg"
                },
            );
            sleep_until(now() + 30.0);
        }
        fs::write(self.root.join(legs::STOP_GATE), b"").context("write the stop gate")?;
        act(topology, "stop gate written: the run ends");
        Ok(())
    }

    /// rmule's trail so far.
    fn trail(&self, docker: &Docker) -> Result<Trail> {
        let output = docker
            .logs(self.rmule.to_owned())
            .to_command()
            .output()
            .with_context(|| format!("docker logs {}", self.rmule))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(error) = String::from_utf8_lossy(&output.stderr)
            .lines()
            .chain(stdout.lines())
            .find(|line| line.starts_with("Error:"))
        {
            bail!("rmule-tools stopped: {error}");
        }
        Ok(Trail::new(&stdout))
    }

    /// Hold until rmule's trail says `done`, failing as `what` past the
    /// step budget.
    fn wait(&self, docker: &Docker, what: &str, done: impl Fn(&Trail) -> bool) -> Result<Trail> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let trail = self.trail(docker)?;
            if done(&trail) {
                return Ok(trail);
            }
            if Instant::now() >= deadline {
                bail!("waited {} s for {what}", self.timeout.as_secs());
            }
            thread::sleep(Duration::from_secs(2));
        }
    }

    /// Hold up to `budget` for `done`; whether it came.
    fn wait_until(
        &self,
        docker: &Docker,
        budget: Duration,
        done: impl Fn(&Trail) -> bool,
    ) -> Result<bool> {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if done(&self.trail(docker)?) {
                return Ok(true);
            }
            thread::sleep(Duration::from_secs(2));
        }
        Ok(false)
    }

    /// Give the downloader playing `role` the file `link` names.
    fn add_link(
        &self,
        docker: &Docker,
        topology: &mut TopologyFile,
        role: &str,
        link: &str,
    ) -> Result<()> {
        let body = topology
            .downloaders
            .iter()
            .find(|body| body.role == role)
            .with_context(|| format!("no {role} downloader"))?;
        let output = docker
            .exec(
                body.container.clone(),
                amulecmd_command(&format!("Add {link}")),
            )
            .to_command()
            .output()
            .with_context(|| format!("add the link to {role}"))?;
        act(
            topology,
            format!(
                "{role} given {link}: {}",
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .lines()
                    .last()
                    .unwrap_or("")
            ),
        );
        Ok(())
    }

    /// Run one `peer transfer capture` against rmule; with `wait`, hold
    /// until it ends.
    fn stimulus(
        &self,
        bench: &mut Bench,
        topology: &mut TopologyFile,
        purpose: &str,
        ranges: &[(u64, u64)],
        wait: bool,
    ) -> Result<Stimulus> {
        let name = format!("rmule-interop-stimulus-{purpose}-{}", self.suffix);
        let output_dir = format!("{RUN_MOUNT}/{ROOT_DIR}/stimulus/{purpose}");
        let gate = format!("gates/stimulus-{purpose}");
        let gate_in_container = format!("{RUN_MOUNT}/{ROOT_DIR}/{gate}");
        let peer = format!("{}:{RMULE_SERVE_TCP_PORT}", topology.rmule_ip);
        let range_wait = STIMULUS_RANGE_WAIT_SECS.to_string();
        let max_seconds = STIMULUS_SECS.to_string();
        let mut container = [
            "ed2k",
            "peer",
            "transfer",
            "capture",
            "--peer",
            &peer,
            "--file",
            &self.peer_link,
            "--output-dir",
            &output_dir,
            "--user-hash",
            STIMULUS_USER_HASH,
            "--nickname",
            "rmule-stimulus",
            "--range-wait-secs",
            &range_wait,
            "--max-seconds",
            &max_seconds,
        ]
        .into_iter()
        .fold(
            // Held at its gate until its address is read: a stimulus whose
            // asks end at once has no address left to read.
            RunContainer::new(self.options.rmule_tools_image.to_owned())
                .detach()
                .name(&name)
                .network(bench.names.network_name.clone())
                .volume(self.options.layout.root(), RUN_MOUNT)
                .entrypoint("sh")
                .arg("-c")
                .arg(HOLD_UNTIL_GATE)
                .arg(&gate_in_container)
                .arg(IMAGE_ENTRYPOINT),
            RunContainer::arg,
        );
        for (start, end) in ranges {
            container = container.arg("--range").arg(format!("{start}-{end}"));
        }
        let started_at = now();
        bench.start_extra(&name, container, &format!("run the {purpose} stimulus"))?;
        let ip = run_checked(
            bench.docker.container_ip(name.clone()),
            "inspect the stimulus ip",
        )?
        .trim()
        .parse()
        .context("stimulus address")?;
        fs::write(self.root.join(&gate), b"").context("release the stimulus")?;
        act(
            topology,
            format!("{purpose} stimulus at {ip} asks {ranges:?}"),
        );
        if wait {
            run_checked(bench.docker.wait(name.clone()), "wait for the stimulus")?;
        }
        Ok(Stimulus {
            purpose: purpose.to_owned(),
            container: name,
            ip,
            started_at,
            ended_at: started_at + STIMULUS_SECS as f64 + 5.0,
            ranges: ranges.to_vec(),
        })
    }
}

pub(super) fn body_ip(topology: &TopologyFile, role: &str) -> Result<Ipv4Addr> {
    topology
        .downloaders
        .iter()
        .find(|body| body.role == role)
        .map(|body| body.ip)
        .with_context(|| format!("no {role} downloader"))
}

/// Record one harness step, stamped.
fn act(topology: &mut TopologyFile, what: impl Into<String>) {
    let what = what.into();
    let at = now();
    println!("peer_partial_share at={at:.3} {what}");
    topology.actions.push(Action { at, what });
}

/// The wall clock in seconds since the epoch.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |since| since.as_secs_f64())
}

/// Sleep until the wall clock reads `at`.
fn sleep_until(at: f64) {
    let left = at - now();
    if left > 0.0 {
        thread::sleep(Duration::from_secs_f64(left));
    }
}
