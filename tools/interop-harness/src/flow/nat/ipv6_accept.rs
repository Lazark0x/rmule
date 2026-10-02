//! `ipv6-net-accept` (ADR-0092): each IPv6-speaking counterparty body is
//! started on a **Fake-Public v6 Plan** address and its own log is read back.
//!
//! The prefix choice is defensible from source — `3fff::/20` is global-unicast
//! shaped and appears in no reject list either body carries — but *defensible
//! from source* is a reading, and a v6 flow that trusted it would be resting
//! every later row on an unverified premise. So the acceptance is measured: the
//! body runs on the prefix, and what it says about the address is written down
//! verbatim, marker or no marker. A body whose log names neither acceptance nor
//! rejection is recorded `undetermined` with its log retained — never upgraded
//! to a pass.
//!
//! The v4 half of the WAN is `45.55.200.0/24` and not the first documentation
//! range, because emule-qt's `isPublicIP()` rejects both `203.0.113.0/24` and
//! `198.51.100.0/24` while stock aMule accepts them: of the three fake-public
//! prefixes, only the third is admitted by every body. A mixed
//! topology on either of the others would fail for a v4 reason while looking
//! like a v6 one.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::artifacts::RunLayout;
use crate::bench_doctor::{BenchDoctor, CAP_DAEMON_IPV6, DoctorReport, SkipReason};
use crate::docker::{InternalNetwork, RunContainer};
use crate::fake_public::{MAX_NODES_PER_SUBNET, fake_public_address, subnet_cidr};
use crate::fake_public_v6::FakePublicV6Plan;
use crate::flow::bench::{Bench, run_checked};

/// The flow's name in every artifact it writes.
const FLOW: &str = "ipv6-net-accept";

/// The fake-public `/24` index every body admits. Index 2 is `45.55.200.0/24`;
/// indices 0 and 1 are the RFC 5737 ranges emule-qt's `isPublicIP()` rejects
/// while stock aMule accepts them, so a mixed topology on either of those would
/// fail for a v4 reason while looking like a v6 one.
const MIXED_BODY_SUBNET_INDEX: usize = 2;

/// Phrases that mean the body treated the address as its own global/public one,
/// matched case-insensitively. Each one is a specific line in a specific body,
/// read from that body's own source and then confirmed on the wire — not a guess
/// at what a client might say:
///
/// * `inbound ipv6 connection from` — kno's aMule, `ListenSocket.cpp:207`. It is
///   logged on the accept path for a *native* IPv6 peer, beside
///   `SetVerifiedIPv6Address(localAddress)`, which keeps the local address only
///   `if (address.IsGloballyRoutableIPv6())` (`amule.h:468`). The line names that
///   local address, so a match with the planned address in it is the body
///   calling the address routable. Needs an inbound connection, which is why the
///   flow dials one.
/// * `ipv6: public address` — emule-qt, `LocalIPv6.cpp:582`. Its local-address
///   scan logs the address it settled on as public; no peer required.
const ACCEPT_MARKERS: [&str; 2] = ["inbound ipv6 connection from", "ipv6: public address"];

/// Phrases that mean the body refused the address.
///
/// * `no global-unicast address on any interface` — emule-qt, `LocalIPv6.cpp:553`:
///   its scan ran and found nothing it would advertise.
/// * `non-routable ipv6` — kno's aMule, `DownloadQueue.cpp:802`, the source-side
///   refusal.
const REJECT_MARKERS: [&str; 2] = [
    "no global-unicast address on any interface",
    "non-routable ipv6",
];

/// The peer TCP port the dialer knocks on. Both bodies default to aMule's 4662.
const BODY_PEER_TCP_PORT: u16 = 4662;

/// How long the dialer holds its connection open. See `dial_ipv6`.
const DIAL_HOLD_SECS: u64 = 3;

/// One counterparty body to stand up on the prefix.
pub struct Ipv6Body<'a> {
    /// The body's short name — its log and row are named for it.
    pub name: &'a str,
    /// Its image tag.
    pub image: &'a str,
    /// Its build context, when `--build-images` is set.
    pub build_context: &'a Path,
    /// `KEY=VALUE` knobs the entrypoint reads.
    pub env: &'a [String],
    /// The log line that means "this body finished starting". Empty means the
    /// flow waits out `settle_secs` instead — which is the honest fallback for a
    /// body whose readiness marker is not yet known.
    pub ready_marker: &'a str,
}

/// The flow's inputs.
pub struct Ipv6NetAcceptOptions<'a> {
    /// The run dir.
    pub layout: &'a RunLayout,
    /// The container runtime to drive.
    pub container_runtime: &'a str,
    /// Build the bodies' images first.
    pub build_images: bool,
    /// The `natgw` image, which is what **Bench Doctor** probes the kernel with.
    pub natgw_image: &'a str,
    /// Keep containers after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget.
    pub timeout_secs: u64,
    /// How long to let a body talk before reading its log, when it has no
    /// readiness marker.
    pub settle_secs: u64,
    /// The bodies to measure.
    pub bodies: &'a [Ipv6Body<'a>],
    /// The image the IPv6 dialer runs from — any image with `python3`. The
    /// `natprobe` recipe already carries one, and reusing it keeps the flow from
    /// inventing a body.
    pub dialer_image: &'a str,
    /// Its build context.
    pub dialer_build_context: &'a Path,
}

/// What one body did with its planned address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct BodyAcceptance {
    /// The body's short name.
    pub(crate) body: String,
    /// The v6 address it was given.
    pub(crate) address: String,
    /// The v4 address it was given, for the record: a v6 rejection and a v4
    /// rejection look identical in most logs.
    pub(crate) address_v4: String,
    /// Whether the address appears anywhere in the body's own log.
    pub(crate) address_in_log: bool,
    /// The accept marker line, verbatim, if one matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) accept_line: Option<String>,
    /// The reject marker line, verbatim, if one matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reject_line: Option<String>,
    /// `accepted` / `rejected` / `undetermined`.
    pub(crate) classification: &'static str,
    /// Where the body's whole log was retained.
    pub(crate) log_file: String,
}

/// The flow's verdict.
#[derive(Debug, Serialize)]
struct AcceptVerdict {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_reason: Option<String>,
    wan_subnet_v4: String,
    wan_subnet_v6: String,
    #[serde(rename = "capability")]
    capabilities: Vec<crate::bench_doctor::Capability>,
    #[serde(rename = "body")]
    bodies: Vec<BodyAcceptance>,
}

/// Classify one body's log. Rejection wins a tie: a log that names both is a
/// body that changed its mind, and the safe reading of "changed its mind" is
/// "did not accept". An accept line counts only when it names the plan's own
/// address: an accept marker about some other address says nothing about
/// this one. A reject line needs no address — the markers are refusals of
/// every address the body saw.
pub(crate) fn classify(
    log: &str,
    address: &str,
) -> (bool, Option<String>, Option<String>, &'static str) {
    let lower = log.to_lowercase();
    let address_in_log = lower.contains(&address.to_lowercase());
    let accept_line = matched_line(log, &ACCEPT_MARKERS, Some(address));
    let reject_line = matched_line(log, &REJECT_MARKERS, None);
    let classification = match (&accept_line, &reject_line) {
        (_, Some(_)) => "rejected",
        (Some(_), None) => "accepted",
        (None, None) => "undetermined",
    };
    (address_in_log, accept_line, reject_line, classification)
}

/// The first log line containing any of `markers` (and `address`, when
/// given), verbatim.
fn matched_line(log: &str, markers: &[&str], address: Option<&str>) -> Option<String> {
    log.lines().find_map(|line| {
        let lower = line.to_lowercase();
        (markers.iter().any(|marker| lower.contains(marker))
            && address.is_none_or(|address| names_address(&lower, &address.to_lowercase())))
        .then(|| line.trim().to_owned())
    })
}

/// Whether `line` names `address` as a whole address, not as the prefix of a
/// longer one (`3fff::2` is not named by `3fff::25`). Both are lower-case.
fn names_address(line: &str, address: &str) -> bool {
    line.match_indices(address).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + address.len()..].chars().next();
        let part_of_address =
            |c: Option<char>| c.is_some_and(|c| c.is_ascii_hexdigit() || c == ':');
        !part_of_address(before) && !part_of_address(after)
    })
}

/// Stand every body up on the plan's `/64` and record what each said.
///
/// # Errors
/// If the bench cannot be built or a body's log cannot be collected. A body that
/// rejects the prefix is not an error — it is a `rejected` row and an `OBSERVED`
/// verdict, which is the measurement the flow exists to take.
pub fn run_ipv6_net_accept(options: Ipv6NetAcceptOptions<'_>) -> Result<()> {
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let result = drive(&mut bench, &options);
    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    result
}

fn drive(bench: &mut Bench, options: &Ipv6NetAcceptOptions<'_>) -> Result<()> {
    if options.build_images {
        for body in options.bodies {
            if body.name == "amule-kno" {
                bench.build_amule_kno_image(body.image, body.build_context)?;
            } else {
                bench.build_image(body.name, body.image, body.build_context)?;
            }
        }
    }
    // Always rebuilt, like `rmule-tools`: it's a 30 s Debian layer plus two
    // `COPY`s, so an edited `entrypoint.sh` reaches the bench without
    // `--build-images`.
    bench.build_image(
        "natprobe",
        options.dialer_image,
        options.dialer_build_context,
    )?;
    let suffix = run_suffix(options.layout)?;
    let plan = FakePublicV6Plan::for_network(1)?;
    let subnet_v4 = subnet_cidr(MIXED_BODY_SUBNET_INDEX)?;

    let doctor = BenchDoctor::new(&bench.docker, options.natgw_image, &suffix).examine()?;
    if let Err(skip) = doctor.require(
        &[CAP_DAEMON_IPV6],
        "whether any counterparty accepts a 3fff::/20 address",
    ) {
        return write_skip(options.layout, &doctor, &skip, &subnet_v4, &plan.subnet());
    }

    let ipv6_dir = options.layout.ipv6_dir();
    fs::create_dir_all(&ipv6_dir).with_context(|| format!("create {}", ipv6_dir.display()))?;
    fs::create_dir_all(options.layout.docker_dir())?;

    let network = format!("rmule-interop-v6wan-{suffix}");
    bench.create_extra_network(
        &network,
        bench.docker.create_internal_network(
            InternalNetwork::new(&network)
                .subnet_v4(&subnet_v4)
                .subnet_v6(plan.subnet()),
        ),
        "create dual-stack fake-public WAN",
    )?;

    let mut rows = Vec::with_capacity(options.bodies.len());
    for (index, body) in options.bodies.iter().enumerate() {
        rows.push(measure_one(
            bench, options, &suffix, &network, &plan, index, body, &ipv6_dir,
        )?);
    }

    let all_accepted = !rows.is_empty() && rows.iter().all(|row| row.classification == "accepted");
    let verdict = AcceptVerdict {
        flow: FLOW,
        verdict: if all_accepted { "PASS" } else { "OBSERVED" },
        skip_reason: None,
        wan_subnet_v4: subnet_v4,
        wan_subnet_v6: plan.subnet(),
        capabilities: doctor.capabilities,
        bodies: rows,
    };
    write_verdict(options.layout, &verdict)
}

#[allow(clippy::too_many_arguments)]
fn measure_one(
    bench: &mut Bench,
    options: &Ipv6NetAcceptOptions<'_>,
    suffix: &str,
    network: &str,
    plan: &FakePublicV6Plan,
    index: usize,
    body: &Ipv6Body<'_>,
    ipv6_dir: &Path,
) -> Result<BodyAcceptance> {
    let address_v4 =
        fake_public_address(MIXED_BODY_SUBNET_INDEX * MAX_NODES_PER_SUBNET + index)?.ip;
    let address = plan.address(index as u16)?;
    let container = format!("rmule-interop-v6body-{}-{suffix}", body.name);
    bench.start_extra(
        &container,
        RunContainer::new(body.image)
            .detach()
            .name(&container)
            .network(network)
            .ip(&address_v4)
            .ip6(&address)
            .cap_add("NET_ADMIN")
            .env_assignments(body.env),
        &format!("run {} on the fake-public v6 plan", body.name),
    )?;

    // Readiness Gate first when the body has a marker, then a **Settle Window**:
    // the marker says the entrypoint launched the daemon, not that the daemon has
    // finished binding its sockets and scanning its interfaces, and the dial
    // below is the stimulus that must land after both.
    if !body.ready_marker.is_empty() {
        crate::flow::gate::wait_for_container_log(
            &bench.docker,
            &container,
            body.ready_marker,
            Duration::from_secs(options.timeout_secs),
        )?;
    }
    std::thread::sleep(Duration::from_secs(options.settle_secs));

    // kno's aMule only classifies its own IPv6 address on the accept path of a
    // native IPv6 connection, so the flow provides one. The dial is Stimulus: it
    // proves nothing by itself, it just makes the body do the thing whose log
    // line IS the measurement.
    dial_ipv6(bench, options, network, plan, &address)?;

    let logs = run_checked(
        bench.docker.logs(container.clone()),
        &format!("collect {} logs", body.name),
    )?;
    let log_file = format!("{}.log", body.name);
    fs::write(ipv6_dir.join(&log_file), &logs)
        .with_context(|| format!("write {}", ipv6_dir.join(&log_file).display()))?;

    let (address_in_log, accept_line, reject_line, classification) = classify(&logs, &address);
    println!(
        "ipv6-net-accept body={} address={address} in_log={address_in_log} classification={classification}",
        body.name
    );
    bench.stop_extra(&container);
    Ok(BodyAcceptance {
        body: body.name.to_owned(),
        address,
        address_v4,
        address_in_log,
        accept_line,
        reject_line,
        classification,
        log_file,
    })
}

/// Open one native-IPv6 TCP connection to the body's peer port from another
/// address on the same `/64`, so a body that only classifies addresses on its
/// accept path has something to accept.
///
/// A failed dial is not fatal: a body that refuses the connection has still been
/// asked, and its log — including its refusal — is what the flow reads next.
fn dial_ipv6(
    bench: &Bench,
    options: &Ipv6NetAcceptOptions<'_>,
    network: &str,
    plan: &FakePublicV6Plan,
    target: &str,
) -> Result<()> {
    // The dialer sits high in the /64 so it never collides with a body index.
    let dialer_v6 = plan.address(200)?;
    // The link is held open for a moment rather than closed on the spot: the
    // body's accept path runs on its own thread, and a connection torn down in
    // the same instant is reaped before it is ever logged. Measured — an
    // immediate close produced no line at all, a held one produced
    // "Inbound IPv6 connection from … on …".
    let script = format!(
        "import socket, sys, time\n\
         s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n\
         s.settimeout(5)\n\
         try:\n\
         \x20   s.connect(('{target}', {BODY_PEER_TCP_PORT}))\n\
         \x20   print('rmule-ipv6-dialer-connected from', s.getsockname()[0])\n\
         \x20   time.sleep({DIAL_HOLD_SECS})\n\
         \x20   s.close()\n\
         except OSError as error:\n\
         \x20   print('rmule-ipv6-dialer-refused', error, file=sys.stderr)\n"
    );
    let container = RunContainer::new(options.dialer_image)
        .remove_after_exit()
        .network(network)
        .ip6(&dialer_v6)
        .entrypoint("python3")
        .arg("-c")
        .arg(script);
    let output = bench
        .docker
        .run_container(container)
        .to_command()
        .output()
        .context("run the IPv6 dialer")?;
    println!(
        "ipv6-net-accept dialer target={target} source={dialer_v6} {}{}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim(),
    );
    Ok(())
}

fn run_suffix(layout: &RunLayout) -> Result<String> {
    layout
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .context("run directory has no utf-8 file name")
}

fn write_skip(
    layout: &RunLayout,
    doctor: &DoctorReport,
    skip: &SkipReason,
    subnet_v4: &str,
    subnet_v6: &str,
) -> Result<()> {
    eprintln!("ipv6-net-accept skipped: {}", skip.reason);
    write_verdict(
        layout,
        &AcceptVerdict {
            flow: FLOW,
            verdict: "SKIPPED",
            skip_reason: Some(skip.reason.clone()),
            wan_subnet_v4: subnet_v4.to_owned(),
            wan_subnet_v6: subnet_v6.to_owned(),
            capabilities: doctor.capabilities.clone(),
            bodies: Vec::new(),
        },
    )
}

fn write_verdict(layout: &RunLayout, verdict: &AcceptVerdict) -> Result<()> {
    let text = toml::to_string_pretty(verdict).context("serialize ipv6-net-accept verdict")?;
    let path = layout.root().join("ipv6-net-accept-verdict.toml");
    println!("{text}");
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_that_says_nothing_about_the_address_is_undetermined_not_accepted() {
        let (in_log, accept, reject, classification) =
            classify("daemon started\nlistening on 4662\n", "3fff:ed2:1::2");
        assert!(!in_log);
        assert_eq!(accept, None);
        assert_eq!(reject, None);
        assert_eq!(classification, "undetermined");
    }

    /// An accept marker about another address — a peer's, or a neighbour on
    /// the plan — is not this body accepting its own.
    #[test]
    fn an_accept_line_about_another_address_is_not_an_acceptance() {
        let log = "IPv6: public address 3fff:ed2:1::25 (eth0)\n\
                   Inbound IPv6 connection from 3fff:ed2:1::2 on 3fff:ed2:1::7.\n";
        let (_, accept, _, classification) = classify(log, "3fff:ed2:1::7");
        assert!(accept.is_some(), "the line names ::7 as the local end");
        assert_eq!(classification, "accepted");
        let (_, accept, _, classification) = classify(log, "3fff:ed2:1::9");
        assert_eq!(accept, None);
        assert_eq!(classification, "undetermined");
        let only_longer = "IPv6: public address 3fff:ed2:1::25 (eth0)\n";
        assert_eq!(classify(only_longer, "3fff:ed2:1::2").3, "undetermined");
    }

    #[test]
    fn a_rejection_outranks_an_acceptance_in_the_same_log() {
        // A body that logged both changed its mind; the honest reading of that
        // is not "accepted".
        let log = "IPv6: public address 3fff:ed2:1::2 (eth0)\n\
                   IPv6: no global-unicast address on any interface\n";
        let (in_log, accept, reject, classification) = classify(log, "3fff:ed2:1::2");
        assert!(in_log);
        assert!(accept.is_some());
        assert!(reject.is_some());
        assert_eq!(classification, "rejected");
    }

    #[test]
    fn the_matched_line_is_kept_verbatim_so_the_classification_is_auditable() {
        // The exact line kno's aMule wrote in the first live run of this flow.
        let log = "  2026-09-16 13:17:10: Inbound IPv6 connection from 3fff:ed2:1::5 on \
                   3fff:ed2:1::2.  \n";
        let (in_log, accept, _, classification) = classify(log, "3fff:ed2:1::2");
        assert!(in_log);
        assert_eq!(
            accept.as_deref(),
            Some(
                "2026-09-16 13:17:10: Inbound IPv6 connection from 3fff:ed2:1::5 on \
                 3fff:ed2:1::2."
            )
        );
        assert_eq!(classification, "accepted");
    }
}
