//! The live legacy leg of `sentinel-sources-legacy`: an rmule-authored
//! **Stimulus** hands a **Sentinel Source**-bearing source list to a *stock
//! aMule 2.3.3*, and the flow records what that aMule then did.
//!
//! The counterparty here is the legacy oracle — the same pinned stock 2.3.3 the
//! whole ADR-0092 body table names. rmule is the server side only because the
//! pinned `ed2ksrv` cannot emit a sentinel row at all;
//! that half is Stimulus and is never evidence, however correct its bytes
//! (ADR-0045, `tools/interop-harness/CONTEXT.md`). The evidence is entirely
//! aMule's: which endpoints it dialled, what its own log says, and whether its
//! session survived.
//!
//! The observable is the dial. A source record decodes to an `address:port`,
//! and every plain record in the plan names an address the stimulus container
//! *holds* and a port it *listens on* — so aMule's dial lands on a **Source
//! Sink** that writes down which record it decoded, and the passive **Capture
//! Sidecar** on aMule's own netns records the SYN independently. A desync shows
//! up as the record *after* the sentinel going undialled (or dialled at the
//! wrong endpoint) while the one before it is dialled.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, amulecmd_command, run_checked,
};
use crate::flow::evidence::count_pcap_rows;
use crate::flow::gate::wait_for_container_log;
use crate::flow::logs::{collect_amule_diagnostics, collect_amule_logs, retain_artifact};

use super::plan::{
    AMULE_SERVER_UDP_PORT, BENCH_SUBNET, CONTROL_FIRST_RECORDS, CONTROL_SECOND_RECORDS,
    PACKED_FIRST_RECORDS, PACKED_SECOND_RECORDS, Record, STIMULUS_IP, STIMULUS_TCP_PORT,
    STIMULUS_UDP_PORT, TCP_RECORDS, all_records, list_spec, sink_address_cidrs, sink_ports,
};

/// The stimulus's readiness marker.
const STIMULUS_READY: &str = "rmule-sentinel-stimulus-ready";

/// aMule's own readiness marker in `ed2k-server` mode with the download-hold
/// knob: the server connection is up and the link is queued.
const AMULE_READY: &str = "rmule-amule-download-sources-ready";

/// How long aMule settles after adding the synthetic link before it reports
/// ready. Short: this flow wants the ready marker, not a filled source list —
/// the sources arrive later, from the stimulus.
const AMULE_SETTLE_SECS: &str = "5";

/// The four extra files the packed datagrams name, so aMule has them in its
/// download queue when the datagrams arrive. Hashes are fabricated and fixed:
/// nothing ever serves these files, they exist to give each packed body a
/// `GetFileByID` hit — without which a body is skipped for a reason that is not
/// the sentinel.
const PACKED_FIRST_HASH: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const PACKED_SECOND_HASH: &str = "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7";
const CONTROL_FIRST_HASH: &str = "c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9";
const CONTROL_SECOND_HASH: &str = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";

/// The size the fabricated links declare.
const PACKED_FILE_SIZE: u64 = 65_536;

/// What the legacy leg needs to stand its bench up.
pub struct LegacyDrive<'a> {
    /// Build the project-owned images first.
    pub build_images: bool,
    /// The stock aMule 2.3.3 image — the legacy oracle.
    pub amule_image: &'a str,
    /// Its recipe.
    pub amule_build_context: &'a Path,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// Its recipe.
    pub capture_build_context: &'a Path,
    /// The `rmule-tools` driver image the stimulus runs from. Always rebuilt:
    /// the stimulus subcommand is workspace code.
    pub rmule_tools_image: &'a str,
    /// Its Dockerfile.
    pub rmule_tools_dockerfile: &'a Path,
    /// Its build context (the repo root).
    pub rmule_tools_build_context: &'a Path,
    /// Extra environment for the aMule container.
    pub amule_env: &'a [String],
    /// Leave the containers standing after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, seconds.
    pub timeout_secs: u64,
    /// How long aMule is watched after the scripted emission fires.
    pub window_secs: u64,
}

/// One dial that landed on a **Source Sink**: aMule naming, in its own
/// connection, the endpoint it decoded out of a record.
pub(crate) struct SinkDial {
    /// The sink endpoint the dial landed on.
    pub(crate) local: String,
    /// The dialling aMule.
    pub(crate) peer: String,
    /// Its first frame, hex (an `OP_HELLO`).
    pub(crate) bytes: String,
}

/// What the legacy leg measured — every field from aMule's own behaviour.
pub(crate) struct LegacyObservation {
    /// How many logins the stimulus answered.
    pub(crate) logins: i64,
    /// Whether the scripted emission actually went out (it is recorded in the
    /// stimulus journal; a `false` here means the leg proved nothing).
    pub(crate) emitted: bool,
    /// What fired the emission. `trigger-file` is the one the flow asks for,
    /// and it is what proves the tap was already up and every named file
    /// already queued when the list went out.
    pub(crate) emit_trigger: String,
    /// Every sink dial, in arrival order.
    pub(crate) sink_dials: Vec<SinkDial>,
    /// `(record label, dialled)` for every plain record in the plan.
    pub(crate) dialled: Vec<(&'static str, bool)>,
    /// `(row name, count)` off the pcap on aMule's own netns.
    pub(crate) wire_rows: Vec<(String, u64)>,
    /// aMule's `amulecmd Status` after the window — whether the session
    /// survived the sentinel-bearing list.
    pub(crate) session_survived: bool,
    /// The `Status` output it survived (or did not) with.
    pub(crate) amule_status: String,
    /// aMule's own log lines naming the source list.
    pub(crate) amule_log_lines: Vec<String>,
}

impl LegacyObservation {
    /// Whether a record with this label was dialled.
    pub(crate) fn was_dialled(&self, label: &str) -> bool {
        self.dialled
            .iter()
            .any(|(name, dialled)| *name == label && *dialled)
    }

    /// One pcap row's count, or `None` when the row was not counted: a
    /// tcpdump that failed is not a silence aMule kept.
    pub(crate) fn wire_row(&self, name: &str) -> Option<u64> {
        self.wire_rows
            .iter()
            .find(|(row, _)| row == name)
            .map(|(_, count)| *count)
    }

    /// [`Self::wire_row`] as the verdict records it: `-1` for never counted.
    pub(crate) fn wire_row_recorded(&self, name: &str) -> i64 {
        self.wire_row(name)
            .map_or(-1, |count| i64::try_from(count).unwrap_or(i64::MAX))
    }
}

/// Stand the bench up, fire the stimulus at the stock aMule, and read back what
/// aMule did.
///
/// # Errors
/// If an image cannot be built, a container cannot be started or gated, or the
/// stimulus journal cannot be read. A counterparty that ignores the list is
/// **not** an error — that is the measurement.
pub(crate) fn drive(
    layout: &RunLayout,
    container_runtime: &str,
    drive: &LegacyDrive<'_>,
) -> Result<LegacyObservation> {
    let mut bench = Bench::new(container_runtime, layout, drive.keep_containers)?;
    let result = stage(&mut bench, layout, drive);
    if let Err(error) = &result {
        eprintln!("sentinel-sources-legacy: legacy leg failed: {error:#}");
        bench.collect_failure_logs(layout);
    }
    bench.cleanup_best_effort();
    result
}

fn stage(
    bench: &mut Bench,
    layout: &RunLayout,
    drive: &LegacyDrive<'_>,
) -> Result<LegacyObservation> {
    if drive.build_images {
        bench.build_image("aMule", drive.amule_image, drive.amule_build_context)?;
        bench.build_image("capture", drive.capture_image, drive.capture_build_context)?;
    }
    // Always rebuilt: the stimulus subcommand is workspace code.
    bench.build_rmule_tools_image(
        drive.rmule_tools_image,
        drive.rmule_tools_dockerfile,
        drive.rmule_tools_build_context,
    )?;

    let timeout = Duration::from_secs(drive.timeout_secs);
    let stimulus_dir = layout.root().join("stimulus");
    fs::create_dir_all(&stimulus_dir)
        .with_context(|| format!("create {}", stimulus_dir.display()))?;
    let capture_dir = layout.root().join("capture");
    fs::create_dir_all(&capture_dir)
        .with_context(|| format!("create {}", capture_dir.display()))?;

    let ed2k_link = fs::read_to_string(layout.synthetic_ed2k_file())
        .with_context(|| format!("read {}", layout.synthetic_ed2k_file().display()))?
        .trim()
        .to_owned();
    let synthetic_hash = link_file_hash(&ed2k_link)?;

    bench.create_network(layout, Some(BENCH_SUBNET))?;
    let stimulus_name = bench.names.server_container_name.clone();
    bench.start_server_container(
        layout,
        stimulus_container(bench, drive, &stimulus_dir, &synthetic_hash),
    )?;
    wait_for_container_log(&bench.docker, &stimulus_name, STIMULUS_READY, timeout)?;

    // aMule downloads the synthetic hash, so it must not already hold the file.
    let amule_incoming = layout.root().join("amule-incoming");
    fs::create_dir_all(&amule_incoming)
        .with_context(|| format!("create {}", amule_incoming.display()))?;
    let amule = bench
        .amule_role_container(drive.amule_image)
        .volume(&amule_incoming, "/incoming")
        .env("AMULE_SHARED_DIR", "/incoming")
        .env("AMULE_DOWNLOAD_LINK", ed2k_link.as_str())
        .env("AMULE_DOWNLOAD_NO_WAIT", "1")
        .env("AMULE_DOWNLOAD_SETTLE", AMULE_SETTLE_SECS)
        .env("AMULE_EXPECTED_FILE_NAME", "shared.bin")
        // Unlocks aMule's own AddDebugLogLineN trail — why a source is added,
        // filtered, or never dialled. Behaviour is unchanged; only its account
        // of itself is.
        .env("AMULE_VERBOSE", "1")
        // Seed the stimulus into aMule's own server list before the daemon
        // starts. `amulecmd Add ed2k://|server|…` routes to the download queue
        // and `Connect ip:port` opens a socket without touching `m_servers`, so
        // without the seed the list is empty — and a client that does not know
        // the server cannot attribute a server-UDP datagram to it. Seeding a
        // contact is configuration, never a patch.
        .env("AMULE_PERSIST_SERVERLIST", "1")
        .env_assignments(drive.amule_env);
    bench.start_amule(layout, amule, AMULE_READY, timeout)?;

    // The tap goes up before the emission, on aMule's own netns, so every SYN
    // it sends is recorded independently of the sink that catches it.
    let amule_container = bench.names.amule_container_name.clone();
    let capture_name = format!("{amule_container}-capture");
    let sidecar = CaptureSidecar {
        image: drive.capture_image,
        name: &capture_name,
        target_container: &amule_container,
        interface: DEFAULT_TAP_INTERFACE,
        host_dir: capture_dir.clone(),
        pcap_file: "amule.pcap",
        bpf: "ip or arp",
    };
    let pcap_path = sidecar.pcap_path();
    bench.start_extra(&capture_name, sidecar.container(), "run capture sidecar")?;

    // The packed datagram's two bodies name files aMule must already hold, or
    // its `GetFileByID` misses and the whole body is skipped for a reason that
    // is not the sentinel.
    for (hash, name) in [
        (PACKED_FIRST_HASH, "packed-first.bin"),
        (PACKED_SECOND_HASH, "packed-second.bin"),
        (CONTROL_FIRST_HASH, "control-first.bin"),
        (CONTROL_SECOND_HASH, "control-second.bin"),
    ] {
        let link = format!(
            "ed2k://|file|{name}|{PACKED_FILE_SIZE}|{}|/",
            hash.to_uppercase()
        );
        run_checked(
            bench.docker.exec(
                bench.names.amule_container_name.clone(),
                amulecmd_command(&format!("Add {link}")),
            ),
            "queue the packed datagram's files in aMule",
        )?;
    }
    retain_artifact(
        &layout.root().join("amule-listeners.log"),
        sockets(bench).as_bytes(),
    );

    // Release the emission now that every file is queued: the stimulus fires
    // once, then runs its observation window out and writes its journal.
    run_checked(
        bench.docker.exec(
            stimulus_name.clone(),
            ["sh", "-c", "touch /out/emit"].map(OsString::from),
        ),
        "release the scripted emission",
    )?;
    println!(
        "sentinel-sources-legacy: emission released; watching aMule for {}s",
        drive.window_secs
    );
    run_checked(
        bench.docker.wait(stimulus_name.clone()),
        "wait for the stimulus observation window",
    )?;

    let journal = fs::read_to_string(stimulus_dir.join("stimulus.toml"))
        .with_context(|| format!("read {}", stimulus_dir.join("stimulus.toml").display()))?;
    let wire_rows = count_wire_rows(bench, &capture_name, &pcap_path);
    bench.stop_extra(&capture_name);

    let amule_status = amule_status(bench);
    if let Err(error) = collect_amule_logs(&bench.docker, layout, &bench.names.amule_container_name)
    {
        eprintln!("warning: aMule log collection: {error:#}");
    }
    if let Err(error) =
        collect_amule_diagnostics(&bench.docker, layout, &bench.names.amule_container_name)
    {
        eprintln!("warning: aMule diagnostics: {error:#}");
    }
    let amule_log_lines = source_log_lines(&layout.amule_diagnostics_stdout_log());

    Ok(observe(&journal, wire_rows, amule_status, amule_log_lines))
}

/// The stimulus container: the server role, holding every plain record's
/// address so a dial reaches a listener instead of dying at ARP.
fn stimulus_container(
    bench: &Bench,
    drive: &LegacyDrive<'_>,
    stimulus_dir: &PathBuf,
    synthetic_hash: &str,
) -> RunContainer {
    let mut container = RunContainer::new(drive.rmule_tools_image)
        .detach()
        .name(bench.names.server_container_name.clone())
        .network(bench.names.network_name.clone())
        .ip(STIMULUS_IP)
        .cap_add("NET_ADMIN")
        .volume(stimulus_dir, "/out")
        .env("RMULE_EXTRA_ADDRS", sink_address_cidrs())
        .arg("ed2k")
        .arg("sentinel-stimulus")
        .arg("--listen")
        .arg(format!("0.0.0.0:{STIMULUS_TCP_PORT}"))
        .arg("--udp-port")
        .arg(STIMULUS_UDP_PORT.to_string())
        .arg("--record")
        .arg(list_spec(synthetic_hash, &TCP_RECORDS))
        .arg("--packed")
        .arg(list_spec(PACKED_FIRST_HASH, &PACKED_FIRST_RECORDS))
        .arg("--packed")
        .arg(list_spec(PACKED_SECOND_HASH, &PACKED_SECOND_RECORDS))
        .arg("--packed-control")
        .arg(list_spec(CONTROL_FIRST_HASH, &CONTROL_FIRST_RECORDS))
        .arg("--packed-control")
        .arg(list_spec(CONTROL_SECOND_HASH, &CONTROL_SECOND_RECORDS))
        .arg("--peer-udp-port")
        .arg(AMULE_SERVER_UDP_PORT.to_string())
        .arg("--emit-trigger-file")
        .arg("/out/emit")
        .arg("--stop-after-emit-secs")
        .arg(drive.window_secs.to_string())
        .arg("--max-seconds")
        .arg(drive.timeout_secs.to_string())
        .arg("--out")
        .arg("/out");
    for port in sink_ports() {
        container = container.arg("--sink").arg(port.to_string());
    }
    container
}

/// The file hash out of an `ed2k://|file|name|size|hash|/` link.
fn link_file_hash(link: &str) -> Result<String> {
    link.split('|')
        .nth(4)
        .map(str::to_lowercase)
        .with_context(|| format!("read the file hash out of {link}"))
}

/// aMule's own bound sockets, so the UDP port the packed datagram was pushed at
/// is a recorded fact rather than an assumption. Best-effort: a runtime that
/// will not exec here costs a diagnostic, not the run.
fn sockets(bench: &Bench) -> String {
    run_checked(
        bench.docker.exec(
            bench.names.amule_container_name.clone(),
            [
                "sh",
                "-lc",
                // `/proc/net/udp` is the fallback that always answers: the
                // image's `ss` is not on a non-login `docker exec` PATH, and the
                // bound UDP port is what says whether the packed datagram was
                // pushed at a socket aMule actually holds.
                "ss -lnup 2>&1; ss -lntp 2>&1; echo '--- /proc/net/udp';                  cat /proc/net/udp /proc/net/udp6 2>&1",
            ]
            .map(OsString::from),
        ),
        "list aMule's bound sockets",
    )
    .unwrap_or_else(|error| format!("could not list aMule's bound sockets: {error:#}"))
}

/// aMule's `Status` after the window. An exec that fails reads as a session
/// that did not survive, with the failure text kept as the evidence.
fn amule_status(bench: &Bench) -> String {
    run_checked(
        bench.docker.exec(
            bench.names.amule_container_name.clone(),
            amulecmd_command("Status"),
        ),
        "read aMule status after the emission",
    )
    .unwrap_or_else(|error| format!("amulecmd Status failed: {error:#}"))
}

/// Count one pcap row per plan record plus the framing rows, off the tap on
/// aMule's netns. A row that cannot be counted is dropped with a warning rather
/// than recorded as `0`: a fabricated zero is exactly what ADR-0045 forbids.
fn count_wire_rows(bench: &Bench, capture: &str, pcap: &str) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, String)> = Vec::new();
    for record in all_records() {
        rows.push((format!("syn_{}", record.label), syn_filter(record)));
    }
    rows.push((
        "syn_broadcast_id".to_owned(),
        "tcp[tcpflags] & tcp-syn != 0 and dst host 255.255.255.255".to_owned(),
    ));
    rows.push((
        "syn_total".to_owned(),
        "tcp[tcpflags] & tcp-syn != 0".to_owned(),
    ));
    rows.push((
        "udp_from_stimulus".to_owned(),
        format!("udp and src host {STIMULUS_IP} and src port {STIMULUS_UDP_PORT}"),
    ));
    rows.push((
        "udp_to_stimulus".to_owned(),
        format!("udp and dst host {STIMULUS_IP} and dst port {STIMULUS_UDP_PORT}"),
    ));
    let mut counted = Vec::with_capacity(rows.len());
    for (name, filter) in rows {
        match count_pcap_rows(&bench.docker, capture, pcap, &filter) {
            Ok(count) => counted.push((name, count)),
            Err(error) => eprintln!("warning: wire row {name} could not be counted: {error:#}"),
        }
    }
    counted
}

/// The BPF that finds a dial at one record's decoded endpoint. A **Sentinel
/// Source** has no address a legacy reader can dial, so its row counts any SYN
/// at the record's port — which is how a reader that unpacked its `0xFFFFFFFF`
/// id into an address would show up.
fn syn_filter(record: &Record) -> String {
    if record.sentinel {
        format!("tcp[tcpflags] & tcp-syn != 0 and dst port {}", record.port)
    } else {
        format!(
            "tcp[tcpflags] & tcp-syn != 0 and dst host {} and dst port {}",
            record.host, record.port
        )
    }
}

/// aMule's own log lines about the source list — the counterparty in its own
/// words, beside the dials.
fn source_log_lines(diagnostics: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(diagnostics) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| {
            let lower = line.to_lowercase();
            lower.contains("source") || lower.contains("foundsources")
        })
        .map(str::to_owned)
        .take(60)
        .collect()
}

/// Read the stimulus journal and the pcap rows into the observation the verdict
/// judges. Split out of the I/O so the read is unit-testable against a journal
/// fixture.
pub(crate) fn observe(
    journal: &str,
    wire_rows: Vec<(String, u64)>,
    amule_status: String,
    amule_log_lines: Vec<String>,
) -> LegacyObservation {
    // A journal that will not parse must be loud: silently reading it as an
    // empty table would turn a broken run into "the counterparty stayed quiet".
    let parsed: toml::Value = match toml::from_str(journal) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("warning: the stimulus journal did not parse: {error}");
            toml::Value::Table(toml::map::Map::new())
        }
    };
    let logins = parsed
        .get("logins")
        .and_then(toml::Value::as_integer)
        .unwrap_or(0);
    let emissions = parsed.get("emitted").and_then(toml::Value::as_array);
    let emitted = emissions.is_some_and(|rows| !rows.is_empty());
    let emit_trigger = emissions
        .and_then(|rows| rows.first())
        .map(|row| string_at(row, "trigger"))
        .unwrap_or_default();
    let sink_dials: Vec<SinkDial> = parsed
        .get("sink_dial")
        .and_then(toml::Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| SinkDial {
                    local: string_at(row, "local"),
                    peer: string_at(row, "peer"),
                    bytes: string_at(row, "bytes"),
                })
                .collect()
        })
        .unwrap_or_default();
    let dialled = all_records()
        .filter_map(|record| {
            let endpoint = record.sink_endpoint()?;
            Some((
                record.label,
                sink_dials.iter().any(|dial| dial.local == endpoint),
            ))
        })
        .collect();
    let session_survived = amule_status.contains("eD2k: Connected");
    LegacyObservation {
        logins,
        emitted,
        emit_trigger,
        sink_dials,
        dialled,
        wire_rows,
        session_survived,
        amule_status,
        amule_log_lines,
    }
}

fn string_at(row: &toml::Value, key: &str) -> String {
    row.get(key)
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOURNAL: &str = r#"
stimulus = "sentinel-stimulus"
listen = "0.0.0.0:4661"
udp_listen = "0.0.0.0:4665"
sinks = ["5001"]
logins = 1
sink_dials = 2

[[emitted]]
transport = "tcp"
peer = "203.0.113.3:1"
label = "found-sources-0"
trigger = "trigger-file"
bytes = "e342"

[[sink_dial]]
local = "203.0.113.50:5001"
peer = "203.0.113.3:2"
bytes = "e301"

[[sink_dial]]
local = "203.0.113.60:5003"
peer = "203.0.113.3:3"
bytes = "e301"
"#;

    #[test]
    fn a_dial_at_each_plain_records_endpoint_reads_as_that_record_decoded() {
        let observation = observe(
            JOURNAL,
            Vec::new(),
            "eD2k: Connected".to_owned(),
            Vec::new(),
        );
        assert_eq!(observation.logins, 1);
        assert!(observation.emitted);
        assert!(observation.was_dialled("before_sentinel"));
        assert!(observation.was_dialled("after_sentinel"));
        assert!(
            !observation.was_dialled("packed_second"),
            "a record nothing dialled must stay false",
        );
        assert!(observation.session_survived);
    }

    /// A journal the run never produced must not read as a counterparty that
    /// stayed quiet: every field falls to its zero and `emitted` is false, which
    /// is what makes the verdict report the leg as unproven.
    #[test]
    fn an_unreadable_journal_reads_as_nothing_measured() {
        let observation = observe("not toml at all {{{", Vec::new(), String::new(), Vec::new());
        assert_eq!(observation.logins, 0);
        assert!(!observation.emitted);
        assert!(observation.sink_dials.is_empty());
        assert!(!observation.session_survived);
    }
}
