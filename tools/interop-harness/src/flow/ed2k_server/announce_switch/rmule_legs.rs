//! rmule's own legs of the announce-switch proof, against the two servers the
//! probe measured. rmule serves two files on Lugdunum, places a third in its
//! shared directory and switches to ed2k-server (`ed2k serve start
//! --switch-to`); a second leg does the same withholding its shares from a
//! server that grants related search (`--withhold-from-related-search`).
//! A tap on each server's TCP port reads every `OP_OFFERFILES` rmule sent it
//! and the flags each server's `OP_IDCHANGE` granted.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::flow::bench::{Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT};
use crate::flow::ed2k_server::rmule_tools::run_to_exit;
use crate::flow::ed2k_server::search_wire::ED2KSRV_IP;
use crate::flow::ed2k_server::search_wire::server_tap::{granted_flags, offered_origins};

/// The files rmule shares at start, and the one it adds before the switch.
const START_FILES: [&str; 2] = ["announce-alpha.bin", "announce-beta.bin"];
const ADDED_FILE: &str = "announce-gamma.bin";
/// Seconds from the first login to the switch, and the whole run.
const SWITCH_AFTER_SECS: &str = "20";
const RUN_SECS: &str = "50";

/// One rmule leg: its name, rmule's static address and user hash, and
/// whether it withholds.
struct Leg {
    name: &'static str,
    ip: &'static str,
    user_hash: &'static str,
    withhold: bool,
}

const LEGS: [Leg; 2] = [
    Leg {
        name: "switch",
        ip: "203.0.113.71",
        user_hash: "6B21D8F40C3E4A5791E0B6C2A74D3F18",
        withhold: false,
    },
    Leg {
        name: "withhold",
        ip: "203.0.113.72",
        user_hash: "7C32E9A51D4F5B6802F1C7D3B85E4A29",
        withhold: true,
    },
];

/// The two servers a leg taps: a label, the container, and the address
/// rmule dials.
pub(super) struct Servers<'a> {
    /// Lugdunum's container and address.
    pub(super) lugdunum: (&'a str, Ipv4Addr),
    /// ed2k-server's container.
    pub(super) ed2ksrv: &'a str,
}

/// Run both legs; one summary line per leg and server.
///
/// # Errors
/// If a container cannot be run or a tap read, or rmule never logged in.
pub(super) fn run(
    bench: &mut Bench,
    rmule_tools_image: &str,
    capture_image: &str,
    root: &Path,
    servers: &Servers<'_>,
) -> Result<Vec<String>> {
    let files = root.join("rmule");
    fs::create_dir_all(&files).with_context(|| format!("create {}", files.display()))?;
    for (seed, name) in START_FILES.iter().chain([&ADDED_FILE]).enumerate() {
        fs::write(files.join(name), content(seed)).with_context(|| format!("write {name}"))?;
    }
    let mut lines = Vec::new();
    for leg in &LEGS {
        lines.extend(run_leg(
            bench,
            rmule_tools_image,
            capture_image,
            root,
            servers,
            leg,
        )?);
    }
    Ok(lines)
}

fn run_leg(
    bench: &mut Bench,
    rmule_tools_image: &str,
    capture_image: &str,
    root: &Path,
    servers: &Servers<'_>,
    leg: &Leg,
) -> Result<Vec<String>> {
    let taps = [
        ("lugdunum", servers.lugdunum.0),
        ("ed2k-server", servers.ed2ksrv),
    ];
    let mut tap_names = Vec::new();
    for (label, container) in taps {
        let tap = format!("{container}-{}-tap", leg.name);
        let sidecar = CaptureSidecar {
            image: capture_image,
            name: &tap,
            target_container: container,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.to_path_buf(),
            pcap_file: &pcap_name(leg, label),
            bpf: "tcp port 4661",
        };
        bench.start_extra(&tap, sidecar.container(), "run a server tap")?;
        tap_names.push(tap);
    }
    std::thread::sleep(Duration::from_secs(2));

    let first = format!("{}:{ED2K_SERVER_PORT}", servers.lugdunum.1);
    let second = format!("{ED2KSRV_IP}:4661");
    let start_files: Vec<String> = START_FILES
        .iter()
        .map(|name| format!("/w/rmule/{name}"))
        .collect();
    let added = format!("/w/rmule/{ADDED_FILE}");
    let mut args = vec!["ed2k", "serve", "start"];
    for file in &start_files {
        args.extend(["--file", file.as_str()]);
    }
    args.extend([
        "--server",
        &first,
        "--switch-to",
        &second,
        "--switch-after",
        SWITCH_AFTER_SECS,
        "--add-at-switch",
        &added,
        "--listen",
        "0.0.0.0:4662",
        "--tcp-port",
        "4662",
        "--user-hash",
        leg.user_hash,
        "--nickname",
        "announce-switch",
        "--max-seconds",
        RUN_SECS,
    ]);
    if leg.withhold {
        args.push("--withhold-from-related-search");
    }
    let rmule = format!("{}-{}-rmule", servers.lugdunum.0, leg.name);
    let logs = run_to_exit(bench, rmule_tools_image, &rmule, leg.ip, root, &args)?;
    bench.stop_extra(&rmule);
    for tap in &tap_names {
        bench.stop_extra(tap);
    }
    if !logs.contains("rmule-serve-switch connecting") {
        bail!("{} leg: rmule never reached the switch", leg.name);
    }

    let client: Ipv4Addr = leg.ip.parse()?;
    let mut lines = Vec::new();
    for (label, _) in taps {
        let pcap = root.join(pcap_name(leg, label));
        let flags = granted_flags(&pcap, client)?
            .map_or_else(|| "none".to_owned(), |flags| format!("{flags:#x}"));
        // Each offer as `count@time`, then the ID:port every entry wore.
        let offered: Vec<String> = offered_origins(&pcap, client)?
            .iter()
            .map(|(at, origins)| {
                let marks: Vec<String> = origins
                    .iter()
                    .map(|(id, port)| format!("{id:08x}:{port:04x}"))
                    .collect();
                format!("{}@{at:.1}({})", origins.len(), marks.join(" "))
            })
            .collect();
        lines.push(format!(
            "leg={} server={label} granted_flags={flags} offers=[{}]",
            leg.name,
            offered.join(",")
        ));
    }
    Ok(lines)
}

fn pcap_name(leg: &Leg, label: &str) -> String {
    format!("rmule-{}-{label}.pcap", leg.name)
}

/// A file's bytes, distinct per `seed` so every file is its own content.
fn content(seed: usize) -> Vec<u8> {
    (0..300_000usize)
        .map(|index| (index.wrapping_mul(131 + 2 * seed) ^ (index >> 7) ^ seed) as u8)
        .collect()
}
