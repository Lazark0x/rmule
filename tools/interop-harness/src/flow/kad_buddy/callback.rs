//! Flow M's **third party** (README `kad-core-buddy --callback-downloader`): a High-ID rmule
//! downloader handed only the ed2k link of the file the firewalled aMule
//! shares, so ADR-0061 route 4 runs end to end against a live aMule target.
//!
//! Flow M already stands up everything the road needs on the far side: the
//! firewalled aMule (debug image) holds its buddy link to the Core-pumped
//! rmule stimulus, and under `--publish-source` publishes its type-3 row —
//! buddy IP, buddy UDP port, `TAG_BUDDYHASH` — to the member placed at the
//! file's own Kad key. What no flow-M run had was anyone *asking* for a relay.
//! This leg adds the asker:
//!
//! 1. the harness waits for the placed storer to log `SourceIndexed` —
//!    aMule's row is stored, nothing is handed over;
//! 2. only then does the downloader start (seeded with the stimulus and the
//!    members) and its gate open. Not earlier, on purpose: a High-ID Core with
//!    a bound listener is exactly the **fresh UDP Firewall Helper** aMule's
//!    `CUDPFirewallTester` looks for, and an aMule whose UDP verdict reads
//!    open never searches for a buddy at all (run `1790149036`:
//!    `Kad2FirewallUDP from` the downloader, then `New Kad Firewallstate
//!    (UDP): Open` 33 s after Kad start, and no `0x51` ever). Once the UDP
//!    verdict has timed out firewalled, aMule does not re-test it for an hour
//!    (`Kademlia.cpp:106`);
//! 3. the download's Kad search draws that row, `LowIdRoad::BuddyCallback`
//!    sends the plaintext `0x52` to the buddy the row names, the buddy relays
//!    `OP_CALLBACK` (`0x99`) over the held link, and aMule's
//!    `ClientTCPSocket.cpp:1630-1661` dials the downloader's listener back;
//! 4. the dial-back is adopted by User Hash and the file crosses it.
//!
//! Three taps judge it: the stimulus's own (the `0x52` in, the `0x99` out),
//! the downloader's (the `0x52` out, aMule's SYN and `OP_HELLO` in), and
//! flow M's storer tap on aMule's netns. Every claim is a wire row or the
//! downloader's own row; nothing is fabricated (ADR-0045).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CAPTURE_MOUNT, CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, run_checked,
};
use crate::flow::evidence::{count_pcap_rows, write_pcap_first_match};
use crate::flow::gate::wait_for_host_file;
use crate::flow::identity::{hex_lower, parse_ed2k_file_hash};
use crate::flow::kad_member::seed_operand;
use crate::flow::pcap::TcpStream;
use crate::flow::wire_filter::{
    OP_EDONKEYPROT, OP_EMULEPROT, WireFilter, lift_ed2k_frames, link_script,
    refuse_segment_payload, streams_from,
};

/// The downloader's user hash: fixed so a hello and a verdict name one value.
const HASH_DOWNLOADER: &str = "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d";
/// The downloader's Kad ID — far from the file key and from the buddy target,
/// so it is neither a storer nor a recruit candidate.
const DOWNLOADER_KAD_ID: [u8; 16] = [0x2D; 16];
/// The downloader's serve listener: the port the `0x52` invites aMule to dial.
pub(crate) const DOWNLOADER_TCP_PORT: u16 = 4662;
/// The downloader's one UDP bind (Kad, client-UDP and NAT-T share it).
const DOWNLOADER_UDP_PORT: u16 = 4672;
/// How long the download is given once the gate opens.
const DOWNLOAD_WINDOW_SECS: u64 = 300;
/// How long the driver is given past its window to write its row and exit.
const ROW_GRACE_SECS: u64 = 120;
/// The downloader tap's pcap under its host directory.
const DOWNLOADER_PCAP: &str = "downloader.pcap";
/// The `--server` every rmule-tools body names; nothing listens on it.
const ABSENT_SERVER: &str = "192.0.2.1:4661";

/// Where the downloader stands and whom it may ask.
pub(crate) struct DownloaderPlan<'a> {
    /// The `rmule-tools` image it runs in.
    pub(crate) image: &'a str,
    /// The capture image its tap runs in.
    pub(crate) capture_image: &'a str,
    /// Its fake-public address on flow M's network.
    pub(crate) address_v4: String,
    /// `<kad-id>@<ip>:<udp>` operands: the stimulus and every placed member.
    pub(crate) seed: Vec<String>,
    /// The ed2k link — the one fact it is handed.
    pub(crate) link: String,
}

/// The downloader and its tap — or, when aMule's row never reached the
/// storer, the downloader that was never started (its verdict still written).
pub(crate) struct CallbackLeg {
    container: String,
    dir: PathBuf,
    address_v4: String,
    started: bool,
    capture_image: String,
}

/// Wait for the placed storer to index a source — aMule's row, the only one
/// published in this swarm. Returns whether it came inside `timeout`.
///
/// # Errors
/// If the host cannot be polled.
pub(crate) fn await_indexed(storer_events: &Path, timeout: Duration) -> Result<bool> {
    let indexed = wait_for_host_file(storer_events, "SourceIndexed", timeout)?;
    if !indexed {
        println!(
            "kad-buddy-callback: the placed storer indexed no source within {}s; no \
             downloader is started",
            timeout.as_secs()
        );
    }
    Ok(indexed)
}

impl CallbackLeg {
    /// Start the downloader and its tap, then open the downloader's gate —
    /// the tap is attached before the download's first datagram.
    ///
    /// # Errors
    /// If a container cannot be started.
    pub(crate) fn start(
        docker: &Docker,
        layout: &RunLayout,
        names: &KadMeshNames,
        resources: &mut KadResources<'_>,
        plan: DownloaderPlan<'_>,
    ) -> Result<Self> {
        let dir = layout.kad_dir().join("downloader");
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let window = DOWNLOAD_WINDOW_SECS.to_string();
        let gate_secs = "60".to_owned();
        let mut container = RunContainer::new(plan.image)
            .detach()
            .name(&names.requester)
            .network(&names.network_name)
            .ip(&plan.address_v4)
            .env(
                "RMULE_LOG",
                "info,rmule_core::natt=debug,rmule_core::download=debug,\
                 rmule_core::adapters=debug,rmule_core::service=debug",
            )
            .volume(&dir, "/out");
        for arg in [
            "natt",
            "buddy-rendezvous",
            "--role",
            "requester",
            "--server",
            ABSENT_SERVER,
            "--listen",
            &format!("0.0.0.0:{DOWNLOADER_TCP_PORT}"),
            "--udp-port",
            &DOWNLOADER_UDP_PORT.to_string(),
            "--user-hash",
            HASH_DOWNLOADER,
            "--own-ip",
            &plan.address_v4,
            "--share",
            "/etc/hostname",
            "--window",
            &window,
            "--out",
            "/out/buddy-rendezvous.toml",
            // A High-ID downloader: callable, so the brain admits route 4.
            "--assume-open",
            "--kad-id",
            &hex_lower(&DOWNLOADER_KAD_ID),
            "--file",
            &plan.link,
            "--download-out",
            "/out/dl/download.bin",
            "--target-file",
            "/out/target.toml",
            "--target-timeout",
            &gate_secs,
        ] {
            container = container.arg(arg);
        }
        for operand in &plan.seed {
            container = container.arg("--kad-contact").arg(operand);
        }
        run_checked(
            docker.run_container(container),
            "run the callback downloader",
        )?;
        resources.track_started("downloader", names.requester.clone());

        let tap = format!("{}-downloader", names.capture);
        let sidecar = CaptureSidecar {
            image: plan.capture_image,
            name: &tap,
            target_container: &names.requester,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: dir.clone(),
            pcap_file: DOWNLOADER_PCAP,
            bpf: "tcp or udp",
        };
        resources.start_capture(layout, &sidecar, "kad-capture-downloader-container-id.txt")?;
        // Gate only: the transfer requester reads none of these fields, but
        // the driver's gate parser wants all three present.
        let gate = dir.join("target.toml");
        fs::write(
            &gate,
            "user_hash=00000000000000000000000000000000\nbuddy_id=00000000000000000000000000000000\n\
             buddy_udp=0.0.0.0:0\n",
        )
        .with_context(|| format!("write {}", gate.display()))?;
        println!("kad-buddy-callback: downloader started, gate open");
        Ok(Self {
            container: names.requester.clone(),
            dir,
            address_v4: plan.address_v4,
            started: true,
            capture_image: plan.capture_image.to_owned(),
        })
    }

    /// The leg whose downloader never started: nothing to count on its side.
    pub(crate) fn never_started(layout: &RunLayout, names: &KadMeshNames) -> Self {
        Self {
            container: names.requester.clone(),
            dir: layout.kad_dir().join("downloader"),
            address_v4: String::new(),
            started: false,
            capture_image: String::new(),
        }
    }

    /// Whether the downloader ran.
    pub(crate) fn started(&self) -> bool {
        self.started
    }

    /// Give the download its window: wait for the driver's row.
    ///
    /// # Errors
    /// If the host cannot be polled.
    pub(crate) fn run(&self) -> Result<()> {
        let written = wait_for_host_file(
            &self.dir.join("buddy-rendezvous.toml"),
            "role",
            Duration::from_secs(DOWNLOAD_WINDOW_SECS + ROW_GRACE_SECS),
        )?;
        if !written {
            println!("kad-buddy-callback: the downloader wrote no row inside its window");
        }
        Ok(())
    }

    /// Count the leg's wire rows off the two taps, lift the `0x52` and `0x99`
    /// bodies, and write `kad-buddy-callback-verdict.toml`.
    ///
    /// # Errors
    /// If a tap cannot be read, or the verdict is not `PASS` — the named
    /// failing claims are the error.
    pub(crate) fn judge(&self, judged: &Judged<'_>) -> Result<()> {
        let docker = judged.docker;
        let substitute = |filter: &str| {
            filter
                .replace("{d}", &self.address_v4)
                .replace("{a}", judged.amule_ip)
                .replace("{r}", judged.rmule_ip)
                .replace("{dp}", &DOWNLOADER_TCP_PORT.to_string())
                .replace("{rp}", &crate::rmule::RMULE_SERVE_TCP_PORT.to_string())
        };
        let mut rows = Vec::new();
        for row in BUDDY_TAP_ROWS {
            let count = count_pcap_rows(
                docker,
                judged.buddy_tap,
                judged.buddy_pcap,
                row.filter.map_bpf(substitute),
            )?;
            rows.push((row.key, row.label, count));
        }
        for row in AMULE_TAP_ROWS {
            let count = count_pcap_rows(
                docker,
                judged.amule_tap,
                judged.amule_pcap,
                row.filter.map_bpf(substitute),
            )?;
            rows.push((row.key, row.label, count));
        }
        for row in DOWNLOADER_TAP_ROWS {
            // The downloader's tap shares its netns, so it died with the
            // driver's exit: its pcap is read by a one-shot container.
            let count = if self.started {
                count_offline(
                    docker,
                    &self.capture_image,
                    &self.dir,
                    &row.filter.map_bpf(substitute),
                )?
            } else {
                0
            };
            rows.push((row.key, row.label, count));
        }
        for (key, label, count) in &rows {
            println!("kad-buddy-callback row {key} ({label}) = {count}");
        }
        let callback_req = lift(
            docker,
            (judged.buddy_tap, judged.buddy_pcap),
            &BUDDY_TAP_ROWS[0].filter.map_bpf(substitute),
            &judged.buddy_host_dir.join("callback-req-0x52.pcap"),
        )?;
        let relayed = lift(
            docker,
            (judged.buddy_tap, judged.buddy_pcap),
            &BUDDY_TAP_ROWS[1].filter.map_bpf(substitute),
            &judged.buddy_host_dir.join("callback-0x99.pcap"),
        )?;

        let row = fs::read_to_string(self.dir.join("buddy-rendezvous.toml")).unwrap_or_default();
        let field = |key: &str| -> String {
            row.lines()
                .find_map(|line| {
                    let (name, value) = line.split_once('=')?;
                    (name.trim() == key).then(|| value.trim().trim_matches('"').to_owned())
                })
                .unwrap_or_default()
        };
        let link = fs::read_to_string(judged.layout.synthetic_ed2k_file())
            .context("read the synthetic ed2k link")?;
        let expected_hash = hex_lower(&parse_ed2k_file_hash(link.trim())?).to_uppercase();
        let count = |key: &str| {
            rows.iter()
                .find(|(name, _, _)| *name == key)
                .map_or(0, |(_, _, count)| *count)
        };
        let routed = field("routed");
        let claims = [
            (
                "the-firewalled-amule-published-its-buddy-row-to-the-placed-storer",
                self.started,
            ),
            (
                "the-download-routed-the-buddy-callback-from-the-kad-row",
                routed == "buddy emitted_to=peer",
            ),
            (
                "the-0x52-left-the-downloader-for-the-buddy",
                count("downloader_callback_req_0x52_out") > 0,
            ),
            (
                "the-0x52-reached-the-rmule-buddy",
                count("downloader_callback_req_0x52_buddy_tap") > 0,
            ),
            (
                "the-buddy-relayed-op-callback-to-amule-on-the-held-link",
                count("rmule_callback_0x99_to_amule_buddy_tap") > 0,
            ),
            (
                "amule-dialed-back-the-downloaders-listener",
                count("amule_dial_back_syn") > 0,
            ),
            (
                "amule-said-hello-on-the-dial-back",
                count("amule_dial_back_hello_0xe3_0x01") > 0,
            ),
            (
                "the-file-completed-byte-equal-over-the-dial-back",
                field("download_completed") == "true" && field("output_ed2k_hash") == expected_hash,
            ),
        ];
        let pass = claims.iter().all(|(_, holds)| *holds);
        let verdict = if pass { "PASS" } else { "FAIL" };

        let mut out = String::from(
            "# Flow M's third party (kad-core-buddy --callback-downloader): ADR-0061 route 4 against a live\n\
             # firewalled aMule — a High-ID rmule downloader handed only the ed2k link.\n",
        );
        out.push_str(&format!("verdict = \"{verdict}\"\n"));
        out.push_str(&format!(
            "downloader = \"{}:{DOWNLOADER_TCP_PORT}\"\n",
            self.address_v4
        ));
        out.push_str(&format!(
            "downloader_routed = \"{}\"\n",
            routed.replace('"', "'")
        ));
        for key in [
            "download_completed",
            "download_failure",
            "output_bytes",
            "output_ed2k_hash",
        ] {
            out.push_str(&format!("downloader_{key} = \"{}\"\n", field(key)));
        }
        out.push_str(&format!("expected_ed2k_hash = \"{expected_hash}\"\n"));
        out.push_str(&format!(
            "callback_req_0x52_body = \"{}\"\n",
            callback_req.as_deref().map(hex_lower).unwrap_or_default()
        ));
        out.push_str(&format!(
            "callback_0x99_segment = \"{}\"\n",
            relayed.as_deref().map(hex_lower).unwrap_or_default()
        ));
        out.push_str("\n[claims]\n");
        for (name, holds) in &claims {
            out.push_str(&format!("\"{name}\" = {holds}\n"));
        }
        out.push_str("\n[rows]\n");
        for (key, label, count) in &rows {
            out.push_str(&format!("{key} = {count} # {label}\n"));
        }
        let path = judged
            .layout
            .kad_dir()
            .join("kad-buddy-callback-verdict.toml");
        fs::write(&path, &out).with_context(|| format!("write {}", path.display()))?;
        println!("kad-buddy-callback verdict={verdict} routed={routed}");
        if !pass {
            let failing: Vec<&str> = claims
                .iter()
                .filter(|(_, holds)| !holds)
                .map(|(name, _)| *name)
                .collect();
            bail!(
                "kad-buddy-callback: claims not held: {}",
                failing.join(", ")
            );
        }
        Ok(())
    }

    /// The downloader container's name, for log collection.
    pub(crate) fn container(&self) -> &str {
        &self.container
    }
}

/// What [`CallbackLeg::judge`] reads beside its own tap.
pub(crate) struct Judged<'a> {
    pub(crate) docker: &'a Docker,
    pub(crate) layout: &'a RunLayout,
    /// The stimulus-netns tap flow M already runs, and its pcap.
    pub(crate) buddy_tap: &'a str,
    pub(crate) buddy_pcap: &'a str,
    /// Where that tap writes on the host, for the lifted bodies.
    pub(crate) buddy_host_dir: &'a Path,
    /// Flow M's tap on aMule's own netns (tcp and udp under this leg).
    pub(crate) amule_tap: &'a str,
    pub(crate) amule_pcap: &'a str,
    pub(crate) amule_ip: &'a str,
    pub(crate) rmule_ip: &'a str,
}

/// One counted row: `{d}` downloader, `{a}` aMule, `{r}` the rmule buddy,
/// `{dp}` the downloader's listener, `{rp}` the buddy's serve listener.
struct LegRow {
    key: &'static str,
    label: &'static str,
    filter: WireFilter,
}

/// Off the stimulus (buddy) netns. The first two are also the lifted bodies.
const BUDDY_TAP_ROWS: &[LegRow] = &[
    LegRow {
        key: "downloader_callback_req_0x52_buddy_tap",
        label: "KADEMLIA_CALLBACK_REQ from the downloader, at the buddy",
        filter: WireFilter::packets_static(
            "udp and src host {d} and dst host {r} and udp[8] = 0xe4 and udp[9] = 0x52",
        ),
    },
    LegRow {
        key: "rmule_callback_0x99_to_amule_buddy_tap",
        label: "OP_CALLBACK relayed to aMule on the held link",
        filter: WireFilter::ed2k_static("src host {r} and dst host {a}", &[OP_EMULEPROT], 0x99),
    },
];

/// Off aMule's own netns: where its dial-back goes, whatever the address.
const AMULE_TAP_ROWS: &[LegRow] = &[
    LegRow {
        key: "amule_syn_to_listener_port_any_host_amule_tap",
        label: "aMule's TCP SYNs toward the downloader's listener port, any address",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst port {dp} and tcp[tcpflags] & tcp-syn != 0 \
                 and tcp[tcpflags] & tcp-ack == 0",
        ),
    },
    LegRow {
        key: "amule_syn_to_downloader_amule_tap",
        label: "aMule's TCP SYNs toward the downloader's own address",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst host {d} and tcp[tcpflags] & tcp-syn != 0 \
                 and tcp[tcpflags] & tcp-ack == 0",
        ),
    },
];

/// Off the downloader's own netns.
const DOWNLOADER_TAP_ROWS: &[LegRow] = &[
    LegRow {
        key: "downloader_callback_req_0x52_out",
        label: "KADEMLIA_CALLBACK_REQ leaving the downloader for the buddy",
        filter: WireFilter::packets_static(
            "udp and src host {d} and dst host {r} and udp[8] = 0xe4 and udp[9] = 0x52",
        ),
    },
    LegRow {
        key: "amule_dial_back_syn",
        label: "aMule's TCP SYN onto the downloader's listener",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst port {dp} and tcp[tcpflags] & tcp-syn != 0 \
                 and tcp[tcpflags] & tcp-ack == 0",
        ),
    },
    LegRow {
        key: "amule_dial_back_hello_0xe3_0x01",
        label: "OP_HELLO from aMule on the dial-back",
        filter: WireFilter::ed2k_static("src host {a}", &[OP_EDONKEYPROT], 0x01),
    },
    LegRow {
        key: "downloader_syn_to_amule",
        label: "a TCP SYN from the downloader to aMule (its firewall drops any; recorded, not claimed)",
        filter: WireFilter::packets_static(
            "tcp and src host {d} and dst host {a} and tcp[tcpflags] & tcp-syn != 0 \
                 and tcp[tcpflags] & tcp-ack == 0",
        ),
    },
    LegRow {
        key: "downloader_syn_to_buddy_serve",
        label: "a TCP SYN from the downloader to the buddy's serve listener",
        filter: WireFilter::packets_static(
            "tcp and src host {d} and dst host {r} and dst port {rp} \
                 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
        ),
    },
    LegRow {
        key: "amule_payload_segments_to_downloader",
        label: "TCP segments carrying payload from aMule to the downloader",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst host {d} \
                 and (((ip[2:2] - ((ip[0] & 0xf) << 2)) - ((tcp[12] & 0xf0) >> 2)) != 0)",
        ),
    },
];

/// Count `filter` over the downloader's pcap, since the sidecar that wrote it
/// is gone: a packet row from a one-shot capture-image container, an eD2k
/// frame row by walking the file here.
fn count_offline(docker: &Docker, image: &str, dir: &Path, filter: &WireFilter) -> Result<u64> {
    let offline = |script: String| {
        docker.run_container(
            RunContainer::new(image)
                .remove_after_exit()
                .volume(dir, CAPTURE_MOUNT)
                .arg("sh")
                .arg("-c")
                .arg(script),
        )
    };
    let pcap = format!("{CAPTURE_MOUNT}/{DOWNLOADER_PCAP}");
    let bpf = match filter {
        WireFilter::Packets(bpf) => bpf,
        WireFilter::Ed2kFrames { link, .. } => {
            let output = offline(link_script(&pcap, link)?)
                .to_command()
                .output()
                .context("count a downloader-tap row: failed to spawn container runtime")?;
            return Ok(streams_from(&output, DOWNLOADER_PCAP, link)?
                .iter()
                .flat_map(TcpStream::ed2k_frames)
                .filter(|frame| filter.matches(frame))
                .count() as u64);
        }
    };
    refuse_segment_payload(bpf)?;
    let script = format!(
        "tcpdump -nr {pcap} '{bpf}' 2>/tmp/e | wc -l; \
         if grep -vE 'reading from file|truncated dump file' /tmp/e | grep -q .; then \
         cat /tmp/e >&2; exit 1; fi"
    );
    let out = run_checked(offline(script), "count a downloader-tap row")?;
    out.trim()
        .parse::<u64>()
        .with_context(|| format!("non-numeric count {out:?} for `{bpf}`"))
}

/// Lift the first thing `filter` selects on a running tap: a datagram's body
/// for a packet row (its one-packet pcap at `out`), or a whole eD2k frame for
/// a frame row (the link's segments at `out`). The bytes also land at `out`
/// with `.bin`.
pub(crate) fn lift(
    docker: &Docker,
    (tap, pcap): (&str, &str),
    filter: &WireFilter,
    out: &Path,
) -> Result<Option<Vec<u8>>> {
    let name = out
        .file_name()
        .and_then(|name| name.to_str())
        .context("a lifted body needs a file name")?;
    let body = match filter {
        WireFilter::Packets(bpf) => {
            write_pcap_first_match(docker, tap, pcap, bpf, name)?;
            crate::flow::pcap::first_udp_payload(out)?
        }
        WireFilter::Ed2kFrames { .. } => lift_ed2k_frames(docker, tap, pcap, filter, name)?
            .into_iter()
            .next()
            .map(|frame| frame.bytes),
    };
    if let Some(bytes) = &body {
        let bin = out.with_extension("bin");
        fs::write(&bin, bytes).with_context(|| format!("write {}", bin.display()))?;
    }
    Ok(body)
}

/// The downloader's seed: the stimulus and every placed member, as the
/// driver's `--kad-contact` operands. aMule is left out — a firewalled node
/// is no one's routing contact here.
pub(crate) fn seed(stimulus: (&str, &str, u16), members: &[(String, u16, String)]) -> Vec<String> {
    std::iter::once(seed_operand(stimulus.0, stimulus.1, stimulus.2))
        .chain(
            members
                .iter()
                .map(|(address, udp, kad_id)| seed_operand(kad_id, address, *udp)),
        )
        .collect()
}
