//! Flow M's **buddy reask** leg (`kad-core-buddy --buddy-reask`): a queued
//! downloader that lost its reachability asks the firewalled stock aMule
//! for its queue rank through the buddy the aMule's Kad row names —
//! `OP_REASKCALLBACKUDP` (`0x94`) to the buddy, `OP_REASKCALLBACKTCP`
//! (`0x9A`) over the held buddy link, and the aMule's `OP_REASKACK` (`0x91`)
//! straight back to the downloader (`DownloadClient.cpp:1297-1318`,
//! `ClientTCPSocket.cpp:1695-1760`).
//!
//! aMule takes that road only while it is firewalled and the source is a
//! Low ID with a buddy; the direct `0x90` needs `!IsFirewalled()`. A
//! downloader that is firewalled from the start cannot be queued by a
//! firewalled aMule at all — the callback that reaches the aMule asks it to
//! dial the downloader — so the leg is the life the road exists for:
//!
//! 1. `ed2ksrv` stands on flow M's network, and two **holders** (High-ID
//!    rmule requesters, callable by declaration) reach the aMule through the
//!    buddy callback and take both of its upload slots: the aMule runs at
//!    `MaxUpload` 3 KB/s, where it keeps `MIN_UP_CLIENTS_ALLOWED` = 2 slots
//!    (`UploadQueue.cpp:303-313`), and the file is incompressible, so no
//!    holder finishes a part inside the leg;
//! 2. the **downloader** logs in to `ed2ksrv`, whose High ID makes it
//!    callable, while its listener drops every inbound SYN except the
//!    server's probe and the aMule's dial-back — so no Kad contact can prove
//!    its TCP port open and its Kad TCP verdict stays firewalled. Its
//!    download draws the aMule's row, takes the buddy callback and is queued;
//! 3. once it is queued, `ed2ksrv` stops: the downloader is unreachable, and
//!    at `FILEREASKTIME` less 20 s after the rank its reask sweep takes the
//!    buddy road.
//!
//! Every claim is a wire row off one of four taps or a line of a body's own
//! log; nothing is fabricated (ADR-0045).

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::{Docker, RunContainer};
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, run_checked,
};
use crate::flow::ed2ksrv::ED2KSRV;
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::hex_lower;
use crate::flow::kad_buddy::callback::{
    DOWNLOADER_TCP_PORT, DOWNLOADER_UDP_PORT, Judged, RequesterBody, count_offline, lift, open_gate,
};
use crate::flow::logs::collect_kad_logs;
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT, WireFilter};

/// The downloader's user hash and Kad ID: far from the file key and from
/// the buddy target, so it is neither a storer nor a recruit candidate.
const HASH_DOWNLOADER: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
const DOWNLOADER_KAD_ID: [u8; 16] = [0x2E; 16];
/// The holders' user hashes and Kad IDs.
const HOLDERS: [(&str, [u8; 16]); 2] = [
    ("6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e", [0x3E; 16]),
    ("7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e", [0x4E; 16]),
];
/// The aMule's `MaxUpload`, KB/s: under 10 KB/s it keeps two slots.
pub(crate) const AMULE_MAX_UPLOAD_KIB: &str = "3";
/// aMule's `FILEREASKTIME` (`Constants.h`), the reask period rmule mirrors:
/// the buddy reask falls due 20 s before it.
const FILE_REASK_SECS: u64 = 1300;
/// Every body's window: the holders' slots, the downloader's queue and one
/// reask period, with room on both sides.
const BODY_WINDOW_SECS: u64 = 2100;
/// How long the holders may take to hold both slots, and the downloader to
/// be queued once started.
const SLOT_WAIT_SECS: u64 = 600;
/// How long the downloader may take to notice the server went away.
const DISCONNECT_WAIT_SECS: u64 = 120;
/// Past the reask's due time: the reply's grace before the TCP fallback.
const REASK_GRACE_SECS: u64 = 120;
/// How often a body's log is read while the leg waits on it.
const LOG_TICK: Duration = Duration::from_secs(5);
/// The downloader tap's pcap under its host directory.
const DOWNLOADER_PCAP: &str = "downloader.pcap";
/// `ed2ksrv`'s listening port.
const ED2KSRV_PORT: u16 = 4661;
/// The lowest ed2k High ID: a client ID below it is a Low ID.
const LOWEST_HIGH_ID: u64 = 0x0100_0000;

/// Extra seconds flow M keeps its members alive past its tap window under
/// this leg: every wait above, end to end.
pub(crate) const LEG_SECS: u64 =
    2 * SLOT_WAIT_SECS + DISCONNECT_WAIT_SECS + FILE_REASK_SECS + REASK_GRACE_SECS;

/// What flow M hands the leg.
pub(crate) struct ReaskPlan<'a> {
    pub(crate) image: &'a str,
    pub(crate) capture_image: &'a str,
    pub(crate) ed2ksrv_image: &'a str,
    pub(crate) ed2ksrv_config: &'a Path,
    pub(crate) downloader_v4: String,
    pub(crate) holders_v4: [String; 2],
    pub(crate) ed2ksrv_v4: String,
    /// The firewalled aMule's address: the one dial-back the downloader's
    /// listener admits beside the server's probe.
    pub(crate) amule_v4: String,
    /// The bodies' `--kad-contact` operands.
    pub(crate) seed: Vec<String>,
    /// The ed2k link — the one fact each body is handed.
    pub(crate) link: String,
}

/// When each phase of the leg was seen, unix ms (0: never).
#[derive(Default)]
struct Timeline {
    holders_granted: u64,
    downloader_queued: u64,
    server_stopped: u64,
    server_left: u64,
    reask_settled: u64,
    /// The downloader log line that settled the reask.
    settled_by: String,
}

/// The leg that ran.
pub(crate) struct ReaskLeg {
    dir: PathBuf,
    downloader: String,
    holders: Vec<String>,
    ed2ksrv: String,
    downloader_v4: String,
    holders_v4: [String; 2],
    capture_image: String,
    timeline: Timeline,
}

impl ReaskLeg {
    /// Run the leg end to end: `ed2ksrv`, the holders, the downloader, the
    /// server's stop and the wait for the reask.
    ///
    /// # Errors
    /// If a container cannot be started or a log cannot be read. A phase that
    /// never comes is recorded and judged, not an error.
    pub(crate) fn run(
        docker: &Docker,
        layout: &RunLayout,
        names: &KadMeshNames,
        resources: &mut KadResources<'_>,
        plan: &ReaskPlan<'_>,
    ) -> Result<Self> {
        let dir = layout.kad_dir().join("buddy-reask");
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let ed2ksrv = format!("{}-ed2ksrv", names.requester);
        start_ed2ksrv(docker, names, resources, plan, &dir, &ed2ksrv)?;

        let mut holders = Vec::new();
        for (index, (hash, kad_id)) in HOLDERS.iter().enumerate() {
            let name = format!("{}-holder-{index}", names.requester);
            let holder_dir = dir.join(format!("holder-{index}"));
            fs::create_dir_all(&holder_dir)
                .with_context(|| format!("create {}", holder_dir.display()))?;
            let body = RequesterBody {
                image: plan.image,
                name: &name,
                network: &names.network_name,
                address_v4: &plan.holders_v4[index],
                dir: &holder_dir,
                user_hash: hash,
                kad_id: *kad_id,
                link: &plan.link,
                window_secs: BODY_WINDOW_SECS,
                seed: &plan.seed,
                login: None,
            };
            run_checked(docker.run_container(body.container()), "run a slot holder")?;
            resources.track_started(&format!("holder-{index}"), name.clone());
            open_gate(&holder_dir)?;
            holders.push(name);
        }
        let mut timeline = Timeline::default();
        let mut granted = 0;
        for holder in &holders {
            if wait_logs(
                docker,
                holder,
                &["download.peer_slot_granted"],
                Duration::from_secs(SLOT_WAIT_SECS),
            )?
            .is_some()
            {
                granted += 1;
            }
        }
        if granted == holders.len() {
            timeline.holders_granted = unix_ms();
            println!("kad-buddy-reask: both holders hold an upload slot");
        } else {
            println!(
                "kad-buddy-reask: {granted} of 2 holders got a slot; the downloader runs anyway"
            );
        }

        let downloader_dir = dir.join("downloader");
        fs::create_dir_all(&downloader_dir)
            .with_context(|| format!("create {}", downloader_dir.display()))?;
        let server = format!("{}:{ED2KSRV_PORT}", plan.ed2ksrv_v4);
        let body = RequesterBody {
            image: plan.image,
            name: &names.requester,
            network: &names.network_name,
            address_v4: &plan.downloader_v4,
            dir: &downloader_dir,
            user_hash: HASH_DOWNLOADER,
            kad_id: DOWNLOADER_KAD_ID,
            link: &plan.link,
            window_secs: BODY_WINDOW_SECS,
            seed: &plan.seed,
            login: Some(&server),
        };
        run_checked(
            docker.run_container(
                body.container()
                    .cap_add("NET_ADMIN")
                    .env(
                        "RMULE_FORCE_LOW_ID_TCP_PORT",
                        DOWNLOADER_TCP_PORT.to_string(),
                    )
                    .env("RMULE_TCP_ACCEPT_FROM", accept_from(plan)),
            ),
            "run the reasking downloader",
        )?;
        resources.track_started("downloader", names.requester.clone());
        let tap = format!("{}-downloader", names.capture);
        resources.start_capture(
            layout,
            &CaptureSidecar {
                image: plan.capture_image,
                name: &tap,
                target_container: &names.requester,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: downloader_dir.clone(),
                pcap_file: DOWNLOADER_PCAP,
                bpf: "tcp or udp",
            },
            "kad-capture-downloader-container-id.txt",
        )?;
        open_gate(&downloader_dir)?;
        println!("kad-buddy-reask: downloader started on {server}, gate open");

        if wait_logs(
            docker,
            &names.requester,
            &["download.source_remote_queued"],
            Duration::from_secs(SLOT_WAIT_SECS),
        )?
        .is_some()
        {
            timeline.downloader_queued = unix_ms();
            println!("kad-buddy-reask: the aMule queued the downloader; stopping ed2ksrv");
            run_checked(docker.stop_container(&ed2ksrv, 5), "stop ed2ksrv")?;
            timeline.server_stopped = unix_ms();
            if wait_logs(
                docker,
                &names.requester,
                &["server.disconnected"],
                Duration::from_secs(DISCONNECT_WAIT_SECS),
            )?
            .is_some()
            {
                timeline.server_left = unix_ms();
            }
            let due = Duration::from_millis(
                (timeline.downloader_queued + (FILE_REASK_SECS + REASK_GRACE_SECS) * 1000)
                    .saturating_sub(unix_ms()),
            );
            println!(
                "kad-buddy-reask: waiting up to {}s for the reask to settle",
                due.as_secs()
            );
            if let Some(line) = wait_logs(
                docker,
                &names.requester,
                &[
                    "download.source_reask_acked",
                    "download.source_reask_queue_full",
                    "download.source_reasked_over_tcp",
                ],
                due,
            )? {
                timeline.reask_settled = unix_ms();
                timeline.settled_by = line;
            }
        } else {
            println!("kad-buddy-reask: the downloader was never queued");
        }
        // A clean stop finalizes the downloader's pcap before it is counted.
        let _ = run_checked(
            docker.stop_container(&names.requester, 10),
            "stop the reasking downloader",
        );
        Ok(Self {
            dir,
            downloader: names.requester.clone(),
            holders,
            ed2ksrv,
            downloader_v4: plan.downloader_v4.clone(),
            holders_v4: plan.holders_v4.clone(),
            capture_image: plan.capture_image.to_owned(),
            timeline,
        })
    }

    /// Count the leg's rows off the four taps, lift the three bodies, and
    /// write `kad-buddy-reask-verdict.toml`.
    ///
    /// # Errors
    /// If a tap or log cannot be read, or the verdict is not `PASS` — the
    /// failing claims are the error.
    pub(crate) fn judge(&self, judged: &Judged<'_>) -> Result<()> {
        let docker = judged.docker;
        let downloader_log =
            collect_kad_logs(docker, judged.layout, "downloader", &self.downloader)?;
        let mut holder_logs = Vec::new();
        for (index, holder) in self.holders.iter().enumerate() {
            holder_logs.push(collect_kad_logs(
                docker,
                judged.layout,
                &format!("holder-{index}"),
                holder,
            )?);
        }
        collect_kad_logs(docker, judged.layout, "ed2ksrv", &self.ed2ksrv)?;
        let substitute = |filter: &str| {
            filter
                .replace("{d}", &self.downloader_v4)
                .replace("{h0}", &self.holders_v4[0])
                .replace("{h1}", &self.holders_v4[1])
                .replace("{a}", judged.amule_ip)
                .replace("{r}", judged.rmule_ip)
                .replace("{du}", &DOWNLOADER_UDP_PORT.to_string())
        };
        let mut rows = Vec::new();
        for (key, label, filter) in BUDDY_ROWS {
            let filter = filter.map_bpf(substitute);
            let count = crate::flow::evidence::count_pcap_rows(
                docker,
                judged.buddy_tap,
                judged.buddy_pcap,
                filter,
            )?;
            rows.push((*key, *label, count));
        }
        for (key, label, filter) in AMULE_ROWS {
            let filter = filter.map_bpf(substitute);
            let count = crate::flow::evidence::count_pcap_rows(
                docker,
                judged.amule_tap,
                judged.amule_pcap,
                filter,
            )?;
            rows.push((*key, *label, count));
        }
        let downloader_dir = self.dir.join("downloader");
        for (key, label, filter) in DOWNLOADER_ROWS {
            let count = count_offline(
                docker,
                &self.capture_image,
                &downloader_dir,
                &filter.map_bpf(substitute),
            )?;
            rows.push((*key, *label, count));
        }
        for (key, label, count) in &rows {
            println!("kad-buddy-reask row {key} ({label}) = {count}");
        }
        let reask = lift(
            docker,
            (judged.buddy_tap, judged.buddy_pcap),
            &BUDDY_ROWS[0].2.map_bpf(substitute),
            &judged.buddy_host_dir.join("reask-callback-udp-0x94.pcap"),
        )?;
        let relayed = lift(
            docker,
            (judged.buddy_tap, judged.buddy_pcap),
            &BUDDY_ROWS[1].2.map_bpf(substitute),
            &judged.buddy_host_dir.join("reask-callback-tcp-0x9a.pcap"),
        )?;
        let ack = lift(
            docker,
            (judged.amule_tap, judged.amule_pcap),
            &AMULE_ROWS[0].2.map_bpf(substitute),
            &self.dir.join("reask-ack-0x91.pcap"),
        )?;

        let count = |key: &str| {
            rows.iter()
                .find(|(name, _, _)| *name == key)
                .map_or(0, |(_, _, count)| *count)
        };
        let login_id = login_client_id(&downloader_log);
        let claims = [
            (
                "both-holders-took-the-amules-upload-slots",
                holder_logs
                    .iter()
                    .all(|log| log.contains("download.peer_slot_granted"))
                    && count("amule_accept_upload_to_holders") >= 2,
            ),
            (
                "the-downloader-logged-in-high-id-on-ed2ksrv",
                login_id.is_some_and(|id| id >= LOWEST_HIGH_ID),
            ),
            (
                "the-amule-queued-the-downloader",
                downloader_log.contains("download.peer_queued")
                    && count("amule_queue_ranking_to_downloader") > 0,
            ),
            (
                "the-server-session-ended-before-the-reask",
                self.timeline.server_left > 0,
            ),
            (
                "the-0x94-left-the-downloader-for-the-buddy",
                count("reask_callback_udp_0x94_out") > 0,
            ),
            (
                "the-buddy-relayed-it-as-0x9a-on-the-held-link",
                count("reask_callback_tcp_0x9a_buddy_tap") > 0,
            ),
            (
                "the-amule-answered-the-relayed-reask-with-0x91",
                count("amule_reask_ack_0x91_out") > 0,
            ),
            (
                "the-0x91-reached-the-downloader",
                count("reask_ack_0x91_in") > 0,
            ),
            (
                "the-downloader-recorded-the-ack",
                downloader_log.contains("download.source_reask_acked"),
            ),
            (
                "no-direct-0x90-and-no-tcp-reask",
                count("reask_ping_0x90_out") == 0
                    && count("callback_req_0x52_out") == 1
                    && !downloader_log.contains("download.source_reasked_over_tcp"),
            ),
        ];
        let pass = claims.iter().all(|(_, holds)| *holds);
        let verdict = if pass { "PASS" } else { "FAIL" };

        let mut out = String::from(
            "# Flow M's buddy reask leg (kad-core-buddy --buddy-reask): a queued downloader that\n\
             # lost its server High ID reasks the firewalled stock aMule through its buddy.\n",
        );
        out.push_str(&format!("verdict = \"{verdict}\"\n"));
        out.push_str(&format!(
            "downloader = \"{}:{DOWNLOADER_TCP_PORT}\"\n",
            self.downloader_v4
        ));
        out.push_str(&format!(
            "downloader_login_client_id = {}\n",
            login_id.unwrap_or(0)
        ));
        for (key, value) in [
            ("holders_granted_unix_ms", self.timeline.holders_granted),
            ("downloader_queued_unix_ms", self.timeline.downloader_queued),
            ("server_stopped_unix_ms", self.timeline.server_stopped),
            ("server_left_unix_ms", self.timeline.server_left),
            ("reask_settled_unix_ms", self.timeline.reask_settled),
        ] {
            out.push_str(&format!("{key} = {value}\n"));
        }
        out.push_str(&format!(
            "reask_settled_by = \"{}\"\n",
            self.timeline.settled_by
        ));
        for (key, body) in [
            ("reask_callback_udp_0x94_body", &reask),
            ("reask_callback_tcp_0x9a_frame", &relayed),
            ("reask_ack_0x91_body", &ack),
        ] {
            out.push_str(&format!(
                "{key} = \"{}\"\n",
                body.as_deref().map(hex_lower).unwrap_or_default()
            ));
        }
        out.push_str("\n[claims]\n");
        for (name, holds) in &claims {
            out.push_str(&format!("\"{name}\" = {holds}\n"));
        }
        out.push_str("\n[rows]\n");
        for (key, label, count) in &rows {
            out.push_str(&format!("{key} = {count} # {label}\n"));
        }
        let path = judged.layout.kad_dir().join("kad-buddy-reask-verdict.toml");
        fs::write(&path, &out).with_context(|| format!("write {}", path.display()))?;
        println!("kad-buddy-reask verdict={verdict}");
        if !pass {
            let failing: Vec<&str> = claims
                .iter()
                .filter(|(_, holds)| !holds)
                .map(|(name, _)| *name)
                .collect();
            bail!("kad-buddy-reask: claims not held: {}", failing.join(", "));
        }
        Ok(())
    }
}

/// One counted row: `{d}` downloader, `{h0}`/`{h1}` the holders, `{a}` the
/// aMule, `{r}` the rmule buddy, `{du}` the downloader's UDP port.
type Row = (&'static str, &'static str, WireFilter);

/// Off the stimulus (buddy) netns. The first two are also lifted.
const BUDDY_ROWS: &[Row] = &[
    (
        "reask_callback_udp_0x94_buddy_tap",
        "OP_REASKCALLBACKUDP from the downloader, at the buddy",
        WireFilter::packets_static(
            "udp and src host {d} and dst host {r} and udp[8] = 0xc5 and udp[9] = 0x94",
        ),
    ),
    (
        "reask_callback_tcp_0x9a_buddy_tap",
        "OP_REASKCALLBACKTCP relayed to the aMule on the held link",
        WireFilter::ed2k_static("src host {r} and dst host {a}", &[OP_EMULEPROT], 0x9A),
    ),
];

/// Off the aMule's own netns. The first is also lifted.
const AMULE_ROWS: &[Row] = &[
    (
        "amule_reask_ack_0x91_out",
        "OP_REASKACK from the aMule to the downloader",
        WireFilter::packets_static(
            "udp and src host {a} and dst host {d} and udp[8] = 0xc5 and udp[9] = 0x91",
        ),
    ),
    (
        "amule_accept_upload_to_holders",
        "OP_ACCEPTUPLOADREQ from the aMule to a holder",
        WireFilter::ed2k_static(
            "src host {a} and (dst host {h0} or dst host {h1})",
            &[OP_EDONKEYPROT],
            0x55,
        ),
    ),
    (
        "amule_accept_upload_to_downloader",
        "OP_ACCEPTUPLOADREQ from the aMule to the downloader (recorded, not claimed)",
        WireFilter::ed2k_static("src host {a} and dst host {d}", &[OP_EDONKEYPROT], 0x55),
    ),
];

/// Off the downloader's own netns, counted after it stopped.
const DOWNLOADER_ROWS: &[Row] = &[
    (
        "reask_callback_udp_0x94_out",
        "OP_REASKCALLBACKUDP leaving the downloader for the buddy",
        WireFilter::packets_static(
            "udp and src host {d} and dst host {r} and udp[8] = 0xc5 and udp[9] = 0x94",
        ),
    ),
    (
        "reask_ack_0x91_in",
        "OP_REASKACK from the aMule at the downloader's UDP port",
        WireFilter::packets_static(
            "udp and src host {a} and dst host {d} and dst port {du} \
             and udp[8] = 0xc5 and udp[9] = 0x91",
        ),
    ),
    (
        "reask_queue_full_0x93_in",
        "OP_QUEUEFULL from the aMule (recorded, not claimed)",
        WireFilter::packets_static(
            "udp and src host {a} and dst host {d} and udp[8] = 0xc5 and udp[9] = 0x93",
        ),
    ),
    (
        "reask_ping_0x90_out",
        "a direct OP_REASKFILEPING to the aMule",
        WireFilter::packets_static(
            "udp and src host {d} and dst host {a} and udp[8] = 0xc5 and udp[9] = 0x90",
        ),
    ),
    (
        "callback_req_0x52_out",
        "KADEMLIA_CALLBACK_REQ leaving the downloader for the buddy",
        WireFilter::packets_static(
            "udp and src host {d} and dst host {r} and udp[8] = 0xe4 and udp[9] = 0x52",
        ),
    ),
    (
        "amule_queue_ranking_to_downloader",
        "OP_QUEUERANKING from the aMule on the dial-back",
        WireFilter::ed2k_static("src host {a} and dst host {d}", &[OP_EMULEPROT], 0x60),
    ),
];

/// The addresses the downloader's listener still admits: the server's High-ID
/// probe and the aMule's dial-back. No Kad contact is among them, so none can
/// acknowledge its TCP check.
fn accept_from(plan: &ReaskPlan<'_>) -> String {
    format!("{} {}", plan.ed2ksrv_v4, plan.amule_v4)
}

/// Start `ed2ksrv` at the plan's address on flow M's network, its `this_ip`
/// rendered to match.
fn start_ed2ksrv(
    docker: &Docker,
    names: &KadMeshNames,
    resources: &mut KadResources<'_>,
    plan: &ReaskPlan<'_>,
    dir: &Path,
    name: &str,
) -> Result<()> {
    let config = fs::read_to_string(plan.ed2ksrv_config)
        .with_context(|| format!("read {}", plan.ed2ksrv_config.display()))?;
    let rendered: Vec<String> = config
        .lines()
        .map(|line| {
            if line.starts_with("this_ip") {
                format!("this_ip = \"{}\"", plan.ed2ksrv_v4)
            } else {
                line.to_owned()
            }
        })
        .collect();
    let config_path = dir.join("ed2ksrv-config.toml");
    fs::write(&config_path, rendered.join("\n"))
        .with_context(|| format!("write {}", config_path.display()))?;
    let pinned = ED2KSRV.check(docker, plan.ed2ksrv_image)?;
    let container: RunContainer = pinned
        .container()
        .detach()
        .name(name)
        .network(&names.network_name)
        .ip(&plan.ed2ksrv_v4)
        .volume(&config_path, "/etc/ed2k-server/config.toml");
    run_checked(docker.run_container(container), "run ed2k-server")?;
    resources.track_started("ed2ksrv", name.to_owned());
    wait_for_container_log(
        docker,
        name,
        "TCP listener ready",
        Duration::from_secs(SLOT_WAIT_SECS),
    )?;
    fs::write(dir.join("ed2ksrv-pin.txt"), format!("{}\n", pinned.pin()))
        .with_context(|| format!("write the pin under {}", dir.display()))?;
    Ok(())
}

/// Wait until `container`'s log carries one of `patterns`, reading it every
/// [`LOG_TICK`]; the first line that matched, or `None` at `timeout`.
fn wait_logs(
    docker: &Docker,
    container: &str,
    patterns: &[&str],
    timeout: Duration,
) -> Result<Option<String>> {
    let deadline = Instant::now() + timeout;
    loop {
        let output = docker
            .logs(container)
            .to_command()
            .output()
            .with_context(|| format!("docker logs {container}"))?;
        let logs = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = logs
            .lines()
            .find(|line| patterns.iter().any(|pattern| line.contains(pattern)))
        {
            return Ok(Some(line.to_owned()));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(LOG_TICK.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// The client ID the downloader's `--login` printed, if it logged in.
fn login_client_id(log: &str) -> Option<u64> {
    let line = log
        .lines()
        .find(|line| line.starts_with("rmule-natt-buddy-login connected=true"))?;
    line.split_whitespace()
        .find_map(|field| field.strip_prefix("id="))?
        .parse()
        .ok()
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
