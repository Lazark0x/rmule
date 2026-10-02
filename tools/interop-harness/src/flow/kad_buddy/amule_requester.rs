//! Flow M's **stock aMule requester** (README
//! `kad-core-buddy --amule-requester`): the third party
//! `kad-core-buddy --callback-downloader` ran as an rmule downloader, run
//! instead as a second stock aMule 2.3.3 on the debug image, handed only
//! the ed2k link. What it adds is the one `0x52` no earlier run held:
//! **aMule's own**.
//!
//! The road is aMule's, start to finish:
//!
//! 1. the harness waits for the placed storer — an rmule `kad join-node`
//!    member pinned to the file's Kad key — to index the firewalled aMule's
//!    type-3 row, whose `TAG_SERVERIP`/`TAG_SERVERPORT` name the rmule
//!    stimulus's Kad endpoint and whose `TAG_BUDDYHASH` is the stimulus's own
//!    Kad ID (`~aMuleKadID`, the FindBuddy target it sits on);
//! 2. the requester starts, joins, and is gated on `Kad: Connected (ok)`:
//!    `CamuleApp::CanDoCallback` (`amule.cpp:3207-3256`) refuses a Kad-only
//!    node any callback while `CKademlia::IsFirewalled()` holds, and a source
//!    it found while firewalled parks in `DS_LOWTOLOWIP`. Two TCP firewall
//!    testers are in its seed for that verdict — the Core-pumped stimulus
//!    (its dial-back broker) and the firewalled aMule (whose `RequestTCP`
//!    dials out fine);
//! 3. the link waits for the requester's firewall-check client for the
//!    firewalled aMule to be deleted ([`firewall_check_client`]):
//!    while it lives, the row's source attaches to it by user hash and is
//!    dialed directly;
//! 4. the link goes in; `CPartFile::Process` starts a `FILE` search at once,
//!    its `0x34` lands on the placed storer, and the storer's `0x3B` carries
//!    the row; `KademliaSearchFile` (`DownloadQueue.cpp:1760-1776`) builds a
//!    Low-ID client with the buddy IP, port and ID;
//! 5. `TryToConnect` puts it in `DS_WAITCALLBACK` and, with a buddy endpoint
//!    known, sends the plaintext `0x52` to it (`BaseClient.cpp:2133-2141`);
//! 6. the stimulus relays `OP_CALLBACK` (`0x99`) over the link the firewalled
//!    aMule holds, which dials the requester back.
//!
//! Three taps judge it — the stimulus's (the `0x52` in, the `0x99` out), the
//! firewalled aMule's (its dial-back SYN), the requester's own (its `0x34`,
//! the storer's `0x3B`, the `0x52` out) — and the bodies are lifted off them.
//! Nothing is fabricated (ADR-0045).

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmule_primitives::kad_wire_id;

use crate::docker::Docker;
use crate::flow::bench::{
    CaptureSidecar, DEFAULT_TAP_INTERFACE, KadMeshNames, KadResources, amulecmd_command,
    run_checked,
};
use crate::flow::evidence::{count_pcap_rows, verify_bytes};
use crate::flow::gate::wait_for_amule_status;
use crate::flow::identity::{hex_lower, parse_ed2k_file_hash, parse_ipv4_octets};
use crate::flow::kad_buddy::callback::{Judged, lift};
use crate::flow::kad_buddy::id_only_row::FIREWALLED_USER_HASH;
use crate::flow::kad_buddy::requester_datagrams::{FINDSOURCE_WALK_ROW, RequesterDatagrams};
use crate::flow::logs::{collect_amule_logfile, collect_kad_logs};
use crate::flow::mesh::{KAD_TCP_PORT, KadCaptureOptions, KadNodeSpec, start_kad_node};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT, WireFilter};
use crate::kad_seed::KadContact;

mod firewall_check_client;
use firewall_check_client::ReleaseGate;

/// The requester's Kad ID — far from the file key and the buddy target, so
/// it is neither a storer nor a recruit candidate.
const REQUESTER_KAD_ID: [u8; 16] = [0x2E; 16];
/// The requester's pinned user hash, written to `preferences.dat` (the
/// entrypoint's `UserHash` config key does not pin it).
const REQUESTER_USER_HASH: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
/// Offset of the requester's Kad UDP port above the bench base: clear of the
/// firewalled node (`+2`) and the placed members (`+16..`).
const REQUESTER_UDP_OFFSET: u16 = 32;
/// How long the requester may take to read Kad-open before the link goes in
/// anyway (the claim then records that it did not).
const KAD_OPEN_DEADLINE_SECS: u64 = 900;
/// How long the download is given once the link is in.
const DOWNLOAD_WINDOW_SECS: u64 = 300;
/// The requester tap's pcap under its host directory.
const REQUESTER_PCAP: &str = "amule-requester.pcap";

/// What flow M hands the requester beyond its bench.
pub(crate) struct AmuleRequesterPlan<'a> {
    /// The open-node aMule options (image, verbose Kad logging, image env).
    pub(crate) base: KadCaptureOptions<'a>,
    /// Its routing-zone seed: the stimulus, the members, the firewalled aMule.
    pub(crate) seed: Vec<KadContact>,
    /// The placed storer's address, whose `0x3B` the requester reads.
    pub(crate) storer_ip: String,
    /// The firewalled aMule's address, whose firewall-check client the link
    /// waits out.
    pub(crate) firewalled_ip: String,
    /// Arm the requester's crypt layer (`AMULE_KAD_CRYPT=1`): its
    /// Kad sends to crypt-era contacts then leave keyed on their Kad IDs.
    pub(crate) kad_crypt: bool,
    /// The ID-only road carried to a transfer: the firewalled
    /// aMule shares the file, so the dial-back and the file become required.
    pub(crate) findsource_transfer: bool,
}

/// The requester's routing-zone seed: every contact the firewalled node was
/// seeded with, and the firewalled node itself — its `RequestTCP` is one of
/// the two TCP firewall testers the requester's Kad-open verdict needs.
///
/// Order is load-bearing. The whole swarm shares one `/24`, and aMule admits
/// at most two contacts per subnet into a routing bin (run `1790184591`:
/// `Ignored kad contact ... too many contact with the same subnet`), so only
/// the first two seeds become the contacts it hellos — and a firewall check
/// rides only a hello. The two that can dial back go first: the stimulus
/// (the flow's first seed) and the firewalled aMule. With a `join-node`
/// member in the second slot the requester drew one ack per recheck and read
/// Kad-open 6 min 42 s after connecting.
pub(crate) fn requester_seed(firewalled: &KadNodeSpec) -> Vec<KadContact> {
    let mut seed = firewalled.seed_contacts.clone();
    seed.insert(
        1,
        KadContact {
            kad_id: firewalled.kad_id,
            ipv4: firewalled.ip,
            udp_port: firewalled.udp_port,
            tcp_port: KAD_TCP_PORT,
            version: crate::flow::mesh::KAD_CONTACT_VERSION,
        },
    );
    seed
}

/// The requester that ran, and where its evidence sits.
pub(crate) struct AmuleRequesterLeg {
    container: String,
    tap: String,
    dir: PathBuf,
    address_v4: String,
    storer_ip: String,
    kad_open: bool,
    /// How the wait for the firewall-check client's deletion ended.
    release_gate: ReleaseGate,
    completed: bool,
    /// `Some` under the ID-only variant: whether the rmule buddy
    /// held its link before the row was published.
    id_only: Option<bool>,
    /// Whether the requester ran its crypt layer.
    kad_crypt: bool,
    /// Whether the ID-only road was carried to a transfer.
    findsource_transfer: bool,
}

impl AmuleRequesterLeg {
    /// Start the requester and its tap, gate on Kad-open, add the link and
    /// give the download its window.
    ///
    /// # Errors
    /// If a container cannot be started or the link cannot be read.
    pub(crate) fn run(
        docker: &Docker,
        names: &KadMeshNames,
        resources: &mut KadResources<'_>,
        plan: &AmuleRequesterPlan<'_>,
        address_v4: &str,
        id_only: Option<bool>,
    ) -> Result<Self> {
        let layout = plan.base.layout;
        let dir = layout.kad_dir().join("amule-requester");
        let incoming = dir.join("incoming");
        fs::create_dir_all(&incoming).with_context(|| format!("create {}", incoming.display()))?;
        let mut env = plan.base.amule_env.to_vec();
        env.push("AMULE_DEBUG_PEER_CATEGORIES=1".to_owned());
        if plan.kad_crypt {
            env.push("AMULE_KAD_CRYPT=1".to_owned());
        }
        let options = KadCaptureOptions {
            amule_env: &env,
            ..plan.base
        };
        let spec = KadNodeSpec {
            role: "requester".to_owned(),
            container: names.requester.clone(),
            udp_port: plan.base.kad_udp_port_base + REQUESTER_UDP_OFFSET,
            ip: parse_ipv4_octets(address_v4)?,
            kad_id: REQUESTER_KAD_ID,
            user_hash_hex: Some(REQUESTER_USER_HASH),
            shared_host_dir: incoming.clone(),
            bootstrap_peers: Vec::new(),
            routing_zone_seed: true,
            seed_contacts: plan.seed.clone(),
        };
        let node = start_kad_node(docker, &options, &[spec], 0, resources)?;
        let tap = format!("{}-amule-requester", names.capture);
        resources.start_capture(
            layout,
            &CaptureSidecar {
                image: plan.base.capture_image,
                name: &tap,
                target_container: &node.container,
                interface: DEFAULT_TAP_INTERFACE,
                host_dir: dir.clone(),
                pcap_file: REQUESTER_PCAP,
                bpf: "tcp or udp",
            },
            "kad-capture-amule-requester-container-id.txt",
        )?;

        let kad_open = wait_for_amule_status(
            docker,
            &node.container,
            "Kad: Connected (ok)",
            KAD_OPEN_DEADLINE_SECS,
        )?;
        println!("kad-amule-requester: Kad-open before the link = {kad_open}");
        let release_gate = ReleaseGate::hold(docker, layout, &node.container, &plan.firewalled_ip);
        println!(
            "kad-amule-requester: firewall-check client for {} = {:?} after {}s",
            plan.firewalled_ip, release_gate.client, release_gate.waited_secs
        );
        let link = fs::read_to_string(layout.synthetic_ed2k_file())
            .context("read the synthetic ed2k link")?;
        let link = link.trim();
        run_checked(
            docker.exec(
                node.container.clone(),
                amulecmd_command(&format!("Add {link}")),
            ),
            "hand the aMule requester the ed2k link",
        )?;
        println!("kad-amule-requester: link added, download window {DOWNLOAD_WINDOW_SECS}s");
        let completed = await_completed(&incoming, link, DOWNLOAD_WINDOW_SECS)?;
        println!("kad-amule-requester: file completed = {completed}");
        Ok(Self {
            container: node.container,
            tap,
            dir,
            address_v4: address_v4.to_owned(),
            storer_ip: plan.storer_ip.clone(),
            kad_open,
            release_gate,
            completed,
            id_only,
            kad_crypt: plan.kad_crypt,
            findsource_transfer: plan.findsource_transfer,
        })
    }

    /// Count the rows off the three taps, lift the `0x3B`, `0x52` and `0x99`
    /// bodies, and write `kad-amule-requester-verdict.toml`.
    ///
    /// # Errors
    /// If a tap or log cannot be read, or a claim does not hold.
    pub(crate) fn judge(&self, judged: &Judged<'_>) -> Result<()> {
        let docker = judged.docker;
        collect_kad_logs(docker, judged.layout, "requester", &self.container)?;
        collect_amule_logfile(docker, judged.layout, "requester", &self.container);
        let substitute = |filter: &str| {
            filter
                .replace("{q}", &self.address_v4)
                .replace("{s}", &self.storer_ip)
                .replace("{a}", judged.amule_ip)
                .replace("{r}", judged.rmule_ip)
                .replace("{qp}", &KAD_TCP_PORT.to_string())
        };
        let requester_pcap = self.pcap();
        let taps = [
            (judged.buddy_tap, judged.buddy_pcap, BUDDY_TAP_ROWS),
            (judged.amule_tap, judged.amule_pcap, AMULE_TAP_ROWS),
            (
                self.tap.as_str(),
                requester_pcap.as_str(),
                REQUESTER_TAP_ROWS,
            ),
        ];
        let mut rows = Vec::new();
        for (tap, pcap, table) in taps {
            for row in table {
                let count = count_pcap_rows(docker, tap, pcap, row.filter.map_bpf(substitute))?;
                println!(
                    "kad-amule-requester row {} ({}) = {count}",
                    row.key, row.label
                );
                rows.push((row.key, row.label, count));
            }
        }
        let link = fs::read_to_string(judged.layout.synthetic_ed2k_file())
            .context("read the synthetic ed2k link")?;
        let file_hash = parse_ed2k_file_hash(link.trim())?;
        let requester_datagrams = RequesterDatagrams::read(
            judged,
            (&self.tap, &requester_pcap, &self.dir),
            &substitute,
            file_hash,
        )?;
        rows.extend(requester_datagrams.rows(self.id_only.is_some()));
        let callback_req = requester_datagrams.callback_req(judged.buddy_host_dir)?;
        let relayed = lift(
            docker,
            (judged.buddy_tap, judged.buddy_pcap),
            &BUDDY_TAP_ROWS[0].filter.map_bpf(substitute),
            &judged.buddy_host_dir.join("relayed-callback-0x99.pcap"),
        )?;
        let search_res = lift(
            docker,
            (&self.tap, &requester_pcap),
            &REQUESTER_TAP_ROWS[0].filter.map_bpf(substitute),
            &self.dir.join("storer-search-res-0x3b.pcap"),
        )?;
        // A SYN answering one of the requester's `0x53`
        // firewall checks wears the same shape as a genuine dial-back, before
        // the relay or after it, so the dial-back is read off the firewalled
        // aMule's own log, where the connect's cause is in order.
        let storer_log = fs::read_to_string(
            judged
                .layout
                .kad_node_logs_dir("storer")
                .join("amule-logfile.log"),
        )
        .unwrap_or_default();
        let dialed_back = storer_log_shows_a_dial_back_after_the_callback(
            &storer_log,
            judged.rmule_ip,
            &self.address_v4,
        );

        let requester_ip = parse_ipv4_octets(&self.address_v4)?;
        let callback_fields = callback_req
            .as_deref()
            .is_some_and(|body| names_the_row(body, file_hash));
        let relay_fields = match (&callback_req, &relayed) {
            (Some(req), Some(relay)) => relay_repeats(req, relay, requester_ip),
            _ => false,
        };
        let count = |key: &str| {
            rows.iter()
                .find(|(name, _, _)| *name == key)
                .map_or(0, |(_, _, count)| *count)
        };
        let findsource = self.id_only.map(|link_held| {
            let log = fs::read_to_string(
                judged
                    .layout
                    .kad_node_logs_dir("requester")
                    .join("amule-logfile.log"),
            )
            .unwrap_or_default();
            FindSourceRoad {
                link_held,
                adopted: search_res.as_deref().and_then(adopted_id_only_row),
                searched_buddy: log.contains("Searching buddy for lowid connection"),
                endpoint_branch: log.contains("KadCallbackReq (size=34)"),
                walked: count(FINDSOURCE_WALK_ROW) > 0,
            }
        });
        let claims = [
            (
                "the-amule-requester-read-kad-open-before-the-link",
                self.kad_open,
            ),
            (
                "the-placed-storer-answered-the-requesters-source-search",
                count("storer_search_res_0x3b_in") > 0,
            ),
            (
                "the-0x52-left-the-amule-requester-for-the-buddy",
                count("requester_callback_req_0x52_out") > 0,
            ),
            (
                "the-0x52-reached-the-rmule-buddy",
                count("requester_callback_req_0x52_buddy_tap") > 0,
            ),
            (
                "the-0x52-names-the-rows-buddy-the-links-file-and-the-requesters-port",
                callback_fields,
            ),
            (
                "the-buddy-relayed-op-callback-to-the-firewalled-amule",
                count("rmule_callback_0x99_to_amule_buddy_tap") > 0,
            ),
            (
                "the-0x99-repeats-the-0x52-and-names-the-requester-host-order",
                relay_fields,
            ),
            (
                "the-firewalled-amule-dialed-the-requester-back",
                dialed_back,
            ),
        ];
        // The ID-only variant's firewalled aMule shares nothing, so it never
        // completes a dial-back — the claim is genuinely computed (ordered against the relayed
        // `0x99`, never just a SYN count),
        // then moved to observed rather than required: sharing nothing
        // legitimately reads it false, and the walk is this variant's own
        // capture. Carried to a transfer it shares, so the relay,
        // the dial-back and the file are required again.
        let (mut claims, observed): (Vec<Claim>, Vec<Claim>) = match &findsource {
            None => (claims.to_vec(), Vec::new()),
            Some(road) => {
                let held = (
                    "the-rmule-buddy-held-its-link-before-the-publish",
                    road.link_held,
                );
                let road_claims = claims[..5].iter().copied().chain(road.claims());
                if self.findsource_transfer {
                    let byte_equal = self.completed
                        && verify_bytes(
                            judged.layout,
                            &self
                                .dir
                                .join("incoming")
                                .join(synthetic_file_name(link.trim())?),
                            "the aMule requester",
                        )
                        .is_ok();
                    let transfer = [
                        (
                            "the-adopted-row-carries-the-firewalled-amules-user-hash",
                            road.adopted.as_deref().is_some_and(|hash| {
                                hash.eq_ignore_ascii_case(FIREWALLED_USER_HASH)
                            }),
                        ),
                        ("the-requester-completed-the-file-byte-equal", byte_equal),
                    ];
                    (
                        road_claims
                            .chain(claims[5..8].iter().copied())
                            .chain(transfer)
                            .collect(),
                        vec![held],
                    )
                } else {
                    let mut observed = claims[5..8].to_vec();
                    observed.push(held);
                    (road_claims.collect(), observed)
                }
            }
        };
        // Under the requester's crypt layer the `0x52` must cross
        // keyed, and rmule's buddy must have decoded it — its relay names the
        // requester, which only the decrypted body and the datagram's source
        // can give it.
        if self.kad_crypt {
            let stimulus_log =
                fs::read_to_string(judged.layout.kad_node_stderr_log("rmule")).unwrap_or_default();
            claims.push((
                "the-0x52-reached-the-buddy-keyed-on-its-kad-id",
                requester_datagrams.callback_req_keyed(),
            ));
            claims.push((
                "the-rmule-buddy-decoded-the-keyed-0x52-and-relayed-it",
                relay_fields && stimulus_log_shows_the_relay(&stimulus_log, &self.address_v4),
            ));
        }
        let pass = claims.iter().all(|(_, holds)| *holds);
        let verdict = if pass { "PASS" } else { "FAIL" };

        let mut out = String::from(
            "# Flow M's stock aMule requester (kad-core-buddy --amule-requester): aMule's own 0x52 to\n\
             # the rmule buddy its type-3 row names, and rmule's relay of it.\n",
        );
        out.push_str(&format!("verdict = \"{verdict}\"\n"));
        if self.id_only.is_some() {
            out.push_str("variant = \"id-only-row\"\n");
        }
        out.push_str(&format!(
            "requester = \"{}:{KAD_TCP_PORT}\"\n",
            self.address_v4
        ));
        out.push_str(&format!("requester_file_completed = {}\n", self.completed));
        out.push_str(&self.release_gate.verdict_toml());
        for (key, body) in [
            ("callback_req_0x52_body", &callback_req),
            ("callback_0x99_segment", &relayed),
            ("storer_search_res_0x3b_body", &search_res),
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
        if !observed.is_empty() {
            out.push_str("\n[observed]\n");
            for (name, holds) in &observed {
                out.push_str(&format!("\"{name}\" = {holds}\n"));
            }
        }
        out.push_str(&requester_datagrams.crypt_toml(self.kad_crypt));
        out.push_str("\n[rows]\n");
        for (key, label, count) in &rows {
            out.push_str(&format!("{key} = {count} # {label}\n"));
        }
        let path = judged
            .layout
            .kad_dir()
            .join("kad-amule-requester-verdict.toml");
        fs::write(&path, &out).with_context(|| format!("write {}", path.display()))?;
        println!("kad-amule-requester verdict={verdict}");
        if !pass {
            let failing: Vec<&str> = claims
                .iter()
                .filter(|(_, holds)| !holds)
                .map(|(name, _)| *name)
                .collect();
            bail!(
                "kad-amule-requester: claims not held: {}",
                failing.join(", ")
            );
        }
        Ok(())
    }

    /// The requester tap's pcap, inside its sidecar.
    fn pcap(&self) -> String {
        format!("{}/{REQUESTER_PCAP}", crate::flow::bench::CAPTURE_MOUNT)
    }
}

/// Wait until the link's file sits complete in the requester's incoming
/// directory (aMule moves it there on completion), bounded by `window_secs`.
fn await_completed(incoming: &std::path::Path, link: &str, window_secs: u64) -> Result<bool> {
    let mut fields = link.split('|');
    let (Some(name), Some(size)) = (fields.nth(2), fields.next()) else {
        bail!("ed2k link has no name/size fields: {link}");
    };
    let size: u64 = size
        .parse()
        .with_context(|| format!("ed2k link size is not a number: {size:?}"))?;
    let path = incoming.join(name);
    let deadline = Instant::now() + Duration::from_secs(window_secs);
    loop {
        if fs::metadata(&path).is_ok_and(|meta| meta.len() == size) {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_secs(5).min(deadline - Instant::now()));
    }
}

/// Whether a captured `0x52` datagram carries what aMule's `BaseClient.cpp`
/// writer puts there for this flow's row: the buddy ID through `WriteUInt128`
/// (the stimulus's own Kad ID, which flow M pins in wire order), the link's
/// file hash through the same word swap, and the requester's TCP port.
fn names_the_row(body: &[u8], file_hash: [u8; 16]) -> bool {
    body.len() == 36
        && body[..2] == [0xE4, 0x52]
        && body[2..18] == crate::flow::kad_buddy::core::KAD_CORE_BUDDY_RMULE_KAD_ID
        && body[18..34] == kad_wire_id(file_hash)
        && body[34..36] == KAD_TCP_PORT.to_le_bytes()
}

/// Whether the relayed `0x99` segment is `<0xC5><len 4><0x99>` around the
/// `0x52`'s two IDs, the requester's IP octets reversed (the host-order
/// `WriteUInt32` the live aMule capture pinned) and the `0x52`'s port.
fn relay_repeats(req: &[u8], relay: &[u8], requester_ip: [u8; 4]) -> bool {
    let mut reversed = requester_ip;
    reversed.reverse();
    // `req` is a captured datagram checked here whether or not
    // `names_the_row` passed, so its length is checked before it is sliced.
    req.len() == 36
        && relay.len() == 44
        && relay[..6] == [0xC5, 0x27, 0x00, 0x00, 0x00, 0x99]
        && relay[6..38] == req[2..34]
        && relay[38..42] == reversed
        && relay[42..44] == req[34..36]
}

/// Whether the firewalled aMule's own log shows it dialing the requester back
/// **because of** the buddy's relayed callback: after the first `OP_CALLBACK
/// from <buddy>` line, a `Trying to connect to <requester>` line comes before
/// any firewall check the requester asked for. aMule's `0x53` handler connects
/// to the asker too (`KadFirewalled2Req from <requester>` then the same
/// `Trying to connect to` line), before the callback or after it
/// (run `1790206695`'s requester re-checked 107 s after the
/// callback, on a firewalled aMule that shares nothing), and neither is a
/// dial-back.
fn storer_log_shows_a_dial_back_after_the_callback(
    storer_log: &str,
    rmule_ip: &str,
    requester_ip: &str,
) -> bool {
    let callback = format!("OP_CALLBACK from {rmule_ip}");
    let dial = format!("Trying to connect to {requester_ip}:{KAD_TCP_PORT}");
    let check = format!("from {requester_ip}:");
    storer_log
        .lines()
        .skip_while(|line| !line.contains(&callback))
        .find_map(|line| {
            if line.contains(&dial) {
                Some(true)
            } else if line.contains("KadFirewalled") && line.contains(&check) {
                Some(false)
            } else {
                None
            }
        })
        .unwrap_or(false)
}

/// Whether the rmule stimulus logged queuing `OP_CALLBACK` for `requester_ip`
/// on its held buddy link (`kad_runtime/node.rs`, `RelayDisposition::Sent`).
fn stimulus_log_shows_the_relay(stimulus_log: &str, requester_ip: &str) -> bool {
    stimulus_log.lines().any(|line| {
        line.contains("kad buddy relay: OP_CALLBACK queued on the held buddy link")
            && line.contains(&format!("ip: {requester_ip},"))
    })
}

/// A named claim and whether it held.
type Claim = (&'static str, bool);

/// What the ID-only variant reads beyond the taps' counts.
struct FindSourceRoad {
    link_held: bool,
    /// The user hash of the row the requester adopted, when that row names
    /// the buddy by ID alone ([`adopted_id_only_row`]).
    adopted: Option<String>,
    searched_buddy: bool,
    endpoint_branch: bool,
    walked: bool,
}

impl FindSourceRoad {
    /// The variant's own claims, after the first five `kad-core-buddy --amule-requester` ones.
    fn claims(&self) -> [(&'static str, bool); 3] {
        [
            (
                "the-storers-row-names-the-buddy-by-id-alone",
                self.adopted.is_some(),
            ),
            (
                "the-requester-searched-for-the-buddy-not-its-endpoint",
                self.searched_buddy && !self.endpoint_branch,
            ),
            ("the-requester-walked-toward-the-buddy-id", self.walked),
        ]
    }
}

/// The user hash (upper hex) of the row aMule's requester adopts from a
/// lifted `0x3B` body, when that row is a type-3 row naming the rmule buddy by
/// `TAG_BUDDYHASH` with no `TAG_SERVERIP`/`TAG_SERVERPORT`.
///
/// The adopted row is the first: `CheckAndAddSource` drops every later row
/// whose user hash it already holds (`DownloadQueue.cpp:702-724`, kno
/// `ab483654`). So a body qualifies only when every row carries the first's
/// hash — a second row under another hash would be a second source, with a
/// road of its own.
fn adopted_id_only_row(body: &[u8]) -> Option<String> {
    let Ok(rmule_kad::KadDecoded::Plain(envelope)) = rmule_kad::decode_exact(body) else {
        return None;
    };
    let rows = rmule_kad::decode_source_result(&envelope).ok()?;
    let facts: Vec<_> = rows.iter().map(|row| row.facts()).collect::<Option<_>>()?;
    let first = facts.first()?;
    let id_only = first.source_type == 3
        && first.buddy.is_some_and(|buddy| {
            buddy.buddy_udp.is_none()
                && *buddy.buddy_id.as_bytes()
                    == crate::flow::kad_buddy::core::KAD_CORE_BUDDY_RMULE_KAD_ID
        });
    let one_source = facts.iter().all(|row| row.user_hash == first.user_hash);
    (id_only && one_source).then(|| first.user_hash.to_hex_upper())
}

/// The file name an ed2k link names (`ed2k://|file|<name>|<size>|<hash>|/`).
fn synthetic_file_name(link: &str) -> Result<&str> {
    link.split('|')
        .nth(2)
        .with_context(|| format!("ed2k link has no name field: {link}"))
}

/// One counted row: `{q}` the requester, `{s}` the placed storer, `{a}` the
/// firewalled aMule, `{r}` the rmule buddy, `{qp}` the requester's listener.
struct LegRow {
    key: &'static str,
    label: &'static str,
    filter: WireFilter,
}

/// Off the stimulus (buddy) netns; also the lifted relay. The requester's
/// datagrams to the buddy are read by decoding (`requester_datagrams`).
const BUDDY_TAP_ROWS: &[LegRow] = &[LegRow {
    key: "rmule_callback_0x99_to_amule_buddy_tap",
    label: "OP_CALLBACK relayed to the firewalled aMule on the held link",
    filter: WireFilter::ed2k_static("src host {r} and dst host {a}", &[OP_EMULEPROT], 0x99),
}];

/// Off the firewalled aMule's own netns.
const AMULE_TAP_ROWS: &[LegRow] = &[LegRow {
    key: "amule_syn_to_requester_amule_tap",
    label: "the firewalled aMule's TCP SYNs toward the requester's listener",
    filter: WireFilter::packets_static(
        "tcp and src host {a} and dst host {q} and dst port {qp} \
             and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
    ),
}];

/// Off the requester's own netns. The first is also a lifted body; the
/// requester's own Kad datagrams are read by decoding (`requester_datagrams`).
const REQUESTER_TAP_ROWS: &[LegRow] = &[
    LegRow {
        key: "storer_search_res_0x3b_in",
        label: "KADEMLIA2_SEARCH_RES from the placed storer",
        filter: WireFilter::packets_static(
            "udp and src host {s} and dst host {q} and (udp[8] = 0xe4 or udp[8] = 0xe5) \
                 and udp[9] = 0x3b",
        ),
    },
    LegRow {
        key: "amule_dial_back_syn_requester_tap",
        label: "the firewalled aMule's TCP SYN onto the requester's listener",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst host {q} and dst port {qp} \
                 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
        ),
    },
    LegRow {
        key: "amule_dial_back_hello_0xe3_0x01",
        label: "OP_HELLO from the firewalled aMule on the dial-back",
        filter: WireFilter::ed2k_static("src host {a} and dst host {q}", &[OP_EDONKEYPROT], 0x01),
    },
    LegRow {
        key: "amule_payload_segments_to_requester",
        label: "TCP segments carrying payload from the firewalled aMule to the requester",
        filter: WireFilter::packets_static(
            "tcp and src host {a} and dst host {q} \
                 and (((ip[2:2] - ((ip[0] & 0xf) << 2)) - ((tcp[12] & 0xf0) >> 2)) != 0)",
        ),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A short captured `0x52` is judged, not a panic: `relay_repeats` is
    /// called whether or not `names_the_row` passed.
    #[test]
    fn a_short_callback_request_does_not_panic_the_relay_check() {
        let relay = [0_u8; 44];
        assert!(!super::relay_repeats(&[0xE4, 0x52], &relay, [10, 0, 0, 1]));
    }

    /// `kad-core-buddy --callback-downloader`'s captured pair (run `1790155933`,
    /// `rmule-peer/tests/fixtures/buddy_callback/captured/amule-233-callback-dialback-20260923`):
    /// rmule's `0x52` and its relay, which aMule consumed and dialed back on.
    /// The same row shape, so the two field checks must accept it — and must
    /// refuse it once a single field moves.
    const DOWNLOADER_CALLBACK_REQ: [u8; 36] = [
        0xe4, 0x52, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
        0x22, 0x11, 0x00, 0x73, 0x02, 0xbd, 0x08, 0x8e, 0xd1, 0xfc, 0xa7, 0x25, 0x37, 0xa5, 0x91,
        0xdc, 0x17, 0x56, 0x0d, 0x36, 0x12,
    ];
    const DOWNLOADER_FILE_HASH: [u8; 16] = [
        0x08, 0xbd, 0x02, 0x73, 0xa7, 0xfc, 0xd1, 0x8e, 0x91, 0xa5, 0x37, 0x25, 0x0d, 0x56, 0x17,
        0xdc,
    ];
    const DOWNLOADER_REQUESTER: [u8; 4] = [203, 0, 113, 7];

    fn downloader_relay() -> Vec<u8> {
        let mut relay = vec![0xc5, 0x27, 0x00, 0x00, 0x00, 0x99];
        relay.extend_from_slice(&DOWNLOADER_CALLBACK_REQ[2..34]);
        relay.extend_from_slice(&[0x07, 0x71, 0x00, 0xcb, 0x36, 0x12]);
        relay
    }

    /// Run `1790190646`'s stimulus line for
    /// `kad-core-buddy --amule-requester --omit-buddy-endpoint`'s relay: it
    /// names the requester it relayed for, and only that one.
    #[test]
    fn the_stimulus_relay_line_is_read_for_its_requester_alone() {
        let line = "2026-09-23T19:22:34.914192Z DEBUG rmule_core::adapters::kad_runtime::node: \
                    kad buddy relay: OP_CALLBACK queued on the held buddy link \
                    injected=Ipv4Endpoint { ip: 203.0.113.7, port: 4662 }";
        assert!(stimulus_log_shows_the_relay(line, "203.0.113.7"));
        assert!(!stimulus_log_shows_the_relay(line, "203.0.113.70"));
        assert!(!stimulus_log_shows_the_relay(
            &line.replace("queued on the held buddy link", "dropped"),
            "203.0.113.7"
        ));
    }

    #[test]
    fn a_captured_callback_names_the_row_and_a_moved_field_does_not() {
        assert!(names_the_row(
            &DOWNLOADER_CALLBACK_REQ,
            DOWNLOADER_FILE_HASH
        ));
        // The file field raw, not word-swapped: the shape rmule's relay once forwarded.
        let mut raw = DOWNLOADER_CALLBACK_REQ;
        raw[18..34].copy_from_slice(&DOWNLOADER_FILE_HASH);
        assert!(!names_the_row(&raw, DOWNLOADER_FILE_HASH));
    }

    /// The storer's row as rmule serves it, with or without the buddy's
    /// endpoint: only the one without reads as the ID-only row.
    #[test]
    fn a_row_with_the_buddy_endpoint_is_not_id_only() {
        use rmule_kad::{KadBuddyContact, KadId, KadSourceRow, encode_source_result};
        use rmule_primitives::Ipv4Endpoint;
        let id = crate::flow::kad_buddy::core::KAD_CORE_BUDDY_RMULE_KAD_ID;
        let row = |source_id, last_octet, buddy_udp| KadSourceRow {
            source_id,
            source_type: 3,
            ip: std::net::Ipv4Addr::new(203, 0, 113, last_octet),
            tcp_port: 4662,
            udp_port: 4672,
            encryption: None,
            buddy: Some(KadBuddyContact {
                buddy_id: KadId::from_bytes(id),
                buddy_udp,
                buddy_ipv6: None,
                buddy_udp_ipv6: None,
            }),
            ipv6: None,
        };
        let served = |rows: &[KadSourceRow]| {
            let key = KadId::from_bytes([0x60; 16]);
            encode_source_result(key, key, rows).remove(0).encode()
        };
        let endpoint = Some(Ipv4Endpoint::new(
            std::net::Ipv4Addr::new(203, 0, 113, 3),
            4679,
        ));
        let id_only = row([0x77; 16], 8, None);
        assert!(adopted_id_only_row(&served(&[id_only])).is_some());
        assert!(adopted_id_only_row(&served(&[row([0x77; 16], 2, endpoint)])).is_none());
        // The firewalled aMule's own row under the same hash rides
        // behind the ID-only one, and aMule drops it as a known source...
        let own_row = row([0x77; 16], 2, endpoint);
        assert!(adopted_id_only_row(&served(&[id_only, own_row])).is_some());
        // ...but not when it is served first, nor under another hash.
        assert!(adopted_id_only_row(&served(&[own_row, id_only])).is_none());
        let stranger = row([0x78; 16], 2, endpoint);
        assert!(adopted_id_only_row(&served(&[id_only, stranger])).is_none());
    }

    #[test]
    fn a_captured_relay_repeats_its_callback_and_an_in_order_address_does_not() {
        assert!(relay_repeats(
            &DOWNLOADER_CALLBACK_REQ,
            &downloader_relay(),
            DOWNLOADER_REQUESTER
        ));
        // The address in order: rmule's relay before the live capture, which aMule
        // dialed mirrored.
        let mut in_order = downloader_relay();
        in_order[38..42].copy_from_slice(&DOWNLOADER_REQUESTER);
        assert!(!relay_repeats(
            &DOWNLOADER_CALLBACK_REQ,
            &in_order,
            DOWNLOADER_REQUESTER
        ));
    }

    /// The aMule-requester run's own `.2` log, run `1790185890`
    /// (bench run 1790185890, `logs/kad/storer/amule-logfile.log`):
    /// a genuine dial-back, `OP_CALLBACK` then `Trying to connect to` the
    /// requester 0 ms later.
    const RUN_1790185890_STORER_LOG: &str = "\
.2026-09-23 17:58:55: BaseClient.cpp(1622): ED2k Client: Trying to connect to 203.0.113.7:4662\n\
.2026-09-23 18:01:05: ClientTCPSocket.cpp(1631): Remote Client Protocol: Remote Client: OP_CALLBACK from 203.0.113.3\n\
.2026-09-23 18:01:05: BaseClient.cpp(1622): ED2k Client: Trying to connect to 203.0.113.7:4662\n";

    /// The ID-only variant, run `1790190646`
    /// (bench run 1790190646, `logs/kad/storer/amule-logfile.log`):
    /// the only `Trying to connect to` the requester line is the `0x53` firewall tester's
    /// own connect, minutes before `OP_CALLBACK` — the SYN this claim once wrongly counted.
    const RUN_1790190646_STORER_LOG: &str = "\
.2026-09-23 19:19:10: BaseClient.cpp(1622): ED2k Client: Trying to connect to 203.0.113.3:4663\n\
.2026-09-23 19:20:23: BaseClient.cpp(1622): ED2k Client: Trying to connect to 203.0.113.7:4662\n\
.2026-09-23 19:22:34: ClientTCPSocket.cpp(1631): Remote Client Protocol: Remote Client: OP_CALLBACK from 203.0.113.3\n";

    #[test]
    fn run_357s_storer_log_reads_the_dial_back_held() {
        assert!(storer_log_shows_a_dial_back_after_the_callback(
            RUN_1790185890_STORER_LOG,
            "203.0.113.3",
            "203.0.113.7",
        ));
    }

    #[test]
    fn run_436s_storer_log_reads_no_dial_back_after_any_callback() {
        assert!(!storer_log_shows_a_dial_back_after_the_callback(
            RUN_1790190646_STORER_LOG,
            "203.0.113.3",
            "203.0.113.7",
        ));
    }

    #[test]
    fn a_dial_back_log_line_before_every_callback_line_does_not_count() {
        let log = "\
Trying to connect to 203.0.113.7:4662\n\
OP_CALLBACK from 203.0.113.3\n";
        // Same two lines as run 436's, without a repeat after the callback.
        assert!(!storer_log_shows_a_dial_back_after_the_callback(
            log,
            "203.0.113.3",
            "203.0.113.7",
        ));
    }

    /// `kad-core-buddy --amule-requester --omit-buddy-endpoint --requester-kad-crypt`,
    /// run `1790206695` (`logs/kad/storer/amule-logfile.log`): the
    /// firewalled aMule shares nothing, yet a `Trying to connect to` the
    /// requester follows `OP_CALLBACK` — the requester's firewall re-check,
    /// logged the same second.
    #[test]
    fn run_441s_firewall_recheck_after_the_callback_is_no_dial_back() {
        let log = "\
.2026-09-23 23:46:31: KademliaUDPListener.cpp(315): Client Kademlia UDP: KadFirewalled2Req from 203.0.113.7:4704\n\
.2026-09-23 23:46:31: BaseClient.cpp(1622): ED2k Client: Trying to connect to 203.0.113.7:4662\n\
.2026-09-23 23:48:45: ClientTCPSocket.cpp(1631): Remote Client Protocol: Remote Client: OP_CALLBACK from 203.0.113.3\n\
.2026-09-23 23:50:32: KademliaUDPListener.cpp(315): Client Kademlia UDP: KadFirewalled2Req from 203.0.113.7:4704\n\
.2026-09-23 23:50:32: BaseClient.cpp(1622): ED2k Client: Trying to connect to 203.0.113.7:4662\n";
        assert!(!storer_log_shows_a_dial_back_after_the_callback(
            log,
            "203.0.113.3",
            "203.0.113.7",
        ));
    }
}
