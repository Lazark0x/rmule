//! The ID-only fold-in of the live buddy-callback leg: a **Callback
//! Walk**'s `0x52` delivered to an **aMule** that holds a buddy link,
//! and aMule's own `OP_CALLBACK` relay of it.
//!
//! Which aMule, and why: flow M's firewalled debug-image aMule. Its FindBuddy
//! does **not** accept rmule here — the open-side service answers a `0x51`
//! only with both of its own verdicts verified open
//! (`KademliaUDPListener.cpp:1427`), which this Config-A swarm cannot give it.
//! What it does hold is `m_pBuddy`, the link to the Core-pumped stimulus, and
//! `CKademliaUDPListener::ProcessCallbackRequest`
//! (`KademliaUDPListener.cpp:1489-1518`) relays over whatever `GetBuddy()`
//! names: it reads no firewall state and filters no buddy ID (its own
//! `JOHNTODO`). So the relay code a walk reaches is aMule's, byte for byte;
//! only the role that established the link is the inverse of the textbook one.
//!
//! The walker is a `kad join-node` with `--callback-walk`: the operands (the
//! buddy ID, the file, the port) are **Stimulus**, the facts an ID-only row
//! would carry, and the walk, its `SEARCHTOLERANCE` filter and its `0x52` are
//! `rmule_kad`'s shipped path. The buddy ID is `~stimulusKadID` — aMule's own
//! ID, so the walk converges on aMule at distance 0 and the relayed check
//! names the stimulus.
//!
//! The walker's Kad crypt is armed (`--kad-crypt`), so every datagram it sends
//! aMule — the walk's `KADEMLIA2_REQ`s and its `0x52` — leaves obfuscated
//! under aMule's Kad ID, as aMule's own `FINDSOURCE` arm sends
//! (`Search.cpp:1102-1119`). aMule's crypt layer stays as flow M leaves it,
//! disarmed: its receive path decrypts whatever arrives regardless
//! (`EncryptedDatagramSocket.cpp:136`, the preference check commented out),
//! and arming it would obfuscate the Kad rows flow M counts. Run
//! `1790152605` ran the same walk plaintext; its bytes are the promoted
//! fixture, whose shape the obfuscated run's `0x99` repeats.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::docker::Docker;
use crate::flow::bench::{KadMeshNames, KadResources, run_checked};
use crate::flow::evidence::count_pcap_rows;
use crate::flow::gate::wait_for_host_file;
use crate::flow::identity::hex_lower;
use crate::flow::kad_buddy::callback::lift;
use crate::flow::wire_filter::{OP_EMULEPROT, WireFilter};

/// The walker's Kad ID: far from aMule's, so the walk's convergence on aMule
/// is the keyspace's doing.
const WALKER_KAD_ID: [u8; 16] = [0x3C; 16];
/// The walker's Kad UDP bind.
const WALKER_UDP_PORT: u16 = 4672;
/// The port the walk's `0x52` names. Nothing listens there: a dial-back to it
/// is recorded, not required.
const WALKER_TCP_PORT: u16 = 4662;
/// How long the walker lives; its walk ends in under 24 s even in silence.
const WALKER_RUN_SECS: u64 = 150;

/// Where the walker stands and what it is told.
pub(crate) struct WalkPlan<'a> {
    pub(crate) image: &'a str,
    pub(crate) address_v4: String,
    /// aMule's Kad endpoint, `ip:port` — the walker's bootstrap.
    pub(crate) amule_kad: String,
    /// The buddy ID the walk targets, wire order.
    pub(crate) buddy_id: [u8; 16],
    /// The file the `0x52` names, raw MD4 hex.
    pub(crate) file_hash_hex: String,
}

/// A walker that has run.
pub(crate) struct WalkLeg {
    dir: PathBuf,
    address_v4: String,
    buddy_id: [u8; 16],
}

/// What the walk leg's judge reads beside the walker's own log.
pub(crate) struct WalkTaps<'a> {
    pub(crate) docker: &'a Docker,
    pub(crate) layout: &'a crate::artifacts::RunLayout,
    /// Flow M's stimulus-netns tap, and where it writes on the host.
    pub(crate) buddy: (&'a str, &'a str, &'a Path),
    /// Flow M's tap on aMule's netns (udp only), and where it writes.
    pub(crate) amule: (&'a str, &'a str, &'a Path),
    pub(crate) amule_ip: &'a str,
    pub(crate) rmule_ip: &'a str,
}

impl WalkLeg {
    /// Whether an `OP_CALLBACK` segment is aMule's relay of *this* walk: it
    /// echoes the walk's buddy ID and injects the walker's own address,
    /// host-order (octets reversed, `WriteUInt32` of the Kad listener's IP),
    /// with the port the walk named. Only a decrypted `0x52` can yield it.
    fn relay_names_walker(&self, segment: &[u8]) -> bool {
        let Ok(walker) = self.address_v4.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        let mut address = walker.octets();
        address.reverse();
        segment.len() == 44
            && segment[6..22] == self.buddy_id
            && segment[38..42] == address
            && segment[42..44] == WALKER_TCP_PORT.to_le_bytes()
    }

    /// Start the walker and wait for its walk to end.
    ///
    /// # Errors
    /// If the container cannot be started or its log cannot be read.
    pub(crate) fn run(
        docker: &Docker,
        layout: &crate::artifacts::RunLayout,
        names: &KadMeshNames,
        resources: &mut KadResources<'_>,
        plan: WalkPlan<'_>,
    ) -> Result<Self> {
        let dir = layout.kad_dir().join("walker");
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let kad_id = hex_lower(&WALKER_KAD_ID);
        let container = crate::flow::kad_member::PlacedMember {
            image: plan.image,
            container: &names.publisher,
            network: &names.network_name,
            address_v4: &plan.address_v4,
            udp_port: WALKER_UDP_PORT,
            tcp_port: WALKER_TCP_PORT,
            kad_id: &kad_id,
            bootstrap: Some(&plan.amule_kad),
            host_dir: &dir,
            run_secs: WALKER_RUN_SECS,
        }
        .container_spec()
        .arg("--callback-walk")
        .arg(hex_lower(&plan.buddy_id))
        .arg("--callback-file-hash")
        .arg(&plan.file_hash_hex)
        .arg("--callback-tcp-port")
        .arg(WALKER_TCP_PORT.to_string())
        .arg("--kad-crypt")
        .arg("--public-ip")
        .arg(&plan.address_v4);
        run_checked(docker.run_container(container), "run the callback walker")?;
        resources.track_started("walker", names.publisher.clone());
        let ended = wait_for_host_file(
            &dir.join("events.log"),
            "CallbackWalkEnded",
            Duration::from_secs(WALKER_RUN_SECS),
        )?;
        println!("kad-buddy-callback-walk: walk ended={ended}");
        // aMule relays inside the datagram's own handler; a few seconds cover
        // the held link's delivery before the taps are read.
        std::thread::sleep(Duration::from_secs(5));
        Ok(Self {
            dir,
            address_v4: plan.address_v4,
            buddy_id: plan.buddy_id,
        })
    }

    /// Count the walk's rows, lift aMule's relay, and write
    /// `kad-buddy-callback-walk-verdict.toml`.
    ///
    /// # Errors
    /// If a tap cannot be read, or a claim does not hold.
    pub(crate) fn judge(&self, taps: &WalkTaps<'_>) -> Result<()> {
        let substitute = |filter: &str| {
            filter
                .replace("{w}", &self.address_v4)
                .replace("{a}", taps.amule_ip)
                .replace("{r}", taps.rmule_ip)
                .replace("{wp}", &WALKER_TCP_PORT.to_string())
        };
        let mut rows = Vec::new();
        for (tap, rows_here) in [(taps.amule, AMULE_TAP_ROWS), (taps.buddy, BUDDY_TAP_ROWS)] {
            for (key, label, filter) in rows_here {
                let count = count_pcap_rows(taps.docker, tap.0, tap.1, filter.map_bpf(substitute))?;
                println!("kad-buddy-callback-walk row {key} ({label}) = {count}");
                rows.push((*key, *label, count));
            }
        }
        let relayed = lift(
            taps.docker,
            (taps.buddy.0, taps.buddy.1),
            &BUDDY_TAP_ROWS[0].2.map_bpf(substitute),
            &taps.buddy.2.join("amule-callback-0x99.pcap"),
        )?;
        let events = fs::read_to_string(self.dir.join("events.log")).unwrap_or_default();
        let ended = events
            .lines()
            .find(|line| line.contains("CallbackWalkEnded"))
            .unwrap_or("")
            .trim()
            .to_owned();
        let count = |key: &str| {
            rows.iter()
                .find(|(name, _, _)| *name == key)
                .map_or(0, |(_, _, count)| *count)
        };
        let claims = [
            (
                "the-walk-asked-a-contact-within-tolerance",
                ended.contains("Asked(") && !ended.contains("Asked(0)"),
            ),
            (
                "the-walk-0x52-reached-amule-obfuscated",
                count("walker_datagrams_to_amule_amule_tap") > 0
                    && count("walker_plaintext_callback_req_0x52_amule_tap") == 0,
            ),
            (
                "amule-relayed-op-callback-over-its-buddy-link",
                count("amule_callback_0x99_to_buddy_buddy_tap") > 0,
            ),
            (
                "amules-relay-names-the-walker-and-echoes-the-walk",
                relayed
                    .as_deref()
                    .is_some_and(|segment| self.relay_names_walker(segment)),
            ),
        ];
        let pass = claims.iter().all(|(_, holds)| *holds);
        let verdict = if pass { "PASS" } else { "FAIL" };
        let mut out = String::from(
            "# The buddy-callback leg's ID-only fold-in: a Callback Walk's 0x52 delivered to the firewalled\n\
             # aMule, which relays OP_CALLBACK over its own held buddy link (the\n\
             # stimulus). Operands are Stimulus; the walk and aMule's relay are real.\n",
        );
        out.push_str(&format!("verdict = \"{verdict}\"\n"));
        out.push_str(&format!("walker = \"{}\"\n", self.address_v4));
        out.push_str(&format!(
            "walk_buddy_id = \"{}\"\n",
            hex_lower(&self.buddy_id)
        ));
        out.push_str(&format!("walk_ended = \"{}\"\n", ended.replace('"', "'")));
        out.push_str(&format!(
            "amule_callback_0x99_segment = \"{}\"\n",
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
        let path = taps
            .layout
            .kad_dir()
            .join("kad-buddy-callback-walk-verdict.toml");
        fs::write(&path, &out).with_context(|| format!("write {}", path.display()))?;
        println!("kad-buddy-callback-walk verdict={verdict} {ended}");
        if !pass {
            let failing: Vec<&str> = claims
                .iter()
                .filter(|(_, holds)| !holds)
                .map(|(name, _)| *name)
                .collect();
            bail!(
                "kad-buddy-callback-walk: claims not held: {}",
                failing.join(", ")
            );
        }
        Ok(())
    }
}

/// `(key, label, filter)`: `{w}` walker, `{a}` aMule, `{r}` the stimulus.
type Row = (&'static str, &'static str, WireFilter);

/// Off aMule's own netns (flow M's storer tap, udp only). The first is lifted.
const AMULE_TAP_ROWS: &[Row] = &[
    (
        "walker_plaintext_callback_req_0x52_amule_tap",
        "a plaintext KADEMLIA_CALLBACK_REQ from the walker to aMule (must stay 0: crypt armed)",
        WireFilter::packets_static(
            "udp and src host {w} and dst host {a} and udp[8] = 0xe4 and udp[9] = 0x52",
        ),
    ),
    (
        "walker_plaintext_kad_datagrams_amule_tap",
        "plaintext Kad datagrams from the walker to aMule (the bootstrap, keyless by nature)",
        WireFilter::packets_static("udp and src host {w} and dst host {a} and udp[8] = 0xe4"),
    ),
    (
        "walker_datagrams_to_amule_amule_tap",
        "any datagram from the walker to aMule (the walk's liveness)",
        WireFilter::packets_static("udp and src host {w} and dst host {a}"),
    ),
];

/// Off the stimulus's netns. The first is lifted: aMule-authored bytes.
const BUDDY_TAP_ROWS: &[Row] = &[
    (
        "amule_callback_0x99_to_buddy_buddy_tap",
        "OP_CALLBACK from aMule on its held buddy link",
        WireFilter::ed2k_static("src host {a} and dst host {r}", &[OP_EMULEPROT], 0x99),
    ),
    (
        "rmule_dial_back_syn_to_walker_buddy_tap",
        "a TCP SYN from the stimulus to the walker (recorded, not claimed)",
        WireFilter::packets_static(
            "tcp and src host {r} and dst host {w} and dst port {wp} \
         and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
        ),
    ),
];
