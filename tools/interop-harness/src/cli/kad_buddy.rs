//! Subcommands for the Kad buddy / callback family.
//!
//! The knobs here are all about the counterparty's own gates: which ports its
//! entrypoint DROPs, how many helper nodes it needs before its firewall
//! self-check can settle, and how long a window its convergence timers demand.

use std::path::PathBuf;

use crate::cli::bench::{
    BenchArgs, DEFAULT_FILE_SIZE, DEFAULT_RMULE_CLIENT_IMAGE, DEFAULT_TIMEOUT_SECS, FileContent,
    KadBenchArgs, RmuleNodeArgs, stage_synthetic_content,
};
use crate::cli::write_resolved_config;
use anyhow::{Context, Result, bail};
use clap::Args;
use rmule_interop_harness::artifacts::RunLayout;
use rmule_interop_harness::flow::{
    BuddyReaskServer, KadCoreBuddyOptions, KadDirectCallbackOptions, KadFirewalledBuddyOptions,
    KadRequiredCheckOptions, run_kad_core_buddy, run_kad_direct_callback, run_kad_firewalled_buddy,
    run_kad_required_check,
};
use rmule_interop_harness::rmule::RmuleServeContainer;

pub(crate) const FLOW_KAD_FIREWALLED_BUDDY: &str = "kad-firewalled-buddy";
pub(crate) const FLOW_KAD_CORE_BUDDY: &str = "kad-core-buddy";
pub(crate) const FLOW_KAD_DIRECT_CALLBACK: &str = "kad-direct-callback";
pub(crate) const FLOW_KAD_REQUIRED_CHECK: &str = "kad-required-check";

/// Flow R's bound on rmule's verdicts reading open once every helper is up:
/// the UDP verdict alone may take its six-minute timeout (`UDP_TEST_TIMEOUT`)
/// before a second round, and the TCP check waits for two connect-backs.
pub(crate) const DEFAULT_KAD_REQUIRED_CHECK_WINDOW_SECS: u64 = 900;

/// Flow K's bounded tap window. The buddy timer is 20 min (unattended-unsafe);
/// this window proves the firewall + captures the firewalled aMule's join/hello
/// traffic toward rmule, and gives an early FindBuddy a chance.
pub(crate) const DEFAULT_KAD_FIREWALLED_BUDDY_WINDOW_SECS: u64 = 360;

/// Flow M's tap window. Sized from aMule's own stock timers: the FindBuddy flag
/// arms at Kad start + 5 min (`Kademlia.cpp:109`) and the UDP verdict times out
/// 6 min after the first inbound datagram (`UDPFirewallTester.cpp:60`), so the
/// BuddySearch fires around +6–7 min. The window carries that plus the buddy TCP
/// dial and a ping — not the 20 min the interval's name suggests, which is only
/// the re-arm.
pub(crate) const DEFAULT_KAD_CORE_BUDDY_WINDOW_SECS: u64 = 660;

/// Helpers default OFF. They oblige `--block-udp` and `--mesh-members >= 1`,
/// and the one bench run of the old shape — helpers seeded into the
/// counterparty's routing zone, which disqualified them as UDP firewall helpers
/// Saw the counterparty go quiet toward rmule after ~3 min and
/// never run its BuddySearch. The bare two-node topology
/// is the one that has actually produced the `0x51`/`0x5A` + buddy-dial capture,
/// so it stays the default until the helper variant is understood.
pub(crate) const DEFAULT_KAD_CORE_BUDDY_HELPERS: usize = 0;

/// Flow N's tap window. Nothing has to converge: `CPrefs::GetFirewalled()` reads
/// firewalled from Kad start (`m_firewalled` only rises on connect-back acks), so
/// the counterparty's `0x95` gate is open as soon as its Kad is running and the
/// dial-back follows the first honoured callback in seconds. Kept well inside the
/// ~6 min at which flow M saw the two-node extern-port ping probe earn a genuine
/// flood ban — a banned IP's inbound connection is refused on both sides.
pub(crate) const DEFAULT_KAD_DIRECT_CALLBACK_WINDOW_SECS: u64 = 210;

/// How often rmule re-issues the callback. aMule honours one per source IP per
/// three minutes (`CClientList::AllowCallbackRequest`), so this only buys
/// robustness against a stimulus that starts before the counterparty's Kad does.
pub(crate) const DEFAULT_KAD_DIRECT_CALLBACK_EMIT_SECS: u64 = 30;

/// `kad-firewalled-buddy`: a firewalled (or, per capture mode, open) stock
/// aMule against the `kad join-node` runner.
#[derive(Debug, Args)]
pub(crate) struct KadFirewalledBuddyArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) kad: KadBenchArgs,
    #[command(flatten)]
    pub(crate) node: RmuleNodeArgs,
    /// Per-step readiness timeout in seconds (a node's Kad-started log).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Seconds rmule taps before finalizing its capture.
    #[arg(long, default_value_t = DEFAULT_KAD_FIREWALLED_BUDDY_WINDOW_SECS)]
    pub(crate) window: u64,
    /// Leave the aMule's Kad UDP port OPEN (TCP-only firewall — the direct- callback branch).
    /// Default is TCP+UDP-firewalled (buddy).
    #[arg(long)]
    pub(crate) udp_open: bool,
    /// Arm aMule Kad-UDP obfuscation: the aMule node encrypts its outgoing
    /// Kad datagrams toward rmule, which rmule's always-on dual-path receive
    /// decrypts. Default OFF (plain `0xE4` evidence).
    #[arg(long)]
    pub(crate) kad_crypt: bool,
    /// Requester-capture mode (ADR-0058): leave the aMule NON-
    /// firewalled (open Kad UDP) and arm rmule's own firewall self-check, so
    /// rmule emits `0x53`/`0x50` toward the open aMule and captures its `0x58`
    /// reply — the mirror of the firewalled-buddy responder direction.
    /// Switches the verdict to the requester-leg assertion.
    #[arg(long)]
    pub(crate) requester_capture: bool,
    /// Buddy-recruit-capture mode (ADR-0061): leave the aMule NON-
    /// firewalled (open, a candidate buddy) and arm rmule's own buddy recruiter, so
    /// rmule emits its `0x51 KADEMLIA_FINDBUDDY_REQ` toward the open aMule and
    /// captures any `0x5A` answer. Switches the verdict to the recruit-leg
    /// assertion. Mutually exclusive with `--requester-capture`.
    #[arg(long)]
    pub(crate) recruit_buddy: bool,
    /// Verify-key capture mode (ADR-0064): leave the aMule NON-
    /// firewalled and arm **rmule's** Kad datagram crypt + UDP verify keys
    /// (`--kad-crypt --public-ip <its fake-public address>`), so rmule's
    /// `HELLO_RES` carries both the ACK-request misc-options bit and a valid
    /// sender key — the two halves aMule's `Process2HelloResponse` needs before
    /// it will emit its own `0x22 KADEMLIA2_HELLO_RES_ACK`. Implies
    /// `--kad-crypt` on the aMule side and switches the verdict to the
    /// verify-key assertion.
    #[arg(long)]
    pub(crate) verify_keys: bool,
}

/// The Core-pumped stimulus flows' shared shape (M and N): a firewalled stock
/// aMule against `ed2k serve start --kad` in the rust client image.
#[derive(Debug, Args)]
pub(crate) struct CorePumpedArgs {
    #[command(flatten)]
    pub(crate) bench: BenchArgs,
    #[command(flatten)]
    pub(crate) kad: KadBenchArgs,
    /// Rust image the Core-pumped stimulus compiles and runs `rmule-tools` in.
    #[arg(long, default_value = DEFAULT_RMULE_CLIENT_IMAGE)]
    pub(crate) rmule_client_image: String,
    /// Per-step readiness timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub(crate) timeout: u64,
    /// Deterministic synthetic file size in bytes (the stimulus's shared file).
    #[arg(long, default_value_t = DEFAULT_FILE_SIZE)]
    pub(crate) file_size: u64,
    /// What the synthetic file holds: `sparse` stages a file past 4 GiB as
    /// one hole the sharer hashes as zeros, `incompressible` one a throttled
    /// sharer cannot send compressed.
    #[arg(long, value_enum, default_value_t = FileContent::Pattern)]
    pub(crate) file_content: FileContent,
    /// Also drop the aMule's Kad UDP port.
    #[arg(long)]
    pub(crate) block_udp: bool,
    /// Run the stimulus on its LIVE reachability verdicts instead of declaring
    /// them open. Records what the unconverged self-checks do to the ADR-0061
    /// gates — the refusal is itself the documented finding.
    #[arg(long)]
    pub(crate) live_reachability: bool,
    /// Test hook for the ED2K hash command.
    #[arg(long, hide = true)]
    pub(crate) ed2k_hash_command: Option<PathBuf>,
}

impl CorePumpedArgs {
    /// Validate, allocate the run dir, stage the stimulus's shared file (so its
    /// serve registry is non-empty and the listener behaves as a live serve
    /// rather than a bare socket), give the firewalled aMule its empty shared
    /// dir, and write the resolved config.
    fn stage(&self, flow: &'static str) -> Result<(RunLayout, RmuleServeContainer)> {
        self.bench.prepare(&self.kad.build_contexts())?;
        let (run_dir, layout) = self.bench.create_run()?;
        stage_synthetic_content(
            &layout,
            self.file_size,
            self.file_content,
            self.ed2k_hash_command.as_deref(),
        )?;
        std::fs::create_dir_all(layout.amule_dir())
            .with_context(|| format!("create {}", layout.amule_dir().display()))?;
        write_resolved_config(
            &run_dir,
            &self
                .kad
                .resolved_config(flow, &self.bench, self.file_size, self.timeout, 0),
        )?;
        println!("run_dir={}", run_dir.display());
        let stimulus = RmuleServeContainer::cargo_rmule_tools(&self.rmule_client_image)?;
        Ok((layout, stimulus))
    }
}

/// `kad-core-buddy` (flow M).
#[derive(Debug, Args)]
pub(crate) struct KadCoreBuddyArgs {
    #[command(flatten)]
    pub(crate) core: CorePumpedArgs,
    /// Seconds the pcap runs after both sides are up.
    #[arg(long, default_value_t = DEFAULT_KAD_CORE_BUDDY_WINDOW_SECS)]
    pub(crate) window: u64,
    /// Extra OPEN stock aMule nodes that serve as the firewalled node's UDP
    /// firewall helpers. They are seeded with rmule and never with the
    /// counterparty: aMule's `QueryNextClient` refuses a helper its routing zone
    /// already holds, so it must learn them from rmule's answer to its helper
    /// lookup. Requires `--mesh-members >= 1` (rmule and a member fill the
    /// one-`/24` routing bin first) and implies `--block-udp`.
    #[arg(long, default_value_t = DEFAULT_KAD_CORE_BUDDY_HELPERS)]
    pub(crate) helpers: usize,
    /// Give the firewalled aMule the staged synthetic file to SHARE, so it
    /// publishes a source for it once its buddy link attaches.
    ///
    /// `CSharedFileList::Publish` runs the `STOREFILE` branch only while
    /// `GetCount()` is non-zero and — for a firewalled node —
    /// `clientlist->GetBuddyStatus() == Connected`, so this knob is what turns
    /// flow M's buddy recruitment into the type-3 source row rmule's buddy-row reader and
    /// writer are pinned against. Prefer the longer
    /// `--window` default it implies: the publish follows the link.
    ///
    /// Requires `--mesh-members >= 1`: the last member is pinned to the
    /// synthetic file's own Kad key, because `CSearch::StorePacket`
    /// (`Search.cpp:456`) silently refuses to publish to any contact farther
    /// than `SEARCHTOLERANCE` from it.
    #[arg(long)]
    pub(crate) publish_source: bool,
    /// Placed `rmule-tools kad join-node` contacts added to the swarm so the
    /// firewalled counterparty's extern-port probe has more than one contact to
    /// ping.
    ///
    /// A two-node swarm pings its single contact every 15 s forever — 4/min
    /// against the 2/min `KADEMLIA2_PING` budget both clients enforce — which
    /// bans the IP and closes the peer-TCP surface the buddy link needs. Two
    /// members spread the pings AND end the probe (`CPrefs::SetExternKadPort`
    /// stops at two distinct reporters agreeing on a port). Unlike `--helpers`
    /// they do NOT imply `--block-udp`: a `join-node` binds no peer-TCP
    /// listener, so it can never complete the counterparty's UDP firewall check.
    #[arg(long, default_value_t = 0)]
    pub(crate) mesh_members: usize,
    /// The image placed Kad members run `rmule-tools` from.
    #[arg(long, default_value = crate::cli::nat::DEFAULT_RMULE_TOOLS_IMAGE)]
    pub(crate) rmule_tools_image: String,
    /// Arm Kad-UDP crypt on both sides: `--peer-crypt
    /// requested` on the stimulus's `ed2k serve start --kad` (the Core leg —
    /// ADR-0046's one setting arms Kad-UDP crypt and verify keys together) and
    /// `AMULE_KAD_CRYPT=1` on the firewalled aMule. Acceptance is the same
    /// verify-key shape flow K's `--verify-keys` judges: rmule must print
    /// `rmule-kad-crypt-armed`, its log must carry no `UndecodableEnvelope`,
    /// and its tap decodes under the Kad UDP Key the harness passed it
    /// (`--kad-udp-key-seed`). Default OFF, matching every other Kad flow's
    /// plain-`0xE4` evidence.
    #[arg(long)]
    pub(crate) kad_crypt: bool,
    /// Change the stimulus's obfuscation policy mid-run, as
    /// `<secs>:<off|supported|requested|required>`; repeat for several (`ed2k
    /// serve start --peer-crypt-flip`). With `--kad-crypt` the run starts
    /// `requested` against a crypt-armed aMule, so `--peer-crypt-flip 120:off
    /// --peer-crypt-flip 240:requested` shows the running node disarmed and
    /// re-armed. The verdict lists the flips the stimulus marked.
    #[arg(long, value_parser = rmule_interop_harness::rmule::crypt_flip_arg)]
    pub(crate) peer_crypt_flip: Vec<String>,
    /// Add a High-ID rmule downloader handed only the synthetic file's ed2k
    /// link (`kad-core-buddy --callback-downloader`): its download finds aMule's buddy row, sends
    /// the `0x52` to the buddy, and must be dialed back by aMule over the
    /// relayed `OP_CALLBACK`. Requires `--publish-source`; the tap window
    /// becomes the bound on the placed storer's `SourceIndexed` gate.
    #[arg(long)]
    pub(crate) callback_downloader: bool,
    /// Add the ID-only fold-in: after the download, a walker
    /// runs one Callback Walk whose `0x52` lands on the firewalled aMule,
    /// which relays `OP_CALLBACK` over its held buddy link. Requires
    /// `--callback-downloader`.
    #[arg(long)]
    pub(crate) callback_walk: bool,
    /// Run the third party as a stock aMule requester handed only the ed2k
    /// link (`kad-core-buddy --amule-requester`): aMule's own `0x52` to the rmule buddy its
    /// type-3 row names, and the buddy's `0x99` relay of it. Requires
    /// `--publish-source`; replaces `--callback-downloader`.
    #[arg(long)]
    pub(crate) amule_requester: bool,
    /// Make the requester's row ID-only
    /// (`kad-core-buddy --amule-requester --omit-buddy-endpoint`): an rmule
    /// publisher names the buddy by `TAG_BUDDYHASH` alone, the firewalled aMule
    /// shares nothing, and the requester takes aMule's `FINDSOURCE` walk to the
    /// buddy. Requires `--amule-requester`.
    #[arg(long)]
    pub(crate) omit_buddy_endpoint: bool,
    /// Arm the aMule requester's crypt layer (`AMULE_KAD_CRYPT=1`):
    /// its `0x52` then reaches the buddy keyed on the buddy's Kad ID.
    /// Requires `--amule-requester`.
    #[arg(long)]
    pub(crate) requester_kad_crypt: bool,
    /// Carry the `FINDSOURCE` road through to a transfer: the
    /// firewalled aMule shares the file under a pinned user hash, and the
    /// ID-only row is published under that hash after aMule's own row, so
    /// the storer serves it first and the relayed `0x99` ends in a dial-back
    /// that can serve the file. Requires `--omit-buddy-endpoint`.
    #[arg(long)]
    pub(crate) findsource_transfer: bool,
    /// Run the buddy reask leg as the third party (`kad-core-buddy
    /// --buddy-reask`): two holders take the aMule's upload slots, a
    /// downloader on an `ed2ksrv` High ID is queued, the server stops, and
    /// the downloader's reask must go `0x94` to the buddy, `0x9A` over the
    /// held link and `0x91` back. Requires `--publish-source`; pair it with
    /// `--file-content incompressible` and a file of several parts.
    #[arg(long)]
    pub(crate) buddy_reask: bool,
    /// The `ed2ksrv` image `--buddy-reask` runs.
    #[arg(long, default_value = crate::cli::nat::DEFAULT_ED2KSRV_IMAGE)]
    pub(crate) ed2ksrv_image: String,
    /// The `ed2ksrv` bench config `--buddy-reask` renders.
    #[arg(long, default_value = crate::cli::nat::DEFAULT_ED2KSRV_CONFIG)]
    pub(crate) ed2ksrv_config: PathBuf,
}

/// `kad-direct-callback` (flow N).
#[derive(Debug, Args)]
pub(crate) struct KadDirectCallbackArgs {
    #[command(flatten)]
    pub(crate) core: CorePumpedArgs,
    /// Seconds the pcap runs after both sides are up.
    #[arg(long, default_value_t = DEFAULT_KAD_DIRECT_CALLBACK_WINDOW_SECS)]
    pub(crate) window: u64,
    /// Seconds between rmule's `0x95` emissions.
    #[arg(long, default_value_t = DEFAULT_KAD_DIRECT_CALLBACK_EMIT_SECS)]
    pub(crate) emit_every: u64,
}

/// `kad-required-check` (flow R).
#[derive(Debug, Args)]
pub(crate) struct KadRequiredCheckArgs {
    #[command(flatten)]
    pub(crate) core: CorePumpedArgs,
    /// Seconds rmule's verdicts may take to read open once every helper is up.
    #[arg(long, default_value_t = DEFAULT_KAD_REQUIRED_CHECK_WINDOW_SECS)]
    pub(crate) window: u64,
    /// Open stock aMule helpers; at least two.
    #[arg(long, default_value_t = 2)]
    pub(crate) helpers: usize,
    /// rmule's obfuscation policy: `required` is the flow's question,
    /// `requested` its control (which must reach Open/Open, or the flow is
    /// wrong rather than rmule).
    #[arg(long, default_value = "required", value_parser = ["required", "requested"])]
    pub(crate) peer_crypt: String,
}

pub(crate) fn kad_required_check(args: KadRequiredCheckArgs) -> Result<()> {
    if args.core.block_udp || args.core.live_reachability {
        bail!(
            "kad-required-check always runs rmule's live self-checks against OPEN helpers:              --block-udp and --live-reachability do not apply"
        );
    }
    let (layout, stimulus) = args.core.stage(FLOW_KAD_REQUIRED_CHECK)?;
    run_kad_required_check(KadRequiredCheckOptions {
        base: args
            .core
            .kad
            .capture_options(&args.core.bench, &layout, args.core.timeout, 0),
        rmule_client_container: &stimulus,
        helper_count: args.helpers,
        window_secs: args.window,
        peer_crypt: &args.peer_crypt,
    })
}

pub(crate) fn kad_firewalled_buddy(args: KadFirewalledBuddyArgs) -> Result<()> {
    // One capture leg per run: two flags would arm two node behaviors but the
    // flow computes only the first leg's verdict, silently never writing the
    // others — refuse instead of "passing" on the wrong leg.
    let legs = usize::from(args.requester_capture)
        + usize::from(args.recruit_buddy)
        + usize::from(args.verify_keys);
    if legs > 1 {
        bail!("--requester-capture, --recruit-buddy and --verify-keys are mutually exclusive");
    }
    // Each capture leg drives an OPEN aMule; the firewalled-buddy default drops
    // its ports.
    let open_amule = legs == 1;
    args.bench.prepare(&args.kad.build_contexts())?;
    args.node.validate()?;

    let (run_dir, layout) = args.bench.create_run()?;
    // The firewalled aMule mounts an (empty) shared dir; it publishes nothing —
    // this leg is about connectivity, not a file transfer.
    std::fs::create_dir_all(layout.amule_dir())
        .with_context(|| format!("create {}", layout.amule_dir().display()))?;
    write_resolved_config(
        &run_dir,
        &args.kad.resolved_config(
            FLOW_KAD_FIREWALLED_BUDDY,
            &args.bench,
            DEFAULT_FILE_SIZE,
            args.timeout,
            0,
        ),
    )?;
    println!("run_dir={}", run_dir.display());

    run_kad_firewalled_buddy(KadFirewalledBuddyOptions {
        base: args
            .kad
            .capture_options(&args.bench, &layout, args.timeout, 0),
        rmule_image: &args.node.rmule_image,
        rmule_dockerfile: &args.node.rmule_dockerfile,
        rmule_build_context: &args.node.rmule_build_context,
        // Every capture mode (requester self-check, buddy recruit, verify keys)
        // leaves the aMule fully open so it answers rmule's own emit; the
        // firewalled-buddy mode TCP-firewalls it (and, unless `--udp-open`, UDP
        // too).
        block_tcp: !open_amule,
        block_udp: !open_amule && !args.udp_open,
        window_secs: args.window,
        // The verify-key leg needs the counterparty's crypt layer up: aMule reads
        // a sender key only out of a crypt trailer, and answers under one.
        kad_crypt: args.kad_crypt || args.verify_keys,
        requester_capture: args.requester_capture,
        recruit_buddy: args.recruit_buddy,
        verify_keys: args.verify_keys,
    })
}

pub(crate) fn kad_core_buddy(args: KadCoreBuddyArgs) -> Result<()> {
    let (layout, stimulus) = args.core.stage(FLOW_KAD_CORE_BUDDY)?;
    run_kad_core_buddy(KadCoreBuddyOptions {
        base: args
            .core
            .kad
            .capture_options(&args.core.bench, &layout, args.core.timeout, 0),
        rmule_client_container: &stimulus,
        window_secs: args.window,
        helper_count: args.helpers,
        block_udp: args.core.block_udp,
        assume_open: !args.core.live_reachability,
        publish_source: args.publish_source,
        mesh_members: args.mesh_members,
        rmule_tools_image: &args.rmule_tools_image,
        kad_crypt: args.kad_crypt,
        peer_crypt_flip: &args.peer_crypt_flip,
        callback_downloader: args.callback_downloader,
        callback_walk: args.callback_walk,
        amule_requester: args.amule_requester,
        omit_buddy_endpoint: args.omit_buddy_endpoint,
        requester_kad_crypt: args.requester_kad_crypt,
        findsource_transfer: args.findsource_transfer,
        buddy_reask: args.buddy_reask.then_some(BuddyReaskServer {
            image: &args.ed2ksrv_image,
            config: &args.ed2ksrv_config,
        }),
    })
}

pub(crate) fn kad_direct_callback(args: KadDirectCallbackArgs) -> Result<()> {
    let (layout, stimulus) = args.core.stage(FLOW_KAD_DIRECT_CALLBACK)?;
    run_kad_direct_callback(KadDirectCallbackOptions {
        base: args
            .core
            .kad
            .capture_options(&args.core.bench, &layout, args.core.timeout, 0),
        rmule_client_container: &stimulus,
        window_secs: args.window,
        emit_every_secs: args.emit_every,
        assume_open: !args.core.live_reachability,
        block_udp: args.core.block_udp,
    })
}
