//! Diagnostic serve orchestration command (`ed2k serve start`).

pub(crate) mod crypt_flip;
mod switch;

use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::run_log::Level;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, CoreSettings, ExternalAddressOverride,
    KadEnableConfig, KadId, KadShutdownSlot, ObfuscationPolicy, PeerReach,
    ServeCommand as CoreServeCommand, ServerPolicy, open_durable_store_in_memory,
};
use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint, ServerEndpoint};

use crate::cli::DownloadIdentityArgs;
use crate::operand::parse_hex16;

#[derive(Debug, Args)]
pub(crate) struct ServeStartArgs {
    /// A file to share; repeat for several. All of them are shared from one
    /// throwaway directory (a lone file is never shared by itself), and the
    /// first login is asked for only once every one is shared.
    #[arg(long, required = true)]
    file: Vec<PathBuf>,
    /// eD2k server endpoint as `host:port`.
    #[arg(long)]
    server: String,
    /// A second server as `host:port` to switch to after `--switch-after`
    /// seconds: the driver hangs up on `--server` and connects to this one,
    /// as the operator does. Every session is told the whole share set.
    #[arg(long, requires = "switch_after")]
    switch_to: Option<String>,
    /// Seconds after the first login was asked for at which to switch.
    #[arg(long, requires = "switch_to")]
    switch_after: Option<u64>,
    /// A file placed in the shared directory at the switch, shared before the
    /// hang-up; repeat for several. The first server hears of it as an added
    /// offer, the second in its first announce.
    #[arg(long, requires = "switch_to")]
    add_at_switch: Vec<PathBuf>,
    /// Withhold the share set from a server that grants related search
    /// (the Announce Policy, ADR-0099): the core starts under it as it starts
    /// under the operator's. Off unless passed.
    #[arg(long, default_value_t = false)]
    withhold_from_related_search: bool,
    /// Local IPv4 listen address as `ip:port`.
    #[arg(long, default_value = "0.0.0.0:4663")]
    listen: SocketAddrV4,
    /// Maximum seconds to serve before stopping; 0 means run until killed.
    #[arg(long, default_value_t = 0)]
    max_seconds: u64,
    /// Concurrent upload slots granted across all connections
    /// (`CoreConfig::upload_slot_budget`). The default matches core's default;
    /// the peer-UDP reask consume scenario sets it to `1` so a
    /// second requester is held **queued** rather than granted, which is the
    /// precondition for a counterparty's reask cycle.
    #[arg(long, default_value_t = 4)]
    upload_slots: usize,
    /// Also run a Kad node inside this Core — the **Core-Pumped Stimulus Node**.
    /// A stimulus driven straight off `rmule_net::kad` exposes only
    /// a Kad-UDP surface, so an exchange whose second leg arrives over peer-TCP
    /// or the client-UDP socket (buddy serve, callback relay) cannot complete
    /// against it. Here the Kad node shares the Core that owns the serve
    /// listener and the buddy link, so a counterparty can reach both.
    #[arg(long, default_value_t = false)]
    kad: bool,
    /// Pin the Kad ID (32 hex digits) so a counterparty's FindBuddy walk
    /// converges on this node. Omitted, the node takes a random ID and a
    /// distance-driven exchange is left to chance.
    #[arg(long)]
    kad_id_hex: Option<String>,
    /// The **Kad UDP Key** the node's verify keys derive from, in place of
    /// the one the run's store mints. A caller that must open what a
    /// counterparty keys on it chooses the seed here; the tool never prints
    /// it.
    #[arg(long, requires = "kad")]
    kad_udp_key_seed: Option<u32>,
    /// The one UDP listen port (peer reask, NAT-T frames and Kad share it,
    /// ADR-0057); `0` binds ephemeral.
    #[arg(long, default_value_t = 0)]
    udp_port: u16,
    /// This node's external IPv4 (the fake-public address in Config A swarm
    /// topologies, which have no NAT to observe it from). Seeds Address
    /// Learning's Override tier (ADR-0084) — the source the ADR-0058
    /// self-connect guard ends up reading, since it outranks every other
    /// observation. It binds nothing: the socket is the core's wildcard
    /// Family Pair. Omitted, Address Learning works the address out itself
    /// (the Interface tier, once the address is seen on a local interface).
    #[arg(long)]
    own_ip: Option<std::net::Ipv4Addr>,
    /// Kad bootstrap contact as `ip:port`; repeat for several.
    #[arg(long)]
    kad_bootstrap: Vec<SocketAddrV4>,
    /// Write the Kad node's per-datagram tap here — the same
    /// `[u32 LE length][bytes]` frames plus `datagrams.toml`/`meta.toml`
    /// format `kad join-node --capture-dir` writes (ADR-0022), so a
    /// `--kad-crypt` run can be judged frame-by-frame instead of trusted from
    /// the process log alone. Off unless passed.
    #[arg(long)]
    kad_capture_dir: Option<PathBuf>,
    /// Declare this node's own Kad reachability **open** rather than waiting for
    /// the ADR-0058 self-checks. Off unless passed.
    ///
    /// Both self-checks need other open peers to converge — the TCP verdict wants
    /// two connect-back acks from distinct requesters, the UDP verdict two fresh
    /// helpers — so in a stimulus swarm neither settles and the ADR-0061 recruit
    /// gate refuses every `KADEMLIA_FINDBUDDY_REQ` before the counterparty can
    /// reveal what it does next. This is rmule's own posture, the stimulus half of
    /// the exchange; every counterparty byte stays genuine (ADR-0045).
    #[arg(long, default_value_t = false)]
    kad_assume_open: bool,
    /// Reach a **firewalled peer** at this `ip:kad_udp_port` through the ADR-0061
    /// callback chooser, on a repeating cadence for the life of the run
    /// (`CoreCommand::ReachPeer`). The chooser picks route 2 and emits
    /// `OP_DIRECTCALLBACKREQ` (`0x95`) there — aMule addresses its own direct
    /// callback to `GetKadPort()`, and its Kad UDP port and client UDP port are
    /// one socket demuxed on the protocol byte, so the Kad port is the right
    /// destination for a peer-protocol frame.
    ///
    /// Passing this **declares** the counterparty firewalled (LowID) and
    /// direct-callback capable, the two facts a source row or hello would
    /// otherwise carry. It is rmule's own stimulus configuration, the sibling of
    /// `--kad-assume-open`; nothing about the counterparty's answer is assumed,
    /// and every byte it sends back stays genuine (ADR-0045).
    #[arg(long)]
    direct_callback: Option<SocketAddrV4>,
    /// How often to re-issue `--direct-callback`. aMule honours at most one
    /// direct callback per source IP per three minutes
    /// (`CClientList::AllowCallbackRequest`, `MIN2MS(3)`), so a faster cadence
    /// only spends datagrams — it exists so a run that starts before the
    /// counterparty's Kad is up still lands one.
    #[arg(long, default_value_t = 30)]
    direct_callback_every_secs: u64,
    /// Every this many seconds, ask the Core for its diagnostics and print the
    /// Kad self-check verdicts whenever they change, as
    /// `rmule-kad-verdicts tcp=<open|checking|firewalled> udp=<open|firewalled|unverified>`
    /// — the line a bench flow judges rmule's own reachability from.
    /// `0`, the default, asks nothing.
    #[arg(long, default_value_t = 0)]
    report_kad_verdicts_every_secs: u64,
    /// Arm rmule's peer protocol-obfuscation policy (`CoreSettings::obfuscation`,
    /// ADR-0042/0046) for this run — off unless passed. It lights the peer
    /// hello's `MiscOptions2` crypt bits, makes the accepted peer-TCP
    /// connections obfuscation-aware, and arms the peer-UDP per-datagram layer
    /// (dual-path receive; send under the ADR-0046 gate). The **peer-UDP crypt
    /// capture** runs the existing reask scenario with this set
    /// plus the counterparty's `AMULE_CRYPT_SUPPORTED` / `_REQUESTED`, so
    /// aMule's `ShouldReceiveCryptUDPPackets()` sees a crypt-capable rmule and
    /// obfuscates its `0x90`.
    ///
    /// `supported` accepts obfuscation without initiating it; `requested` and
    /// `required` also initiate. Nothing here changes a default — an
    /// unflagged run stays byte-for-byte the plaintext one.
    #[arg(long, value_enum)]
    peer_crypt: Option<PeerCryptPolicyArg>,
    /// Change the obfuscation policy mid-run, as `<secs>:<policy>` with the
    /// policy one of `off`, `supported`, `requested`, `required`; repeat for
    /// several. At each, the running core takes the policy up through its
    /// Core Settings handle — every surface reads it as it decides, and a
    /// connection already negotiated keeps its own (ADR-0046) — and a
    /// `rmule-obfuscation-flip after_secs=… policy=… at_unix_ms=…` line marks
    /// the moment. Seconds count from the first login being asked for, as
    /// `--switch-after` does. `--peer-crypt` is the policy the run starts
    /// under.
    #[arg(long, value_parser = crypt_flip::parse)]
    peer_crypt_flip: Vec<crypt_flip::CryptFlip>,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
}

/// The Kad half of a **Core-Pumped Stimulus Node**. Its identity is the
/// core's: the Kad ID `--kad-id-hex` pinned at build or the store minted, the
/// Kad UDP Key the run's store minted, and the serve listener's port, since
/// peers dial what Kad advertises and a buddy or callback relay only reaches
/// us if the two agree.
fn kad_enable_config(args: &ServeStartArgs) -> KadEnableConfig {
    KadEnableConfig {
        bootstrap: args.kad_bootstrap.clone(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: args.kad_assume_open,
        kad_capture_dir: args.kad_capture_dir.clone(),
        // Installed by `start` itself, once `args.kad` is known.
        kad_shutdown: None,
    }
}

/// The CLI spelling of [`ObfuscationPolicy`] (clap cannot derive `ValueEnum`
/// for a foreign type).
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum PeerCryptPolicyArg {
    Supported,
    Requested,
    Required,
}

impl From<PeerCryptPolicyArg> for ObfuscationPolicy {
    fn from(arg: PeerCryptPolicyArg) -> Self {
        match arg {
            PeerCryptPolicyArg::Supported => Self::Supported,
            PeerCryptPolicyArg::Requested => Self::Requested,
            PeerCryptPolicyArg::Required => Self::Required,
        }
    }
}

pub(crate) async fn start(args: ServeStartArgs) -> Result<()> {
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let config = CoreConfig {
        upload_slot_budget: args.upload_slots,
        // The Address Learning Override tier (ADR-0084); `--own-ip` is its
        // one CLI surface.
        external_address: ExternalAddressOverride {
            v4: args.own_ip,
            ..ExternalAddressOverride::default()
        },
        ..CoreConfig::default()
    };
    let settings = CoreSettings {
        // The serve listener's port is the one advertised, not the
        // identity's default.
        tcp_port: args.listen.port(),
        ..args.identity.settings(CoreSettings::default())
    };
    let settings = CoreSettings {
        obfuscation: args.peer_crypt.map(ObfuscationPolicy::from),
        // One socket for reask, NAT-T and Kad (ADR-0057): the core's one UDP
        // bind.
        udp_port: args.udp_port,
        server_policy: ServerPolicy {
            withhold_from_related_search: args.withhold_from_related_search,
            ..ServerPolicy::default()
        },
        ..settings
    };
    let store = open_durable_store_in_memory()?;
    let builder = args.identity.core_builder(config, settings, store)?;
    let builder = match args.kad_id_hex.as_deref() {
        Some(hex) => builder.kad_id(KadId::from_bytes(parse_hex16("--kad-id-hex", hex)?)),
        None => builder,
    };
    let mut core = match args.kad_udp_key_seed {
        Some(seed) => builder.kad_udp_key(seed),
        None => builder,
    }
    .build();
    let share = crate::share::share_files(&mut core, &args.file, |_| {}).await?;
    core.send(CoreCommand::Serve(CoreServeCommand::StartServing {
        listen_addr: args.listen,
    }))
    .await?;
    crate::node::connect(&core, &server).await?;
    let mut switch = match (&args.switch_to, args.switch_after) {
        (Some(to), Some(after)) => Some(switch::Switch {
            to: ServerEndpoint::parse_host_port(to)
                .with_context(|| format!("parse server endpoint {to}"))?,
            to_text: to.clone(),
            after: Duration::from_secs(after),
            add: args.add_at_switch.clone(),
        }),
        _ => None,
    };
    let began = tokio::time::Instant::now();
    let switch_at = switch.as_ref().map(|switch| began + switch.after);
    let mut crypt_flips = crypt_flip::CryptFlips::new(args.peer_crypt_flip.clone());

    // The external stop lever: installed whenever Kad runs, so
    // SIGTERM/SIGINT below can wait for a *finalized* ADR-0022 tap before
    // this process's own exit — `CoreCommand::DisableKad`
    // reports no such confirmation, only `CoreEvent::KadStopped`, so this
    // diagnostic path keeps its own raw lever rather than switching to it.
    let mut kad_shutdown_handle = None;
    if args.kad {
        let mut kad = kad_enable_config(&args);
        let (slot, handle) = KadShutdownSlot::new();
        kad.kad_shutdown = Some(slot);
        kad_shutdown_handle = Some(handle);
        // With a crypt policy the Core's node arms Kad-UDP crypt — at start,
        // or at a flip that arms one. The marker says so and carries no
        // seed: a verdict that opens what a counterparty keys on it chose the
        // seed itself (`--kad-udp-key-seed`).
        if args.peer_crypt.is_some() || args.peer_crypt_flip.iter().any(|flip| flip.arms()) {
            println!("rmule-kad-crypt-armed");
        }
        core.send(CoreCommand::EnableKad(kad)).await?;
    }

    let deadline = (args.max_seconds > 0)
        .then(|| tokio::time::Instant::now() + Duration::from_secs(args.max_seconds));
    // The direct-callback cadence, when asked for. A `MissedTickBehavior` of
    // `Delay` keeps a slow event drain from bursting the datagrams.
    let mut callback_tick = args.direct_callback.map(|_| {
        let mut ticker =
            tokio::time::interval(Duration::from_secs(args.direct_callback_every_secs.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker
    });
    let mut verdict_tick = (args.kad && args.report_kad_verdicts_every_secs > 0)
        .then(|| tokio::time::interval(Duration::from_secs(args.report_kad_verdicts_every_secs)));
    let mut last_verdicts = None;
    let mut stop = StopRequest::install()?;

    // The select is resolved into a `Step` first: `next_event` borrows the core
    // mutably for the whole select, so a `core.send` arm can only run once that
    // borrow has ended.
    // One value per loop iteration on a low-frequency channel, so the size
    // imbalance between the event arm and the two markers is intentional —
    // the same reasoning `CoreEvent` itself carries.
    #[allow(clippy::large_enum_variant)]
    enum Step {
        Event(Option<CoreEvent>),
        DirectCallback,
        ReportVerdicts,
        Switch,
        CryptFlip,
        Deadline,
        Signal,
    }
    loop {
        let step = tokio::select! {
            event = core.next_event() => Step::Event(event),
            () = async {
                match callback_tick.as_mut() {
                    Some(ticker) => { ticker.tick().await; }
                    None => std::future::pending().await,
                }
            } => Step::DirectCallback,
            () = async {
                match verdict_tick.as_mut() {
                    Some(ticker) => { ticker.tick().await; }
                    None => std::future::pending().await,
                }
            } => Step::ReportVerdicts,
            () = async {
                match (switch.is_some(), switch_at) {
                    (true, Some(at)) => tokio::time::sleep_until(at).await,
                    _ => std::future::pending().await,
                }
            } => Step::Switch,
            () = async {
                match crypt_flips.next_at(began) {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => Step::CryptFlip,
            () = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => Step::Deadline,
            () = stop.recv() => Step::Signal,
        };
        match step {
            Step::Event(event) => {
                let Some(event) = event else {
                    anyhow::bail!("serve event stream ended before stop");
                };
                if let CoreEvent::DiagnosticsSnapshot { snapshot } = &event {
                    report_kad_verdicts(snapshot, &mut last_verdicts);
                    continue;
                }
                println!("{}", event.record().render(Level::Full));
            }
            Step::ReportVerdicts => core.send(CoreCommand::DumpDiagnostics).await?,
            Step::Switch => {
                if let Some(switch) = switch.take() {
                    switch::run(&mut core, &share, &switch).await?;
                }
            }
            Step::CryptFlip => crypt_flips.fire(&core)?,
            Step::DirectCallback => {
                if let Some(target) = args.direct_callback {
                    core.send(CoreCommand::ReachPeer(firewalled_peer_reach(target)))
                        .await?;
                }
            }
            Step::Deadline => {
                // Quit stops serving and every other activity (ADR-0093).
                core.shutdown().await;
                return Ok(());
            }
            Step::Signal => return graceful_shutdown(core, kad_shutdown_handle).await,
        }
    }
}

/// The OS asking serve to stop, each way running the same graceful sequence:
/// SIGTERM (a `docker stop` or an orchestrator's shutdown) or SIGINT (Ctrl-C)
/// on Unix, Ctrl-C on Windows. Installed once before the loop, so a request
/// that lands between two turns of it is held, not lost.
#[cfg(unix)]
struct StopRequest {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl StopRequest {
    fn install() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            terminate: signal(SignalKind::terminate()).context("install SIGTERM handler")?,
            interrupt: signal(SignalKind::interrupt()).context("install SIGINT handler")?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

#[cfg(windows)]
struct StopRequest {
    ctrl_c: tokio::signal::windows::CtrlC,
}

#[cfg(windows)]
impl StopRequest {
    fn install() -> Result<Self> {
        Ok(Self {
            ctrl_c: tokio::signal::windows::ctrl_c().context("install Ctrl-C handler")?,
        })
    }

    async fn recv(&mut self) {
        self.ctrl_c.recv().await;
    }
}

/// Print the Kad self-check verdicts `snapshot` carries when they differ from
/// the last ones printed.
fn report_kad_verdicts(
    snapshot: &rmule_core::diagnostics::DiagnosticsSnapshot,
    last: &mut Option<(&'static str, &'static str)>,
) {
    use rmule_core::diagnostics::{KadFirewallVerdict, KadUdpVerdict};
    let Some(kad) = snapshot.kad else {
        return;
    };
    let tcp = match kad.firewall {
        KadFirewallVerdict::Open => "open",
        KadFirewallVerdict::Checking => "checking",
        KadFirewallVerdict::Firewalled => "firewalled",
    };
    let udp = match kad.udp {
        KadUdpVerdict::Open { .. } => "open",
        KadUdpVerdict::Firewalled => "firewalled",
        KadUdpVerdict::Unverified => "unverified",
    };
    if *last != Some((tcp, udp)) {
        *last = Some((tcp, udp));
        println!("rmule-kad-verdicts tcp={tcp} udp={udp}");
    }
}

/// The bound on reading the Kad tap's finalize confirmation.
/// Read after the Core's quit, which stopped the node through its own lever
/// So the answer is already settled — a guard, not a wait.
const KAD_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// SIGTERM/SIGINT's shutdown sequence: run the Core's own
/// quit — every activity's stop in order, the Kad node's through its one
/// lever, then the persistence flush — and report whether the Kad node's
/// tap finalized, which `kad_shutdown`'s confirmation carries once the
/// activity's stop ended clean. Always exits clean: an un-finalized tap is reported on
/// stdout, not treated as this run's failure, since the reason is bounded
/// and named, not a bug worth a nonzero exit.
async fn graceful_shutdown(
    core: Core,
    kad_shutdown: Option<rmule_core::KadShutdownHandle>,
) -> Result<()> {
    core.shutdown().await;
    if let Some(handle) = kad_shutdown {
        let finalized = handle.request_and_wait(KAD_SHUTDOWN_GRACE).await;
        println!(
            "rmule-kad-tap-finalized={finalized} grace_secs={}",
            KAD_SHUTDOWN_GRACE.as_secs()
        );
    }
    Ok(())
}

/// The `--direct-callback` target as the ADR-0061 chooser reads it: a firewalled
/// (LowID) peer that advertised direct-UDP callback at `kad_udp`, on no server we
/// share and with no buddy published — so route 2 is the only branch that can
/// fire and a `0x95` on the wire cannot be some other route's byte.
///
/// The client id is a sentinel below the LowID threshold. Only its *class* is
/// read (`ClientId::is_high_id`); the exact id would name the peer in a server
/// callback, which this target forecloses.
fn firewalled_peer_reach(kad_udp: SocketAddrV4) -> PeerReach {
    let kad_udp = Ipv4Endpoint::new(*kad_udp.ip(), kad_udp.port());
    PeerReach {
        id: ClientId::from_u32(1),
        // Never dialed on this route — a LowID peer has no plain dial. Carried so
        // the routed event names the peer we aimed at.
        tcp: PeerEndpoint::V4(kad_udp),
        supports_direct_udp_callback: true,
        kad_udp: Some(kad_udp),
        on_our_server: false,
        buddy: None,
        ipv6: None,
        supports_natt: false,
        // Rung 1 is not this driver's route; the ledger key it would need
        // is only ever a hash the caller already holds.
        user_hash: None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rmule_core::{Core, CoreCommand, CoreConfig, open_durable_store_in_memory};

    use super::{KadEnableConfig, KadShutdownSlot};

    /// The external stop lever's proof: the same lever SIGTERM's `graceful_shutdown` fires
    /// — a `KadShutdownHandle::request_and_wait` — stops a running Kad node
    /// and finalizes its ADR-0022 tap (`datagrams.bin.partial` renamed to
    /// `datagrams.bin` beside a written `datagrams.toml`) in a temp dir, with
    /// no SIGTERM or subprocess involved.
    #[tokio::test]
    async fn a_stop_request_finalizes_the_tap_in_a_temp_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = Core::builder(
            CoreConfig::default(),
            open_durable_store_in_memory().expect("in-memory store"),
        )
        .settings(rmule_core::CoreSettings::default())
        .build();
        let (slot, handle) = KadShutdownSlot::new();
        core.send(CoreCommand::EnableKad(KadEnableConfig {
            bootstrap: Vec::new(),
            contacts: Vec::new(),
            nodes_dat_path: None,
            assume_open_reachability: true,
            kad_capture_dir: Some(dir.path().to_path_buf()),
            kad_shutdown: Some(slot),
        }))
        .await
        .expect("EnableKad queued");

        assert!(
            handle.request_and_wait(Duration::from_secs(5)).await,
            "the stop request should confirm inside the grace"
        );
        assert!(
            dir.path().join("datagrams.toml").exists(),
            "a finalized tap writes datagrams.toml (ADR-0022)"
        );
        assert!(
            !dir.path().join("datagrams.bin.partial").exists(),
            "a finalized tap renames the .partial file away"
        );

        core.shutdown().await;
    }
}
