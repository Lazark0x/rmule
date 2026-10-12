//! `rmule-tools nat portmap` — drive a real [`Core`] against a real gateway and
//! record what its **Port Mapping** subsystem (ADR-0086) did.
//!
//! This is the port-mapping driver: the flows in `tools/interop-harness` stand a
//! `miniupnpd` gateway up, put this binary on its LAN, and then judge the
//! *gateway's* table and log. What this writes is rmule's own state — Stimulus,
//! never evidence (ADR-0045) — but it is the only place the two sides can be
//! lined up: the router says "I granted external port N", and this says whether
//! rmule graded that grant `Mapped` or `Degraded`, whether it advertised the
//! endpoint, and whether the fresh `Exact` install fired the Kad recheck.
//!
//! Three seams make the run possible at all, and each exists because the live
//! answer would be wrong inside a container:
//!
//! - **The backends are installed here.** Core ships none — talking to the
//!   operator's router is a deployment decision — so the driver hands it
//!   [`live_mapping_backends`].
//! - **The gateway is pinned, not looked up.** A route lookup inside a
//!   container answers whatever Docker wired, and over IPv6 the default route
//!   is via a link-local next hop the PCP layer cannot legally source from.
//! - **The store is in memory unless a dir is named.** `PortMapSecret` and
//!   `PortMapMethod` are durable, so a second run against a persisted store
//!   opens with a one-protocol short round instead of the full race.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Args, ValueEnum};
use rmule_core::diagnostics::DiagnosticsSnapshot;
use rmule_core::port_mapping::{PortMappingConfig, PortMappingMode};
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, CoreSettings, ExternalAddressOverride,
    KadEnableConfig, KadId, ServeCommand, live_mapping_backends, open_durable_store_in_memory,
};
use rmule_net::family::FamilySelection;
use rmule_net::portmap::{Gateway, GatewaySource, MappingProtocol};
use rmule_primitives::ServerEndpoint;

use crate::cli::DownloadIdentityArgs;
use crate::operand::parse_hex16;

use self::report::Observations;

pub(crate) mod report;

/// The CLI spelling of [`MappingProtocol`] (clap cannot derive `ValueEnum` for
/// a foreign type). Naming a protocol forces the mask to exactly that one —
/// which is how a flow isolates the surface it is measuring instead of reading
/// whichever of the three happened to win the race.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum MappingProtocolArg {
    /// Port Control Protocol (RFC 6887) — the only one covering both families.
    Pcp,
    /// NAT Port Mapping Protocol (RFC 6886), IPv4 only.
    NatPmp,
    /// UPnP-IGD, IPv4 only.
    Upnp,
}

impl From<MappingProtocolArg> for MappingProtocol {
    fn from(arg: MappingProtocolArg) -> Self {
        match arg {
            MappingProtocolArg::Pcp => Self::Pcp,
            MappingProtocolArg::NatPmp => Self::NatPmp,
            MappingProtocolArg::Upnp => Self::Upnp,
        }
    }
}

/// The CLI spelling of [`FamilySelection`] — which families every socket role
/// binds (ADR-0085).
///
/// A flow pins this rather than taking the dual-stack default because the
/// **Desired Mapping Set** is derived from what *bound*: on a dual-stack host
/// an IPv4-only protocol is asked for the v6 rows too, answers `Unsupported`,
/// and the whole trial grades `Partial` — so a UPnP-only run on a dual-stack
/// container could never reach `Exact`, however perfectly the router behaved.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum FamilyArg {
    /// `0.0.0.0` only — the classic surface.
    V4,
    /// `::` only.
    V6,
    /// Both, core's own default.
    Both,
}

impl From<FamilyArg> for FamilySelection {
    fn from(arg: FamilyArg) -> Self {
        match arg {
            FamilyArg::V4 => Self {
                v4: true,
                v6: false,
            },
            FamilyArg::V6 => Self {
                v4: false,
                v6: true,
            },
            FamilyArg::Both => Self { v4: true, v6: true },
        }
    }
}

/// `rmule-tools nat portmap` — run a Core with port mapping armed, watch it,
/// and write the row.
#[derive(Debug, Args)]
pub(crate) struct NatPortMapArgs {
    /// The IPv4 default-route next hop to speak to — the **Gateway Source**,
    /// pinned. Omitted, no IPv4 gateway is offered and every IPv4 mapping
    /// reports `Unsupported`.
    #[arg(long)]
    gateway: Option<Ipv4Addr>,
    /// The local IPv4 a request to `--gateway` is sent from. This is also the
    /// internal address a UPnP `AddPortMapping` names, so it must be this
    /// container's own LAN address.
    #[arg(long)]
    gateway_local: Option<Ipv4Addr>,
    /// The IPv6 next hop. A link-local one (the shape every SLAAC network's
    /// default route takes) also needs `--gateway-v6-interface`: the PCP
    /// backend binds its request to `--gateway-local-v6`, so the
    /// source is pinned either way.
    #[arg(long)]
    gateway_v6: Option<Ipv6Addr>,
    /// The interface a link-local `--gateway-v6` is scoped by; its index is
    /// read from `/sys/class/net/<name>/ifindex`.
    #[arg(long)]
    gateway_v6_interface: Option<String>,
    /// The local IPv6 a request to `--gateway-v6` is sent from.
    #[arg(long)]
    gateway_local_v6: Option<Ipv6Addr>,
    /// Race only these protocols; repeat the flag. Empty races all three.
    #[arg(long = "protocol", value_enum)]
    protocols: Vec<MappingProtocolArg>,
    /// Which address families every socket role binds.
    #[arg(long = "family", value_enum, default_value = "both")]
    families: FamilyArg,
    /// The lifetime to ask the gateway for. Small on purpose in a flow: PCP's
    /// first renewal rung is L/2 floored at 4 s, so a short lease is what makes
    /// a renewal observable inside a bounded window.
    #[arg(long, default_value_t = 12)]
    lease_secs: u64,
    /// Withdraw every mapping on a clean exit (ADR-0086's `release_on_exit`).
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    release_on_exit: bool,
    /// The PCP Mapping Nonce secret. `0` is legitimate — the nonce is still
    /// stable, just guessable — and is what a flow uses.
    #[arg(long, default_value_t = 0)]
    secret: u32,
    /// Bind the eD2k peer listener here. Binding it is what grows the
    /// **Desired Mapping Set** by the TCP row, which is the mapping that earns
    /// a High-ID.
    #[arg(long, default_value = "0.0.0.0:4662")]
    listen: SocketAddrV4,
    /// The eD2k server the run connects to, as the operator's connect does. A
    /// closed local port is the normal value in a flow with no server: the
    /// login failure is non-fatal and the listener binds regardless, which is
    /// all the mapper needs.
    #[arg(long, default_value = "127.0.0.1:4661")]
    server: String,
    /// Also run a Kad node in this Core. It adds no mapping of its own — Kad
    /// rides the one UDP socket (ADR-0057) — but it gives the firewall
    /// self-check a surface, which is what the Kad verdict is read from.
    #[arg(long)]
    kad: bool,
    /// The one UDP port (peer reask, NAT-T frames and Kad share it, ADR-0057).
    /// Fixed rather than ephemeral so a flow can pre-claim it on the gateway;
    /// `0` binds ephemeral.
    #[arg(long, default_value_t = 4672)]
    udp_port: u16,
    /// Pin the Kad ID (32 hex digits).
    #[arg(long)]
    kad_id_hex: Option<String>,
    /// Kad bootstrap contact as `ip:port`; repeat for several. Dialed one at a
    /// time on the node's own cadence, and the loop stops the moment the first
    /// answer lands — so a flow that needs *several* known helpers seeds
    /// [`kad_contacts`](Self::kad_contacts) instead.
    #[arg(long)]
    kad_bootstrap: Vec<SocketAddrV4>,
    /// A Kad contact that is already placed in the keyspace, as
    /// `ip:udp_port:tcp_port:kad_id_hex` (32 hex digits); repeat for several.
    ///
    /// These enter the routing table directly (`KadCommand::MergeContacts`,
    /// ADR-0065's "v1/v2-merge"), which is the warm-restart shape a deployment
    /// reaches through its own `nodes.dat`. A flow seeds them rather than
    /// bootstrap endpoints when it needs a *known number* of helpers: the
    /// bootstrap dial loop stops on the first answer, so it can only ever
    /// deliver one, and the ≥2-ack TCP verdict needs two connect-backs.
    #[arg(long = "kad-contact")]
    kad_contacts: Vec<String>,
    /// State this host's external IPv6 outright (ADR-0084's Override tier,
    /// exempt from the corroboration filter). The **Desired Mapping Set** gates
    /// every v6 row on a Known IPv6, so without a v6 the mapper never asks for
    /// a pinhole at all.
    #[arg(long)]
    external_v6: Option<Ipv6Addr>,
    /// How long to watch before writing the row.
    #[arg(long, default_value_t = 60)]
    window_secs: u64,
    /// How often to sample the diagnostics.
    #[arg(long, default_value_t = 500)]
    poll_ms: u64,
    /// Where to write the row.
    #[arg(long)]
    out: Option<PathBuf>,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
}

/// How long the driver waits for [`Core::shutdown`]'s event drain before
/// giving up on it.
///
/// The harness finding this budget was added for — a serving session's task
/// spinning on a closed `watch::Sender` it read as a spurious wakeup, so the
/// drain never terminated — is fixed (a closed channel now reads
/// as a stop, proven by `shutdown_returns_after_a_serving_session`, which
/// returns in milliseconds). See the ADR-0092 amendment for what the
/// port-mapping flows actually measured; that record stays as written.
///
/// The bound stays anyway, now as an ordinary drive-a-real-process safety net
/// rather than a known-hang workaround: this run talks to a real gateway (and,
/// with `--kad`, a real Kad node), and `release_on_exit`'s own need — the
/// command channel closed, which happens the instant `shutdown()` is called,
/// not when it returns — is satisfied whether or not the drain finishes in
/// time. A future hang from a genuinely slow teardown path costs a bounded
/// wait and an honest `drained=false` in the printed row, never a stuck
/// process.
const SHUTDOWN_DRAIN_BUDGET: Duration = Duration::from_secs(5);

/// How long the process stays alive after the command channel closes, so the
/// mapping runtime's fire-and-forget release datagrams reach the gateway. Past
/// its own 2 s courtesy budget with room for the round trip.
const RELEASE_GRACE: Duration = Duration::from_secs(4);

/// The pinned **Gateway Source**: exactly the next hops the harness named, in
/// the order it named them. Empty is a legitimate answer for a family — a host
/// with no default route maps nothing, and that is a fact to report.
#[derive(Debug)]
struct PinnedGateways(Vec<Gateway>);

impl GatewaySource for PinnedGateways {
    fn gateways(&self) -> Vec<Gateway> {
        self.0.clone()
    }
}

/// Run the driver.
///
/// # Errors
/// If the pinned gateway arguments are incomplete, if the Core cannot start, or
/// if the row cannot be written. A gateway that refuses every protocol is not
/// an error — it is the row this command exists to write.
pub(crate) async fn run_nat_portmap(args: NatPortMapArgs) -> Result<()> {
    let gateways = pinned_gateways(&args)?;
    let mask = protocol_mask(&args.protocols);
    let config = CoreConfig {
        external_address: ExternalAddressOverride {
            v4: None,
            v6: args.external_v6,
        },
        address_families: args.families.into(),
        port_mapping: PortMappingConfig {
            protocols: mask,
            lease: Duration::from_secs(args.lease_secs),
            release_on_exit: args.release_on_exit,
        },
        ..CoreConfig::default()
    };

    println!(
        "rmule-portmap-armed gateways={} protocols_mask={mask} lease_secs={} release_on_exit={}",
        gateways.len(),
        args.lease_secs,
        args.release_on_exit,
    );
    for gateway in &gateways {
        println!(
            "rmule-portmap-gateway next_hop={} scope_id={:?} local={}",
            gateway.address, gateway.scope_id, gateway.local_address,
        );
    }

    let builder = args
        .identity
        .core_builder(
            config,
            CoreSettings {
                // One socket for reask, NAT-T and Kad (ADR-0057): the mapping
                // set this command measures holds one UDP mapping, at this port.
                udp_port: args.udp_port,
                port_mapping: PortMappingMode::Auto,
                // The listener's own port is the advertised one (the same
                // rule `ed2k serve start` follows), so a helper's
                // connect-back reaches the listener the mapping forwards to.
                tcp_port: args.listen.port(),
                ..args.identity.settings(CoreSettings::default())
            },
            open_durable_store_in_memory()?,
        )?
        .gateway_source(PinnedGateways(gateways.clone()))
        .mapping_backends(live_mapping_backends(args.secret));
    let mut core = match args.kad_id_hex.as_deref() {
        Some(hex) => builder.kad_id(KadId::from_bytes(parse_hex16("--kad-id-hex", hex)?)),
        None => builder,
    }
    .build();

    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: args.listen,
    }))
    .await?;
    crate::node::connect(&core, &server).await?;
    if args.kad {
        core.send(CoreCommand::EnableKad(kad_enable_config(&args)?))
            .await?;
    }

    let mut observations = Observations::new(&args, mask, &gateways);
    watch(&mut core, &mut observations, &args).await?;

    // The row is written BEFORE the shutdown: the release pass is what a flow
    // asserts an empty gateway table against, and a row that only existed after
    // it could not say what was released.
    let text = observations.render();
    print!("{text}");
    if let Some(path) = args.out.as_deref() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, &text).with_context(|| format!("write {}", path.display()))?;
        println!("rmule-portmap-row-written path={}", path.display());
    }

    // `release_on_exit` rides the runtime outliving the actor: dropping the
    // command channel is what closes the mapping runtime's control channel and
    // starts the release pass, and the pass has a 2 s courtesy budget of
    // fire-and-forget datagrams — so the grace below is what actually lets them
    // leave.
    //
    // The drain is bounded (see `SHUTDOWN_DRAIN_BUDGET`'s own doc for why — the spin this guarded
    // against is fixed); the row still
    // records which way it went.
    let drained = tokio::time::timeout(SHUTDOWN_DRAIN_BUDGET, core.shutdown())
        .await
        .is_ok();
    tokio::time::sleep(RELEASE_GRACE).await;
    println!(
        "rmule-portmap-shutdown-complete released_on_exit={} drained={drained}",
        args.release_on_exit
    );
    Ok(())
}

/// Watch the Core for the window, sampling diagnostics and folding every
/// transition into `observations`.
async fn watch(
    core: &mut Core,
    observations: &mut Observations,
    args: &NatPortMapArgs,
) -> Result<()> {
    // The select is resolved into a `Step` first: `next_event` borrows the core
    // mutably for the whole select, so the `send` that asks for the next
    // diagnostics dump can only run once that borrow has ended.
    #[allow(clippy::large_enum_variant)]
    enum Step {
        Event(Option<CoreEvent>),
        Poll,
        Deadline,
    }

    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.window_secs);
    let mut poll = tokio::time::interval(Duration::from_millis(args.poll_ms.max(50)));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let step = tokio::select! {
            event = core.next_event() => Step::Event(event),
            _ = poll.tick() => Step::Poll,
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Step::Deadline,
        };
        match step {
            Step::Event(None) => bail!("core event stream ended before the window closed"),
            Step::Event(Some(CoreEvent::DiagnosticsSnapshot { snapshot })) => {
                observations.observe(&snapshot, started.elapsed());
            }
            Step::Event(Some(event)) => observations.note_event(&event, started.elapsed()),
            Step::Poll => {
                // The sync accessor carries the mapping and address rows; the
                // Kad verdict lives with the actor, so the dump is what brings
                // it back. Both are folded, so a run with Kad off still records
                // every mapping transition at the poll cadence.
                let snapshot: DiagnosticsSnapshot = core.diagnostics_snapshot();
                observations.observe(&snapshot, started.elapsed());
                core.send(CoreCommand::DumpDiagnostics).await?;
            }
            Step::Deadline => return Ok(()),
        }
    }
}

/// The protocol mask a run races: the named protocols, or all three.
fn protocol_mask(protocols: &[MappingProtocolArg]) -> u8 {
    if protocols.is_empty() {
        return MappingProtocol::ALL
            .into_iter()
            .fold(0, |mask, protocol| mask | protocol.mask_bit());
    }
    protocols
        .iter()
        .fold(0, |mask, arg| mask | MappingProtocol::from(*arg).mask_bit())
}

/// The pinned next hops, refusing a half-named pair rather than guessing the
/// other half — a wrong source address is the one failure mode that looks like
/// a protocol refusal.
fn pinned_gateways(args: &NatPortMapArgs) -> Result<Vec<Gateway>> {
    let mut gateways = Vec::new();
    match (args.gateway, args.gateway_local) {
        (Some(next_hop), Some(local)) => gateways.push(Gateway::v4(next_hop, local)),
        (None, None) => {}
        _ => bail!("--gateway and --gateway-local are named together or not at all"),
    }
    match (args.gateway_v6, args.gateway_local_v6) {
        (Some(next_hop), Some(local)) => {
            if is_link_local_v6(local) {
                bail!(
                    "--gateway-local-v6 {local} is link-local; a pinhole to it names an \
                     address no peer can reach (RFC 6887 section 8.4)"
                );
            }
            let scope_id = match (is_link_local_v6(next_hop), &args.gateway_v6_interface) {
                (true, Some(interface)) => Some(interface_index(interface)?),
                (true, None) => bail!(
                    "--gateway-v6 {next_hop} is link-local; name the interface it is on with \
                     --gateway-v6-interface"
                ),
                (false, _) => None,
            };
            gateways.push(Gateway {
                address: IpAddr::V6(next_hop),
                scope_id,
                local_address: IpAddr::V6(local),
            });
        }
        (None, None) => {}
        _ => bail!("--gateway-v6 and --gateway-local-v6 are named together or not at all"),
    }
    if gateways.is_empty() {
        bail!(
            "no gateway pinned: name --gateway/--gateway-local, --gateway-v6/--gateway-local-v6, or both"
        );
    }
    Ok(gateways)
}

/// The kernel's index for `interface` — the zone a link-local next hop is
/// scoped by.
fn interface_index(interface: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{interface}/ifindex");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {path} for --gateway-v6-interface"))?;
    text.trim()
        .parse()
        .with_context(|| format!("{path} holds {text:?}, not an interface index"))
}

/// `fe80::/10` — the scope a PCP request must never leave from.
const fn is_link_local_v6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// Parse one `--kad-contact ip:udp_port:tcp_port:kad_id_hex` into a contact the
/// node can merge straight into its routing table.
///
/// Every field is required rather than defaulted: a contact whose ports or
/// identity were guessed would be a routing-table entry that names nothing real,
/// and the node would carry it until a probe timed out.
fn parse_kad_contact(spec: &str) -> Result<rmule_core::KadContact> {
    let fields: Vec<&str> = spec.split(':').collect();
    let [ip, udp_port, tcp_port, kad_id] = fields.as_slice() else {
        bail!("--kad-contact {spec} is not ip:udp_port:tcp_port:kad_id_hex");
    };
    let endpoint = rmule_kad::KadNodeEndpoint::new(
        ip.parse()
            .with_context(|| format!("--kad-contact {spec}: bad IPv4 {ip}"))?,
        udp_port
            .parse()
            .with_context(|| format!("--kad-contact {spec}: bad UDP port {udp_port}"))?,
    );
    Ok(rmule_core::KadContact::new(
        KadId::from_bytes(parse_hex16("--kad-contact", kad_id)?),
        endpoint,
        tcp_port
            .parse()
            .with_context(|| format!("--kad-contact {spec}: bad TCP port {tcp_port}"))?,
        KAD_CONTACT_VERSION,
    ))
}

/// The Kad protocol version a seeded contact is recorded at. `8` is what aMule
/// 2.3.3 announces for itself, and the only counterparty a flow seeds is a
/// stock aMule.
const KAD_CONTACT_VERSION: u8 = 8;

/// The Kad half; its identity is the core's, the Kad ID `--kad-id-hex`
/// pinned at build or the store minted.
fn kad_enable_config(args: &NatPortMapArgs) -> Result<KadEnableConfig> {
    Ok(KadEnableConfig {
        bootstrap: args.kad_bootstrap.clone(),
        contacts: args
            .kad_contacts
            .iter()
            .map(|spec| parse_kad_contact(spec))
            .collect::<Result<Vec<_>>>()?,
        nodes_dat_path: None,
        // Never: the whole point of `portmap-highid` is that the verdict flips
        // because a mapping made the node genuinely reachable, and a declared
        // posture would fabricate exactly that.
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    })
}
