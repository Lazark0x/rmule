//! `rmule-tools natt buddy-rendezvous` — the NAT-T
//! `natt-buddy-rendezvous-{cone,restricted,symmetric}` driver: ADR-0091 rung 1
//! through its **second** Rendezvous coordinator.
//!
//! Three bodies, one command. A firewalled **target** joins a private Kad mesh
//! from a **Seeded Bootstrap** and recruits a serving **buddy** over a live
//! FINDBUDDY walk (`0x51` → `0x5A`, ADR-0061); a second firewalled node — the
//! **requester** — reaches it by embedding an `OP_RENDEZVOUS` in an
//! `OP_REASKCALLBACKUDP` (`0x94`) addressed to that buddy, which relays `0x9A`
//! over the held link and answers `OP_NATT_ENDPOINT_HINT` (`0xAA`) with the
//! target's observed endpoint. Both ends burst, the requester dials, and a uTP
//! **Tunnel** rises over the pinhole.
//!
//! # Why there is no eD2k server on this WAN
//!
//! The buddy is the coordinator, and ADR-0091 tries the server coordinator
//! *first* whenever the candidate is on our connected server. A server on the
//! path would therefore measure the row `natt-server-punch-cone` already took
//! Each body still issues `StartServing`, because the bind is
//! what it needs — the serve listener is the buddy link's accept surface and
//! the port the hello advertises — and the bind is its own fact, taken on the
//! actor before any login is awaited (the bind-is-not-login contract). No
//! login is sent unless `--login` asks for one.
//!
//! `natt-buddy-recruit-amule` is the exception: its target recruits a stock
//! aMule, which keeps a buddy only while the hello reads a Low ID, so its
//! server variant passes `--login` and the target stands on the Low ID its
//! gateway earns it before Kad starts.
//!
//! # What the requester is told out of band, and why
//!
//! In the `natt-buddy-rendezvous-*` rows the requester is handed the target's
//! **User Hash**, its buddy's **Kad ID** and that buddy's UDP endpoint, and
//! issues `CoreCommand::ReachPeer` — the same command an operator sends. The
//! operands are **Stimulus**: they declare two facts a source row would
//! otherwise carry, and everything downstream — the route tree, the
//! rendezvous, the relay, the acting path, the burst, the dial and the Tunnel
//! — is the shipped path.
//!
//! In the `natt-buddy-transfer-*` rows it is handed only the
//! ed2k link: the target publishes a buddy row once its buddy is held, and the
//! requester's download finds it over Kad ([`transfer`]). The harness's
//! target file is then only the gate that says the publish has happened.
//!
//! All three bodies are rmule, so every row here is **`rmule-only`**
//! (ADR-0045's 2026-09-16 amendment) and is scored *exercised* against a
//! proven NAT, never captured.

mod first_dial;
mod row;
mod transfer;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use rmule_core::run_log::Level;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, ExternalAddressOverride, KadEnableConfig, PeerBuddy,
    PeerReach, ServeCommand as CoreServeCommand, open_durable_store_in_memory,
};
use rmule_kad::KadId;
use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint, ServerEndpoint, UserHash};

use crate::operand::{parse_hex16, parse_seeded_kad_contacts, parse_user_hash};

use self::row::BuddyRow;

/// How often a file the harness writes on a shared mount is looked for, and
/// how often the buddy slot is re-read while a recruit is awaited. A poll
/// because neither has an event to wait on from here.
const GATE_POLL: Duration = Duration::from_secs(5);

/// Which body this process is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum BuddyRole {
    /// The open relay: answers the `0x51` recruit, holds the target's link,
    /// relays `0x9A` and answers `0xAA`. Fake-public, no gateway.
    Buddy,
    /// The firewalled node being reached: joins the mesh, recruits the buddy,
    /// consumes the relayed rendezvous and bursts.
    Target,
    /// The firewalled node doing the reaching: emits the `0x94`, takes the
    /// hint, bursts and dials (ADR-0091's rule: the side that asked
    /// dials).
    Requester,
}

impl BuddyRole {
    const fn name(self) -> &'static str {
        match self {
            Self::Buddy => "buddy",
            Self::Target => "target",
            Self::Requester => "requester",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct NattBuddyRendezvousArgs {
    /// Which body to be.
    #[arg(long, value_enum)]
    role: BuddyRole,
    /// The eD2k endpoint a download names. Nothing dials it (ADR-0095) unless
    /// `--login` asks for the operator's connect: the bind is what the body
    /// needs, and a download with no session and Kad running starts
    /// serverless.
    #[arg(long)]
    server: String,
    /// Log in to `--server` before Kad starts, as the operator's connect
    /// (`natt-buddy-recruit-amule`'s server variant): a firewalled home node
    /// stands on its server Low ID when it recruits, and the id its hello
    /// presents is the one an open aMule keeps a buddy by.
    #[arg(long)]
    login: bool,
    /// Seconds to wait for the `--login` session; a login that never lands is
    /// a row, not an error.
    #[arg(long, default_value_t = 60)]
    login_timeout: u64,
    /// The serve listener: the buddy link's accept surface.
    #[arg(long, default_value = "0.0.0.0:4662")]
    listen: SocketAddrV4,
    /// The one UDP bind — Kad, client-UDP and NAT-T share it (ADR-0057).
    /// It is pinned rather than ephemeral because the mapping the buddy
    /// observes on the `0x51` is the mapping the punch must reach.
    #[arg(long, default_value_t = 4672)]
    udp_port: u16,
    /// A file to share, so the serve activity has one.
    #[arg(long)]
    share: PathBuf,
    /// Our nickname.
    #[arg(long, default_value = "rmule-natt")]
    nickname: String,
    /// Our user hash as hex (32 chars).
    #[arg(long)]
    user_hash: String,
    /// Our Kad ID as hex (32 chars). The buddy's is the target's inverted, so
    /// the FINDBUDDY walk toward `~ourKadID` converges on it at distance zero.
    #[arg(long)]
    kad_id: Option<String>,
    /// This node's external IPv4 (the fake-public address the mesh assigns
    /// it — no NAT here to observe it from). Seeds Address Learning's
    /// Override tier (ADR-0084), which outranks every observation and is
    /// what the ADR-0058 self-connect guard ends up reading. Omitted,
    /// Address Learning works the address out itself.
    #[arg(long)]
    own_ip: Option<Ipv4Addr>,
    /// One **Seeded Bootstrap** contact, `<kad-id-hex>@<ipv4>:<udp-port>`,
    /// repeatable. Seeded as an already-placed contact (`MergeContacts`, the
    /// ADR-0065 v1/v2-merge), not as a dial candidate: a walk needs contacts
    /// in the keyspace, and a bootstrap round trip would only re-earn what the
    /// harness already knows.
    #[arg(long = "kad-contact")]
    kad_contacts: Vec<String>,
    /// A Kad node to **bootstrap** from, `<ipv4>:<udp-port>`, repeatable —
    /// where a placed contact would stay silent. A seeded contact is merged
    /// already-responded and never greeted, so the node it names never learns
    /// of us; a bootstrap dial puts us in that node's table, which is what a
    /// UDP Firewall Helper needs to be found by someone else's helper lookup.
    #[arg(long = "kad-bootstrap")]
    kad_bootstrap: Vec<SocketAddrV4>,
    /// Declare this node's surface open instead of waiting for the ADR-0058
    /// self-checks — the **Core-Pumped Stimulus Node** posture.
    /// The buddy needs it: the open-node buddy service refuses every
    /// `FINDBUDDY_REQ` while its own UDP verdict reads unverified, and no
    /// self-check can settle *open* in a mesh this size.
    #[arg(long)]
    assume_open: bool,
    /// Where to announce that the buddy slot reads `Held` — the **Readiness
    /// Gate** the harness opens the requester on (`--role target`).
    #[arg(long)]
    buddy_out: Option<PathBuf>,
    /// Seconds to wait for the recruit to land (`--role target`). The ADR-0058
    /// UDP verdict settles firewalled by a six-minute timeout and the recruit
    /// gate keeps five minutes clear of the last recheck, so this is minutes,
    /// not seconds.
    #[arg(long, default_value_t = 600)]
    buddy_timeout: u64,
    /// The file the harness writes naming the target and its buddy
    /// (`--role requester`): `user_hash=`, `buddy_id=`, `buddy_udp=`.
    #[arg(long)]
    target_file: Option<PathBuf>,
    /// Seconds to wait for that file.
    #[arg(long, default_value_t = 600)]
    target_timeout: u64,
    /// A file to share once the buddy is held (`--role target`,
    /// `natt-buddy-transfer-*`), so its source publish names the buddy.
    #[arg(long)]
    publish: Option<PathBuf>,
    /// A file to share once the ADR-0058 UDP verdict reads **open**
    /// (`--role target`, `natt-udp-selfcheck-cone`), instead of waiting for a
    /// buddy: a firewalled node whose UDP port a helper proved open publishes
    /// the type-6 row with the direct-callback bit, and needs no buddy.
    #[arg(long, conflicts_with = "publish")]
    publish_on_udp_open: Option<PathBuf>,
    /// The ed2k file link to download (`--role requester`,
    /// `natt-buddy-transfer-*`). With it the requester is told nothing about
    /// the target: the target file is only the gate, and Kad finds the source.
    #[arg(long)]
    file: Option<String>,
    /// Where the downloaded file lands (with `--file`).
    #[arg(long, default_value = "/out/dl/download.bin")]
    download_out: PathBuf,
    /// Arm this body's peer obfuscation policy (`CoreSettings::obfuscation`),
    /// which also arms its Kad-UDP crypt — so a UDP Firewall
    /// Helper keys its `0x62` on the verify key an `0xA7` carried.
    /// Off unless passed: an unflagged body stays plaintext.
    #[arg(long, value_enum)]
    peer_crypt: Option<crate::serve::PeerCryptPolicyArg>,
    /// Seconds to run once this body's part has begun.
    #[arg(long, default_value_t = 180)]
    window: u64,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
}

/// Run one body of the buddy rendezvous and write its row.
///
/// # Errors
/// If an operand will not parse or the core cannot be started. A buddy that is
/// never recruited, a relay that is refused or a Tunnel that never rises is a
/// **row** — those are the measurements the three rows exist to take.
pub(crate) async fn run_buddy_rendezvous(args: NattBuddyRendezvousArgs) -> Result<()> {
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let our_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let kad_id = args
        .kad_id
        .as_deref()
        .map(|hex| parse_hex16("--kad-id", hex))
        .transpose()?
        .map(KadId::from_bytes);
    let contacts = parse_seeded_kad_contacts(&args.kad_contacts)?;
    let download_plan = args.file.clone().map(|link| transfer::DownloadPlan {
        link,
        output: args.download_out.clone(),
        server: server.clone(),
        window: Duration::from_secs(args.window),
    });

    let mut row = BuddyRow {
        role: args.role.name(),
        seeded_contacts: u32::try_from(contacts.len()).unwrap_or(u32::MAX),
        ..BuddyRow::default()
    };

    let builder = Core::builder(
        CoreConfig {
            // The Address Learning Override tier (ADR-0084); `--own-ip` is
            // its one CLI surface.
            external_address: ExternalAddressOverride {
                v4: args.own_ip,
                ..ExternalAddressOverride::default()
            },
            ..CoreConfig::default()
        },
        open_durable_store_in_memory()?,
    )
    .settings(rmule_core::CoreSettings {
        nickname: args.nickname.clone(),
        tcp_port: args.listen.port(),
        udp_port: args.udp_port,
        obfuscation: args.peer_crypt.map(rmule_core::ObfuscationPolicy::from),
        download_dir: download_plan
            .as_ref()
            .map(|plan| crate::output::download_dir(std::slice::from_ref(&plan.output)))
            .transpose()?,
        ..rmule_core::CoreSettings::default()
    })
    .user_hash(our_hash);
    let mut core = match kad_id {
        Some(kad_id) => builder.kad_id(kad_id),
        None => builder,
    }
    .build();
    let _share = crate::share::share_files(&mut core, std::slice::from_ref(&args.share), |event| {
        row::observe(event, &mut row);
    })
    .await?;
    core.send(CoreCommand::Serve(CoreServeCommand::StartServing {
        listen_addr: args.listen,
    }))
    .await?;
    // The bind, not the login: the buddy link rides the listener the bind
    // produced, and only `--login` asks for a session on top of it.
    drain_until_serving(&mut core, Duration::from_secs(30), &mut row).await?;
    if args.login {
        // Before Kad, so every hello the recruit sends presents the id the
        // server granted rather than a serverless one.
        crate::node::connect(&core, &server).await?;
        await_login(&mut core, Duration::from_secs(args.login_timeout), &mut row).await?;
        println!(
            "rmule-natt-buddy-login connected={} id={} failure={:?}",
            row.connected, row.client_id, row.login_failure
        );
    }

    if let Some(kad_id) = kad_id {
        row.kad_id = hex_lower(kad_id.as_bytes());
        core.send(CoreCommand::EnableKad(KadEnableConfig {
            bootstrap: args.kad_bootstrap.clone(),
            contacts,
            nodes_dat_path: None,
            assume_open_reachability: args.assume_open,
            kad_capture_dir: None,
            kad_shutdown: None,
        }))
        .await?;
        // Nothing is forced here: the pump injects the node's own
        // TCP verdict as a level at Kad start, so `UdpFirewallTester`'s six
        // minutes run from the moment Kad comes up and the ADR-0061 recruit
        // gate opens on the product's own clock. The flow measures what a home
        // node behind a NAT actually does.
        row.kad_enabled = true;
    }

    println!(
        "rmule-natt-buddy-ready role={} hash={} kad_id={} contacts={}",
        row.role, args.user_hash, row.kad_id, row.seeded_contacts
    );

    match args.role {
        BuddyRole::Buddy => {
            // The relay has nothing to ask for: it holds its window open so
            // accepting a recruit, relaying a rendezvous and answering a hint
            // are measurements rather than zeroes nobody took.
            drain(&mut core, Duration::from_secs(args.window), &mut row).await?;
        }
        BuddyRole::Target => target(&mut core, &args, &mut row).await?,
        BuddyRole::Requester => match download_plan {
            Some(plan) => {
                if await_gate(&mut core, &args).await? {
                    transfer::download(&mut core, plan, &mut row).await?;
                } else {
                    row.routed = "no-target-file".to_owned();
                }
            }
            None => requester(&mut core, &args, &mut row).await?,
        },
    }

    row::snapshot(&mut core, &mut row).await?;
    row::write(&args.out, &row)
}

/// The firewalled half being reached: wait out the ADR-0058 verdicts until the
/// recruit lands, announce the buddy it landed on, then hold the window open
/// for the relayed rendezvous.
async fn target(core: &mut Core, args: &NattBuddyRendezvousArgs, row: &mut BuddyRow) -> Result<()> {
    if let Some(path) = args.publish_on_udp_open.as_deref() {
        return target_udp_open(core, args, path, row).await;
    }
    let started = Instant::now();
    let held = await_buddy(core, Duration::from_secs(args.buddy_timeout), row).await?;
    let mut _published = None;
    if held {
        row.buddy_held_after_secs = i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX);
        if let Some(path) = args.buddy_out.as_deref() {
            std::fs::write(
                path,
                format!("state=Held\nafter_secs={}\n", row.buddy_held_after_secs),
            )
            .with_context(|| format!("write {}", path.display()))?;
        }
        println!(
            "rmule-natt-buddy-held after_secs={} state={}",
            row.buddy_held_after_secs, row.buddy_state
        );
        if let Some(path) = args.publish.as_deref() {
            _published = Some(transfer::publish(core, path, row).await?);
        }
    } else {
        println!(
            "rmule-natt-buddy-absent state={} last_refusal={}",
            row.buddy_state, row.buddy_last_recruit_refusal
        );
    }
    drain(core, Duration::from_secs(args.window), row).await
}

/// The firewalled half doing the reaching: take the target and its buddy from
/// the harness, ask the one route chooser to reach it, and run the window the
/// hint, the burst, the dial and the Tunnel have to happen in, with the
/// first-dial marker watched from before the rendezvous is armed.
async fn requester(
    core: &mut Core,
    args: &NattBuddyRendezvousArgs,
    row: &mut BuddyRow,
) -> Result<()> {
    let path = args
        .target_file
        .as_deref()
        .context("--role requester needs --target-file <path>")?;
    let Some(target) = await_target(core, path, Duration::from_secs(args.target_timeout)).await?
    else {
        row.routed = "no-target-file".to_owned();
        return Ok(());
    };
    let mut first_dial = first_dial::Watch::armed();
    core.send(CoreCommand::ReachPeer(reach(&target))).await?;
    match target.road {
        Road::Buddy {
            buddy_id,
            buddy_udp,
        } => println!(
            "rmule-natt-buddy-reach buddy_udp={buddy_udp} buddy_id={}",
            hex_lower(buddy_id.as_bytes()),
        ),
        Road::DirectUdp { kad_udp } => println!("rmule-natt-direct-udp-reach kad_udp={kad_udp}"),
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.window);
    drain_until(core, deadline, &mut first_dial, row).await
}

/// Wait for the harness's gate file, keeping the core's events drained — the
/// transfer requester's only use of it: the fields are the rendezvous
/// requester's, and this one reads none of them.
async fn await_gate(core: &mut Core, args: &NattBuddyRendezvousArgs) -> Result<bool> {
    let path = args
        .target_file
        .as_deref()
        .context("--role requester needs --target-file <path>")?;
    Ok(
        await_target(core, path, Duration::from_secs(args.target_timeout))
            .await?
            .is_some(),
    )
}

/// The target and the road to it, as the harness named them.
struct Target {
    user_hash: UserHash,
    road: Road,
}

/// How the requester is told to reach the target.
enum Road {
    /// Through its buddy (rung 1's buddy coordinator): the
    /// `natt-buddy-rendezvous-*` rows.
    Buddy {
        buddy_id: KadId,
        buddy_udp: Ipv4Endpoint,
    },
    /// Straight to its Kad UDP port with an `OP_DIRECTCALLBACKREQ` (`0x95`,
    /// ADR-0061 route 2): the `natt-udp-selfcheck-*` rows, whose
    /// target is firewalled with UDP verified open and needs no buddy. The
    /// target's dial-back carries the hello that advertises the route.
    DirectUdp { kad_udp: Ipv4Endpoint },
}

/// The `PeerReach` rung 1's buddy coordinator needs.
///
/// `on_our_server` is honestly `false` — this body has no session at all — and
/// that is what routes past the server coordinator to the buddy. `id` is a
/// Low-ID value because the coordinator is only reached from the LowID→LowID
/// rung; no address is fabricated for it (a Low-ID candidate has none, which
/// is what its id *means*), so `tcp` carries the unspecified address and the
/// port the selector never reads for it.
///
/// A [`Road::DirectUdp`] target is the Low-ID peer route 2 reaches: it
/// advertised the direct callback and named its Kad UDP port, and holds no
/// buddy — so no coordinator is offered.
fn reach(target: &Target) -> PeerReach {
    let (buddy_id, buddy_udp) = match target.road {
        Road::Buddy {
            buddy_id,
            buddy_udp,
        } => (buddy_id, buddy_udp),
        Road::DirectUdp { kad_udp } => {
            return PeerReach {
                id: ClientId::from_u32(1),
                tcp: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)),
                supports_direct_udp_callback: true,
                kad_udp: Some(kad_udp),
                on_our_server: false,
                buddy: None,
                ipv6: None,
                supports_natt: false,
                user_hash: Some(target.user_hash),
            };
        }
    };
    PeerReach {
        id: ClientId::from_u32(1),
        tcp: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)),
        supports_direct_udp_callback: false,
        kad_udp: None,
        on_our_server: false,
        buddy: Some(PeerBuddy {
            buddy_id,
            buddy_udp: Some(buddy_udp),
        }),
        ipv6: None,
        // The buddy coordinator's only voucher for the target (ADR-0091): the
        // server needs none because it holds the target's own `0xF9`, but no
        // server stands here.
        supports_natt: true,
        user_hash: Some(target.user_hash),
    }
}

/// Run the core's event loop for `budget`, recording what it said.
async fn drain(core: &mut Core, budget: Duration, row: &mut BuddyRow) -> Result<()> {
    let deadline = tokio::time::Instant::now() + budget;
    drain_until(core, deadline, &mut first_dial::Watch::off(), row).await
}

/// Run the core's event loop until `deadline`, recording what it said and
/// taking the readings `first_dial` owes.
async fn drain_until(
    core: &mut Core,
    deadline: tokio::time::Instant,
    first_dial: &mut first_dial::Watch,
    row: &mut BuddyRow,
) -> Result<()> {
    while let Some(event) = first_dial::next_event(core, deadline, first_dial, row).await? {
        println!("{}", event.record().render(Level::Full));
        row::observe(&event, row);
    }
    Ok(())
}

/// Drain until the serve listener says it came up, so the row's `serving` is a
/// fact rather than an assumption. A body whose listener never binds still
/// runs — it simply reports the bind it did not get.
async fn drain_until_serving(core: &mut Core, budget: Duration, row: &mut BuddyRow) -> Result<()> {
    let deadline = tokio::time::Instant::now() + budget;
    while !row.serving {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            event = core.next_event() => event,
        };
        let Some(event) = event else { break };
        println!("{}", event.record().render(Level::Full));
        row::observe(&event, row);
    }
    Ok(())
}

/// Drain until the session says it logged in or failed, recording either on
/// the row; a session that never answers inside `budget` is named there too.
async fn await_login(core: &mut Core, budget: Duration, row: &mut BuddyRow) -> Result<()> {
    let deadline = tokio::time::Instant::now() + budget;
    while !row.connected && row.login_failure.is_empty() {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                row.login_failure = format!("no session within {budget:?}");
                break;
            }
            event = core.next_event() => event,
        };
        let Some(event) = event else { break };
        println!("{}", event.record().render(Level::Full));
        row::observe(&event, row);
    }
    Ok(())
}

/// Poll the buddy slot until it reads `Held`, keeping the core's events
/// drained. Returns whether the recruit landed inside `budget`.
async fn await_buddy(core: &mut Core, budget: Duration, row: &mut BuddyRow) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        row::poll_buddy(core, row).await?;
        if row.buddy_state == "Held" {
            return Ok(true);
        }
        let poll = tokio::time::Instant::now() + GATE_POLL;
        if poll >= deadline {
            // One last reading on the deadline itself, so a recruit that
            // landed in the final interval is not reported as an absence.
            row::poll_buddy(core, row).await?;
            return Ok(row.buddy_state == "Held");
        }
        loop {
            let event = tokio::select! {
                () = tokio::time::sleep_until(poll) => break,
                event = core.next_event() => event,
            };
            let Some(event) = event else { return Ok(false) };
            println!("{}", event.record().render(Level::Full));
            row::observe(&event, row);
        }
    }
}

/// The UDP self-check's target: wait for the ADR-0058 UDP verdict to read
/// open, announce it, share the file so the publish states what that verdict
/// earned, then hold the window for the publish walk.
async fn target_udp_open(
    core: &mut Core,
    args: &NattBuddyRendezvousArgs,
    path: &Path,
    row: &mut BuddyRow,
) -> Result<()> {
    let started = Instant::now();
    row.udp_open_after_secs = -1;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.buddy_timeout);
    let open = loop {
        if let Some(snapshot) = await_snapshot(core, row).await?
            && let Some(kad) = snapshot.kad
        {
            row.udp_verdict = row::udp_verdict_name(kad.udp).to_owned();
            if let rmule_core::diagnostics::KadUdpVerdict::Open { port } = kad.udp {
                break Some(port);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        let poll = tokio::time::Instant::now() + GATE_POLL;
        loop {
            let event = tokio::select! {
                () = tokio::time::sleep_until(poll) => break,
                event = core.next_event() => event,
            };
            let Some(event) = event else { break };
            println!("{}", event.record().render(Level::Full));
            row::observe(&event, row);
        }
    };
    match open {
        Some(port) => {
            row.udp_open_after_secs =
                i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX);
            println!(
                "rmule-natt-udp-open after_secs={} port={port}",
                row.udp_open_after_secs
            );
            let _published = transfer::publish(core, path, row).await?;
            drain(core, Duration::from_secs(args.window), row).await
        }
        None => {
            println!("rmule-natt-udp-not-open verdict={}", row.udp_verdict);
            drain(core, Duration::from_secs(args.window), row).await
        }
    }
}

/// Poll for the harness's target file while keeping the core's events drained.
async fn await_target(core: &mut Core, path: &Path, budget: Duration) -> Result<Option<Target>> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Some(target) = read_target(path)? {
            return Ok(Some(target));
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
            event = core.next_event() => {
                let Some(event) = event else { return Ok(None) };
                println!("{}", event.record().render(Level::Full));
            }
        }
    }
}

/// Read the target file, or `None` while it is absent. Anything short of all
/// its fields is a file still arriving, never a malformed target.
fn read_target(path: &Path) -> Result<Option<Target>> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(None);
    };
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{key}=")))
            .map(str::trim)
    };
    let endpoint = |key: &str, text: &str| -> Result<Ipv4Endpoint> {
        let udp: SocketAddrV4 = text
            .parse()
            .with_context(|| format!("parse {key} {text}"))?;
        Ok(Ipv4Endpoint::new(*udp.ip(), udp.port()))
    };
    let Some(hash) = field("user_hash") else {
        return Ok(None);
    };
    // A buddy pair or a Kad UDP endpoint: anything short of one is a file
    // still arriving.
    let road = match (field("buddy_id"), field("buddy_udp"), field("kad_udp")) {
        (Some(buddy_id), Some(buddy_udp), _) => Road::Buddy {
            buddy_id: KadId::from_bytes(parse_hex16("buddy_id", buddy_id)?),
            buddy_udp: endpoint("buddy_udp", buddy_udp)?,
        },
        (None, None, Some(kad_udp)) => Road::DirectUdp {
            kad_udp: endpoint("kad_udp", kad_udp)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(Target {
        user_hash: UserHash::from_bytes(parse_user_hash(hash)?),
        road,
    }))
}

/// Ask for one diagnostics snapshot and read it back.
///
/// Every event that arrives before the snapshot does is still observed
/// The first-dial watch takes its first reading right after
/// `ReachPeer` is sent, and a driver that discarded events while it waited for a
/// snapshot could lose `PeerReachRouted` — the only event `row.routed` is
/// ever set from — in the same race the polling itself was added to close.
async fn await_snapshot(
    core: &mut Core,
    row: &mut BuddyRow,
) -> Result<Option<rmule_core::diagnostics::DiagnosticsSnapshot>> {
    core.send(CoreCommand::DumpDiagnostics).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            event = core.next_event() => event,
        };
        let Some(event) = event else { return Ok(None) };
        if let CoreEvent::DiagnosticsSnapshot { snapshot } = event {
            return Ok(Some(snapshot));
        }
        println!("{}", event.record().render(Level::Full));
        row::observe(&event, row);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
