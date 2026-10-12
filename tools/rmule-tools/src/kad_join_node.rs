//! The rmule **Kad Stimulus Node** runner for the Kad interop scenarios
//! (ADR-0043) — `rmule-tools kad join-node`, the entrypoint the
//! harness's rmule-node docker image runs inside the private mesh.
//!
//! Runs one live `rmule_net::kad` node: it bootstraps into an aMule hub, taps
//! every datagram into the mounted artifacts directory, and appends each
//! `KadEvent` to an events log. All acceptance judgement lives in the harness
//! on the host — this runner only participates and records.
//!
//! Three behaviours, selected by the publish flags:
//!
//! - **Join:** bootstrap and answer whatever the hub sends, proving
//!   routability. The hub drives the interaction.
//! - **Source stimulus:** with `--publish-file-hash`, additionally act
//!   as the **Kad Publisher** and **Kad Requester** — once a contact responds,
//!   publish a synthetic file's source (`0x44`) to the aMule storer, then search
//!   for it (`0x34`). `--publish-buddy-id` makes that row the firewalled
//!   type-3 one naming its buddy — by ID alone, or with the endpoint
//!   (`--publish-buddy-udp`) and IPv6 (`--publish-buddy-ipv6`, `bi6`) a
//!   firewalled rmule's own row carries.
//! - **Keyword stimulus (ADR-0062):** with `--publish-keyword-name`,
//!   publish a shared file's keyword (`0x43`) then search it back (`0x33`). The
//!   two undriven keyword legs against a live aMule storer.
//!
//! In every stimulus, aMule's `0x4B` ack and genuine `0x3B` answer are the
//! evidence; rmule's own bytes are never evidence.

use std::fmt::Write as _;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use rmule_kad::{
    FileHash, KadBuddyContact, KadCommand, KadEvent, KadId, KadKeywordSearchRequest, KadNodeConfig,
    KadNodeEndpoint, KadPublishRequest, KadSharedFile, KadSourceLookupRequest, SourceLookupTarget,
    UserHash,
};
use rmule_net::kad::{KadNetConfig, KadNetHandle, spawn};

use crate::operand::parse_hex16;

/// How often the bootstrap command is re-issued until the hub responds; UDP
/// is lossy and the sans-I/O node deliberately has no retry policy of its own.
const BOOTSTRAP_RETRY: Duration = Duration::from_secs(20);

/// How often the current stimulus step (publish, then search) is re-issued
/// until its aMule answer arrives. `0x4B`/`0x3B` are success-only — aMule
/// stays silent for a publish it dropped (e.g. before it has entered LAN mode
/// and stopped self-reporting UDP-firewalled) — so a publisher that gets no
/// ack must simply try again, exactly as a real client would.
const STIMULUS_RETRY: Duration = Duration::from_secs(8);

/// The default Kad Publisher User Hash for the join scenario, which never
/// publishes. The stimulus scenario overrides it with `--user-hash-hex` so the
/// captured source row's 16-byte ID matches exactly one known identity.
const DEFAULT_USER_HASH_HEX: &str = "77777777777777777777777777777777";

#[derive(Debug, Args)]
pub(crate) struct KadJoinNodeArgs {
    /// UDP address to bind the node on.
    #[arg(long)]
    bind: SocketAddr,
    /// The node's Kad ID as 32 hex chars.
    #[arg(long)]
    id_hex: String,
    /// eD2k TCP port advertised in the Kad headers.
    #[arg(long)]
    tcp_port: u16,
    /// The hub to bootstrap from, as an `ipv4:udp-port` endpoint.
    #[arg(long)]
    bootstrap: String,
    /// Directory the datagram capture tap writes into.
    #[arg(long)]
    capture_dir: PathBuf,
    /// File every `KadEvent` line is appended to.
    #[arg(long)]
    events_file: PathBuf,
    /// Seconds the node runs before shutting down and finalizing its capture.
    #[arg(long)]
    run_secs: u64,
    /// The Kad Publisher User Hash as 32 hex chars.
    #[arg(long, default_value = DEFAULT_USER_HASH_HEX)]
    user_hash_hex: String,
    /// Source-stimulus mode: the synthetic file hash to publish then search
    /// (32 hex chars). Requires `--publish-file-size`.
    #[arg(long)]
    publish_file_hash: Option<String>,
    /// Source-stimulus mode: the synthetic file's size in bytes.
    #[arg(long)]
    publish_file_size: Option<u64>,
    /// Source-stimulus mode: publish the source as a firewalled type-3 row
    /// naming this buddy **by ID alone** (32 hex chars, wire order) —
    /// `TAG_BUDDYHASH` with no `TAG_SERVERIP`/`TAG_SERVERPORT`, the row a stock
    /// aMule never writes (its publisher always has the endpoint,
    /// `Search.cpp:840-855`, kno `ab483654`). A downloader reading it must walk
    /// toward the ID to find the buddy. Requires
    /// `--publish-file-hash`.
    #[arg(long, requires = "publish_file_hash")]
    publish_buddy_id: Option<String>,
    /// With `--publish-buddy-id`: the buddy's Kad UDP endpoint (`ip:port`),
    /// written as `TAG_SERVERIP`/`TAG_SERVERPORT` — the trio a firewalled
    /// rmule's own row always carries, since its slot holds the endpoint the
    /// `0x5A` answered from.
    #[arg(long, requires = "publish_buddy_id")]
    publish_buddy_udp: Option<SocketAddrV4>,
    /// With `--publish-buddy-id`: the buddy's IPv6, written as the `bi6` tag
    /// (ADR-0087) — what core's slot states once the held buddy
    /// link knows it. **Stimulus**: no buddy link exists behind the knob.
    #[arg(long, requires = "publish_buddy_id")]
    publish_buddy_ipv6: Option<std::net::Ipv6Addr>,
    /// Keyword-stimulus mode: the shared filename whose keyword
    /// rmule publishes (`0x43`) then searches back (`0x33`). Reuses
    /// `--publish-file-hash`/`--publish-file-size` as the result-row identity;
    /// mutually exclusive with the source stimulus.
    #[arg(long)]
    publish_keyword_name: Option<String>,
    /// With `--publish-keyword-name`: send the keyword search right behind the
    /// publish command, while the publish walk still holds the keyword, then
    /// wait for the publish the search displaced to run and be acked before
    /// searching again.
    #[arg(long, requires = "publish_keyword_name")]
    search_during_publish: bool,
    /// Arm the ADR-0058 firewall self-check requester: rmule then piggybacks its
    /// own `0x50`/`0x53` checks on hello traffic toward the hub (the requester-
    /// capture leg). Off in the plain join / stimulus scenarios.
    #[arg(long)]
    firewall_self_check: bool,
    /// Arm the ADR-0061 buddy recruiter: once the hub responds, emit a
    /// `0x51 KADEMLIA_FINDBUDDY_REQ` toward it (target `~ourKadID`) and log the
    /// `0x5A` answer / `BuddyFound` if one lands. rmule's own genuine recruit bytes
    /// go on the wire; the counterparty answer is the capture (an open hub with a
    /// free buddy slot answers `0x5A`).
    #[arg(long)]
    recruit_buddy: bool,
    /// Arm one **Callback Walk**: once the hub responds,
    /// issue `KadCommand::CallbackWalk` toward this buddy ID (32 hex chars,
    /// wire order), so the walk sends its `0x52` to every responded contact
    /// within `SEARCHTOLERANCE` of it. The operands are **Stimulus** — the
    /// facts an ID-only source row would carry — and the walk, its tolerance
    /// filter and its `0x52` are the shipped path. Needs
    /// `--callback-file-hash` and `--callback-tcp-port`.
    #[arg(long, requires_all = ["callback_file_hash", "callback_tcp_port"])]
    callback_walk: Option<String>,
    /// The file the walk's `0x52` names, raw MD4 as 32 hex chars.
    #[arg(long)]
    callback_file_hash: Option<String>,
    /// The TCP port the walk's `0x52` invites the firewalled client to dial.
    #[arg(long)]
    callback_tcp_port: Option<u16>,
    /// Arm the ADR-0046 Kad datagram crypt and the verify-key layer:
    /// obfuscate outbound datagrams and trail
    /// `<receiverVerifyKey><senderVerifyKey>`, so a crypt-on aMule sees a valid
    /// sender key and will answer the `0x22` three-way ACK. The two arm
    /// together because the trailer only exists inside the crypt header.
    #[arg(long)]
    kad_crypt: bool,
    /// Our own public IP, which the verify-key derivation binds learned keys to
    /// (aMule retires every key on an address change). Required with
    /// `--kad-crypt`; in the fake-public bench this is the container's address.
    #[arg(long)]
    public_ip: Option<Ipv4Addr>,
    /// The **Kad UDP Key** `--kad-crypt` derives verify keys from. A caller
    /// that must open what a counterparty keys on it chooses the seed here;
    /// the tool never prints it. Omitted, the run mints its own.
    #[arg(long, requires = "kad_crypt")]
    kad_udp_key_seed: Option<u32>,
    /// Our Known IPv6, as the **Advertised Endpoints** chooser would settle it
    /// (ADR-0084). Carried into the node with `KadCommand::SetAdvertisedIpv6`,
    /// which is the only way the tag is ever set — a Kad node never reads an
    /// interface of its own. While it is set, every source publish carries the
    /// `ip6` tag (ADR-0087); omitted, none does, which is the control leg the
    /// `ipv6-kad-tags` flow needs to attribute the tag to this knob.
    #[arg(long)]
    advertised_ipv6: Option<std::net::Ipv6Addr>,
    /// Hold the first bootstrap dial back this many seconds (default 0 — dial at
    /// once). A hub that already carries us in its routing table (a seeded
    /// contact) hellos us on its OWN maintenance timer, but only while it still
    /// considers the contact due for a check: aMule's `CRoutingZone::OnSmallTimer`
    /// picks the oldest entry, and any datagram we send refreshes it
    /// (`CContact::UpdateType` pushes the expiry an hour out). Dialing first
    /// therefore pre-empts the hub's own hello — and some counterparty exchanges
    /// (the `0x22` three-way ACK) can only be captured with the hub as initiator.
    #[arg(long, default_value_t = 0)]
    bootstrap_delay_secs: u64,
}

/// The cross-flag facts `run` needs beyond the raw arguments: the parsed
/// identities and the resolved stimulus target (source xor keyword).
struct Resolved {
    id: KadId,
    bootstrap: KadNodeEndpoint,
    user_hash: UserHash,
    /// `Some` iff source-stimulus mode: the file to publish then search for.
    publish_target: Option<SourceLookupTarget>,
    /// `Some` iff keyword-stimulus mode. Mutually exclusive with
    /// `publish_target`.
    keyword_share: Option<KadSharedFile>,
    public_ip: Ipv4Addr,
    /// `Some` iff a Callback Walk is armed: the command it issues once.
    callback_walk: Option<KadCommand>,
    /// `Some` iff the source publish names its buddy by ID alone.
    buddy_publish: Option<KadBuddyContact>,
}

fn resolve(args: &KadJoinNodeArgs) -> Result<Resolved> {
    let id = KadId::from_bytes(parse_hex16("--id-hex", &args.id_hex)?);
    let user_hash = UserHash::from_bytes(parse_hex16("--user-hash-hex", &args.user_hash_hex)?);
    let bootstrap_addr = args
        .bootstrap
        .parse::<SocketAddr>()
        .context("--bootstrap must be an `ip:port` endpoint")?;
    let SocketAddr::V4(v4) = bootstrap_addr else {
        bail!("--bootstrap must be an IPv4 endpoint");
    };
    let bootstrap = KadNodeEndpoint::new(*v4.ip(), v4.port());

    let publish_file_hash = args
        .publish_file_hash
        .as_deref()
        .map(|hex| FileHash::from_hex(hex).context("--publish-file-hash must be 32 hex digits"))
        .transpose()?;

    // Keyword mode reuses the file hash + size (its result-row identity) and adds
    // the shared name from which the node derives the keyword. It is mutually
    // exclusive with the source stimulus — one target pin per run.
    let keyword_share = match args.publish_keyword_name.clone() {
        Some(filename) => {
            let (Some(hash), Some(size)) = (publish_file_hash, args.publish_file_size) else {
                bail!("--publish-keyword-name needs --publish-file-hash and --publish-file-size");
            };
            Some(KadSharedFile {
                file_hash: hash,
                filename,
                size,
                // The captured recipe pins an unclassifiable file: zero complete
                // sources, no FILETYPE (three-tag 0x43, matching aMule).
                complete_sources: 0,
                file_type: None,
            })
        }
        None => None,
    };

    let publish_target = match (publish_file_hash, args.publish_file_size) {
        _ if keyword_share.is_some() => None,
        (Some(hash), Some(size)) => Some(SourceLookupTarget::new(hash, size)),
        (None, None) => None,
        _ => bail!("--publish-file-hash and --publish-file-size must be given together"),
    };

    let public_ip = match (args.kad_crypt, args.public_ip) {
        (true, None) => bail!(
            "--kad-crypt needs --public-ip: the verify-key derivation binds learned keys to our own address"
        ),
        (_, Some(ip)) => ip,
        (false, None) => Ipv4Addr::UNSPECIFIED,
    };

    let callback_walk = match (
        args.callback_walk.as_deref(),
        args.callback_file_hash.as_deref(),
        args.callback_tcp_port,
    ) {
        (Some(buddy), Some(file), Some(tcp_port)) => Some(KadCommand::CallbackWalk {
            buddy_id: KadId::from_bytes(parse_hex16("--callback-walk", buddy)?),
            file_hash: FileHash::from_hex(file)
                .context("--callback-file-hash must be 32 hex digits")?,
            tcp_port,
        }),
        _ => None,
    };

    let buddy_publish = args
        .publish_buddy_id
        .as_deref()
        .map(|hex| -> Result<KadBuddyContact> {
            Ok(KadBuddyContact {
                buddy_id: KadId::from_bytes(parse_hex16("--publish-buddy-id", hex)?),
                buddy_udp: args
                    .publish_buddy_udp
                    .map(|udp| rmule_primitives::Ipv4Endpoint::new(*udp.ip(), udp.port())),
                buddy_ipv6: args.publish_buddy_ipv6,
                buddy_udp_ipv6: None,
            })
        })
        .transpose()?;

    Ok(Resolved {
        id,
        bootstrap,
        user_hash,
        publish_target,
        keyword_share,
        public_ip,
        callback_walk,
        buddy_publish,
    })
}

/// Mint this run's private verify-key derivation secret (aMule
/// `thePrefs::GetKadUDPKey()`, a random `u32` persisted per installation). A
/// stimulus node is single-run, so minting it fresh each start is the honest
/// shape: keys learned under a previous secret are meant to be dead.
fn kad_udp_key_secret() -> u32 {
    let mut raw = [0u8; 4];
    getrandom::fill(&mut raw).expect("OS entropy for the Kad UDP key secret");
    u32::from_le_bytes(raw)
}

/// Where the stimulus flow is in its publish→search progression. Each step
/// fires exactly once, gated on the prior step's observed aMule answer, so the
/// capture holds one clean `0x44`→`0x4B`→`0x34`→`0x3B` exchange.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stimulus {
    /// Join scenario: never publishes.
    Disabled,
    /// Waiting for the first contact to respond before publishing.
    AwaitingContact,
    /// Publish and search sent together; waiting for the search to end.
    Preempting,
    /// `0x44` sent; waiting for aMule's `0x4B` publish ack.
    Published,
    /// `0x34` sent; waiting for aMule's `0x3B` source answer.
    Searched,
    /// `0x3B` decoded into sources: the wall has fallen.
    Complete,
}

impl Stimulus {
    /// Whether the flow is waiting on an aMule answer that success-only opcodes
    /// never NAK — the states the retry timer re-issues.
    const fn awaits_answer(self) -> bool {
        matches!(self, Self::Published | Self::Searched)
    }
}

pub(crate) async fn run(args: KadJoinNodeArgs) -> Result<()> {
    let resolved = resolve(&args)?;

    // A capture of a counterparty datagram encrypted under a key *we* handed
    // out is only decodable — now or in a fixture years later — if this seed
    // is on the record: the caller's, when it names one.
    let verify_key_secret = args
        .kad_crypt
        .then(|| args.kad_udp_key_seed.unwrap_or_else(kad_udp_key_secret));

    let mut node = spawn(
        KadNetConfig {
            node: KadNodeConfig {
                id: resolved.id,
                tcp_port: args.tcp_port,
                udp_port: args.bind.port(),
                user_hash: resolved.user_hash,
            },
            capture_dir: Some(args.capture_dir.clone()),
            nodes_dat_path: None,
            firewall_self_check: args.firewall_self_check,
            obfuscation: verify_key_secret.map(|secret| {
                rmule_kad::KadObfuscation::new(rmule_net::kad::os_datagram_nonce)
                    .with_verify_keys(secret, resolved.public_ip)
            }),
            contact_admission: None,
        },
        args.bind,
    )
    .await
    .context("spawn the rmule Kad node")?;

    // Rung 0's Kad half (ADR-0087): the chooser's verdict is injected, never
    // read off an interface, so the flow states it and the node publishes it.
    if let Some(address) = args.advertised_ipv6 {
        node.command(KadCommand::SetAdvertisedIpv6 {
            address: Some(address),
        })
        .await
        .context("carry the advertised IPv6 into the Kad node")?;
        println!("rmule-kad-advertised-ipv6 address={address}");
    }
    if let Some(buddy) = resolved.buddy_publish {
        node.command(KadCommand::SetPublishPosture {
            posture: rmule_kad::KadPublishPosture::Firewalled { buddy: Some(buddy) },
        })
        .await
        .context("name the publish's buddy")?;
        println!(
            "rmule-kad-buddy-publish buddy_id={} buddy_udp={:?} buddy_ipv6={:?}",
            crate::capture::hex_lower(buddy.buddy_id.as_bytes()),
            buddy.buddy_udp,
            buddy.buddy_ipv6
        );
    }

    let mut events_log = std::fs::File::create(&args.events_file)
        .with_context(|| format!("create {}", args.events_file.display()))?;

    // The harness waits for this marker before starting the aMule hub, so the
    // hub's seeded rmule contact is already listening when aMule boots.
    println!("rmule-kad-join-node-ready bind={}", node.local_addr());
    if args.firewall_self_check {
        // The requester-capture leg: rmule piggybacks its own
        // `0x50`/`0x53` firewall checks on hello traffic toward the hub.
        println!("rmule-kad-firewall-self-check-armed");
    }
    if args.recruit_buddy {
        // The buddy recruiter: rmule emits its `0x51` toward the hub
        // once it responds, capturing whatever the hub answers.
        println!("rmule-kad-buddy-recruit-armed");
    }
    if resolved.callback_walk.is_some() {
        println!("rmule-kad-callback-walk-armed");
    }
    if verify_key_secret.is_some() {
        // The verify-key capture leg. A counterparty's `0x22` comes back
        // encrypted under the sender key *we* handed it, i.e. under
        // `udp_verify_key(seed, its_ip)`; the verdict opens it with the seed it
        // passed in. The seed is our private derivation secret: never printed.
        println!("rmule-kad-crypt-armed public_ip={}", resolved.public_ip);
    }
    if args.bootstrap_delay_secs > 0 {
        println!(
            "rmule-kad-bootstrap-delayed secs={}",
            args.bootstrap_delay_secs
        );
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.run_secs);
    // `interval_at` rather than `interval`: the first tick is the first dial, so
    // the delay knob is simply where that tick starts (0 = immediately, the
    // default every other scenario uses).
    let mut bootstrap_retry = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(args.bootstrap_delay_secs),
        BOOTSTRAP_RETRY,
    );
    let mut stimulus_retry = tokio::time::interval(STIMULUS_RETRY);
    let mut hub_responded = false;
    // The buddy recruiter fires its single `0x51` once, on the first hub response.
    let mut recruited = false;
    // The Callback Walk fires once, on the first hub response.
    let mut walked = false;
    // Keyword stimulus and source stimulus share the
    // publish→search progression; this picks which commands/events each step uses.
    let keyword_mode = resolved.keyword_share.is_some();
    let mut stimulus = if resolved.publish_target.is_some() || keyword_mode {
        Stimulus::AwaitingContact
    } else {
        Stimulus::Disabled
    };

    // A resolved select step so the `next_event` mutable borrow ends before a
    // command arm reissues on the node (the driver-pump borrow discipline).
    enum Step {
        Deadline,
        BootstrapTick,
        StimulusTick,
        Event(Option<KadEvent>),
    }

    loop {
        let step = tokio::select! {
            () = tokio::time::sleep_until(deadline) => Step::Deadline,
            _ = bootstrap_retry.tick(), if !hub_responded => Step::BootstrapTick,
            _ = stimulus_retry.tick(), if stimulus.awaits_answer() => Step::StimulusTick,
            event = node.next_event() => Step::Event(event),
        };

        match step {
            Step::Deadline => break,
            Step::BootstrapTick => {
                node.command(KadCommand::Bootstrap {
                    endpoint: resolved.bootstrap,
                })
                .await
                .context("issue the bootstrap command")?;
                println!(
                    "rmule-kad-join-node-bootstrap sent to {}:{}",
                    resolved.bootstrap.ip(),
                    resolved.bootstrap.udp_port()
                );
            }
            Step::StimulusTick => {
                // Re-issue the step still waiting for its aMule answer (the
                // success-only 0x4B/0x3B never NAK, so a dropped step just retries).
                match stimulus {
                    Stimulus::Published => {
                        issue_publish(&node, &resolved).await?;
                        println!("rmule-kad-stimulus-publish retried");
                    }
                    Stimulus::Searched => {
                        issue_search(&node, &resolved).await?;
                        println!("rmule-kad-stimulus-search retried");
                    }
                    _ => {}
                }
            }
            Step::Event(None) => bail!("driver stopped early"),
            Step::Event(Some(event)) => {
                if matches!(event, KadEvent::ContactResponded { .. }) {
                    hub_responded = true;
                }
                let mut line = String::new();
                write!(line, "event={event:?}")?;
                println!("{line}");
                writeln!(events_log, "{line}")?;
                events_log.flush()?;

                // Advance the stimulus flow. Each arm both issues its command
                // and advances the state, so every step fires exactly once (a
                // later PublishComplete after the ack no longer matches the
                // Published arm). The `next_event` borrow is already released.
                match stimulus {
                    Stimulus::AwaitingContact if hub_responded && args.search_during_publish => {
                        issue_publish(&node, &resolved).await?;
                        issue_search(&node, &resolved).await?;
                        println!("rmule-kad-stimulus-publish sent");
                        println!("rmule-kad-stimulus-search sent during the publish");
                        stimulus = Stimulus::Preempting;
                    }
                    Stimulus::AwaitingContact if hub_responded => {
                        issue_publish(&node, &resolved).await?;
                        println!("rmule-kad-stimulus-publish sent");
                        stimulus = Stimulus::Published;
                        stimulus_retry.reset();
                    }
                    Stimulus::Preempting
                        if matches!(event, KadEvent::KeywordSearchComplete { .. }) =>
                    {
                        println!("rmule-kad-stimulus-search ended; awaiting the publish");
                        stimulus = Stimulus::Published;
                        stimulus_retry.reset();
                    }
                    Stimulus::Published if is_publish_acked(&event, keyword_mode) => {
                        issue_search(&node, &resolved).await?;
                        println!("rmule-kad-stimulus-search sent");
                        stimulus = Stimulus::Searched;
                        stimulus_retry.reset();
                    }
                    Stimulus::Searched if is_search_answered(&event, keyword_mode) => {
                        println!("rmule-kad-stimulus-complete");
                        stimulus = Stimulus::Complete;
                    }
                    _ => {}
                }

                // Fire the single buddy recruit once the hub has responded:
                // rmule's `0x51` goes toward the hub, and any `0x5A` /
                // `BuddyFound` the hub answers is logged through the same events
                // sink above (the capture is the hub's genuine answer bytes).
                if args.recruit_buddy && hub_responded && !recruited {
                    node.command(KadCommand::RecruitBuddy {
                        target: resolved.bootstrap,
                    })
                    .await
                    .context("issue the buddy recruit command")?;
                    println!("rmule-kad-buddy-recruit sent");
                    recruited = true;
                }
                if let Some(walk) = resolved
                    .callback_walk
                    .as_ref()
                    .filter(|_| hub_responded && !walked)
                {
                    node.command(walk.clone())
                        .await
                        .context("issue the callback walk command")?;
                    println!("rmule-kad-callback-walk sent");
                    walked = true;
                }
            }
        }
    }

    let summary = node.shutdown().await.context("clean node shutdown")?;
    println!(
        "rmule-kad-join-node-done datagrams_in={} datagrams_out={} non_ipv4_dropped={}",
        summary.datagrams_in, summary.datagrams_out, summary.non_ipv4_dropped
    );
    Ok(())
}

/// aMule's `0x4B` publish ack ends a step: for a source publish it surfaces as
/// `PublishAcked` (or `PublishComplete` if the ack raced the walk's own
/// termination); for a keyword publish it is `KeywordPublishAcked` /
/// `KeywordPublishComplete`. Either arms the search.
fn is_publish_acked(event: &KadEvent, keyword: bool) -> bool {
    if keyword {
        matches!(
            event,
            KadEvent::KeywordPublishAcked { .. } | KadEvent::KeywordPublishComplete { .. }
        )
    } else {
        matches!(
            event,
            KadEvent::PublishAcked { .. } | KadEvent::PublishComplete { .. }
        )
    }
}

/// aMule's `0x3B` answer to the search: `SourcesFound` for a source search,
/// `KeywordsFound` for a keyword search. Concludes the stimulus.
fn is_search_answered(event: &KadEvent, keyword: bool) -> bool {
    if keyword {
        matches!(event, KadEvent::KeywordsFound { .. })
    } else {
        matches!(event, KadEvent::SourcesFound { .. })
    }
}

/// Issue the mode's publish command (`0x43` keyword or `0x44` source).
async fn issue_publish(node: &KadNetHandle, resolved: &Resolved) -> Result<()> {
    if let Some(file) = &resolved.keyword_share {
        node.command(KadCommand::PublishKeywords { file: file.clone() })
            .await
            .context("issue the keyword publish command")?;
    } else if let Some(target) = resolved.publish_target {
        node.command(KadCommand::PublishSource {
            request: KadPublishRequest::new(target),
        })
        .await
        .context("issue the source publish command")?;
    }
    Ok(())
}

/// Issue the mode's search command (`0x33` keyword or `0x34` source). The
/// keyword query is the shared filename — the node derives the lead-keyword
/// target and emits the plain `0x33`.
async fn issue_search(node: &KadNetHandle, resolved: &Resolved) -> Result<()> {
    if let Some(file) = &resolved.keyword_share {
        node.command(KadCommand::SearchKeywords {
            request: KadKeywordSearchRequest::new(file.filename.clone()),
        })
        .await
        .context("issue the keyword search command")?;
    } else if let Some(target) = resolved.publish_target {
        node.command(KadCommand::SearchSources {
            request: KadSourceLookupRequest::new(target),
        })
        .await
        .context("issue the source search command")?;
    }
    Ok(())
}
