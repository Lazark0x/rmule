//! Command-line surface: the clap command tree plus the value-enum bridges.
//! Per-command argument structs live with the code that consumes them (in the
//! protocol-area modules); this module owns the routing enums that tie them
//! together and the identity args shared across the core-orchestration commands.

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use rmule_primitives::{Ed2kFileClass, UserHash};

use crate::bootstrap_fetch::BootstrapFetchArgs;
use crate::download::{
    DownloadPauseArgs, DownloadReopenArgs, DownloadResumeArgs, DownloadStartArgs,
    DownloadStatusArgs,
};
use crate::ed2k::{
    LiveCaptureArgs, SearchWireArgs, SentinelStimulusArgs, ServerProbeArgs, SliceCaptureArgs,
};
use crate::ipv6::{
    Ipv6HelloArgs, Ipv6HoldSlotArgs, Ipv6RouteArgs, Ipv6ServerProbeArgs, Ipv6SxAskArgs,
    Ipv6UdpKeyArgs,
};
use crate::kad_handoff::KadHandoffArgs;
use crate::kad_join_node::KadJoinNodeArgs;
use crate::nat::{NatPeerReachArgs, NatPortMapArgs, NatProbeArgs};
use crate::natt::{
    NattBuddyRendezvousArgs, NattCapsUtpArgs, NattServerPunchArgs, NattTunnelTransferArgs,
};
use crate::peer::{PeerCaptureArgs, PeerReaskCaptureArgs, PeerTransferCaptureArgs};
use crate::register_sources::RegisterSourcesArgs;
use crate::search::SearchArgs;
use crate::serve::ServeStartArgs;

#[derive(Debug, Parser)]
#[command(name = "rmule-tools")]
#[command(about = "Protocol primitive inspection tools for rmule")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Ed2k {
        #[command(subcommand)]
        command: Ed2kCommand,
    },
    /// Kad-only live workflows driven directly over the `rmule_net::kad`
    /// runtime (no eD2k leg; the ed2k→Kad handoff lives under `ed2k`).
    Kad {
        #[command(subcommand)]
        command: KadSubcommand,
    },
    /// Bench-provenance workflows for the NAT topologies (ADR-0092). These
    /// observe the *bench*, never a counterparty, so their output is Stimulus
    /// and is written as a run-dir row rather than promoted as a fixture.
    Nat {
        #[command(subcommand)]
        command: NatSubcommand,
    },
    /// The IPv6-dialect drivers (ADR-0087) the IPv6 harness flows run. Each
    /// one writes rmule's own row — Stimulus — and retains the counterparty
    /// bytes it drew beside it, which is what a flow judges.
    Ipv6 {
        #[command(subcommand)]
        command: Ipv6Subcommand,
    },
    /// The NAT-T transport drivers (ADR-0091) the NAT-T harness flows run.
    /// Each binds the one client-UDP socket a running node binds and puts the
    /// dialect's own `0xB2` frames on a counterparty's; what rmule emits is
    /// Stimulus, and the inbound datagrams retained beside the row are what a
    /// flow judges (ADR-0045).
    Natt {
        #[command(subcommand)]
        command: NattSubcommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum NattSubcommand {
    /// Put the dialect's three opening frames — the `CAPS` probe, the `KEY`
    /// frame a dial arms, and a uTP `ST_SYN` — on a counterparty's client-UDP
    /// socket and record what it did with each (`natt-caps-utp`).
    CapsUtp(NattCapsUtpArgs),
    /// Log a real `Core` in to an eD2k server from behind a **NAT Gateway**
    /// and ask that server to introduce it to another Low-ID rmule peer
    /// (`natt-server-punch-*`). Both ends are rmule, so every value it reports
    /// is an `rmule-only` row scored *exercised*; the server's own `0x60` and
    /// `0x61` are the counterparty bytes the flow judges.
    ServerPunch(Box<NattServerPunchArgs>),
    /// Move a file between two Low-ID rmule nodes over the Tunnel an
    /// eD2k-server-coordinated punch raises (`natt-tunnel-transfer`) — rung 1
    /// of the ADR-0061 tree, end to end. One process is the sharing target,
    /// the other the downloading requester; both are `rmule-only` rows.
    TunnelTransfer(Box<NattTunnelTransferArgs>),
    /// Reach a firewalled rmule through its Kad serving **buddy**
    /// (`natt-buddy-rendezvous-*`) — ADR-0091 rung 1 through its second
    /// Rendezvous coordinator. One process is the open buddy, one the
    /// firewalled target that recruits it over a live FINDBUDDY walk, and one
    /// the firewalled requester that embeds an `OP_RENDEZVOUS` in a `0x94`
    /// addressed to that buddy. All three are rmule, so every row is
    /// `rmule-only`.
    BuddyRendezvous(Box<NattBuddyRendezvousArgs>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum Ipv6Subcommand {
    /// Dial one peer in the family its endpoint names, advertise the dialect's
    /// hello block, and record what the counterparty's `OP_HELLOANSWER`
    /// carried (`ipv6-hello-tags`, `ipv6-direct-dial-lowid`).
    Hello(Ipv6HelloArgs),
    /// Put one obfuscated `OP_REASKFILEPING` on a counterparty's client-UDP
    /// socket and record whether the answer comes back keyed at the same
    /// address width (`ipv6-udp-key`).
    UdpKey(Ipv6UdpKeyArgs),
    /// Ask a real `Core` which ADR-0061 route reaches a Low-ID peer that named
    /// an IPv6, and record the verdict (`ipv6-direct-dial-lowid`).
    Route(Ipv6RouteArgs),
    /// Log in to a live eD2k server with the dialect's advert on and write down
    /// the server's whole IPv6 surface (`ipv6-server-sentinel`).
    ServerProbe(Ipv6ServerProbeArgs),
    /// Queue on a counterparty for its shared file with an IPv6 in the hello,
    /// and hold the link (`ipv6-extsx`, the source the answer should carry).
    HoldSlot(Ipv6HoldSlotArgs),
    /// Ask a counterparty for sources — inside the `0xA4` bundle, or with the
    /// standalone SX1 ask — and retain its answer (`ipv6-extsx`,
    /// `ipv6-extsx-kno`, the capture).
    SxAsk(Ipv6SxAskArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum NatSubcommand {
    /// The **Reflector Probe**'s client half: run RFC 5780's mapping- and
    /// filtering-behaviour discovery against the harness's `natprobe` reflector
    /// from inside a NAT gateway's LAN, and write the observed behaviour beside
    /// the gateway's claim. Mandatory in the same run for any negative NAT
    /// verdict (ADR-0045 as amended).
    Probe(NatProbeArgs),
    /// One side of the **Pinned-Pair Reach** leg: aim the pinned port at
    /// another *translated* client's gateway and record what came back. The
    /// reflector probe's sixth test addresses an untranslated host on the WAN
    /// and therefore cannot see two gateways colliding over the same pinned
    /// port; this is the leg that does.
    PeerReach(NatPeerReachArgs),
    /// Drive a real `Core` with the three live **Mapping Backends**
    /// (ADR-0086) pointed at a pinned gateway, and record what its Port
    /// Mapping subsystem did: one row per desired mapping, the **Address
    /// Learning** verdict each grant earned, and the Kad firewall verdict.
    /// Everything it writes is rmule's own state and is never evidence
    /// (ADR-0045); the gateway's own table beside it is what a port-mapping
    /// flow judges on.
    Portmap(Box<NatPortMapArgs>),
}

#[derive(Debug, Subcommand)]
pub(crate) enum KadSubcommand {
    /// The Kad Stimulus Node runner for the interop scenarios (ADR-0043): join
    /// an aMule hub, optionally publish/search a source or keyword stimulus,
    /// tap every datagram, and log every `KadEvent`.
    JoinNode(KadJoinNodeArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum Ed2kCommand {
    ParseLink {
        link: String,
    },
    CanonicalLink {
        link: String,
    },
    HashFile {
        path: std::path::PathBuf,
    },
    PartHashes {
        path: std::path::PathBuf,
    },
    /// Decode an in-memory sentinel-bearing `OP_FOUNDSOURCES` payload through
    /// this binary's own sentinel-safe reader (ADR-0085) and assert it reads
    /// clean. No arguments, no fixture, no network: the readiness marker
    /// `tools/interop-harness`'s `sentinel-sources-legacy` flow
    /// (ADR-0092) points `--sentinel-reader-probe` at.
    SentinelProbe,
    /// Run the rmule-authored eD2k server that hands a **Sentinel Source**-bearing
    /// list (ADR-0085) to whatever logs in, and record what that counterparty
    /// then did. Everything it emits is Stimulus and is never evidence
    /// (ADR-0045); the journal's `received` / `sink_dial` rows — the
    /// counterparty's own frames and the endpoint it dialled — are. Driven by
    /// `tools/interop-harness`'s `sentinel-sources-legacy` flow (ADR-0092).
    SentinelStimulus(SentinelStimulusArgs),
    /// diagnostic durable download orchestration commands.
    Download {
        #[command(subcommand)]
        command: DownloadCommand,
    },
    Packet {
        #[command(subcommand)]
        command: PacketCommand,
    },
    Login {
        #[command(subcommand)]
        command: LoginCommand,
    },
    ServerPacket {
        #[command(subcommand)]
        command: PacketCommand,
    },
    ClientPacket {
        #[command(subcommand)]
        command: PacketCommand,
    },
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    /// Connected-server eD2k search diagnostic command.
    Search(SearchArgs),
    /// Diagnostic serve orchestration commands.
    Serve {
        #[command(subcommand)]
        command: ServeCommand,
    },
    /// Register many fabricated High-ID source identities for one file hash on a
    /// live eD2k server (ADR-0043 controlled-identity harness leg):
    /// stages the ≥12 sources a downloading aMule must learn before its
    /// `OP_ANSWERSOURCES` packs (the packed-source capture recipes).
    RegisterSources(RegisterSourcesArgs),
    /// Live peer protocol workflows that compose `rmule_net::ed2k` with
    /// `rmule_net::peer` through the application-level
    /// [`PeerHandshakeContext`](rmule_peer::PeerHandshakeContext) bridge.
    Peer {
        #[command(subcommand)]
        command: PeerSubcommand,
    },
    /// The ed2k→Kad handoff runner (ADR-0067): dial a Kad-running peer, run a
    /// Kad node in the same process, and broker the peer's `CT_EMULE_UDPPORTS`
    /// Kad endpoint into the node's bootstrap dial until it reaches contact.
    KadHandoff(KadHandoffArgs),
    /// The HTTP-bootstrap cold-start runner (ADR-0065 + ADR-0067, flow H):
    /// fetch `server.met` + `nodes.dat` over HTTP, connect to the fetched eD2k
    /// server, and Kad-join from the fetched contacts.
    BootstrapFetch(BootstrapFetchArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PeerSubcommand {
    Welcome {
        #[command(subcommand)]
        command: PeerWelcomeCommand,
    },
    Transfer {
        #[command(subcommand)]
        command: PeerTransferCommand,
    },
    /// Offline inspection of `OP_HELLO` / `OP_HELLOANSWER` peer packets.
    Packet {
        #[command(subcommand)]
        command: PacketCommand,
    },
    /// Fire bare `OP_REASKFILEPING 0x90` datagrams at a live counterparty's
    /// client-UDP socket and capture its raw error-branch replies (`0x92`
    /// file-not-found / `0x93` queue-full) as fixture files (ADR-0057,
    /// operator-run captures).
    ReaskCapture(PeerReaskCaptureArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PeerWelcomeCommand {
    /// Connect to a live eD2k server, observe `LoginAccepted`, then dial
    /// the supplied peer endpoint and capture the peer welcome bytes.
    Capture(PeerCaptureArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PeerTransferCommand {
    /// Drive the full hello → probe → hash-set → slot → parts flow
    /// against a peer for one file and capture the wire bytes.
    Capture(PeerTransferCaptureArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum DownloadCommand {
    /// Start a diagnostic durable download.
    Start(DownloadStartArgs),
    /// Resume a diagnostic durable download.
    Resume(DownloadResumeArgs),
    /// Mark a diagnostic durable download paused.
    Pause(DownloadPauseArgs),
    /// List resumable diagnostic durable downloads.
    Status(DownloadStatusArgs),
    /// Open a past run's Durable Store as a restarted node does and serve
    /// what it holds, resuming nothing: each queued or paused download is
    /// offered once its Offer Check has read its parts again (ADR-0113).
    Reopen(DownloadReopenArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServeCommand {
    /// Share one file, log in to an eD2k server, announce it, and serve peers.
    Start(ServeStartArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServerCommand {
    Welcome {
        #[command(subcommand)]
        command: WelcomeCommand,
    },
    /// Probe a live server's advertised compression (`SRV_TCPFLG`, via login)
    /// and UDP-obfuscation (`SRV_UDPFLG`, via status/crypt ping) capabilities.
    Probe(ServerProbeArgs),
    /// Drive the server-UDP status→desc→global-search chain against a live
    /// server and capture the raw counterparty replies (`0x97`, `0xA3` desc,
    /// `0x99` search) as fixture files (operator-run captures).
    UdpCapture(ServerUdpCaptureArgs),
    /// Send bursts of back-to-back searches, tokenisation probes, Related-Files
    /// Searches and a `0x98` burst to a live server, and report what it did
    /// with each.
    SearchWire(SearchWireArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ServerUdpCaptureArgs {
    /// Server endpoint as `host:port` (the eD2k TCP port). The UDP status/desc/
    /// search datagrams go to TCP+4 (the server-UDP offset).
    pub(crate) endpoint: String,
    /// Directory to write the captured raw reply datagrams into.
    #[arg(long)]
    pub(crate) out: std::path::PathBuf,
    /// Global-search query keyword (fires `OP_GLOBSEARCHREQ`; the reply is the
    /// `0x99` packing golden when the server has ≥2 matching files).
    #[arg(long, default_value = "shared")]
    pub(crate) query: String,
    /// Per-step UDP reply timeout, seconds (the eserver runs amd64-emulated).
    #[arg(long, default_value_t = 15)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Subcommand)]
pub(crate) enum WelcomeCommand {
    /// Connect to a live eD2k server, observe its welcome burst, and
    /// write a capture directory.
    Live(LiveCaptureArgs),
    /// Slice an existing capture directory's `s2c.bin` into per-packet
    /// fixture files (`NN_<snake_name>.bin`).
    Slice(SliceCaptureArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum PacketCommand {
    Inspect { path: std::path::PathBuf },
}

#[derive(Debug, Subcommand)]
pub(crate) enum LoginCommand {
    Inspect { path: std::path::PathBuf },
}

/// Identity operands shared by the core-orchestration commands (download,
/// search, serve). Flattened into each command's args and projected onto the
/// Core Settings the command's core presents by [`settings`](Self::settings);
/// the protocol version is core's own.
#[derive(Debug, Args)]
pub(crate) struct DownloadIdentityArgs {
    /// Local nickname tag.
    #[arg(long, default_value = "rmule-tools")]
    pub(crate) nickname: String,
    /// Local user hash as upper-case hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    pub(crate) user_hash: String,
    /// Local TCP port advertised to the server and peer.
    #[arg(long, default_value_t = 4662)]
    pub(crate) tcp_port: u16,
    /// Where the node's Secure User Identification key lives, one store per
    /// `--user-hash` (created on first use, reused after): a fixed hash then
    /// proves with the same key every run, as a counterparty's `clients.met`
    /// expects. Without it the key is the node store's own —
    /// persistent under `download --data-dir`, fresh per run otherwise.
    #[arg(long)]
    pub(crate) identity_dir: Option<std::path::PathBuf>,
}

impl DownloadIdentityArgs {
    /// The User Hash these operands name — the node's, fixed at build.
    pub(crate) fn user_hash(&self) -> Result<UserHash> {
        Ok(UserHash::from_bytes(crate::operand::parse_user_hash(
            &self.user_hash,
        )?))
    }

    /// `settings` presenting the nickname and TCP port these operands name:
    /// every login and hello the tool's core sends presents them.
    pub(crate) fn settings(&self, settings: rmule_core::CoreSettings) -> rmule_core::CoreSettings {
        rmule_core::CoreSettings {
            nickname: self.nickname.clone(),
            tcp_port: self.tcp_port,
            ..settings
        }
    }

    /// The default production builder over `store`, as the node these
    /// operands name, under `settings`, proving with the key
    /// `--identity-dir` keeps for it.
    pub(crate) fn core_builder(
        &self,
        config: rmule_core::CoreConfig,
        settings: rmule_core::CoreSettings,
        store: std::sync::Arc<rmule_core::DurableStore>,
    ) -> Result<
        rmule_core::CoreBuilder<
            rmule_core::RuntimeSourceLookupService,
            rmule_core::RuntimePeerTransferService,
            rmule_core::RuntimeServeRuntimeService,
            rmule_core::RuntimeKadFactory,
        >,
    > {
        crate::node::core_builder(
            config,
            settings,
            store,
            self.user_hash()?,
            self.identity_dir.as_deref(),
        )
    }
}

#[derive(Debug, clap::ValueEnum, Clone, Copy)]
pub(crate) enum CaptureModeArg {
    ProtocolOnly,
    Full,
}

impl From<CaptureModeArg> for rmule_net::peer::CaptureMode {
    fn from(value: CaptureModeArg) -> Self {
        match value {
            CaptureModeArg::ProtocolOnly => Self::ProtocolOnly,
            CaptureModeArg::Full => Self::Full,
        }
    }
}

/// The seven classes aMule's search-type dropdown offers
/// (`SearchDlg.cpp:479-487`). `archive` and `cd-image` reach the wire as
/// `"Pro"` — the network has no term of their own for them.
#[derive(Debug, clap::ValueEnum, Clone, Copy)]
pub(crate) enum SearchTypeArg {
    Audio,
    Video,
    Image,
    Document,
    Program,
    Archive,
    CdImage,
}

impl From<SearchTypeArg> for Ed2kFileClass {
    fn from(value: SearchTypeArg) -> Self {
        match value {
            SearchTypeArg::Audio => Self::Audio,
            SearchTypeArg::Video => Self::Video,
            SearchTypeArg::Image => Self::Image,
            SearchTypeArg::Document => Self::Document,
            SearchTypeArg::Program => Self::Program,
            SearchTypeArg::Archive => Self::Archive,
            SearchTypeArg::CdImage => Self::CdImage,
        }
    }
}

/// The obfuscation policy for an outbound peer dial (ADR-0042).
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum ObfuscationArg {
    Supported,
    Requested,
    Required,
}

impl From<ObfuscationArg> for rmule_net::peer::ObfuscationPolicy {
    fn from(arg: ObfuscationArg) -> Self {
        match arg {
            ObfuscationArg::Supported => Self::Supported,
            ObfuscationArg::Requested => Self::Requested,
            ObfuscationArg::Required => Self::Required,
        }
    }
}
