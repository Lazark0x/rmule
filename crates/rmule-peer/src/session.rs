//! The sans-I/O state machine for one eD2k peer conversation.
//!
//! `PeerSession` owns no socket, no clock and no runtime: a driver feeds it
//! bytes and commands and drains writes and events from
//! [`poll_output`](PeerSession::poll_output), so identical inputs produce
//! identical outputs. The runtime half lives in `rmule-net` (ADR-0081,
//! ADR-0021).
//!
//! A connection is bidirectional on one socket (ADR-0031): the session both
//! pulls parts (its **Requester Capability**) and serves them (its **Server
//! Capability**), interleaving probe, hash-set and slot legs for unrelated
//! files around the single in-flight slot each direction allows (ADR-0025).
//!
//! ## Layout
//!
//! This file owns the struct, the constructors and the driver-facing
//! lifecycle — `start`, the signal entry points, `poll_output` and the close
//! discipline. Each protocol leg implements its own half in a private
//! submodule: `wire` (the byte boundary and opcode routing), `identity` (the
//! peer's identity, read at the hello and kept current), `download` and
//! `serve` (the two capabilities), `source_exchange`, `aich`, `multipacket`,
//! `mule_info`, `human_layer` and `secure_ident`; each leg also owns the bookkeeping it
//! carries between packets (the per-file flow in `download`, the pending
//! bundle in `multipacket`, the SUI exchange in `secure_ident`). The
//! vocabulary a driver speaks lives in `command`, `event` and `error`,
//! re-exported here.

mod aich;
mod command;
mod download;
mod error;
mod event;
mod human_layer;
mod identity;
mod mule_info;
mod multipacket;
mod secure_ident;
mod serve;
mod source_exchange;
mod wire;

pub use self::command::{
    ConnectionCommand, PeerCommand, PeerOutput, RequesterCommand, ServerCommand, SideCommand,
};
pub use self::error::{PeerCloseReason, PeerError, SecureIdentFailure};
pub use self::event::{
    ConnectionEvent, FileProbeStatus, IdentityChange, NoticeEvent, PeerEvent, RequesterEvent,
    ServerEvent, SideEvent, SlotReleaseReason,
};
pub use self::source_exchange::SourceExchangeSupport;

use std::collections::HashMap;

use rmule_primitives::{FileHash, Packet, PeerEndpoint, SessionCore};

use crate::capability::{MiscOptions1, MiscOptions2, UdpPortsAdvert};
use crate::handshake::{PeerHandshakeContext, SecureIdentConfig};
use crate::hello::{Hello, PeerHelloBody};
use crate::software::SoftwareEvidence;
use crate::source_exchange::ServedSourcesVersion;

use self::download::{CompressedBlocksInFlight, FileFlow};
use self::multipacket::PendingMultipacketAnswer;
use self::secure_ident::SuiState;

/// The protocol phase of the conversation — the one piece of bookkeeping
/// every leg reads.
#[derive(Debug)]
enum State {
    BeforeStart,
    /// Inbound: constructed via `new_inbound`, waiting for the dialing
    /// peer's `OP_HELLO` before we reply `OP_HELLOANSWER`.
    AwaitingHello,
    AwaitingHelloAnswer,
    Identified,
    Closed,
}

/// One peer conversation, role-neutral.
///
/// `new_outbound` dials and sends the hello through `start()`; `new_inbound`
/// waits for the peer's hello and answers it. The session is reusable: probe
/// and hash-set flows for unrelated files interleave freely around the one
/// `active_slot` it chases and the one `served_slot` it grants (ADR-0025,
/// ADR-0031).
pub struct PeerSession {
    peer: PeerEndpoint,
    ctx: PeerHandshakeContext,
    state: State,
    core: SessionCore<PeerEvent, PeerCloseReason>,
    per_file: HashMap<FileHash, FileFlow>,
    /// How many `OP_COMPRESSEDPART` blocks are mid-accumulation across all of
    /// `per_file`. The count's field is private to the `download` leg, so only
    /// `on_compressed_part` — the one place that inserts into or removes from
    /// `FileFlow::compressed_blocks` — can move it.
    compressed_blocks_in_flight: CompressedBlocksInFlight,
    active_slot: Option<FileHash>,
    /// The peer sent `OP_ACCEPTUPLOADREQ` with no slot asked on this link —
    /// an uploader promoting us by dial-back, or on a link it held — and
    /// nothing has answered it yet: neither an ask of ours nor a decline.
    slot_offered: bool,
    /// `Some` once the Server Capability has granted this connection an
    /// upload slot for a file (set by `GrantSlot`, cleared when the peer
    /// cancels it). The serve-side mirror of `active_slot`; the
    /// cross-connection queue/rank/budget lives in core (ADR-0031).
    served_slot: Option<FileHash>,
    /// Bundled-request answers awaiting composition into one `OP_MULTIPACKETANSWER`
    /// (ADR-0054), keyed by the file a peer's `OP_MULTIPACKET`/
    /// `OP_MULTIPACKET_EXT` named. Populated when the bundle is fanned in,
    /// drained by [`Self::try_flush_multipacket_answer`] once every sub-item the
    /// bundle actually asked for has answered.
    served_multipacket: HashMap<FileHash, PendingMultipacketAnswer>,
    /// The file a still-unanswered `OP_AICHFILEHASHREQ` (standalone or bundled)
    /// named — `OP_AICHFILEHASHANS`/`AnswerAichFileHash` carries no file hash of
    /// its own (the file is "the connection's requested file"), so this is the
    /// only way to route the eventual answer back to a pending bundle. Sessions
    /// don't yet track more than one outstanding AICH-root request at a time.
    served_aich_request: Option<FileHash>,
    /// The wire form each file's latest source ask is answered in (ADR-0055),
    /// picked from the asker's advert when the ask arrived and kept here so
    /// core answers with sources alone. Overwritten by the next ask for the
    /// same file and taken by the answer, so it holds only asks still owed
    /// one: a second answer to one ask is refused like an unasked one.
    served_sources: HashMap<FileHash, ServedSourcesVersion>,
    /// The remote peer's advertised `MiscOptions1`, read from its hello
    /// (`None` for a non-eMule / pre-extended peer). Gates whether we may
    /// send it compressed parts, and whether we bundle our own file requests
    /// into an `OP_MULTIPACKET` (bit 1, ADR-0054 emit).
    peer_misc_options: Option<MiscOptions1>,
    /// The remote peer's advertised `MiscOptions2` (`None` when absent). Read
    /// alongside `peer_misc_options` at identify time; the ExtMultiPacket bit
    /// (bit 5) alone decides whether a bundled request frames as the `0xA4`
    /// (with `size8`) or base `0x92` form (ADR-0054 emit).
    peer_misc_options2: Option<MiscOptions2>,
    /// The peer's identity as its hello named it, every later revision
    /// applied (`identity`): the one copy every `Identified` and
    /// `IdentityRevised` carries whole. Its User Hash names whom Secure User
    /// Identification proved (ADR-0041); its **Static Capability Claim**
    /// (`CT_MOD_MISCOPTIONS`, ADR-0087) gates what rmule may *write* this
    /// peer: the ExtSX record form and its two optional identity tags.
    peer_identity: Option<crate::identity::PeerIdentity>,
    /// What the peer has said about its software on this connection: its
    /// hello and any legacy `OP_EMULEINFO`, folded in arrival order.
    peer_software: SoftwareEvidence,
    /// The client-UDP reask contact a legacy `OP_EMULEINFO` named, and whether
    /// the identified hello already named one of its own.
    peer_legacy_reask: Option<(u16, u8)>,
    peer_hello_named_reask: bool,
    /// Secure User Identification material (ADR-0041), set via
    /// [`with_secure_ident`](Self::with_secure_ident). `None` runs the
    /// connection without SUI; `Some` advertises the capability and drives the
    /// challenge/response exchange.
    secure_ident: Option<SecureIdentConfig>,
    /// Secure User Identification exchange state (ADR-0041). Idle unless both we
    /// (`secure_ident`) and the peer advertised the capability.
    sui: SuiState,
    /// The protocol-obfuscation crypt stance to advertise in the hello
    /// (`MiscOptions2`, ADR-0042), set via
    /// [`with_crypt_advertisement`](Self::with_crypt_advertisement) from the
    /// connection's obfuscation policy. `None` advertises no crypt capability.
    crypt_advert: Option<MiscOptions2>,
    /// rmule's real bound reask/Kad ports to advertise in the hello
    /// (`CT_EMULE_UDPPORTS`, ADR-0057/0047), set via
    /// [`with_udp_ports_advertisement`](Self::with_udp_ports_advertisement) from
    /// the live client-UDP socket. `None` advertises no reask endpoint — Honest
    /// Capability Advertisement, since a node with no bound client-UDP socket
    /// cannot answer a peer-UDP reask.
    udp_ports_advert: Option<UdpPortsAdvert>,
    /// Our Known IPv6 for the hello's `CT_MOD_IP_V6` tag (ADR-0087), set via
    /// [`with_ipv6_advertisement`](Self::with_ipv6_advertisement) from the
    /// Advertised Endpoints chooser. `None` omits the tag — the claim bit
    /// still rides, since it names a capability rather than an address.
    ipv6_advert: Option<std::net::Ipv6Addr>,
    /// The IPv6 the peer has been told is ours: what our hello named, then
    /// each `OP_CHANGE_CLIENT_IP` since. An announcement goes out only when
    /// [`Self::ipv6_advert`] moves away from it (ADR-0087).
    ipv6_told: Option<std::net::Ipv6Addr>,
    /// Our serving buddy for the hello's `CT_EMULE_BUDDYIP` / `BUDDYUDP` /
    /// `SERVINGBUDDYIPV6` tags (ADR-0061/0087), set via
    /// [`with_serving_buddy_advertisement`](Self::with_serving_buddy_advertisement).
    /// `None` omits all three.
    serving_buddy_advert: Option<crate::handshake::ServingBuddyAdvert>,
    /// Light the hello's `MiscOptions2` direct-UDP-callback bit,
    /// set via
    /// [`with_direct_udp_callback_advertisement`](Self::with_direct_udp_callback_advertisement).
    direct_udp_callback_advert: bool,
    /// Diagnostic/capture-only override for the hello's advertised
    /// source-exchange nibble (ADR-0055 evidence), set via
    /// [`with_source_exchange_capture_override`](Self::with_source_exchange_capture_override).
    /// `None` advertises the registry's Honest Capability Advertisement
    /// (nibble 1) as normal.
    source_exchange_capture_override: Option<u8>,
    /// Diagnostic/capture-only override for the hello's advertised
    /// extended-requests version, set via
    /// [`with_extended_requests_capture_override`](Self::with_extended_requests_capture_override).
    /// `None` advertises the registry's `1`.
    extended_requests_capture_override: Option<u8>,
}

impl PeerSession {
    fn with_state(peer: PeerEndpoint, ctx: PeerHandshakeContext, state: State) -> Self {
        Self {
            peer,
            ctx,
            state,
            core: SessionCore::new(),
            per_file: HashMap::new(),
            compressed_blocks_in_flight: CompressedBlocksInFlight::default(),
            active_slot: None,
            slot_offered: false,
            served_slot: None,
            served_multipacket: HashMap::new(),
            served_aich_request: None,
            served_sources: HashMap::new(),
            peer_misc_options: None,
            peer_misc_options2: None,
            peer_identity: None,
            peer_software: SoftwareEvidence::default(),
            peer_legacy_reask: None,
            peer_hello_named_reask: false,
            secure_ident: None,
            sui: SuiState::default(),
            crypt_advert: None,
            udp_ports_advert: None,
            ipv6_advert: None,
            ipv6_told: None,
            serving_buddy_advert: None,
            direct_udp_callback_advert: false,
            source_exchange_capture_override: None,
            extended_requests_capture_override: None,
        }
    }

    /// Dialing side: `start()` sends our `OP_HELLO` and we await
    /// `OP_HELLOANSWER`.
    #[must_use]
    pub fn new_outbound(peer: PeerEndpoint, ctx: PeerHandshakeContext) -> Self {
        Self::with_state(peer, ctx, State::BeforeStart)
    }

    /// Accepting side (ADR-0031): we await the dialing peer's `OP_HELLO`,
    /// then reply `OP_HELLOANSWER`. There is no `start()` to call — the
    /// conversation opens when the peer's hello arrives.
    #[must_use]
    pub fn new_inbound(peer: PeerEndpoint, ctx: PeerHandshakeContext) -> Self {
        Self::with_state(peer, ctx, State::AwaitingHello)
    }

    /// Enable Secure User Identification for this connection (ADR-0041): the
    /// hello advertises the capability and, against a SUI-capable peer, the
    /// session runs the challenge/response exchange and emits
    /// `IdentityVerified`. Chainable on `new_outbound` / `new_inbound`; the
    /// application supplies the keypair and a fresh per-connection challenge.
    #[must_use]
    pub fn with_secure_ident(mut self, config: SecureIdentConfig) -> Self {
        self.secure_ident = Some(config);
        self
    }

    /// Advertise a protocol-obfuscation crypt stance in the hello (`MiscOptions2`,
    /// ADR-0042). Chainable on `new_outbound` / `new_inbound`; the runtime adapter
    /// derives the stance from the connection's obfuscation policy so a real aMule
    /// can choose to obfuscate-dial rmule. The word still carries the ADR-0047
    /// registry's ExtMultiPacket bit (ADR-0054) even when `advert` is an
    /// all-dark crypt stance — only skipping this call omits the tag entirely.
    #[must_use]
    pub fn with_crypt_advertisement(mut self, advert: MiscOptions2) -> Self {
        self.crypt_advert = Some(advert);
        self
    }

    /// Advertise rmule's real bound reask/Kad ports in the hello
    /// (`CT_EMULE_UDPPORTS` + the `MiscOptions1` UDP-version nibble, ADR-0057).
    /// Chainable on `new_outbound` / `new_inbound`; the runtime adapter passes
    /// the shared client-UDP socket's live ports only while the reask uploader
    /// serves, so the advert is Honest Capability Advertisement (a peer reasks a
    /// port rmule actually answers). Omitting the call omits the tag.
    #[must_use]
    pub fn with_udp_ports_advertisement(mut self, advert: UdpPortsAdvert) -> Self {
        self.udp_ports_advert = Some(advert);
        self
    }

    /// Diagnostic/capture-only: advertise `nibble` as the hello's
    /// source-exchange version instead of the registry's honest default (1).
    /// Chainable on `new_outbound` / `new_inbound`. ADR-0055's "consume
    /// `0x82` v3" capture recipe is this toggle's reason to exist: aMule's
    /// SX1 serve path answers a plain `OP_REQUESTSOURCES` at the
    /// *requester's* (rmule's own) advertised nibble, so advertising 3
    /// (aMule's own default) for one diagnostic connection is what makes
    /// aMule's reply land at v3 geometry instead of the honest v1 rmule
    /// otherwise ships. Never call this outside a staged capture — it is not
    /// Honest Capability Advertisement.
    #[must_use]
    pub fn with_source_exchange_capture_override(mut self, nibble: u8) -> Self {
        self.source_exchange_capture_override = Some(nibble);
        self
    }

    /// Diagnostic/capture-only: advertise `level` as the hello's
    /// extended-requests version instead of the registry's honest `1`, and
    /// speak the level it negotiates. A bench stimulus that holds nothing
    /// claims `0` so an aMule-family answerer lists it as a source of unknown
    /// status — what rmule itself once was — instead of dropping
    /// it as holding no part the asker lacks. Never call this outside a staged
    /// capture — it is not Honest Capability Advertisement.
    #[must_use]
    pub fn with_extended_requests_capture_override(mut self, level: u8) -> Self {
        self.extended_requests_capture_override = Some(level);
        self
    }

    /// The hello tags of the hello or hello answer about to be written —
    /// the moment the peer is told our IPv6.
    fn hello_body_to_write(&mut self) -> PeerHelloBody {
        self.ipv6_told = self.ipv6_advert;
        self.advertised_hello_body()
    }

    /// The hello tags this session sends, capture overrides applied.
    fn advertised_hello_body(&self) -> PeerHelloBody {
        let mut body = PeerHelloBody::from_handshake_context(&self.ctx, &self.hello_advert());
        if let Some(nibble) = self.source_exchange_capture_override {
            MiscOptions1::override_source_exchange_version(&mut body.tags, nibble);
        }
        if let Some(level) = self.extended_requests_capture_override {
            MiscOptions1::override_extended_requests_version(&mut body.tags, level);
        }
        body
    }

    /// Advertise our Known IPv6 in the hello's `CT_MOD_IP_V6` tag (ADR-0087).
    /// Chainable on `new_outbound` / `new_inbound`; the runtime adapter passes
    /// what the Advertised Endpoints chooser settled (ADR-0084: Known *and*
    /// not probed-unreachable), so the tag is only ever written for an address
    /// a peer can actually reach. Omitting the call omits the tag — the
    /// `CT_MOD_MISCOPTIONS` claim bit still rides, because it says what rmule
    /// can speak rather than where it can be found.
    #[must_use]
    pub const fn with_ipv6_advertisement(mut self, address: std::net::Ipv6Addr) -> Self {
        self.ipv6_advert = Some(address);
        self
    }

    /// Name our serving buddy in the hello (ADR-0061): `CT_EMULE_BUDDYIP` and
    /// `CT_EMULE_BUDDYUDP`, plus `CT_EMULE_SERVINGBUDDYIPV6` when the advert
    /// knows the buddy's IPv6 (ADR-0087) — the hello half of the buddy contact
    /// whose Kad half is a source publish's buddy row. Chainable on
    /// `new_outbound` / `new_inbound`; core passes what its firewalled slot
    /// names, so the call is made only while we are
    /// firewalled behind a held buddy link. Omitting the call omits all three.
    #[must_use]
    pub const fn with_serving_buddy_advertisement(
        mut self,
        buddy: crate::handshake::ServingBuddyAdvert,
    ) -> Self {
        self.serving_buddy_advert = Some(buddy);
        self
    }

    /// Light `MiscOptions2` bit 12 (`SupportsDirectUDPCallback`) in the hello:
    /// we accept an `OP_DIRECTCALLBACKREQ` (`0x95`) and dial back. Core calls
    /// it only while its Self Reach says so; omitting the call
    /// leaves the bit dark.
    #[must_use]
    pub const fn with_direct_udp_callback_advertisement(mut self) -> Self {
        self.direct_udp_callback_advert = true;
        self
    }

    /// What this session advertises in a hello right now.
    fn hello_advert(&self) -> crate::handshake::HelloAdvert {
        crate::handshake::HelloAdvert {
            secure_ident: self.secure_ident.is_some(),
            crypt: self.crypt_advert,
            udp_ports: self.udp_ports_advert,
            ipv6: self.ipv6_advert,
            serving_buddy: self.serving_buddy_advert,
            direct_udp_callback: self.direct_udp_callback_advert,
        }
    }

    #[must_use]
    /// The peer this session talks to, fixed when it was created.
    pub const fn peer_endpoint(&self) -> PeerEndpoint {
        self.peer
    }

    /// Open the conversation: emit `HelloSent` and an `OP_HELLO`
    /// write. Idempotent — no-op outside `BeforeStart`.
    pub fn start(&mut self) {
        if !matches!(self.state, State::BeforeStart) {
            return;
        }
        let bytes = Hello::new(self.hello_body_to_write())
            .encode_packet()
            .encode();
        self.core
            .push_event(PeerEvent::Connection(ConnectionEvent::HelloSent));
        self.core.push_write(bytes.into());
        self.state = State::AwaitingHelloAnswer;
    }

    /// Driver-facing signal that the connect-to-hello-answer deadline
    /// elapsed. Mirrors the sans-I/O pattern from ADR-0021: the session
    /// owns no clock; the runtime layer calls this when its
    /// `tokio::time::timeout` fires.
    pub fn hello_deadline_elapsed(&mut self) {
        if matches!(
            self.state,
            State::AwaitingHelloAnswer | State::AwaitingHello
        ) {
            self.close(PeerCloseReason::HelloTimeout);
        }
    }

    /// Driver-facing signal that the active slot context has been
    /// silent past the slot-stale deadline. Per ADR-0025 the session
    /// owns no clock; the runtime calls this when its
    /// `slot_stale_timeout` fires.
    pub fn signal_slot_stale(&mut self) {
        let Some(active) = self.active_slot else {
            return;
        };
        self.release_slot(active, SlotReleaseReason::Stale);
    }

    /// Driver-facing signal that the idle-close deadline elapsed (no
    /// active slot, no probe traffic). Per ADR-0025 the runtime owns
    /// the timer; the session translates the signal into a graceful
    /// local close.
    pub fn signal_idle_close(&mut self) {
        if self.active_slot.is_some() {
            return;
        }
        self.close(PeerCloseReason::Local);
    }

    /// Take the next effect. The driver drains to `None` after every other
    /// call, which is what keeps this state machine free of a clock.
    pub fn poll_output(&mut self) -> Option<PeerOutput> {
        self.core.poll_output()
    }

    /// Serve answers must not put bytes on the wire before the hello
    /// exchange. Returns `true` when identified; otherwise emits a
    /// `CommandRejected` (matching the requester command guards) and
    /// returns `false`.
    fn require_identified(&mut self) -> bool {
        if matches!(self.state, State::Identified) {
            return true;
        }
        // Commands are always locally issued, so a too-early one is core's
        // ordering bug — rejected under the core-attributed variant, never
        // as a peer protocol violation.
        self.reject(PeerError::CommandBeforeIdentified);
        false
    }

    fn write_packet(&mut self, packet: Packet) {
        self.core.push_write(packet.encode().into());
    }

    /// Queue a `CommandRejected` event carrying `reason` — the single home
    /// for the command-guard rejections the handlers raise.
    fn reject(&mut self, reason: PeerError) {
        self.core
            .push_event(PeerEvent::Notice(NoticeEvent::CommandRejected { reason }));
    }

    fn close_protocol_violation(&mut self) {
        self.close(PeerCloseReason::ProtocolViolation);
    }

    /// Close with `reason`: [`SessionCore::close`] owns the paired
    /// `Disconnected`-then-`Close` discipline; this wrapper locks the
    /// protocol state machine into `Closed`. `PeerCloseReason` is `Copy`,
    /// so the reason rides on both outputs cheaply.
    fn close(&mut self, reason: PeerCloseReason) {
        self.state = State::Closed;
        self.core.close(
            PeerEvent::Connection(ConnectionEvent::Disconnected { reason }),
            reason,
        );
    }
}
