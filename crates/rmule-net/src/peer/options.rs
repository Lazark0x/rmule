//! The knobs a caller sets before dialing or accepting a peer: the four
//! timeouts the runtime distinguishes, the capture destination and how much of
//! the stream it keeps, and the Secure User Identification and obfuscation
//! material the session negotiates with.

use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmule_peer::{SecureIdentConfig, ServingBuddyAdvert, UdpPortsAdvert};
use rmule_primitives::PeerCrypt;

use crate::peer::obfuscation::ObfuscationConfig;

/// Tunables for [`Connection::connect`](crate::peer::Connection::connect).
///
/// Split into the failure modes consumers actually distinguish: TCP
/// connect (SYN), peer-hello response (peer accepted TCP but silent at
/// the protocol layer), slot stale (peer accepted slot then went
/// silent), and idle close (no work pending, graceful disconnect).
/// Capture mirrors the `ed2k` module's ADR-0022 layout; filenames are
/// peer-direction (`inbound.bin` / `outbound.bin`) because the peer
/// protocol has no server side.
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    /// Cap on the TCP handshake alone — not on anything the peer says after.
    pub connect_timeout: Duration,
    /// Cap on the peer identifying itself once TCP is up; armed as the
    /// driver's one startup deadline and disarmed by the hello.
    pub hello_timeout: Duration,
    /// Cap on silence from a peer that already granted an upload slot.
    pub slot_stale_timeout: Duration,
    /// How long an established link with nothing pending is held open before
    /// a graceful disconnect.
    pub idle_close_timeout: Duration,
    /// Directory to stage this connection's capture in; `None` runs without
    /// a capture task at all.
    pub capture_dir: Option<PathBuf>,
    /// How much of the stream that capture keeps.
    pub capture_mode: CaptureMode,
    /// Secure User Identification material for this connection (ADR-0041), or
    /// `None` to dial/accept without SUI. When `Some`, the session advertises the
    /// capability and proves identity to a SUI-capable peer.
    pub secure_ident: Option<SecureIdentConfig>,
    /// Protocol obfuscation policy for this connection (ADR-0042), or `None`
    /// to dial/accept plaintext only. When `Some`, the inbound listener does
    /// byte-0 discrimination and accepts an obfuscated handshake; the hello
    /// advertises crypt support.
    pub obfuscation: Option<ObfuscationConfig>,
    /// What the dial knows of the **peer's** crypt side (ADR-0049): the stance
    /// its source record stated and the User Hash that keys an obfuscated dial
    /// toward it (ADR-0042). [`Connection::connect`](crate::peer::Connection::connect)
    /// meets it with [`Self::obfuscation`] by aMule's outbound rule
    /// ([`PeerCrypt::outbound`]): obfuscate when both support and either
    /// requests, as a must when either requires, and refuse the dial before
    /// any socket when a requiring side meets one that cannot. The default —
    /// [`PeerCrypt::unknown`], a server-lookup source with no crypt byte —
    /// reads as a peer that stated no crypt. Unused on the accept path (the
    /// responder keys from its own User Hash).
    pub peer_crypt: PeerCrypt,
    /// Diagnostic/capture-only: advertise this nibble as the outbound hello's
    /// source-exchange version instead of rmule's honest default (1), via
    /// [`PeerSession::with_source_exchange_capture_override`](rmule_peer::PeerSession::with_source_exchange_capture_override).
    /// `None` leaves the honest advert. Needed for the ADR-0053/0055 packed-
    /// `0x82` capture: aMule answers a plain `OP_REQUESTSOURCES` at the
    /// *requester's* advertised nibble and cross-checks the geometry against its
    /// *own* advertised nibble (3), so rmule must advertise 3 for aMule's packed
    /// reply to both land at v3 geometry and reconcile on decode. Never set
    /// outside a staged capture — it is not Honest Capability Advertisement.
    pub source_exchange_capture_override: Option<u8>,
    /// Diagnostic/capture-only: advertise this extended-requests version
    /// instead of rmule's honest `1`, via
    /// [`PeerSession::with_extended_requests_capture_override`](rmule_peer::PeerSession::with_extended_requests_capture_override).
    /// `None` leaves the honest advert. A bench's **queued requester** holds
    /// nothing, so an aMule-family answerer — which lists a source only when
    /// it holds a part the asker lacks, or when its status is unknown —
    /// lists it only if it claims `0`. Never set outside a staged capture.
    pub extended_requests_capture_override: Option<u8>,
    /// rmule's real bound reask/Kad ports to advertise in this connection's hello
    /// (`CT_EMULE_UDPPORTS`, ADR-0057/0047), or `None` to advertise no reask
    /// endpoint. The core actor sets it to the live shared client-UDP socket's
    /// ports only while the reask uploader serves — Honest Capability
    /// Advertisement, so a peer never learns a reask port rmule cannot answer.
    pub udp_ports: Option<UdpPortsAdvert>,
    /// Our Known IPv6 for this connection's hello `CT_MOD_IP_V6` tag
    /// (ADR-0087), or `None` to omit it. The core actor sets it from the
    /// Advertised Endpoints chooser, so the tag names an address a peer can
    /// actually reach; the `CT_MOD_MISCOPTIONS` claim bit rides either way,
    /// because it says what rmule can speak rather than where it is.
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// Our serving buddy for this connection's hello — `CT_EMULE_BUDDYIP`,
    /// `CT_EMULE_BUDDYUDP` (ADR-0061) and, when the buddy has one,
    /// `CT_EMULE_SERVINGBUDDYIPV6` (ADR-0087) — or `None` to omit all three.
    /// Core sets it from its firewalled slot, so it rides only while we are
    /// firewalled behind a held buddy link.
    pub serving_buddy: Option<ServingBuddyAdvert>,
    /// Light the hello's `MiscOptions2` direct-UDP-callback bit (bit 12):
    /// we accept an `OP_DIRECTCALLBACKREQ` (`0x95`). Core sets it from its
    /// Self Reach per connection.
    pub direct_udp_callback: bool,
    /// How this link follows our Advertised IPv6 after its hello, or `None`
    /// for a link that never announces a move. Each wake hands the session
    /// the address read then, as `AnnounceIpv6Change`; the session decides
    /// whether the peer is owed an `OP_CHANGE_CLIENT_IP` (ADR-0087).
    pub ipv6_follow: Option<Ipv6Follow>,
}

/// What a live link follows our Advertised IPv6 by: a wake on every move of
/// what [`Self::read`] can answer, and the read itself. The link holds only a
/// receiver, so following ends with the link and keeps nothing alive.
#[derive(Clone)]
pub struct Ipv6Follow {
    /// Changes whenever the address [`Self::read`] answers may have moved.
    pub changed: tokio::sync::watch::Receiver<u64>,
    /// The address to name now, or `None` while there is none to name.
    pub read: Arc<dyn Fn() -> Option<Ipv6Addr> + Send + Sync>,
}

impl std::fmt::Debug for Ipv6Follow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv6Follow").finish_non_exhaustive()
    }
}

/// Per ADR-0024 `ProtocolOnly` is the default to keep captures small
/// for real downloads. `Full` keeps `OP_SENDINGPART` payload bytes
/// verbatim and is opt-in for one-off byte-faithful captures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CaptureMode {
    /// Part payload bytes are elided from the stream files.
    #[default]
    ProtocolOnly,
    /// Part payload bytes are kept byte-for-byte.
    Full,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            hello_timeout: Duration::from_secs(15),
            slot_stale_timeout: Duration::from_secs(60),
            idle_close_timeout: Duration::from_secs(300),
            capture_dir: None,
            capture_mode: CaptureMode::default(),
            secure_ident: None,
            obfuscation: None,
            peer_crypt: PeerCrypt::unknown(),
            source_exchange_capture_override: None,
            extended_requests_capture_override: None,
            udp_ports: None,
            ipv6: None,
            serving_buddy: None,
            direct_udp_callback: false,
            ipv6_follow: None,
        }
    }
}
