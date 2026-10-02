//! Kad2 opcode constants for the source-lookup, node-maintenance, and
//! source-publish slices.
//!
//! Only the Kad2 opcodes rmule's current slices need are typed here, matching
//! the wire bytes cited in `docs/reference/notes/kad-packet-framing.md`
//! (bootstrap, hello, ping/pong, lookup-walk, source search, source publish,
//! keyword search/publish, notes search/publish). Kad1 is out of scope, as are
//! firewall/buddy/callback (their own `reachability` codec owns them).
//!
//! The keyword requests [`KADEMLIA2_SEARCH_KEY_REQ`] (`0x33`) and
//! [`KADEMLIA2_PUBLISH_KEY_REQ`] (`0x43`) are constants but **not**
//! [`Kad2Opcode`] variants: like the firewall checks, they route to their own
//! codec module (`keyword_store`) before the node-maintenance `Kad2Message`
//! decode, so the dispatch enum stays the node-maintenance surface. Their
//! results ride `KADEMLIA2_SEARCH_RES` (`0x3B`) — the same opcode source search
//! answers, disambiguated by the owning walk (ADR-0062).
//!
//! The notes requests [`KADEMLIA2_SEARCH_NOTES_REQ`] (`0x35`) and
//! [`KADEMLIA2_PUBLISH_NOTES_REQ`] (`0x45`) are constants but likewise **not**
//! [`Kad2Opcode`] variants: they route to their own codec module (`notes`) the
//! same way, before the node-maintenance decode. Unlike keyword, notes never
//! replies with anything — **Empty-Storer Parity** (ADR-0063): rmule builds no
//! notes state, so `0x35` always answers empty and `0x45` is always refused,
//! both wire-silent.
//!
//! [`KADEMLIA2_PUBLISH_RES_ACK`] (`0x4C`) is defined but likewise stays out of
//! the [`Kad2Opcode`] dispatch enum: aMule 2.3.3's plain path never emits it and
//! an inbound `0x4C` hits the unknown-opcode throw, so rmule keeps it an
//! emit-only constant for the dormant publish-res-ack hook (ADR-0062, wired
//! in `node.rs`).

/// `KADEMLIA2_BOOTSTRAP_REQ` — bootstrap request.
pub const KADEMLIA2_BOOTSTRAP_REQ: u8 = 0x01;
/// `KADEMLIA2_BOOTSTRAP_RES` — bootstrap result.
pub const KADEMLIA2_BOOTSTRAP_RES: u8 = 0x09;
/// `KADEMLIA2_HELLO_REQ` — node contact validation request.
pub const KADEMLIA2_HELLO_REQ: u8 = 0x11;
/// `KADEMLIA2_HELLO_RES` — node contact validation response.
pub const KADEMLIA2_HELLO_RES: u8 = 0x19;
/// `KADEMLIA2_HELLO_RES_ACK` — the third leg of the IP-verification handshake:
/// the ACK a contact returns after a `HELLO_RES` requested one (misc-options
/// bit 2), proving its IP is not spoofed (ADR-0064).
pub const KADEMLIA2_HELLO_RES_ACK: u8 = 0x22;
/// `KADEMLIA2_REQ` — lookup next-hop request.
pub const KADEMLIA2_REQ: u8 = 0x21;
/// `KADEMLIA2_SEARCH_KEY_REQ` — keyword search request (routed to
/// `keyword_store`, not [`Kad2Opcode`]; see the module note).
pub const KADEMLIA2_SEARCH_KEY_REQ: u8 = 0x33;
/// `KADEMLIA2_PUBLISH_KEY_REQ` — keyword publish request (routed to
/// `keyword_store`, not [`Kad2Opcode`]; see the module note).
pub const KADEMLIA2_PUBLISH_KEY_REQ: u8 = 0x43;
/// `KADEMLIA2_RES` — lookup next-hop response.
pub const KADEMLIA2_RES: u8 = 0x29;
/// `KADEMLIA2_SEARCH_NOTES_REQ` — notes search request (routed to `notes`, not
/// [`Kad2Opcode`]; Empty-Storer Parity, ADR-0063 — see the module note).
pub const KADEMLIA2_SEARCH_NOTES_REQ: u8 = 0x35;
/// `KADEMLIA2_SEARCH_SOURCE_REQ` — source-lookup request.
pub const KADEMLIA2_SEARCH_SOURCE_REQ: u8 = 0x34;
/// `KADEMLIA2_SEARCH_RES` — source/search result.
pub const KADEMLIA2_SEARCH_RES: u8 = 0x3B;
/// `KADEMLIA2_PUBLISH_SOURCE_REQ` — source-publish request.
pub const KADEMLIA2_PUBLISH_SOURCE_REQ: u8 = 0x44;
/// `KADEMLIA2_PUBLISH_NOTES_REQ` — notes publish request (routed to `notes`,
/// not [`Kad2Opcode`]; Empty-Storer Parity, ADR-0063 — see the module note).
pub const KADEMLIA2_PUBLISH_NOTES_REQ: u8 = 0x45;
/// `KADEMLIA2_PUBLISH_RES` — publish result (source/key/notes share it).
pub const KADEMLIA2_PUBLISH_RES: u8 = 0x4B;
/// `KADEMLIA2_PUBLISH_RES_ACK` — the publisher's null-payload ack of a
/// publish result. Emit-only and dormant (ADR-0062): see the module note.
pub const KADEMLIA2_PUBLISH_RES_ACK: u8 = 0x4C;
/// `KADEMLIA2_PING` — liveness/external-port probe.
pub const KADEMLIA2_PING: u8 = 0x60;
/// `KADEMLIA2_PONG` — ping answer carrying the observed sender UDP port.
pub const KADEMLIA2_PONG: u8 = 0x61;

/// The Kad2 opcodes rmule models.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kad2Opcode {
    /// [`KADEMLIA2_BOOTSTRAP_REQ`] — ask a known endpoint for a starter set of
    /// contacts.
    BootstrapReq,
    /// [`KADEMLIA2_BOOTSTRAP_RES`] — the responder's own info plus contacts.
    BootstrapRes,
    /// [`KADEMLIA2_HELLO_REQ`] — introduce ourselves and ask to be seated.
    HelloReq,
    /// [`KADEMLIA2_HELLO_RES`] — the answer to a hello.
    HelloRes,
    /// [`KADEMLIA2_HELLO_RES_ACK`] — the IP-verification ack that closes the
    /// three-way.
    HelloResAck,
    /// [`KADEMLIA2_REQ`] — ask for the contacts closest to a target.
    LookupReq,
    /// [`KADEMLIA2_RES`] — the closest contacts a lookup found.
    LookupRes,
    /// [`KADEMLIA2_SEARCH_SOURCE_REQ`] — ask a storer for a file's sources.
    SearchSourceReq,
    /// [`KADEMLIA2_SEARCH_RES`] — a result batch; source and keyword searches
    /// share it.
    SearchRes,
    /// [`KADEMLIA2_PUBLISH_SOURCE_REQ`] — offer ourselves as a file's source.
    PublishSourceReq,
    /// [`KADEMLIA2_PUBLISH_RES`] — a storer's ack, carrying its load byte.
    PublishRes,
    /// [`KADEMLIA2_PING`] — liveness and external-port probe.
    Ping,
    /// [`KADEMLIA2_PONG`] — the ping answer, naming the port it arrived from.
    Pong,
}

impl Kad2Opcode {
    /// Recognize a modelled Kad2 opcode byte, or `None` for any other byte.
    #[must_use]
    pub const fn try_from_u8(byte: u8) -> Option<Self> {
        match byte {
            KADEMLIA2_BOOTSTRAP_REQ => Some(Self::BootstrapReq),
            KADEMLIA2_BOOTSTRAP_RES => Some(Self::BootstrapRes),
            KADEMLIA2_HELLO_REQ => Some(Self::HelloReq),
            KADEMLIA2_HELLO_RES => Some(Self::HelloRes),
            KADEMLIA2_HELLO_RES_ACK => Some(Self::HelloResAck),
            KADEMLIA2_REQ => Some(Self::LookupReq),
            KADEMLIA2_RES => Some(Self::LookupRes),
            KADEMLIA2_SEARCH_SOURCE_REQ => Some(Self::SearchSourceReq),
            KADEMLIA2_SEARCH_RES => Some(Self::SearchRes),
            KADEMLIA2_PUBLISH_SOURCE_REQ => Some(Self::PublishSourceReq),
            KADEMLIA2_PUBLISH_RES => Some(Self::PublishRes),
            KADEMLIA2_PING => Some(Self::Ping),
            KADEMLIA2_PONG => Some(Self::Pong),
            _ => None,
        }
    }

    /// The wire byte for this opcode.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::BootstrapReq => KADEMLIA2_BOOTSTRAP_REQ,
            Self::BootstrapRes => KADEMLIA2_BOOTSTRAP_RES,
            Self::HelloReq => KADEMLIA2_HELLO_REQ,
            Self::HelloRes => KADEMLIA2_HELLO_RES,
            Self::HelloResAck => KADEMLIA2_HELLO_RES_ACK,
            Self::LookupReq => KADEMLIA2_REQ,
            Self::LookupRes => KADEMLIA2_RES,
            Self::SearchSourceReq => KADEMLIA2_SEARCH_SOURCE_REQ,
            Self::SearchRes => KADEMLIA2_SEARCH_RES,
            Self::PublishSourceReq => KADEMLIA2_PUBLISH_SOURCE_REQ,
            Self::PublishRes => KADEMLIA2_PUBLISH_RES,
            Self::Ping => KADEMLIA2_PING,
            Self::Pong => KADEMLIA2_PONG,
        }
    }
}
