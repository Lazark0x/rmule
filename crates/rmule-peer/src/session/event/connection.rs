//! The **Connection** group of [`PeerEvent`](super::PeerEvent): the link
//! itself — the opening, the peer's identity and every later revision of it,
//! the Secure User Identification verdict, and the close.

use rmule_primitives::UserHash;

use crate::identity::PeerIdentity;
use crate::session::{PeerCloseReason, SecureIdentFailure};

/// What the session learned about the link and the peer on it. `Identified`
/// precedes every request the peer makes, and `Disconnected` is the last
/// event of every session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// Our `OP_HELLO` is on the wire; the peer has said nothing back yet.
    HelloSent,
    /// The peer answered the handshake and named itself — the first point at
    /// which anything about it is known.
    Identified {
        /// Everything its hello carried: user hash, client, ports, capabilities.
        identity: PeerIdentity,
    },
    /// An identified peer's identity changed, and this is all of it now: an
    /// `OP_EMULEINFO` / `OP_EMULEINFOANSWER` revised its software, its
    /// client-UDP reask contact or its source-exchange facts — a pre-0.42
    /// mule states its version and SX version only there — or an
    /// `OP_CHANGE_CLIENT_IP` (`0xAC`) moved its Known IPv6 (ADR-0087), or an
    /// `OP_CHANGE_CLIENT_ID` (`0x4D`) gave it a new Client ID. One
    /// event per change, in the order the session applied them, each carrying
    /// the identity as it stands after that change, so a consumer that keeps
    /// the identity replaces it whole and one that acts on a change reads
    /// `what`.
    IdentityRevised {
        /// The peer's identity, every revision so far applied.
        identity: PeerIdentity,
        /// Which part of it this revision changed.
        what: IdentityChange,
    },
    /// The peer's hello was refused under a named code (ADR-0050). Emitted
    /// immediately before the `Disconnected` its protocol-violation close
    /// raises; the refusal carries the name and mod the peer wrote before its
    /// frame went wrong.
    HelloRefused {
        /// Why, and what the peer said of itself.
        refusal: crate::hello::HelloRefusal,
    },
    /// Secure User Identification proved the peer owns the **User Hash** it
    /// claimed; `public_key` is its RSA public key DER (ADR-0041). Core binds
    /// this as a **Secured Identity** so credit cannot be spoofed. Non-terminal.
    IdentityVerified {
        /// The hash now proven to belong to this peer.
        user_hash: UserHash,
        /// Its RSA public key, DER-encoded — what core keeps to recognise it.
        public_key: Vec<u8>,
    },
    /// A Secure User Identification exchange failed (bad public key or a
    /// signature that did not verify). Non-terminal — the session stays open and
    /// the peer keeps only unsecured credit (ADR-0041).
    SecureIdentFailed {
        /// Which step of the proof failed.
        reason: SecureIdentFailure,
    },
    /// An `OP_CHANGE_CLIENT_ID` (`0x4D`) says the peer now answers to
    /// `client_id` on the server at `server`. Nothing moves yet: aMule takes
    /// a Low ID only for a server it knows, and the server's port from its
    /// own list (`ClientTCPSocket.cpp:773-787`), which only core holds — it
    /// answers with [`ConnectionCommand::TakeClientId`](crate::ConnectionCommand::TakeClientId).
    /// A High ID that is not the address the link came from is ignored here.
    ClientIdOffered {
        /// The id the peer says it holds now.
        client_id: rmule_primitives::ClientId,
        /// The server the packet names beside it.
        server: std::net::Ipv4Addr,
    },
    /// The last word about this session. Emitted exactly once, immediately
    /// before the close it explains (ADR-0044).
    Disconnected {
        /// What ended it.
        reason: PeerCloseReason,
    },
}

/// Which part of an identified peer's [`PeerIdentity`] one
/// [`ConnectionEvent::IdentityRevised`] changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityChange {
    /// Which client it runs ([`PeerIdentity::software`]).
    Software,
    /// Its client-UDP reask contact ([`PeerIdentity::client_udp_reask`]),
    /// which its hello did not name.
    ReaskContact,
    /// What it says about source exchange
    /// ([`PeerIdentity::source_exchange`], ADR-0108).
    SourceExchange,
    /// The IPv6 it now holds ([`PeerIdentity::peer_ipv6`]).
    Ipv6,
    /// The Client ID it now answers to ([`PeerIdentity::client_id`]), after
    /// an `OP_CHANGE_CLIENT_ID`.
    ClientId,
}
