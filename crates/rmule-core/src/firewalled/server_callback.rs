//! **Server callback consume**: the `OP_CALLBACKREQUESTED` (`0x35`) our server
//! relays when a peer on it asked to reach us, and its IPv6 sibling
//! `OP_CALLBACKREQUESTED_IPV6` (`0x26`) — the other end of the requester's
//! **Low-ID Callback** (ADR-0039, ADR-0061).
//!
//! The requester wants to download *from us*, so the answer is a dial-back
//! into the serve pipeline and never a download: aMule's handler builds a
//! `CUpDownClient` with no file and calls `TryToConnect`
//! ([`ServerSocket.cpp#L554`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerSocket.cpp#L554)).
//!
//! The refusal matrix, in the order it is consulted, each read at the request
//! and stored nowhere:
//!
//! - our session reads High-ID → [`HighId`](ServerCallbackRefusal::HighId): a
//!   server sends the opcode only to a Low-ID client, and a High-ID one is
//!   dialed directly;
//! - the requester's address lies in a Reserved Range its server cannot vouch
//!   for (ADR-0085) → [`ReservedAddress`](ServerCallbackRefusal::ReservedAddress):
//!   the one address gate, `0x26`'s sixteen bytes included;
//! - the requester is our own listen endpoint →
//!   [`SelfConnect`](ServerCallbackRefusal::SelfConnect)
//!   ([`OwnListenEndpoint`], ADR-0058);
//! - the node is not serving → [`NotServing`](ServerCallbackRefusal::NotServing):
//!   a dialed link would have no hello to write;
//! - the two crypt stances cannot meet →
//!   [`CryptIncompatible`](ServerCallbackRefusal::CryptIncompatible), aMule's
//!   `TryToConnect` precondition (ADR-0049).
//!
//! The crypt stance is the `0x35` crypt extension's connect-options and User
//! Hash, for this one dial (ADR-0049's "never merged" row). The 6-byte form and
//! every `0x26` state none, so the requester reads unknown: plaintext, and
//! refused outright when our own policy requires crypt.
//!
//! Pure: the in-flight bound and the dial itself are the session's enactment
//! (`server_session::dial_backs`).

use rmule_ed2k::PeerCallbackCrypt;
use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::{ClientId, Informant, OutboundCrypt, PeerCrypt, PeerEndpoint, UserHash};

use crate::reachability::OwnListenEndpoint;

/// The decoded `0x35` / `0x26` facts the consume reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServerCallbackConsume {
    /// Where the requester listens, as the server names it.
    pub(crate) requester: PeerEndpoint,
    /// The `0x35` crypt extension, when the server relayed the `>= 23`-byte
    /// form.
    pub(crate) crypt: Option<PeerCallbackCrypt>,
}

/// Our side of the consume, read at the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServerCallbackContext {
    /// The id our session holds now: the login's, moved by each later
    /// `OP_IDCHANGE`.
    pub(crate) session_id: ClientId,
    /// The server, as the Informant the requester's address is judged
    /// against.
    pub(crate) server: Informant,
    /// Our own listen endpoint, for the self-connect guard.
    pub(crate) own: OwnListenEndpoint,
    /// Whether the serve pipeline is up to take the dialed link.
    pub(crate) serving: bool,
    /// **Our own** obfuscation policy, `None` when obfuscation is off.
    pub(crate) crypt: Option<ObfuscationPolicy>,
}

/// What [`consume_server_callback`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerCallbackVerdict {
    /// Dial `requester` back and hand the stream to the serve pipeline as the
    /// dialer's side.
    DialBack {
        requester: PeerEndpoint,
        /// The User Hash the dial's crypt handshake keys on — the extension's
        /// own — or `None` for a plaintext dial.
        obfuscate_toward: Option<UserHash>,
    },
    /// Refuse silently, as aMule's guards do.
    Refuse { reason: ServerCallbackRefusal },
}

/// Why a server-relayed callback was not dialed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerCallbackRefusal {
    /// Our session holds a High ID: the requester can dial us itself.
    HighId,
    /// The requester's address lies in a Reserved Range the server cannot
    /// vouch for.
    ReservedAddress,
    /// The requester is our own listen endpoint.
    SelfConnect,
    /// The node is not serving.
    NotServing,
    /// Our policy and the requester's stance cannot meet.
    CryptIncompatible,
    /// A callback dial to that endpoint is already in flight, or the
    /// in-flight budget is spent — the enactment's own refusal.
    Busy,
}

/// Consume one server-relayed callback: apply the refusal matrix (module
/// header) in order, then read the crypt rule.
pub(crate) fn consume_server_callback(
    req: &ServerCallbackConsume,
    ctx: &ServerCallbackContext,
) -> ServerCallbackVerdict {
    let refuse = |reason| ServerCallbackVerdict::Refuse { reason };
    if ctx.session_id.is_high_id() {
        return refuse(ServerCallbackRefusal::HighId);
    }
    if !ctx.server.admits(req.requester.ip()) {
        return refuse(ServerCallbackRefusal::ReservedAddress);
    }
    if ctx.own.matches(req.requester) {
        return refuse(ServerCallbackRefusal::SelfConnect);
    }
    if !ctx.serving {
        return refuse(ServerCallbackRefusal::NotServing);
    }
    let requester = req
        .crypt
        .map_or_else(PeerCrypt::unknown, PeerCallbackCrypt::peer_crypt);
    match requester.outbound(ObfuscationPolicy::stance_of(ctx.crypt)) {
        OutboundCrypt::Plaintext => ServerCallbackVerdict::DialBack {
            requester: req.requester,
            obfuscate_toward: None,
        },
        OutboundCrypt::Obfuscated { toward, .. } => ServerCallbackVerdict::DialBack {
            requester: req.requester,
            obfuscate_toward: Some(toward),
        },
        OutboundCrypt::Incompatible => refuse(ServerCallbackRefusal::CryptIncompatible),
    }
}

#[cfg(test)]
mod tests;
