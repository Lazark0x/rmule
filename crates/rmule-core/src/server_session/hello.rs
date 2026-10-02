//! The hello context a connection presents: our identity with the live
//! server session's id and server, or client id 0 and no server between
//! sessions (ADR-0098, "Every hello names the live session").

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{ClientId, ClientIdentity};

/// The hello context every dial presents at the moment it dials: our
/// `identity`, and the live session's id and server — client id 0 and no
/// server between sessions. aMule and eMule write the connected server's
/// address and port into every hello, zeros when not connected
/// (`CUpDownClient::SendHelloTypePacket`: aMule `BaseClient.cpp:1621-1628`,
/// eMuleAI `BaseClient.cpp:2212-2218`) — never a server a download was once
/// started on.
pub(crate) fn live_peer_handshake_context(
    identity: &ClientIdentity,
    own: &crate::own_identity::SharedOwnIdentity,
) -> PeerHandshakeContext {
    let session = own.connected_session();
    PeerHandshakeContext {
        identity: identity.clone().with_extra_tags(Vec::new()),
        client_id: session.map_or(ClientId::from_u32(0), |session| session.client_id),
        connected_server: session.and_then(|session| session.server),
    }
}

/// Where a long-lived surface reads the hello it presents: the listener's
/// accept pump and its tunnel and callback admissions, and the firewalled
/// front's buddy dial. It is read at each connection, never kept as a copy,
/// so a hello names the live session's server and its **current** id — the
/// one a mid-session `OP_IDCHANGE` assigned — or none between
/// sessions, the same cell every download and Kad dial reads.
#[derive(Clone)]
pub(crate) enum HelloSource {
    /// Our identity, and the live session as the shared session facts hold it.
    Live {
        identity: ClientIdentity,
        own: crate::own_identity::SharedOwnIdentity,
    },
    /// One fixed context, for a test that drives an admission directly.
    #[cfg(test)]
    Fixed(PeerHandshakeContext),
}

impl HelloSource {
    /// The hello `identity` presents under the live session in `own`.
    pub(crate) const fn live(
        identity: ClientIdentity,
        own: crate::own_identity::SharedOwnIdentity,
    ) -> Self {
        Self::Live { identity, own }
    }

    /// The hello to present now.
    pub(crate) fn now(&self) -> PeerHandshakeContext {
        match self {
            Self::Live { identity, own } => live_peer_handshake_context(identity, own),
            #[cfg(test)]
            Self::Fixed(ctx) => ctx.clone(),
        }
    }
}

impl std::fmt::Debug for HelloSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HelloSource").field(&self.now()).finish()
    }
}
