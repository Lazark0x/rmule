//! The **Connection** group of [`PeerCommand`](super::PeerCommand): what we
//! say about the link itself.

use crate::capability::ModMiscOptions;
use crate::ipv6::ChangeClientIpV6;

use super::super::{PeerCloseReason, PeerSession, State};

/// A command about the link rather than either capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionCommand {
    /// Close the link, sending nothing further.
    Disconnect,
    /// Our Advertised IPv6 moved to this address (`OP_CHANGE_CLIENT_IP`
    /// `0xAC`, ADR-0087); without the announcement a peer keeps dialing the
    /// address we no longer hold. The session sends it at most once per
    /// move, and only to a peer whose hello claims `MODMISC_IPV6`. Before the
    /// peer identifies nothing is rejected: a hello not yet written names the
    /// new address itself, and one already written is followed by the
    /// announcement when the peer identifies.
    AnnounceIpv6Change(std::net::Ipv6Addr),
    /// Take the Client ID a [`ConnectionEvent::ClientIdOffered`](crate::ConnectionEvent::ClientIdOffered)
    /// offered, on `server` when core knows the server it named. A Low ID
    /// without a known server, or a High ID that is not the link's own
    /// address, moves nothing.
    TakeClientId {
        /// The id offered.
        client_id: rmule_primitives::ClientId,
        /// The known server the peer is now on, at the port core knows it at.
        server: Option<rmule_primitives::Ipv4Endpoint>,
    },
}

impl PeerSession {
    pub(super) fn apply_connection(&mut self, command: ConnectionCommand) {
        match command {
            ConnectionCommand::Disconnect => self.close(PeerCloseReason::Local),
            ConnectionCommand::TakeClientId { client_id, server } => {
                self.take_client_id(client_id, server);
            }
            ConnectionCommand::AnnounceIpv6Change(address) => {
                self.ipv6_advert = Some(address);
                if matches!(self.state, State::Identified) {
                    self.announce_ipv6_change();
                }
            }
        }
    }

    /// Tell an identified, IPv6-capable peer our current IPv6 when it is not
    /// what the peer was last told (emule-qt `UpDownClient.cpp:4670-4697`).
    pub(in crate::session) fn announce_ipv6_change(&mut self) {
        let Some(address) = self.ipv6_advert else {
            return;
        };
        if self.ipv6_told == Some(address)
            || !self
                .peer_mod_misc()
                .is_some_and(ModMiscOptions::supports_ipv6)
        {
            return;
        }
        // An address no 16-byte tag can identify is refused at the
        // constructor, so a mis-wired caller sends nothing rather than naming
        // a peer two ways.
        if let Some(announcement) = ChangeClientIpV6::new(address) {
            self.write_packet(announcement.encode_packet());
            self.ipv6_told = Some(address);
        }
    }
}
