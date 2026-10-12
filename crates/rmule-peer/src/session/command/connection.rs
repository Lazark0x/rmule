//! The **Connection** group of [`PeerCommand`](super::PeerCommand): what we
//! say about the link itself.

use crate::ipv6::ChangeClientIpV6;

use super::super::{PeerCloseReason, PeerSession};

/// A command about the link rather than either capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionCommand {
    /// Close the link, sending nothing further.
    Disconnect,
    /// Announce a changed Known IPv6 on this established session
    /// (`OP_CHANGE_CLIENT_IP` `0xAC`, ADR-0087). Core issues it when the
    /// Advertised Endpoints chooser settles on a different address than the
    /// one this session's hello named; without it a peer keeps dialing the
    /// address we no longer hold. Guarded by `require_identified` — a peer
    /// that has not yet heard our hello has nothing to correct.
    AnnounceIpv6Change(std::net::Ipv6Addr),
}

impl PeerSession {
    pub(super) fn apply_connection(&mut self, command: ConnectionCommand) {
        match command {
            ConnectionCommand::Disconnect => self.close(PeerCloseReason::Local),
            ConnectionCommand::AnnounceIpv6Change(address) => {
                // An address no 16-byte tag can identify is refused at the
                // constructor, so a mis-wired caller sends nothing rather than
                // naming a peer two ways.
                if let Some(announcement) = ChangeClientIpV6::new(address)
                    && self.require_identified()
                {
                    self.write_packet(announcement.encode_packet());
                }
            }
        }
    }
}
