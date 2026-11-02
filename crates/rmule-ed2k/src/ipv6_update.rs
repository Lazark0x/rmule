//! `OP_IPV6_UPDATE` (`0x63`): an address that moved after login, told to the
//! server in place of a re-login (ADR-0087). Sent only to a server that set
//! `0x8000` in `OP_IDCHANGE`.
//!
//! ed2k-server's own, at v0.9.85 (`878fc830`): README *IPv6*, `login.rs`
//! `Ipv6Update`. Read for facts and cite-and-rewritten (ADR-0004).

use std::net::Ipv6Addr;

use rmule_primitives::{Packet, PacketProtocol};

use crate::Opcode;

/// `OP_IPV6_UPDATE`, client → server. Body: sixteen address bytes, or sixteen
/// zeros to withdraw the address the login's `CT_MOD_IP_V6` named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv6Update {
    /// The address to publish from now on, `None` to publish none.
    pub address: Option<Ipv6Addr>,
}

impl Ipv6Update {
    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let address = self.address.unwrap_or(Ipv6Addr::UNSPECIFIED);
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::Ipv6Update.as_u8(),
            address.octets().to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// README *IPv6*: sixteen raw bytes under `0xE3 0x63`, zeros to withdraw.
    #[test]
    fn the_update_is_the_address_and_zeros_withdraw_it() {
        let address: Ipv6Addr = "2001:db8::9".parse().expect("address");
        let packet = Ipv6Update {
            address: Some(address),
        }
        .encode_packet();
        assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
        assert_eq!(packet.opcode(), 0x63);
        assert_eq!(packet.payload(), address.octets());
        assert_eq!(
            Ipv6Update { address: None }.encode_packet().payload(),
            [0; 16]
        );
    }
}
