//! The IPv6 dialect's client↔client address surface (ADR-0087): the three
//! 16-byte hello tags rmule reads and writes, the one it refuses, and
//! `OP_CHANGE_CLIENT_IP` — the mid-session correction that keeps a peer's view
//! of our address from going stale.
//!
//! Every address here rides as a `TAGTYPE_HASH`: sixteen raw bytes, MSB-first,
//! no length prefix. The tag is the *fact* — a peer treats its presence, never
//! the `CT_MOD_MISCOPTIONS` IPv6 bit, as "this client is reachable over IPv6".
//!
//! Two refusals are load-bearing, and both are the harder reading of the spec:
//!
//! * `CT_MOD_SVR_IP_V6` (`0xAF`) is a **server** tag. In a peer hello it would
//!   let one unauthenticated peer tell us what our server's address is, so it
//!   is skipped rather than read as an address.
//! * `CT_MOD_YOUR_IP` (`0xAD`) has an integer form that names an IPv4. Reading
//!   it would let one peer set what rmule believes its own public IPv4 to be —
//!   and a client wrong about its own address is wrong about whether it is
//!   firewalled. Only the hash form is read, and only as one **vote** into the
//!   ADR-0084 quorum.

use std::net::Ipv6Addr;

use rmule_primitives::{
    CT_EMULE_SERVINGBUDDYIPV6, CT_MOD_IP_V6, CT_MOD_YOUR_IP, Ipv6Endpoint, Packet, Tag, TagValue,
    is_usable_tag_identity,
};

use crate::error::PeerIpv6DecodeError;
use crate::opcode::PeerOpcode;

/// The IPv6 addresses a peer's hello carried, each admitted only under
/// `IsUsableTagIdentity`.
///
/// A field that stayed `None` means the tag was absent, malformed, in the
/// wrong type, or named an address a 16-byte tag cannot identify — all four
/// are the same outcome for a reader, which is exactly the point: a refused
/// tag leaves rmule where it was, never somewhere worse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerIpv6Tags {
    /// `CT_MOD_IP_V6`: the peer's own reachable IPv6, and the only thing that
    /// makes it dialable in this family.
    pub peer_ipv6: Option<Ipv6Addr>,
    /// `CT_MOD_YOUR_IP`, hash form: the peer's view of *our* IPv6. One vote
    /// for the ADR-0084 quorum, never an adopted address on its own.
    pub reflected_ipv6: Option<Ipv6Addr>,
    /// `CT_EMULE_SERVINGBUDDYIPV6`: the peer's buddy's IPv6, the v6 half of
    /// the ADR-0061 buddy contact.
    pub serving_buddy_ipv6: Option<Ipv6Addr>,
}

impl PeerIpv6Tags {
    /// Read the dialect's address tags out of a hello's tag list.
    #[must_use]
    pub fn from_hello_tags(tags: &[Tag]) -> Self {
        let mut read = Self::default();
        for tag in tags {
            let (Some(id), TagValue::Hash(bytes)) = (tag.name().id(), tag.value()) else {
                // The integer form of `CT_MOD_YOUR_IP` lands here and is
                // dropped without a second look.
                continue;
            };
            let address = Ipv6Addr::from(*bytes);
            if !is_usable_tag_identity(address) {
                continue;
            }
            let slot = match id {
                CT_MOD_IP_V6 => &mut read.peer_ipv6,
                CT_MOD_YOUR_IP => &mut read.reflected_ipv6,
                CT_EMULE_SERVINGBUDDYIPV6 => &mut read.serving_buddy_ipv6,
                // `CT_MOD_SVR_IP_V6` (`0xAF`) included: a server tag has no
                // meaning from a peer, so it is skipped rather than believed.
                _ => continue,
            };
            // The last usable copy wins, as each reference assigns per tag.
            *slot = Some(address);
        }
        read
    }
}

/// `OP_CHANGE_CLIENT_IP` (`0xAC`, under `OP_EDONKEYPROT`) — sixteen raw
/// address bytes, no tag wrapper.
///
/// Sent on an established session when our Known IPv6 changes. Without it a
/// peer that learned our address at hello time keeps dialing the old one after
/// a prefix renumber or an RFC 4941 privacy rotation, which on IPv6 is routine
/// rather than exceptional.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeClientIpV6(Ipv6Addr);

impl ChangeClientIpV6 {
    /// The address the sender now holds. Refuses one no 16-byte tag could
    /// identify — the same `IsUsableTagIdentity` gate the hello tag passes
    /// through, since this packet says the same thing later.
    #[must_use]
    pub fn new(address: Ipv6Addr) -> Option<Self> {
        is_usable_tag_identity(address).then_some(Self(address))
    }

    /// The address it carries.
    #[must_use]
    pub const fn address(self) -> Ipv6Addr {
        self.0
    }

    /// Frame the announcement.
    #[must_use]
    pub fn encode_packet(self) -> Packet {
        Packet::new(
            PeerOpcode::ChangeClientIpV6.protocol(),
            PeerOpcode::ChangeClientIpV6.as_u8(),
            self.0.octets().to_vec(),
        )
    }

    /// Read an announcement.
    ///
    /// # Errors
    /// [`PeerIpv6DecodeError::WrongSize`] when the payload is not exactly the
    /// sixteen address bytes, [`PeerIpv6DecodeError::UnusableAddress`] when it
    /// is well-formed but names an address a tag cannot identify.
    pub fn decode_packet(packet: &Packet) -> Result<Self, PeerIpv6DecodeError> {
        let payload = packet.payload();
        let bytes: [u8; Ipv6Endpoint::ADDR_WIRE_LEN] =
            payload
                .try_into()
                .map_err(|_| PeerIpv6DecodeError::WrongSize {
                    expected: Ipv6Endpoint::ADDR_WIRE_LEN,
                    actual: payload.len(),
                })?;
        let address = Ipv6Addr::from(bytes);
        Self::new(address).ok_or(PeerIpv6DecodeError::UnusableAddress { address })
    }
}

#[cfg(test)]
mod tests;
