//! An IPv4 address as the 32-bit word a protocol carries it as. Every wire
//! integer is little-endian; what differs is the integer an address packs to,
//! and stock keeps both in a bare `uint32` with a hand swap between them:
//!
//! - [`Ed2kIp`], `a | b<<8 | c<<16 | d<<24`, the bytes of a `sockaddr` read on
//!   a little-endian host (stock's "network order"), so `a.b.c.d` travels as
//!   `a b c d`. A High ID, a server's address, a serving buddy's
//!   (`CT_EMULE_BUDDYIP`, Kad's `TAG_SERVERIP`).
//! - [`KadIp`], `a<<24 | b<<16 | c<<8 | d`, the address as a number (stock's
//!   "host order", `CContact::GetIPAddress`), so `a.b.c.d` travels as
//!   `d c b a`. A Kad contact, `TAG_SOURCEIP`, an `OP_CALLBACK` requester.
//!
//! [`HybridId`] is the third reading stock swaps by hand: a [`ClientId`] whose
//! High form rides in Kad's order and whose Low form rides as itself. This file
//! is the one place these words are packed or unpacked; everywhere else an
//! address is an [`Ipv4Addr`] and a word is one of these types.

use std::net::Ipv4Addr;

use crate::ClientId;

/// An IPv4 address in eD2k's word: the octets in dotted order, read
/// little-endian. Read off the wire with [`Self::from_wire`], written with
/// [`Self::wire`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ed2kIp(u32);

impl Ed2kIp {
    /// `ip`'s word.
    #[must_use]
    pub const fn new(ip: Ipv4Addr) -> Self {
        Self(u32::from_le_bytes(ip.octets()))
    }

    /// The word as a little-endian read took it off the wire.
    #[must_use]
    pub const fn from_wire(word: u32) -> Self {
        Self(word)
    }

    /// The integer a wire field holds.
    #[must_use]
    pub const fn wire(self) -> u32 {
        self.0
    }

    /// The address.
    #[must_use]
    pub const fn ip(self) -> Ipv4Addr {
        let [a, b, c, d] = self.0.to_le_bytes();
        Ipv4Addr::new(a, b, c, d)
    }
}

/// An IPv4 address in Kad's word: the address as a number. Read off the wire
/// with [`Self::from_wire`], written with [`Self::wire`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadIp(u32);

impl KadIp {
    /// `ip`'s word.
    #[must_use]
    pub const fn new(ip: Ipv4Addr) -> Self {
        Self(u32::from_be_bytes(ip.octets()))
    }

    /// The word as a little-endian read took it off the wire.
    #[must_use]
    pub const fn from_wire(word: u32) -> Self {
        Self(word)
    }

    /// The integer a wire field holds.
    #[must_use]
    pub const fn wire(self) -> u32 {
        self.0
    }

    /// The address.
    #[must_use]
    pub const fn ip(self) -> Ipv4Addr {
        let [a, b, c, d] = self.0.to_be_bytes();
        Ipv4Addr::new(a, b, c, d)
    }
}

/// A [`ClientId`] as a hybrid-id source exchange carries it: a High ID in
/// Kad's word, a Low ID as itself (stock's `GetUserIDHybrid`, 2.3.3
/// `PartFile.cpp:2641`, read back at `:2787`).
///
/// Which it is reads off the received word, before any swap. A Low ID's
/// magnitude is the same in either reading, and a High ID's word stays at or
/// above the ceiling in either, barring a leftmost dotted octet of 0, which no
/// routable address has: the asymmetry the encoding rests on. Stock's
/// `IsLowID(dwID)` tests the same pre-swap word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HybridId(u32);

impl HybridId {
    /// The word as a little-endian read took it off the wire.
    #[must_use]
    pub const fn from_wire(word: u32) -> Self {
        Self(word)
    }

    /// The integer the wire field holds.
    #[must_use]
    pub const fn wire(self) -> u32 {
        self.0
    }

    /// The id in hybrid form.
    #[must_use]
    pub const fn from_client_id(id: ClientId) -> Self {
        if id.is_high_id() {
            Self(id.as_u32().swap_bytes())
        } else {
            Self(id.as_u32())
        }
    }

    /// The eD2k id this word names.
    #[must_use]
    pub const fn client_id(self) -> ClientId {
        if ClientId::from_u32(self.0).is_high_id() {
            ClientId::from_u32(self.0.swap_bytes())
        } else {
            ClientId::from_u32(self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `0x58` aMule answers for 203.0.113.3 carries `03 71 00 cb`
    /// (`amule-233-firewall-selfcheck-requester`), and its login and hello
    /// frames carry the address as `cb 00 71 03`.
    #[test]
    fn each_word_travels_in_its_own_order() {
        let ip = Ipv4Addr::new(203, 0, 113, 3);
        assert_eq!(KadIp::new(ip).wire().to_le_bytes(), [3, 113, 0, 203]);
        assert_eq!(Ed2kIp::new(ip).wire().to_le_bytes(), [203, 0, 113, 3]);
        assert_eq!(KadIp::from_wire(KadIp::new(ip).wire()).ip(), ip);
        assert_eq!(Ed2kIp::from_wire(Ed2kIp::new(ip).wire()).ip(), ip);
    }

    #[test]
    fn a_hybrid_id_swaps_a_high_id_and_carries_a_low_one_as_it_is() {
        let high = ClientId::from_ipv4(Ipv4Addr::new(203, 0, 113, 3));
        assert_eq!(
            HybridId::from_client_id(high).wire().to_le_bytes(),
            [3, 113, 0, 203]
        );
        assert_eq!(
            HybridId::from_wire(HybridId::from_client_id(high).wire()).client_id(),
            high
        );

        let low = ClientId::from_u32(0x0000_1234);
        assert_eq!(HybridId::from_client_id(low).wire(), 0x0000_1234);
        assert_eq!(HybridId::from_wire(0x0000_1234).client_id(), low);
    }
}
