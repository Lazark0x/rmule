//! The **Sentinel Source** convention every server source list shares
//! (ADR-0085, emule-qt `docs/protocol/ipv6-spec.md` §4.4): a record whose
//! 32-bit id field is `0xFFFFFFFF` names no IPv4 address at all — its real
//! address is sixteen bytes carried **inline, as the record's last field**,
//! after the port and after any obfuscation fields the list form carries.
//!
//! Reading it has two hard rules. The sixteen bytes are always consumed, so
//! the next record starts where it really starts; and an address that is not
//! a usable identity (`is_usable_tag_identity`) costs its record and nothing
//! else. A list that cannot be walked to its declared count, or that leaves
//! bytes nothing accounts for, is a **Malformed Tail**: the reader keeps only
//! the records before its first sentinel, which sit at the same offsets in any
//! layout, and reports the verdict instead of failing.

use crate::{ClientId, Ipv6Endpoint, PeerSource, is_usable_tag_identity};

/// How a source list's **Sentinel Source** records read (ADR-0085). Carried on
/// the decoded body so the diagnostic surfaces without the reader having to
/// fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceListTail {
    /// Every record, sentinel or not, was read to its last field and the list
    /// measured exactly. `sentinels` is 0 for a classic all-IPv4 list.
    Read {
        /// How many records carried the sentinel id.
        sentinels: usize,
    },
    /// The list could not be walked to its declared count, or left bytes
    /// nothing accounts for. Every record from the first sentinel on is
    /// dropped — once a variable-length record may have been misread no later
    /// offset is trustworthy — and every record before it stands.
    Malformed {
        /// How many sentinel records the walk met before it stopped.
        sentinels: usize,
        /// How many bytes the walk could not account for.
        tail_len: usize,
    },
}

impl SourceListTail {
    /// Whether the list failed to measure what its records declare.
    #[must_use]
    pub const fn is_malformed(self) -> bool {
        matches!(self, Self::Malformed { .. })
    }

    /// How many records carried the sentinel id, malformed list or not.
    #[must_use]
    pub const fn sentinels(self) -> usize {
        match self {
            Self::Read { sentinels } | Self::Malformed { sentinels, .. } => sentinels,
        }
    }
}

impl PeerSource {
    /// The inline address a **Sentinel Source** record carries as its last
    /// field: sixteen network-order bytes.
    pub const SENTINEL_ADDRESS_LEN: usize = Ipv6Endpoint::ADDR_WIRE_LEN;

    /// Classify a record's id and port, refusing the sentinel id: a record
    /// that carries it names an IPv6 address the caller must read inline
    /// ([`Self::from_sentinel_address`]), never the broadcast address its id
    /// would unpack to. The checked form of [`Self::new`] every wire reader
    /// uses.
    #[must_use]
    pub const fn from_record(client_id: ClientId, tcp_port: u16) -> Option<Self> {
        if client_id.as_u32() == Self::IPV6_SENTINEL {
            None
        } else {
            Some(Self::new(client_id, tcp_port))
        }
    }

    /// The source a **Sentinel Source** record names: its inline address at
    /// the record's port, or `None` when the address is not a usable identity
    /// (loopback, link-local, multicast, ULA, mapped, unspecified) — the same
    /// gate every other IPv6 reader applies (ADR-0087).
    #[must_use]
    pub const fn from_sentinel_address(
        bytes: [u8; Self::SENTINEL_ADDRESS_LEN],
        tcp_port: u16,
    ) -> Option<Self> {
        let endpoint = Ipv6Endpoint::from_addr_bytes(bytes, tcp_port);
        if is_usable_tag_identity(endpoint.ip) {
            Some(Self::Ipv6(endpoint))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn the_sentinel_id_is_never_classified_as_an_address() {
        assert_eq!(
            PeerSource::from_record(ClientId::from_u32(PeerSource::IPV6_SENTINEL), 4662),
            None,
            "0xFFFFFFFF is not 255.255.255.255"
        );
    }

    #[test]
    fn an_unusable_sentinel_address_names_no_source() {
        for refused in [
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "fd00::1",
        ] {
            let address: Ipv6Addr = refused.parse().unwrap();
            assert_eq!(
                PeerSource::from_sentinel_address(address.octets(), 4662),
                None,
                "{refused} is not a source"
            );
        }
        let global: Ipv6Addr = "2a01:4f8::11:2233".parse().unwrap();
        assert_eq!(
            PeerSource::from_sentinel_address(global.octets(), 4662),
            Some(PeerSource::Ipv6(Ipv6Endpoint::new(global, 4662)))
        );
    }
}
