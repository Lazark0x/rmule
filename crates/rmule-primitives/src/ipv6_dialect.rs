//! The IPv6 dialect's shared wire vocabulary (ADR-0087): the tag ids every
//! surface names, and the one rule that decides whether an address arriving in
//! a tag may stand as an identity at all.
//!
//! These live here rather than in `rmule-peer` because the same ids appear on
//! three surfaces — the peer hello, the server login and `OP_SERVERIDENT`, and
//! the ExtSX record — and an id that meant two different things on two of them
//! would be a wire bug nobody could see in one file.

use std::net::Ipv6Addr;

use crate::{Tag, TagName, TagValue};

/// `ST_IPV6` (`0x99`) — an IPv6 server's address in a `server.met` row, and
/// **on disk only: never on the wire**.
///
/// Named here rather than beside the file format because the three ids are
/// only unconfusable together. `0x99` is the disk tag, `0xAE`
/// ([`CT_MOD_IP_V6`]) is the client's own address going *up* to a server, and
/// `0xAF` ([`CT_MOD_SVR_IP_V6`]) is the server's own address coming *down* —
/// and the one server that implements the dialect calls `0xAE` "ST_IPV6" in
/// its own issue tracker, which is exactly the collision a reader needs the
/// three spelled out in one place to survive.
pub const ST_IPV6: u8 = 0x99;

/// `CT_EMULE_SERVINGBUDDYIPV6` (`0xA0`) — a buddy's IPv6, where ADR-0061's
/// `CT_EMULE_BUDDYIP` carries its IPv4. Client↔client.
pub const CT_EMULE_SERVINGBUDDYIPV6: u8 = 0xA0;

/// `CT_MOD_MISCOPTIONS` (`0xAA`) — the **Static Capability Claim** word.
pub const CT_MOD_MISCOPTIONS: u8 = 0xAA;

/// `ST_IPV6_STATUS` (`0xAB`) — a server's IPv6 probe verdict, `UINT8`.
/// Server→client, in `OP_SERVERIDENT`.
pub const ST_IPV6_STATUS: u8 = 0xAB;

/// A server's `ST_IPV6_STATUS` verdict on the IPv6 a client advertised
/// (ADR-0087 §1.3) — the `0xAB` tag's bitfield, kept whole.
///
/// Only one combination means anything to a client: **`PROBED` set and
/// `REACHABLE` clear** suppresses further advertisement. An absent tag and an
/// unprobed verdict never suppress, which is why the default everywhere is
/// "nothing was said" rather than "probed and failed" — a server that accepts
/// an address on trust rather than dialling back reports `HAVE | REACHABLE`
/// and never `PROBED`, so by its own design it can never suppress anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ServerIpv6Status(u32);

impl ServerIpv6Status {
    /// `IPV6ST_HAVE` — the server holds an IPv6 for this client.
    pub const HAVE: u32 = 0x01;
    /// `IPV6ST_REACHABLE` — the server reached that address.
    pub const REACHABLE: u32 = 0x02;
    /// `IPV6ST_PROBED` — the server actually dialled back rather than
    /// believing the client.
    pub const PROBED: u32 = 0x04;

    /// Wrap the advertised word. The tag SHOULD be `TAGTYPE_UINT8` but a
    /// receiver must accept any integer width, so the widest is stored and
    /// unknown bits are kept rather than masked.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The word as advertised.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether [`Self::HAVE`] is set.
    #[must_use]
    pub const fn has_address(self) -> bool {
        self.0 & Self::HAVE != 0
    }

    /// Whether [`Self::REACHABLE`] is set.
    #[must_use]
    pub const fn is_reachable(self) -> bool {
        self.0 & Self::REACHABLE != 0
    }

    /// Whether [`Self::PROBED`] is set.
    #[must_use]
    pub const fn was_probed(self) -> bool {
        self.0 & Self::PROBED != 0
    }

    /// The one combination that suppresses a client's IPv6 advertisement:
    /// probed **and** not reached. Anything else — including `HAVE` alone,
    /// `HAVE | REACHABLE` on trust, or an unknown bit — leaves the client
    /// advertising.
    #[must_use]
    pub const fn suppresses_advertisement(self) -> bool {
        self.was_probed() && !self.is_reachable()
    }
}

/// `CT_MOD_YOUR_IP` (`0xAD`) — the sender's view of *our* address. Only its
/// hash form is ever read: the integer form would let one unverified peer
/// decide what we believe our own public IPv4 to be, and a client wrong about
/// its own address is wrong about whether it is firewalled.
pub const CT_MOD_YOUR_IP: u8 = 0xAD;

/// `CT_MOD_IP_V6` (`0xAE`) — the sender's own reachable IPv6, `TAGTYPE_HASH`.
/// Client→client and client→server; the **fact** behind the `MODMISC_IPV6`
/// claim bit.
pub const CT_MOD_IP_V6: u8 = 0xAE;

/// `CT_MOD_SVR_IP_V6` (`0xAF`) — a **server's own** public IPv6. Refused in a
/// peer hello: from a peer it would name our server's address on one
/// unauthenticated party's say-so.
pub const CT_MOD_SVR_IP_V6: u8 = 0xAF;

/// Whether an IPv6 address may stand as an identity when it arrives in a
/// 16-byte tag — ADR-0087's `IsUsableTagIdentity`.
///
/// A tag carries the address and nothing else: there is no room for a scope
/// id. So a link-local peer is `fe80::1` in the tag and `fe80::1%3` on the
/// socket, and two peers on two interfaces collapse into one identity. Only a
/// global-unicast address (`2000::/3`) survives that round trip unchanged, so
/// only a global-unicast address is admitted. Dropping the scope from the
/// index instead is not the fix: `fe80::1%3` and `fe80::1%9` really are
/// different peers.
#[must_use]
pub const fn is_usable_tag_identity(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xe000) == 0x2000
}

/// One of the dialect's sixteen-byte address tags, in the **old-format**
/// length-prefixed name spelling (`01 01 00 AE …`) every hello and login
/// carries.
///
/// The value is a [`TagValue::Hash`] and never a blob. That is the whole
/// reason this lives beside the ids instead of once per surface: a writer that
/// reaches for `TAGTYPE_BLOB` emits four length bytes a `TAGTYPE_HASH` reader
/// consumes as the first four bytes of the address, and **every tag after it
/// in the packet shifts** — a fumble the one server implementing this dialect
/// made in its writing direction and had to fix.
///
/// Use [`ipv6_address_tag_compact`] where the surface writes new-format names
/// (`server.met`'s `ST_IPV6`); the two differ only in the name spelling.
#[must_use]
pub fn ipv6_address_tag(id: u8, address: Ipv6Addr) -> Tag {
    Tag::new(
        TagName::length_prefixed_id(id),
        TagValue::Hash(address.octets()),
    )
}

/// [`ipv6_address_tag`] in the **new-format** compact name spelling
/// (`81 99 …`) — what `server.met`'s `ST_IPV6` row is written with, beside the
/// compact name tags already in that file.
#[must_use]
pub fn ipv6_address_tag_compact(id: u8, address: Ipv6Addr) -> Tag {
    Tag::new(TagName::compact_id(id), TagValue::Hash(address.octets()))
}

/// The address a dialect tag carries, or `None` when the tag is not one:
/// wrong id, wrong type (the integer form of `CT_MOD_YOUR_IP` lands here), or
/// an address [`is_usable_tag_identity`] refuses.
///
/// All four outcomes are deliberately one outcome for a reader — a refused tag
/// leaves rmule where it was, never somewhere worse.
#[must_use]
pub fn read_ipv6_address_tag(tag: &Tag, id: u8) -> Option<Ipv6Addr> {
    let (Some(name), TagValue::Hash(bytes)) = (tag.name().id(), tag.value()) else {
        return None;
    };
    if name != id {
        return None;
    }
    let address = Ipv6Addr::from(*bytes);
    is_usable_tag_identity(address).then_some(address)
}

/// The key per-address **accounting** uses — a rate limit's bucket, a
/// per-address cap's slot (ADR-0087).
///
/// IPv4 accounts per exact address. IPv6 accounts per **`/64`**, not per
/// `/128`: a host is routinely delegated a whole `/64` and can mint addresses
/// inside it without asking anyone, so a per-`/128` bucket is evaded by
/// rotating the low half — including by RFC 4941 privacy addressing, which
/// does it on a timer without meaning to.
///
/// **Accounting only.** This is never an identity, never a ban scope, never an
/// index key and never a routing decision. Two hosts in one `/64` really are
/// two hosts: they must share a rate limit, and they must not share a queue
/// slot, a credit record or a reask attribution. That is why the reask
/// attribution compares the whole 128 bits and this does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccountingKey {
    /// One IPv4 address.
    V4(std::net::Ipv4Addr),
    /// The high 64 bits of an IPv6 address — its delegated prefix.
    V6Prefix(u64),
}

impl AccountingKey {
    /// The accounting key for `address`, **unmapped first** (kno's
    /// `RateLimitScope`, `src/PeerAddressing.h:227-231`, calls `Unmapped()`
    /// before keying).
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) keys as its IPv4: with no
    /// unmap every mapped address folds to `V6Prefix(0)` — the `/64` of
    /// `::/96` — so every mapped address on the network would share one
    /// bucket. [`std::net::IpAddr::to_canonical`] unmaps only that form; the
    /// deprecated IPv4-*compatible* form (`::a.b.c.d`) is a different bit
    /// pattern that `to_canonical` leaves alone (kno's own `Unmapped()` does
    /// the same — the reference has no ingress site for the compatible form
    /// at all), so it keys by its `/64` like any other native IPv6 address.
    ///
    /// This is called from construction, not at the socket: ADR-0085's Family
    /// Pairs bind `IPV6_V6ONLY`, so a socket never reports a mapped address,
    /// but `AccountingKey` is also built from a peer's *claim* — a direct
    /// callback's requester, a rate-limited source — where nothing stops one
    /// from writing its address in mapped form.
    #[must_use]
    pub fn of(address: std::net::IpAddr) -> Self {
        match address.to_canonical() {
            std::net::IpAddr::V4(ip) => Self::V4(ip),
            std::net::IpAddr::V6(ip) => Self::V6Prefix((ip.to_bits() >> 64) as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only global unicast survives the trip through a scope-less tag.
    #[test]
    fn a_tag_identity_must_be_global_unicast() {
        assert!(is_usable_tag_identity("2001:db8::1".parse().unwrap()));
        assert!(is_usable_tag_identity("2a01:4f8::1".parse().unwrap()));
        // Link-local (two interfaces, one tag), unique-local, loopback and the
        // unspecified address all name something the tag cannot disambiguate.
        assert!(!is_usable_tag_identity("fe80::1".parse().unwrap()));
        assert!(!is_usable_tag_identity("fd00::1".parse().unwrap()));
        assert!(!is_usable_tag_identity(Ipv6Addr::LOCALHOST));
        assert!(!is_usable_tag_identity(Ipv6Addr::UNSPECIFIED));
        // `::ffff:0.0.0.0` is refused by the same rule, without a special case.
        assert!(!is_usable_tag_identity("::ffff:0.0.0.0".parse().unwrap()));
    }

    /// The spec's own worked bytes for the two name spellings, and the type
    /// byte that is the whole point: `0x01` `TAGTYPE_HASH`, sixteen raw bytes,
    /// **no four-byte length prefix**. A blob here shifts every later tag in
    /// the packet.
    #[test]
    fn an_address_tag_is_sixteen_raw_bytes_under_hash_not_blob() {
        let address: Ipv6Addr = "2a01:4f8::1".parse().unwrap();
        let mut expected = vec![0x01, 0x01, 0x00, CT_MOD_IP_V6];
        expected.extend_from_slice(&address.octets());
        assert_eq!(ipv6_address_tag(CT_MOD_IP_V6, address).encode(), expected);
        assert_eq!(expected.len(), 4 + 16);

        // `server.met`'s `ST_IPV6` is the same value under the compact name.
        let mut compact = vec![0x81, ST_IPV6];
        compact.extend_from_slice(&address.octets());
        assert_eq!(ipv6_address_tag_compact(ST_IPV6, address).encode(), compact);
    }

    /// One reader, four refusals that must all read the same: wrong id, wrong
    /// type, and an address no scope-less tag can identify.
    #[test]
    fn reading_an_address_tag_refuses_the_wrong_id_type_and_scope() {
        let address: Ipv6Addr = "2a01:4f8::1".parse().unwrap();
        let tag = ipv6_address_tag(CT_MOD_IP_V6, address);
        assert_eq!(read_ipv6_address_tag(&tag, CT_MOD_IP_V6), Some(address));
        assert_eq!(read_ipv6_address_tag(&tag, CT_MOD_SVR_IP_V6), None);

        // The integer form of `CT_MOD_YOUR_IP` — one unverified party naming
        // our public IPv4 — is refused by type, not by a special case.
        let integer_form = Tag::new(
            TagName::length_prefixed_id(CT_MOD_YOUR_IP),
            TagValue::U32(0xC0A8_0001),
        );
        assert_eq!(read_ipv6_address_tag(&integer_form, CT_MOD_YOUR_IP), None);

        let link_local = ipv6_address_tag(CT_MOD_IP_V6, "fe80::1".parse().unwrap());
        assert_eq!(read_ipv6_address_tag(&link_local, CT_MOD_IP_V6), None);
    }

    /// Accounting buckets by `/64`, so rotating the low half does not buy a
    /// fresh bucket — and two addresses in *different* prefixes never share
    /// one.
    #[test]
    fn ipv6_accounting_buckets_by_prefix_and_ipv4_by_exact_address() {
        let one = AccountingKey::of("2001:db8:0:1::a".parse().unwrap());
        let rotated = AccountingKey::of("2001:db8:0:1:ffff:ffff:ffff:ffff".parse().unwrap());
        let elsewhere = AccountingKey::of("2001:db8:0:2::a".parse().unwrap());

        assert_eq!(one, rotated, "a privacy rotation stays in its own bucket");
        assert_ne!(one, elsewhere);

        // IPv4 accounts per exact address: no prefix folding, because an IPv4
        // host is not handed a range it can mint from.
        let a = AccountingKey::of("198.51.100.7".parse().unwrap());
        let b = AccountingKey::of("198.51.100.8".parse().unwrap());
        assert_ne!(a, b);
        assert_ne!(a, one, "the two families never collide");
    }

    /// A mapped address keys as its IPv4 (kno's `Unmapped()`): the whole point
    /// is that `::ffff:1.2.3.4` and `1.2.3.4` are the same accounting subject,
    /// and two different mapped addresses do not collapse into each other
    /// just because they share the `::ffff:0:0/96` prefix.
    #[test]
    fn a_mapped_address_keys_as_its_ipv4() {
        let mapped: std::net::IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        let plain: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(AccountingKey::of(mapped), AccountingKey::of(plain));

        let other_mapped: std::net::IpAddr = "::ffff:1.2.3.5".parse().unwrap();
        assert_ne!(
            AccountingKey::of(mapped),
            AccountingKey::of(other_mapped),
            "two mapped addresses are two IPv4 hosts, not one bucket"
        );
    }

    /// Unmapping is narrow: it reads only the modern mapped form
    /// (`::ffff:a.b.c.d`, all ones in bits 80-95). A native IPv6 address is
    /// untouched and still keys by `/64` — unmapping never widens.
    #[test]
    fn a_native_ipv6_address_is_not_unmapped() {
        let native: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(AccountingKey::of(native), AccountingKey::of(native));
        assert_ne!(
            AccountingKey::of(native),
            AccountingKey::of("1.2.3.4".parse().unwrap())
        );
    }

    /// The deprecated IPv4-*compatible* form (`::a.b.c.d`, bits 80-95 zero
    /// rather than all-ones) is a different bit pattern than the mapped form
    /// and is **not** unmapped — matching kno's `Unmapped()`, which only ever
    /// tests for `::ffff:0:0/96`, and the fact that no reference ingress path
    /// produces the compatible form at all. It keys by its `/64` like any
    /// other native IPv6 address, so it shares a bucket with `::` and every
    /// other address in `::/64`, not with its embedded IPv4.
    #[test]
    fn the_compatible_form_is_not_unmapped_and_keys_by_prefix() {
        let compatible: std::net::IpAddr = "::1.2.3.4".parse().unwrap();
        let native_in_same_prefix: std::net::IpAddr = "::5".parse().unwrap();
        assert_eq!(
            AccountingKey::of(compatible),
            AccountingKey::of(native_in_same_prefix)
        );
        assert_ne!(
            AccountingKey::of(compatible),
            AccountingKey::of("1.2.3.4".parse().unwrap())
        );
    }
}
