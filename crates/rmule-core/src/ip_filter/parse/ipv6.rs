//! The ipfilter dat **IPv6 rule grammar** (ADR-0085): the shapes amule-kno
//! (`IPFilterMatch.h:214-266`) and emule-qt (`IPFilter.cpp:173-210`,
//! `:658-708`) read from the same files as the IPv4 ranges.
//!
//! A line is an IPv6 rule only when its first field (everything before the
//! first comma) holds a colon, as kno decides it; a line that does not parse
//! here falls through to the IPv4 grammar untouched. The range is a prefix
//! `addr/len`, a bare literal (`/128`) or emule-qt's `start - end`, optionally
//! behind emule-qt's `description:` prefix. The tail `, level , description`
//! is optional, and a level that is missing or is not a number below 256 is
//! 0, kno's default: blocked at every threshold.

use std::net::Ipv6Addr;

/// One IPv6 rule: the inclusive range as numeric addresses, and its level.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::ip_filter) struct Ipv6Rule {
    pub(in crate::ip_filter) start: u128,
    pub(in crate::ip_filter) end: u128,
    pub(in crate::ip_filter) level: u8,
}

/// The line as an IPv6 rule, or `None` when it is not one.
pub(super) fn parse_ipv6_rule(line: &[u8]) -> Option<Ipv6Rule> {
    let (spec, tail) = match line.iter().position(|&b| b == b',') {
        Some(comma) => (&line[..comma], Some(&line[comma + 1..])),
        None => (line, None),
    };
    if !spec.contains(&b':') || matches!(trim(spec).first(), Some(b';' | b'#')) {
        return None;
    }
    let (start, end) = parse_range(spec).or_else(|| behind_description(spec))?;
    Some(Ipv6Rule {
        start,
        end,
        level: tail.map_or(0, level),
    })
}

/// emule-qt's PeerGuardian-style `description:<range>`. The description is
/// text: it holds no colon of its own and at least one byte no IPv6 literal
/// holds. Every IPv6 literal holds colons, so without both a malformed or
/// reversed range would read as a rule naming a fragment of itself
/// (`2001:db8::1-2001:db8::ff` would block `db8::ff`).
fn behind_description(spec: &[u8]) -> Option<(u128, u128)> {
    let colon = spec.iter().position(|&b| b == b':')?;
    let description = &spec[..colon];
    let in_a_literal = |b: &u8| b.is_ascii_hexdigit() || *b == b'.';
    if description.iter().all(in_a_literal) {
        return None;
    }
    parse_range(&spec[colon + 1..])
}

/// `addr/len`, `start - end` or a bare literal, as an inclusive range.
fn parse_range(spec: &[u8]) -> Option<(u128, u128)> {
    let spec = std::str::from_utf8(trim(spec)).ok()?;
    if let Some((address, length)) = spec.split_once('/') {
        let length = length.trim_matches([' ', '\t']);
        if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let length: u32 = length.parse().ok().filter(|&length| length <= 128)?;
        let address = u128::from(literal(address)?);
        let host_bits = u128::MAX.checked_shr(length).unwrap_or(0);
        return Some((address & !host_bits, address | host_bits));
    }
    if let Some((start, end)) = spec.split_once(" - ") {
        let (start, end) = (u128::from(literal(start)?), u128::from(literal(end)?));
        return (start <= end).then_some((start, end));
    }
    let address = u128::from(literal(spec)?);
    Some((address, address))
}

fn literal(text: &str) -> Option<Ipv6Addr> {
    text.trim_matches([' ', '\t']).parse().ok()
}

/// The level field of the tail: up to the second comma, a number below 256,
/// else 0.
fn level(tail: &[u8]) -> u8 {
    let field = tail.split(|&b| b == b',').next().unwrap_or_default();
    std::str::from_utf8(trim(field))
        .ok()
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}

/// `[ \t\r]*` stripped from both ends, the lexer's `WS` class.
fn trim(bytes: &[u8]) -> &[u8] {
    let is_ws = |b: &u8| matches!(b, b' ' | b'\t' | b'\r');
    let start = bytes.iter().position(|b| !is_ws(b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_ws(b))
        .map_or(start, |end| end + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> u128 {
        u128::from(text.parse::<Ipv6Addr>().unwrap())
    }

    fn rule(line: &str) -> Option<(u128, u128, u8)> {
        parse_ipv6_rule(line.as_bytes()).map(|rule| (rule.start, rule.end, rule.level))
    }

    /// Every shape both references read: a prefix, a bare literal, a range
    /// and the description prefix, with and without the level tail.
    #[test]
    fn every_shape_the_references_read_is_one_rule() {
        let db8 = (
            address("2001:db8::"),
            address("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
        );
        assert_eq!(rule("2001:db8::/32"), Some((db8.0, db8.1, 0)));
        assert_eq!(
            rule("  2001:db8::/32 , 100 , an ISP\r"),
            Some((db8.0, db8.1, 100))
        );
        assert_eq!(rule("Evil Corp:2001:db8::/32"), Some((db8.0, db8.1, 0)));
        assert_eq!(
            rule("2001:db8::1 - 2001:db8::ff , 3 , a range"),
            Some((address("2001:db8::1"), address("2001:db8::ff"), 3))
        );
        assert_eq!(
            rule("2001:db8::7"),
            Some((address("2001:db8::7"), address("2001:db8::7"), 0))
        );
        assert_eq!(rule("::/0"), Some((0, u128::MAX, 0)));
    }

    /// A prefix length that splits a byte, as kno tests it: `/33` keeps the
    /// top bit of the third group and frees the rest.
    #[test]
    fn a_prefix_that_splits_a_byte_covers_exactly_its_half() {
        let (start, end, _) = rule("2001:db8:8000::/33").unwrap();
        assert_eq!(start, address("2001:db8:8000::"));
        assert_eq!(end, address("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert_eq!(
            rule("2001:db8:ffff::5/33").map(|(start, end, _)| (start, end)),
            Some((start, end)),
            "an address with host bits set names the same prefix"
        );
    }

    /// A missing or unreadable level is 0, blocked at every threshold.
    #[test]
    fn a_missing_or_unreadable_level_is_zero() {
        for line in [
            "2001:db8::/32",
            "2001:db8::/32 ,",
            "2001:db8::/32 , , no level",
            "2001:db8::/32 , high , words",
            "2001:db8::/32 , 256 , too big",
        ] {
            assert_eq!(rule(line).map(|(.., level)| level), Some(0), "{line}");
        }
    }

    /// What is not an IPv6 rule falls through to the IPv4 grammar: every IPv4
    /// form, a comment, an out-of-range prefix, a reversed range, and a
    /// malformed range whose fragment would otherwise read as a rule.
    #[test]
    fn what_is_not_an_ipv6_rule_falls_through() {
        for line in [
            "1.2.3.4 - 1.2.3.5 , 0 , v4 peer guardian",
            "Some Evil Corp:10.0.0.0-10.0.0.255",
            "# 2001:db8::/32",
            "; 2001:db8::/32",
            "2001:db8::/129",
            "2001:db8::/",
            "2001:db8::ff - 2001:db8::1",
            "2001:db8::1-2001:db8::ff",
            "fe80::1%eth0",
            "",
        ] {
            assert_eq!(rule(line), None, "{line}");
        }
    }
}
