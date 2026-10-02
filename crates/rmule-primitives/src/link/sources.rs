//! A file link's classic source hints (ADR-0089): the peers
//! its `sources,` tokens name — aMule's `<host>:<port>[:<crypt>[:<hash>]]`
//! entries and eMule's `sources@YYMMDD,` expiring form — and the web sources
//! its `s=` fields name. Reading is tolerant: a bad entry is skipped, never
//! fatal, because the link is complete without any of its hints.

use std::fmt::{self, Write as _};
use std::net::Ipv4Addr;

use crate::{SourceCryptOptions, UserHash};

/// The crypt byte's bit that says a user hash follows it (aMule
/// `ED2KLink.cpp:221`, "source ready for encryption, hash included").
const CRYPT_HASH_INCLUDED: u8 = 0x80;

/// Longest host name a peer entry may carry — the DNS limit.
const MAX_HOST_NAME_LEN: usize = 253;

/// The source hints of a file link beside its `s6=` IPv6 hints.
///
/// Hints, not identity: a link means the same file whatever it carries here,
/// and every entry is an unverified claim of where the file might be. Most
/// links carry none, and every download's file link holds one of these, so
/// the empty value costs a pointer and the hints live behind it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkSources(Option<Box<Hints>>);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Hints {
    peers: Vec<LinkPeer>,
    web: Vec<String>,
}

impl LinkSources {
    /// The hints `peers` (the `sources,` tokens', in the order written) and
    /// `web` (the `s=` URLs, kept as written).
    #[must_use]
    pub fn new(peers: Vec<LinkPeer>, web: Vec<String>) -> Self {
        if peers.is_empty() && web.is_empty() {
            return Self(None);
        }
        Self(Some(Box::new(Hints { peers, web })))
    }

    /// The `sources,` tokens' peers, in the order they were written.
    #[must_use]
    pub fn peers(&self) -> &[LinkPeer] {
        self.0.as_ref().map_or(&[], |hints| &hints.peers)
    }

    /// The `s=` web sources, kept as written. rmule downloads nothing over
    /// HTTP; they are read because eMule reads them.
    #[must_use]
    pub fn web(&self) -> &[String] {
        self.0.as_ref().map_or(&[], |hints| &hints.web)
    }

    /// Whether the link carried no classic hint at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

/// One peer a `sources,` token names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkPeer {
    /// Where the peer is: an address, or a name to resolve first.
    pub host: LinkPeerHost,
    /// The peer's TCP port; never zero.
    pub port: u16,
    /// aMule's third field: the peer's crypt byte, as its source-exchange
    /// entry would carry it.
    pub crypt: Option<SourceCryptOptions>,
    /// aMule's fourth field, present exactly when the crypt byte sets bit
    /// `0x80`: the user hash an obfuscated dial is keyed on.
    pub user_hash: Option<UserHash>,
    /// eMule's `sources@YYMMDD,` date: from the start of that day (UTC) the
    /// entry is no longer a source.
    pub expires: Option<LinkSourceExpiry>,
}

/// Where a link's peer is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LinkPeerHost {
    /// An IPv4 literal.
    Ipv4(Ipv4Addr),
    /// A host name, lower-cased, resolved when the download starts.
    Name(String),
}

impl fmt::Display for LinkPeerHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(ip) => write!(f, "{ip}"),
            Self::Name(name) => f.write_str(name),
        }
    }
}

/// The day an expiring `sources@YYMMDD,` token stops naming sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkSourceExpiry {
    year: u16,
    month: u8,
    day: u8,
}

impl LinkSourceExpiry {
    /// The date, when it is one: `year` 2000..=2099 (the token's two digits),
    /// `month` 1..=12, `day` 1..=31.
    #[must_use]
    pub const fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        if year < 2000 || year > 2099 || month == 0 || month > 12 || day == 0 || day > 31 {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// The year, 2000..=2099.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    /// The month, 1..=12.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, 1..=31.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// Whether the entry has expired at `unix_seconds`: eMule's
    /// `tExpire <= time(NULL)` against the day's start, read as UTC where
    /// eMule's `mktime` reads local time.
    #[must_use]
    pub fn has_passed(self, unix_seconds: u64) -> bool {
        self.start_unix_seconds() <= unix_seconds
    }

    /// Seconds from the Unix epoch to 00:00 UTC of the day (the civil-date
    /// day count of H. Hinnant's `days_from_civil`).
    fn start_unix_seconds(self) -> u64 {
        let (month, day) = (u64::from(self.month), u64::from(self.day));
        let year = u64::from(self.year) - u64::from(month <= 2);
        let era = year / 400;
        let year_of_era = year - era * 400;
        let shifted_month = (month + 9) % 12;
        let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        days * 86_400
    }
}

/// Read one `sources` field (its name already matched, case-insensitively) into
/// `peers`, taking at most `room` entries. A malformed `@` date costs that
/// token's entries, never the link.
pub(super) fn read_sources_token(field: &str, room: usize, peers: &mut Vec<LinkPeer>) {
    let rest = &field["sources".len()..];
    let (expires, entries) = match rest.strip_prefix('@') {
        Some(dated) => {
            let Some((date, entries)) = dated.split_once(',') else {
                return;
            };
            let Some(expires) = parse_expiry(date) else {
                return;
            };
            (Some(expires), entries)
        }
        None => match rest.strip_prefix(',') {
            Some(entries) => (None, entries),
            None => return,
        },
    };
    peers.extend(
        entries
            .split(',')
            .filter_map(|entry| read_peer(entry.trim(), expires))
            .take(room),
    );
}

/// eMule's `YYMMDD`, read as the years 2000..=2099.
fn parse_expiry(date: &str) -> Option<LinkSourceExpiry> {
    if date.len() != 6 || !date.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let two = |at: usize| date[at..at + 2].parse::<u8>().ok();
    LinkSourceExpiry::new(2000 + u16::from(two(0)?), two(2)?, two(4)?)
}

/// One `<host>:<port>[:<crypt>[:<hash>]]` entry, or `None` for one that
/// names no dialable peer.
fn read_peer(entry: &str, expires: Option<LinkSourceExpiry>) -> Option<LinkPeer> {
    let mut parts = entry.split(':');
    let host = read_host(parts.next()?)?;
    let port = parts
        .next()?
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)?;
    let crypt = match parts.next() {
        None | Some("") => None,
        Some(byte) => Some(SourceCryptOptions::from_byte(byte.parse().ok()?)),
    };
    let user_hash = match crypt {
        Some(crypt) if crypt.as_byte() & CRYPT_HASH_INCLUDED != 0 => {
            Some(UserHash::from_hex(parts.next()?).ok()?)
        }
        _ => None,
    };
    Some(LinkPeer {
        host,
        port,
        crypt,
        user_hash,
        expires,
    })
}

/// An IPv4 literal, else a plausible host name; neither for the unspecified
/// address or text no resolver would take.
fn read_host(host: &str) -> Option<LinkPeerHost> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return (!ip.is_unspecified()).then_some(LinkPeerHost::Ipv4(ip));
    }
    let plausible = !host.is_empty()
        && host.len() <= MAX_HOST_NAME_LEN
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        // A dotted-digit string that failed as IPv4 is a bad address, not a name.
        && !host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.');
    plausible.then(|| LinkPeerHost::Name(host.to_ascii_lowercase()))
}

/// An `s=` value eMule would take as a web source: a URL with a scheme and a
/// host (its `InternetCrackUrl` gate).
pub(super) fn read_web_source(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    let host = rest.split(['/', ':', '?', '#']).next()?;
    let valid_scheme = !scheme.is_empty()
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    (valid_scheme && !host.is_empty()).then(|| value.to_owned())
}

/// The `sources` tokens that write `peers` back, one per run of peers
/// sharing an expiry, each preceded by its `|` separator.
pub(super) fn write_sources_tokens(out: &mut String, peers: &[LinkPeer]) {
    for group in peers.chunk_by(|a, b| a.expires == b.expires) {
        out.push_str("|sources");
        if let Some(expires) = group[0].expires {
            let _ = write!(
                out,
                "@{:02}{:02}{:02}",
                expires.year - 2000,
                expires.month,
                expires.day
            );
        }
        for peer in group {
            let _ = write!(out, ",{}:{}", peer.host, peer.port);
            if let Some(crypt) = peer.crypt {
                let _ = write!(out, ":{}", crypt.as_byte());
            }
            if let Some(hash) = peer.user_hash {
                let _ = write!(out, ":{}", hash.to_hex_upper());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The day count is a calendar, not a ceremony: 2026-09-30 00:00 UTC is
    /// 1_790_726_400, and a leap day sits between February and March.
    #[test]
    fn an_expiry_starts_at_the_utc_midnight_of_its_day() {
        let day = LinkSourceExpiry::new(2026, 9, 30).unwrap();
        assert_eq!(day.start_unix_seconds(), 1_790_726_400);
        assert!(day.has_passed(1_790_726_400));
        assert!(!day.has_passed(1_790_726_399));
        let march = LinkSourceExpiry::new(2024, 3, 1).unwrap();
        let february = LinkSourceExpiry::new(2024, 2, 28).unwrap();
        assert_eq!(
            march.start_unix_seconds() - february.start_unix_seconds(),
            2 * 86_400
        );
    }
}
