//! The `server.met` file format: the on-disk server list every eD2k client
//! ships and trades.
//!
//! Two header markers are accepted — aMule's own and the older shared one.
//! The **known.met** marker one byte past them is deliberately refused
//! (ADR-0066's header trap), because the two files are otherwise
//! indistinguishable from their first byte.
//!
//! The decoder, the row model and the duplicate-merge rule live here, one
//! contract: the merge rule is aMule's `LoadServerMet` duplicate branch, and
//! which field a fresh row may overwrite is only meaningful beside the
//! decoder that produced it. The writer is the `encode` submodule's, and a
//! row's empty name is materialised there by the same rule the reader
//! applies (`synthesize_name`). The figure and obfuscation tags are their own
//! submodules.

use std::io::Read;

use flate2::read::GzDecoder;
use rmule_primitives::{
    Ed2kText, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, ST_IPV6, Tag, TagValue, WireReader,
    read_ipv6_address_tag,
};
use thiserror::Error;

mod encode;
mod figures;
mod obfuscation;

pub use figures::ServerMetFigures;
pub use obfuscation::ServerMetObfuscation;

/// aMule's own server.met writer marks the file `0xE0`.
const HEADER_AMULE: u8 = 0xE0;
/// `MET_HEADER` in aMule's `DataFileVersion.h` — the older/eMule-shared
/// marker, also accepted. `MET_HEADER_WITH_LARGEFILES` (`0x0F`) is the
/// **known.met** header, one past this, and is deliberately NOT accepted
/// (ADR-0066's header trap).
const HEADER_MET: u8 = 0x0E;

/// Tag IDs read from a per-server tag block, per aMule
/// `src/include/tags/ServerTags.h` and `CServer::AddTagFromFile`.
const TAG_SERVERNAME: u8 = 0x01;
const TAG_DESCRIPTION: u8 = 0x0B;
const TAG_PREFERENCE: u8 = 0x0E;
/// `ST_AUXPORTSLIST` — a string of comma-separated aux TCP ports.
const TAG_AUXPORTSLIST: u8 = 0x93;

const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
const ZIP_MAGIC: [u8; 2] = [0x50, 0x4B];

/// The ceiling on a **gzip-inflated** server.met payload. The download is
/// untrusted (ADR-0065 fetcher), so a small gzip bomb could otherwise inflate
/// without bound (OOM DoS). A real server list — even tens of thousands of
/// servers — sits comfortably under this, so the cap only ever rejects an
/// adversarial stream. Mirrors `rmule_primitives::inflate`'s posture: bound the
/// *output*, not the ratio.
const MAX_INFLATED_LEN: usize = 16 * 1024 * 1024;

/// Whole-file rejection reasons for a server.met download. There is no
/// row-level variant: a malformed or truncated per-server row never
/// surfaces here — see [`ServerMet::decode`]'s truncation posture.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ServerMetError {
    /// The payload announced itself as gzip but is not a readable stream.
    #[error("server.met gzip container failed to inflate")]
    GzipInflateFailed,

    /// The gzip stream inflates past the crate's 16 MiB ceiling — a bomb, since no
    /// real server list approaches it.
    #[error("server.met gzip stream inflates past rmule's size ceiling")]
    GzipInflatedTooLarge,

    #[error(
        "server.met container looks like a zip archive; rmule does not unpack zip (ADR-0066 documented divergence)"
    )]
    /// The payload is a zip archive; rmule unpacks gzip only.
    UnsupportedContainer,

    /// The payload is empty, so there is not even a version byte to check.
    #[error("server.met payload is empty: no version byte to read")]
    MissingHeader,

    /// The first byte is not a version this format uses — the payload is
    /// something else entirely (a mirror's error page, say).
    #[error("server.met version byte 0x{byte:02X} is neither 0xE0 nor MET_HEADER (0x0E)")]
    InvalidHeader {
        /// The byte found where a version was expected.
        byte: u8,
    },
}

/// A server priority as loaded from server.met's `ST_PREFERENCE` tag.
///
/// aMule's own comment on the wire values: "Server priorities are not in
/// sorted order" — `Normal = 0`, `High = 1`, `Low = 2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerPriority {
    /// The default, wire value `0`.
    Normal,
    /// Preferred, wire value `1`.
    High,
    /// Deprioritised, wire value `2` — note the values do not sort.
    Low,
}

impl ServerPriority {
    /// Out-of-range raw values normalize to `Normal` — aMule's own
    /// `LoadServerMet` quirk-check (`SRV_PR_MIN`/`SRV_PR_MAX`), replicated
    /// verbatim per ADR-0066.
    ///
    /// Public because the wire value is also the *persisted* value: a store
    /// that keeps a server row (`rmule_core`'s managed server list, ADR-0080)
    /// writes [`to_raw`](Self::to_raw) and reads it back through here, so the
    /// file format and the database agree by construction instead of by a
    /// second hand-written mapping.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Normal,
            1 => Self::High,
            2 => Self::Low,
            _ => Self::Normal,
        }
    }

    /// The `ST_PREFERENCE` wire value the writer emits — the exact inverse of
    /// [`from_raw`](Self::from_raw) over the three in-range values (aMule
    /// `Normal = 0`, `High = 1`, `Low = 2`). Public for the same reason as
    /// [`from_raw`](Self::from_raw): persistence reuses the wire mapping.
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Normal => 0,
            Self::High => 1,
            Self::Low => 2,
        }
    }
}

/// One parsed server.met row.
///
/// `ST_SERVERNAME`/`ST_DESCRIPTION`/`ST_PREFERENCE` project onto typed
/// fields, and the figures onto [`ServerMetFigures`]; every other
/// well-formed tag is tolerantly **skipped**,
/// not preserved. This is a deliberate divergence from the ADR-0018
/// preserve-unknown-tags doctrine used elsewhere in this crate: aMule's
/// own `CServer` has no generic tag slot to preserve into (unrecognized
/// tags are simply dropped in `AddTagFromFile`), and server.met has no
/// production re-encoder for a preserved tail to ever round-trip through
/// (ADR-0066: "No production writers").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMetEntry {
    endpoint: Ipv4Endpoint,
    ipv6: Option<std::net::Ipv6Addr>,
    name: Ed2kText,
    description: Ed2kText,
    priority: ServerPriority,
    figures: ServerMetFigures,
    obfuscation: ServerMetObfuscation,
    aux_ports: Vec<u16>,
}

impl ServerMetEntry {
    /// A server.met row from its modelled fields — the writer counterpart of
    /// [`ServerMet::decode`], and how a caller builds a learned-server list to
    /// persist. The four fields are exactly what the decoder
    /// projects; an empty `name` is materialised as aMule's synthesised
    /// `Server <ip:port>` at [`ServerMet::encode`] time, matching the reader.
    #[must_use]
    pub const fn new(
        endpoint: Ipv4Endpoint,
        name: Ed2kText,
        description: Ed2kText,
        priority: ServerPriority,
    ) -> Self {
        Self {
            endpoint,
            ipv6: None,
            name,
            description,
            priority,
            figures: ServerMetFigures::NONE,
            obfuscation: ServerMetObfuscation::NONE,
            aux_ports: Vec::new(),
        }
    }

    /// This row with the aux-ports list a file recorded for the server.
    #[must_use]
    pub fn with_aux_ports(mut self, aux_ports: Vec<u16>) -> Self {
        self.aux_ports = aux_ports;
        self
    }

    /// The ports `ST_AUXPORTSLIST` named, in order, the one to dial first.
    /// Empty when the row carried none, or an empty tag, which some server.mets
    /// do (`Server.cpp:226`). The header port ([`Self::endpoint`]) is then, and
    /// when a list is present still is, the server's standard port.
    #[must_use]
    pub fn aux_ports(&self) -> &[u16] {
        &self.aux_ports
    }

    /// This row with its figures attached — what a file that recorded a
    /// server's last answer carries.
    #[must_use]
    pub fn with_figures(mut self, figures: ServerMetFigures) -> Self {
        self.figures = figures;
        self
    }

    /// This row with the obfuscation facts a file recorded for the server.
    #[must_use]
    pub const fn with_obfuscation(mut self, obfuscation: ServerMetObfuscation) -> Self {
        self.obfuscation = obfuscation;
        self
    }

    /// What the row said about obfuscated TCP: the UDP flags word and the
    /// obfuscation TCP port, each `None` when its tag was absent.
    #[must_use]
    pub const fn obfuscation(&self) -> ServerMetObfuscation {
        self.obfuscation
    }

    /// The figures the row carried: ping, counts, limits, version and the
    /// time of the last answer, each `None` when its tag was absent.
    #[must_use]
    pub const fn figures(&self) -> &ServerMetFigures {
        &self.figures
    }

    /// This row with an `ST_IPV6` (`0x99`) address attached — the writer half
    /// of ADR-0087 §4.8.
    ///
    /// An IPv6-only row pairs this with an **unspecified header IP** (`0`),
    /// which is the whole compatibility trick: stock eMule drops the unknown
    /// tag and then rejects the resulting `ip == 0` entry, so it *ignores* an
    /// IPv6 server rather than mis-dialling one. Callers that hold both
    /// families write both.
    #[must_use]
    pub const fn with_ipv6(mut self, address: std::net::Ipv6Addr) -> Self {
        self.ipv6 = Some(address);
        self
    }

    /// The row's `ST_IPV6` address, when it carried one an IPv6 tag may
    /// identify at all.
    #[must_use]
    pub const fn ipv6(&self) -> Option<std::net::Ipv6Addr> {
        self.ipv6
    }

    /// The row's IPv6 endpoint — the `ST_IPV6` address at the header's port,
    /// because `server.met` has one port field and no way to express two.
    #[must_use]
    pub const fn ipv6_endpoint(&self) -> Option<Ipv6Endpoint> {
        match self.ipv6 {
            Some(ip) => Some(Ipv6Endpoint::new(ip, self.endpoint.port)),
            None => None,
        }
    }

    /// The address a dialer should use for this row, or `None` when the row
    /// names none at all.
    ///
    /// IPv4 wins whenever the header carries one, **including on a dual row**:
    /// a HighID *is* the packed public IPv4, so reaching a dual-stack server
    /// over IPv6 costs a HighID for nothing (ADR-0087 §4.7). The `ST_IPV6`
    /// address is the answer only when there is no IPv4 to prefer.
    ///
    /// `None` is the zero-header-IP row with no `ST_IPV6` tag — precisely what
    /// stock eMule rejects when adding a server. Reading that zero as
    /// `0.0.0.0` would install a server nobody can dial, which is the
    /// never-write-a-v6-peer-as-`0` rule met from the reading side.
    #[must_use]
    pub const fn dialable_address(&self) -> Option<std::net::IpAddr> {
        if !self.endpoint.ip.is_unspecified() {
            return Some(std::net::IpAddr::V4(self.endpoint.ip));
        }
        match self.ipv6 {
            Some(ip) => Some(std::net::IpAddr::V6(ip)),
            None => None,
        }
    }

    /// Whether this row names **only** an IPv6 server: a zero header IP plus an
    /// `ST_IPV6` tag.
    ///
    /// Routability must be judged on the 128-bit address, never on the `u32`
    /// projection — that projection is `0` for every IPv6 row, so a validator
    /// reading it would reject all of them.
    #[must_use]
    pub const fn is_ipv6_only(&self) -> bool {
        self.endpoint.ip.is_unspecified() && self.ipv6.is_some()
    }

    /// The row's header endpoint as the file carries it: `0.0.0.0` on every
    /// IPv6-only row (emule-qt writes header IP 0 for them), so it is **not**
    /// an identity — [`Self::identity`] is.
    #[must_use]
    pub const fn endpoint(&self) -> Ipv4Endpoint {
        self.endpoint
    }

    /// The row's identity for merge purposes: its [`Self::dialable_address`]
    /// at the header's port. Two IPv6-only rows on one port are two servers,
    /// though both headers read `0.0.0.0:port`. A row that names no address at
    /// all keys on its header, as before.
    #[must_use]
    pub const fn identity(&self) -> PeerEndpoint {
        match self.dialable_address() {
            Some(std::net::IpAddr::V6(ip)) => {
                PeerEndpoint::V6(Ipv6Endpoint::new(ip, self.endpoint.port))
            }
            Some(std::net::IpAddr::V4(_)) | None => PeerEndpoint::V4(self.endpoint),
        }
    }

    /// Its name, byte-faithful. Empty when the file carried none; the writer
    /// synthesises `Server <ip:port>` at encode time, as the reader does.
    #[must_use]
    pub const fn name(&self) -> &Ed2kText {
        &self.name
    }

    /// Its description, byte-faithful and often empty.
    #[must_use]
    pub const fn description(&self) -> &Ed2kText {
        &self.description
    }

    /// The row's priority.
    #[must_use]
    pub const fn priority(&self) -> ServerPriority {
        self.priority
    }

    /// Fold a freshly parsed duplicate — same [`Self::identity`] — into an
    /// already-installed entry. Mirrors aMule's `LoadServerMet` duplicate
    /// branch verbatim: `listname` always takes the fresh value,
    /// `description` only takes it when non-empty, and every other field
    /// — `priority` included — stays `self`'s. Not a general overwrite
    /// merge; this is the "parse-before-install" contract ADR-0066 pins
    /// for the caller that reconciles a download against a known-server
    /// registry (out of this decoder's scope).
    #[must_use]
    pub fn merge(mut self, fresh: Self) -> Self {
        debug_assert_eq!(
            self.identity(),
            fresh.identity(),
            "ServerMetEntry::merge expects both entries to share an identity"
        );
        self.name = fresh.name;
        if !fresh.description.as_bytes().is_empty() {
            self.description = fresh.description;
        }
        // `ST_IPV6` follows `description`'s rule rather than `listname`'s: a
        // fresh row that carries no address says nothing about the family, and
        // forgetting the one we hold would make an IPv6 server undialable
        // because a v4-only mirror listed it too.
        if fresh.ipv6.is_some() {
            self.ipv6 = fresh.ipv6;
        }
        // The figures go with the later answer: a row that heard the
        // server more recently replaces them, an older or timeless one does
        // not.
        if fresh.figures.last_ping.unwrap_or(0) > self.figures.last_ping.unwrap_or(0) {
            self.figures = fresh.figures;
        }
        // Obfuscation facts follow `description`'s rule: a fresh row silent
        // about a fact does not unlearn it.
        self.obfuscation = self.obfuscation.overlaid_by(fresh.obfuscation);
        // The ports we hold to dial a server on are not a mirror's to change;
        // a row with none takes the fresh row's.
        if self.aux_ports.is_empty() {
            self.aux_ports = fresh.aux_ports;
        }
        self
    }
}

/// A fully parsed server.met payload — the decoder's whole observable
/// output for one download. A later caller (ADR-0065's fetcher/installer,
/// not this decoder) reconciles `entries()` against its own
/// known-server registry via [`ServerMetEntry::merge`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMet {
    entries: Vec<ServerMetEntry>,
    declared_count: u32,
    /// The file ended inside the 4-byte count, so no count was declared at all.
    count_truncated: bool,
}

impl ServerMet {
    /// Decode a downloaded server.met payload.
    ///
    /// Unwraps a **gzip** container transparently (rejecting a stream that
    /// inflates past the 16 MiB ceiling); a **zip** container is rejected
    /// (documented divergence, ADR-0066); anything else is treated as an
    /// already-plain server.met. After the leading version byte validates,
    /// rows stream as `ip4/port2/tagcount4` + tags. A row that runs out of
    /// bytes or fails to decode ends the walk — every row parsed before it is
    /// still returned, matching aMule's own single whole-file exception
    /// boundary around `LoadServerMet` (an error partway through leaves every
    /// already-added server in place). Such a short read is not silent:
    /// [`Self::is_truncated`] reports it against the header's declared count.
    pub fn decode(raw: &[u8]) -> Result<Self, ServerMetError> {
        let body = unwrap_container(raw)?;
        let (entries, declared_count) = parse_entries(&body)?;
        Ok(Self {
            entries,
            declared_count: declared_count.unwrap_or(0),
            count_truncated: declared_count.is_none(),
        })
    }

    /// The rows parsed, in file order. Fewer than
    /// [`Self::declared_count`] when the walk stopped early.
    #[must_use]
    pub fn entries(&self) -> &[ServerMetEntry] {
        &self.entries
    }

    /// Take the parsed rows, consuming the decoded file.
    #[must_use]
    pub fn into_entries(self) -> Vec<ServerMetEntry> {
        self.entries
    }

    /// The server count the file header declared. A well-formed download has
    /// `declared_count() == entries().len()`; a larger value means the row walk
    /// stopped early on a truncated or undecodable row.
    #[must_use]
    pub const fn declared_count(&self) -> u32 {
        self.declared_count
    }

    /// Whether the row walk ended before the header's declared count — a
    /// truncated or partially-corrupt download. Lets a caller surface a short
    /// read instead of treating a corrupt file as a merely-small server list.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.count_truncated || self.declared_count as usize > self.entries.len()
    }
}

/// The ports of an `ST_AUXPORTSLIST` string. A part that is not a non-zero
/// port is left out; aMule reads only the first with `StrToULong`.
fn parse_aux_ports(list: &str) -> Vec<u16> {
    list.split(',')
        .filter_map(|part| part.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .collect()
}

fn unwrap_container(raw: &[u8]) -> Result<Vec<u8>, ServerMetError> {
    if raw.starts_with(&GZIP_MAGIC) {
        inflate_gzip_capped(raw, MAX_INFLATED_LEN)
    } else if raw.starts_with(&ZIP_MAGIC) {
        Err(ServerMetError::UnsupportedContainer)
    } else {
        Ok(raw.to_vec())
    }
}

/// Inflate a gzip container, rejecting a stream that expands past `cap` bytes.
/// The download is untrusted (ADR-0065 fetcher); an uncapped inflate lets a
/// tiny gzip bomb exhaust memory. Reads one byte past `cap` so an over-cap
/// stream is detectable, then refuses it — bounding the *output* the same way
/// `rmule_primitives::inflate` bounds the packed-frame path.
fn inflate_gzip_capped(raw: &[u8], cap: usize) -> Result<Vec<u8>, ServerMetError> {
    let mut inflated = Vec::new();
    GzDecoder::new(raw)
        .take(cap as u64 + 1)
        .read_to_end(&mut inflated)
        .map_err(|_| ServerMetError::GzipInflateFailed)?;
    if inflated.len() > cap {
        return Err(ServerMetError::GzipInflatedTooLarge);
    }
    Ok(inflated)
}

/// Parse the version byte and the row stream, returning the rows recovered and
/// the header's declared server count (`None` when the count field itself was
/// truncated). The caller compares the two to detect a short read.
fn parse_entries(body: &[u8]) -> Result<(Vec<ServerMetEntry>, Option<u32>), ServerMetError> {
    let (&header, rest) = body.split_first().ok_or(ServerMetError::MissingHeader)?;
    if header != HEADER_AMULE && header != HEADER_MET {
        return Err(ServerMetError::InvalidHeader { byte: header });
    }

    let mut reader = WireReader::new(rest);
    // A count too short to read is the same "whole-file catch, keep
    // what's already loaded" posture as any other truncation — nothing had
    // loaded yet, so the list is empty, but `is_truncated` still reports it.
    let Some(count) = reader.read_u32_le("server count").ok() else {
        return Ok((Vec::new(), None));
    };

    let mut entries = Vec::new();
    for _ in 0..count {
        match decode_entry(&mut reader) {
            Some(entry) => entries.push(entry),
            None => break,
        }
    }
    Ok((entries, Some(count)))
}

fn decode_entry(reader: &mut WireReader<'_>) -> Option<ServerMetEntry> {
    let endpoint = Ipv4Endpoint::decode(
        &reader
            .read_array::<{ Ipv4Endpoint::WIRE_LEN }>("server endpoint")
            .ok()?,
    );
    let tag_count = reader.read_u32_le("server tag count").ok()?;

    let mut name = Ed2kText::from_bytes(Vec::new());
    let mut description = Ed2kText::from_bytes(Vec::new());
    let mut priority = ServerPriority::Normal;
    let mut ipv6 = None;
    let mut figures = ServerMetFigures::default();
    let mut obfuscation = ServerMetObfuscation::NONE;
    let mut aux_ports = Vec::new();

    for _ in 0..tag_count {
        let (tag, consumed) = Tag::decode_prefix(reader.remaining_bytes()).ok()?;
        reader.skip(consumed, "server tag").ok()?;
        match (tag.name().id(), tag.value()) {
            // First tag wins within one row — aMule's own
            // `if (listname.IsEmpty())` / `if (description.IsEmpty())`
            // guards in `AddTagFromFile`.
            (Some(TAG_SERVERNAME), TagValue::String(text)) if name.as_bytes().is_empty() => {
                name = text.clone();
            }
            (Some(TAG_DESCRIPTION), TagValue::String(text))
                if description.as_bytes().is_empty() =>
            {
                description = text.clone();
            }
            (Some(TAG_PREFERENCE), TagValue::U32(raw)) => {
                priority = ServerPriority::from_raw(*raw);
            }
            // `ST_IPV6` (ADR-0087 §4.8): first tag wins, as the spec requires
            // outright — "a second `ST_IPV6` tag MUST NOT overwrite the
            // first". `read_ipv6_address_tag` also refuses the blob form and
            // any address a scope-less 16-byte tag cannot identify, so a row
            // carrying `fe80::1` keeps its IPv4 half and loses only the tag.
            (Some(ST_IPV6), _) if ipv6.is_none() => {
                ipv6 = read_ipv6_address_tag(&tag, ST_IPV6);
            }
            // `ST_AUXPORTSLIST`: a non-empty list replaces an earlier one, an
            // empty tag says nothing (`Server.cpp:222-231`).
            (Some(TAG_AUXPORTSLIST), TagValue::String(text)) => {
                let ports = parse_aux_ports(&text.to_display_string());
                if !ports.is_empty() {
                    aux_ports = ports;
                }
            }
            // The figures, and every other tag tolerantly skipped —
            // see `ServerMetEntry`'s doc comment.
            _ => {
                figures.read(&tag);
                obfuscation.read(&tag);
            }
        }
    }

    if name.as_bytes().is_empty() {
        name = synthesize_name(endpoint, ipv6);
    }

    Some(ServerMetEntry {
        endpoint,
        ipv6,
        name,
        description,
        priority,
        figures,
        obfuscation,
        aux_ports,
    })
}

/// aMule's `Server <ip:port>` for a nameless row, spelled from the address a
/// dialer would use: an IPv6-only row reads `Server [v6]:port`, never the
/// `0.0.0.0` its header carries.
fn synthesize_name(endpoint: Ipv4Endpoint, ipv6: Option<std::net::Ipv6Addr>) -> Ed2kText {
    match ipv6 {
        Some(ip) if endpoint.ip.is_unspecified() => {
            Ed2kText::from_utf8(format!("Server {}", Ipv6Endpoint::new(ip, endpoint.port)))
        }
        _ => Ed2kText::from_utf8(format!("Server {}:{}", endpoint.ip, endpoint.port)),
    }
}

#[cfg(test)]
mod tests;
