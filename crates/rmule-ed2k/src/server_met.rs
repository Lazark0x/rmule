//! The `server.met` file format: the on-disk server list every eD2k client
//! ships and trades.
//!
//! Two header markers are accepted — aMule's own and the older shared one.
//! The **known.met** marker one byte past them is deliberately refused
//! (ADR-0066's header trap), because the two files are otherwise
//! indistinguishable from their first byte.
//!
//! Decoder, row model and duplicate-merge rule stay in one file on purpose.
//! They are one contract, not three: the merge rule is aMule's `LoadServerMet`
//! duplicate branch — which field a fresh row may overwrite is only meaningful
//! beside the decoder that produced it — and a row's empty name is
//! materialised at encode time by the same rule the reader applies. Splitting
//! them would put two halves of one behaviour a file apart. (The production
//! half is under the 500-line soft target; the rest of the file is its inline
//! tests, which the conventions keep beside the code they exercise.)

use std::io::Read;

use flate2::read::GzDecoder;
use rmule_primitives::{
    Ed2kText, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint, ST_IPV6, Tag, TagName, TagValue,
    ipv6_address_tag_compact, read_ipv6_address_tag,
};
use thiserror::Error;

mod figures;

pub use figures::ServerMetFigures;

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
        }
    }

    /// This row with its figures attached — what a file that recorded a
    /// server's last answer carries.
    #[must_use]
    pub fn with_figures(mut self, figures: ServerMetFigures) -> Self {
        self.figures = figures;
        self
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
            declared_count,
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
        self.declared_count as usize > self.entries.len()
    }

    /// Wrap a learned-server list for [`encode`](Self::encode); the declared
    /// count is the entry count, so the result is never [`is_truncated`](Self::is_truncated).
    #[must_use]
    pub fn from_entries(entries: Vec<ServerMetEntry>) -> Self {
        let declared_count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        Self {
            entries,
            declared_count,
        }
    }

    /// Encode a learned-server list as an aMule-readable server.met, the
    /// symmetric writer for [`decode`](Self::decode). Header
    /// `0xE0` (aMule's own `SaveServerMet` marker), a `u32` server count, then
    /// per row `ip4/port2/tagcount4` and the tags.
    ///
    /// ## Documented divergence — a lossy, not byte-exact, re-encode
    ///
    /// This does **not** reproduce aMule's `SaveServerMet` bytes, and cannot:
    /// aMule writes twelve-plus tags per row (users/files/ping/… and each
    /// string tag twice, a BOM-unicode copy then a plain one), but the decoder
    /// models only name/description/priority and the figures — every other tag
    /// is dropped on read (ADR-0066: "server.met has no production re-encoder
    /// for a preserved tail"). So the writer emits exactly those, each string
    /// tag once;
    /// the file **field**-round-trips through [`decode`](Self::decode) and reads
    /// cleanly in aMule (`ST_SERVERNAME`/`ST_DESCRIPTION`/`ST_PREFERENCE` are
    /// `AddTagFromFile`-recognised), it is simply smaller than aMule's own.
    /// `ST_PREFERENCE` is always written (aMule always does); the name and
    /// description tags only when non-empty, matching `SaveServerMet`'s
    /// `!IsEmpty()` guards.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![HEADER_AMULE];
        // Count the rows actually written below — never the (possibly larger)
        // declared count a truncated decode carried, which would promise rows
        // the body lacks.
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.endpoint.encode());

            let mut tags = Vec::with_capacity(4);
            // aMule synthesises "Server <ip:port>" for a nameless server on
            // read; the writer materialises it so a decode → encode → decode
            // round-trip is a fixed point (no name flips to empty).
            let name = if entry.name.as_bytes().is_empty() {
                synthesize_name(entry.endpoint, entry.ipv6)
            } else {
                entry.name.clone()
            };
            tags.push(Tag::new(
                TagName::compact_id(TAG_SERVERNAME),
                TagValue::String(name),
            ));
            if !entry.description.as_bytes().is_empty() {
                tags.push(Tag::new(
                    TagName::compact_id(TAG_DESCRIPTION),
                    TagValue::String(entry.description.clone()),
                ));
            }
            tags.push(Tag::new(
                TagName::compact_id(TAG_PREFERENCE),
                TagValue::U32(entry.priority.to_raw()),
            ));
            // `ST_IPV6` rides as a new-format `TAGTYPE_HASH` — `81 99` then
            // sixteen raw network-order bytes (ADR-0087 §4.8). Written only
            // when the row holds one, so a v4 file stays byte-identical to
            // what it was before this tag existed.
            if let Some(address) = entry.ipv6 {
                tags.push(ipv6_address_tag_compact(ST_IPV6, address));
            }
            // The figures the row holds, each only when present, in
            // the tags aMule reads them from.
            tags.extend(entry.figures.tags());

            let tag_count = u32::try_from(tags.len()).expect("a row's tags fit u32");
            out.extend_from_slice(&tag_count.to_le_bytes());
            for tag in &tags {
                out.extend(tag.encode());
            }
        }
        out
    }
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
/// the header's declared server count (`0` when the count field itself was
/// truncated). The caller compares the two to detect a short read.
fn parse_entries(body: &[u8]) -> Result<(Vec<ServerMetEntry>, u32), ServerMetError> {
    let (&header, rest) = body.split_first().ok_or(ServerMetError::MissingHeader)?;
    if header != HEADER_AMULE && header != HEADER_MET {
        return Err(ServerMetError::InvalidHeader { byte: header });
    }

    let mut cursor = Cursor::new(rest);
    // A count too short to read is the same "whole-file catch, keep
    // what's already loaded" posture as any other truncation — here
    // nothing had loaded yet, so the honest answer is an empty list.
    let Some(count) = cursor.read_u32() else {
        return Ok((Vec::new(), 0));
    };

    let mut entries = Vec::new();
    for _ in 0..count {
        match decode_entry(&mut cursor) {
            Some(entry) => entries.push(entry),
            None => break,
        }
    }
    Ok((entries, count))
}

fn decode_entry(cursor: &mut Cursor<'_>) -> Option<ServerMetEntry> {
    let endpoint = cursor.read_endpoint()?;
    let tag_count = cursor.read_u32()?;

    let mut name = Ed2kText::from_bytes(Vec::new());
    let mut description = Ed2kText::from_bytes(Vec::new());
    let mut priority = ServerPriority::Normal;
    let mut ipv6 = None;
    let mut figures = ServerMetFigures::default();

    for _ in 0..tag_count {
        let (tag, consumed) = Tag::decode_prefix(cursor.remaining_bytes()).ok()?;
        cursor.advance(consumed)?;
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
            // The figures, and every other tag tolerantly skipped —
            // see `ServerMetEntry`'s doc comment.
            _ => figures.read(&tag),
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

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining_bytes(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    fn advance(&mut self, len: usize) -> Option<()> {
        let end = self.pos.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let start = self.pos;
        self.advance(len)?;
        Some(&self.bytes[start..self.pos])
    }

    fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes(bytes.try_into().expect("4-byte slice")))
    }

    fn read_endpoint(&mut self) -> Option<Ipv4Endpoint> {
        let bytes = self.take(Ipv4Endpoint::WIRE_LEN)?;
        Some(Ipv4Endpoint::decode(
            bytes.try_into().expect("`take` guarantees exact length"),
        ))
    }
}

#[cfg(test)]
mod tests;
