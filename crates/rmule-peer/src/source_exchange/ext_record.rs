//! The **ExtSX record** (ADR-0087): source exchange's variable-length entry
//! form, admitted into rmule as the IPv6 carrier and nothing else.
//!
//! A classic entry is a fixed stride, so a reader validates it by arithmetic:
//! `count × stride == body`. An ExtSX record is a header plus a tag list, so
//! that check has no meaning and is replaced by bounds-checked reads with a
//! truncation guard. The tags are where IPv6 enters source exchange at all —
//! without them rmule could never *receive* an IPv6 source from a peer.
//!
//! ```text
//! uint32  clientID        the source's 32-bit id, octets in wire order
//! uint16  tcpPort         one port, both families
//! uint8   tagCount
//! tagCount × new-format tag
//! ```
//!
//! Two rules keep a malformed record from costing more than itself:
//!
//! * **Unknown tags are skipped by type, never fatal.** eMuleAI returns out of
//!   its whole `AddClientSources` on one unrecognised tag, losing every source
//!   in the packet including the ones it already accepted. `MODMISC_EXTXS_SKIPTAGS`
//!   exists to work around that bug; rmule has the bug's fix instead, and
//!   claims the bit honestly.
//! * **The two families are judged independently.** A record is discarded only
//!   when *both* are unusable — in particular a Low-ID source carrying a usable
//!   IPv6 survives, which is the exact inverse of the classic Low-ID rule.
//!
//! Emission is gated: the record form goes only to a peer that advertised
//! `MODMISC_EXTXS`, and its two optional identity tags only to a peer that also
//! advertised `MODMISC_EXTXS_SKIPTAGS`. A receiver accepts both from anyone.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::{
    CT_MOD_IP_V6, ClientId, Ipv4Endpoint, Ipv6Endpoint, PeerSource, PrimitiveError,
    SourceCryptOptions, SourceSighting, Tag, TagName, TagValue, UserHash, WireReader,
    WireTruncated, is_usable_tag_identity,
};
use thiserror::Error;

use super::entry::SourceExchangeEntry;

/// The source-exchange version an ExtSX answer declares. Pinned at 1 and not
/// to be raised: version 2 and above re-enable the classic optional tail,
/// which an ExtSX reader has no way to tell from a tag list.
pub(crate) const EXT_SX_VERSION: u8 = 1;

/// `CT_EMULE_SERVERIP` — the declaring server's address, always paired with
/// [`CT_EMULE_SERVERTCP`].
const CT_EMULE_SERVERIP: u8 = 0xBA;
/// `CT_EMULE_SERVERTCP` — that server's port.
const CT_EMULE_SERVERTCP: u8 = 0xBB;
/// `CT_EMULE_USERHASH` — the source's User Hash. Emitted only to a
/// `SKIPTAGS` peer; accepted from anyone.
const CT_EMULE_USERHASH: u8 = 0xBC;
/// `CT_EMULE_CONOPTS` — the source's crypt options. Same emission gate.
const CT_EMULE_CONOPTS: u8 = 0xBE;

/// The fixed head of a record: `[id 4][port 2][tagCount 1]`.
const RECORD_HEAD_LEN: usize = 7;

/// Why an ExtSX record list could not be read. Both variants are
/// non-terminal: aMule drops a malformed source answer silently, and the
/// dialect's whole point is that one bad record must not cost the packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ExtSourceRecordError {
    /// A record ended inside a field its shape requires, or inside a tag.
    #[error("ExtSX record truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the shape requires at that point.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },
    /// A tag's type byte is one eD2k does not define, so its width — and the
    /// offset of everything after it — is unknown.
    #[error("ExtSX record carries a tag of undefined type 0x{tag_type:02X}")]
    UnknownTagType {
        /// The type byte.
        tag_type: u8,
    },
    /// The declared records were read and bytes remained. A record list is
    /// the whole body — a tail means the sender and the reader disagree about
    /// the format, which no per-record tolerance can repair.
    #[error("ExtSX record list left {remaining} trailing bytes after {count} records")]
    TrailingBytes {
        /// Records the header declared.
        count: u16,
        /// Bytes still unread.
        remaining: usize,
    },
}

/// What a peer's `CT_MOD_MISCOPTIONS` claim permits rmule to *write* it
/// (ADR-0087). Emission-only: every tag named here is accepted on read from
/// any peer, claim or no claim.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExtSxEmission {
    /// The peer claimed `MODMISC_EXTXS_SKIPTAGS`, so the optional
    /// `CT_EMULE_USERHASH` / `CT_EMULE_CONOPTS` tags are safe to send: an
    /// unknown tag will cost it that tag rather than the whole answer.
    pub skip_tags: bool,
}

/// Write one record.
pub(crate) fn encode_ext_record(
    out: &mut Vec<u8>,
    entry: SourceExchangeEntry,
    emission: ExtSxEmission,
) {
    let source = entry.source();
    // A source with no ed2k wire form takes the Placeholder Low ID: the field
    // is fixed-width and must hold something, and `0` would read as a Low ID
    // with no server to broker it (`HasEd2kWireForm`).
    let wire_id = match source.peer_source() {
        None | Some(PeerSource::Ipv6(_)) => ClientId::IPV6_ONLY_PLACEHOLDER.as_u32(),
        Some(record) => record.wire_id(),
    };
    out.extend_from_slice(&wire_id.to_le_bytes());
    out.extend_from_slice(&entry.tcp_port().to_le_bytes());

    let mut tags = Vec::with_capacity(5);
    if let Some(server) = entry.server() {
        // Always a pair: a server address with no port names nothing dialable.
        tags.push(Tag::new(
            TagName::compact_id(CT_EMULE_SERVERIP),
            TagValue::compact_uint(u32::from_le_bytes(server.ip.octets())),
        ));
        tags.push(Tag::new(
            TagName::compact_id(CT_EMULE_SERVERTCP),
            TagValue::compact_uint(u32::from(server.port)),
        ));
    }
    if let Some(endpoint) = entry.ipv6() {
        tags.push(Tag::new(
            TagName::compact_id(CT_MOD_IP_V6),
            TagValue::Hash(endpoint.ip.octets()),
        ));
    }
    if emission.skip_tags {
        if let Some(hash) = source.user_hash() {
            tags.push(Tag::new(
                TagName::compact_id(CT_EMULE_USERHASH),
                TagValue::Hash(*hash.as_bytes()),
            ));
        }
        if let Some(crypt) = source.crypt_options() {
            tags.push(Tag::new(
                TagName::compact_id(CT_EMULE_CONOPTS),
                TagValue::U8(crypt.as_byte()),
            ));
        }
    }

    out.push(u8::try_from(tags.len()).expect("a record models at most five tags"));
    for tag in tags {
        out.extend_from_slice(&tag.encode());
    }
}

/// Read exactly `count` records out of `body`, which must be the whole entry
/// region.
///
/// # Errors
/// [`ExtSourceRecordError::Truncated`] when a record or one of its tags runs
/// past the body, [`ExtSourceRecordError::TrailingBytes`] when bytes remain
/// after the declared count.
pub(crate) fn decode_ext_records(
    body: &[u8],
    count: u16,
) -> Result<Vec<SourceExchangeEntry>, ExtSourceRecordError> {
    // The count is untrusted, so the reservation is bounded by what the body
    // could actually hold rather than by what it claims.
    let mut records = Vec::with_capacity((count as usize).min(body.len() / RECORD_HEAD_LEN));
    let mut reader = WireReader::new(body);
    for _ in 0..count {
        records.push(decode_ext_record(&mut reader)?);
    }
    if !reader.is_exhausted() {
        return Err(ExtSourceRecordError::TrailingBytes {
            count,
            remaining: reader.remaining(),
        });
    }
    Ok(records)
}

/// Read one record, advancing `reader`.
fn decode_ext_record(
    reader: &mut WireReader<'_>,
) -> Result<SourceExchangeEntry, ExtSourceRecordError> {
    let mut head = WireReader::new(reader.take(RECORD_HEAD_LEN, "record head")?);
    let raw_id = head.read_u32_le("record client id")?;
    let tcp_port = head.read_u16_le("record port")?;
    let tag_count = head.read_u8("record tag count")?;

    let mut read = RecordTags::default();
    for _ in 0..tag_count {
        let remaining = reader.remaining_bytes();
        if let Ok((tag, consumed)) = Tag::decode_prefix(remaining) {
            reader.advance_clamped(consumed);
            read.apply(&tag);
            continue;
        }
        // `MODMISC_EXTXS_SKIPTAGS` is rmule's promise that a tag it cannot
        // read costs that tag, never the answer (emule-qt `PartFile.cpp:2796`
        // reads each with `Tag(data, true)`): skip it by its type's width.
        let consumed = Tag::skip_prefix(remaining).map_err(|error| match error {
            PrimitiveError::UnsupportedTagType { tag_type } => {
                ExtSourceRecordError::UnknownTagType { tag_type }
            }
            _ => ExtSourceRecordError::Truncated {
                needed: reader.position() + remaining.len() + 1,
                actual: reader.position() + remaining.len(),
            },
        })?;
        reader.advance_clamped(consumed);
    }
    Ok(read.project(ClientId::from_u32(raw_id), tcp_port))
}

impl From<WireTruncated> for ExtSourceRecordError {
    fn from(truncated: WireTruncated) -> Self {
        Self::Truncated {
            needed: truncated.needed,
            actual: truncated.available,
        }
    }
}

/// The tags one record carried, projected to scalars. A tag this list has no
/// name for is skipped — the walk has already consumed it by type, so the
/// next record's offset is never in doubt.
#[derive(Default)]
struct RecordTags {
    server_ip: Option<u32>,
    server_port: Option<u16>,
    ipv6: Option<Ipv6Addr>,
    user_hash: Option<UserHash>,
    crypt_options: Option<SourceCryptOptions>,
}

impl RecordTags {
    fn apply(&mut self, tag: &Tag) {
        let Some(name) = tag.name().id() else {
            return;
        };
        match (name, tag.value()) {
            (CT_EMULE_SERVERIP, value) => set_first(&mut self.server_ip, widen_uint(value)),
            (CT_EMULE_SERVERTCP, value) => set_first(
                &mut self.server_port,
                widen_uint(value).and_then(|it| u16::try_from(it).ok()),
            ),
            (CT_MOD_IP_V6, TagValue::Hash(bytes)) => {
                let address = Ipv6Addr::from(*bytes);
                // `IsUsableTagIdentity`: a scope-less tag cannot name a
                // link-local peer, so such a record keeps only its v4 half.
                if is_usable_tag_identity(address) {
                    set_first(&mut self.ipv6, Some(address));
                }
            }
            (CT_EMULE_USERHASH, TagValue::Hash(bytes)) => {
                set_first(&mut self.user_hash, Some(UserHash::from_bytes(*bytes)));
            }
            (CT_EMULE_CONOPTS, value) => set_first(
                &mut self.crypt_options,
                widen_uint(value)
                    .and_then(|it| u8::try_from(it).ok())
                    .map(SourceCryptOptions::from_byte),
            ),
            _ => {}
        }
    }

    /// Judge the two families independently and build the entry.
    fn project(self, id: ClientId, tcp_port: u16) -> SourceExchangeEntry {
        let classic = PeerSource::new(id, tcp_port);
        let ipv6 = self.ipv6.map(|ip| Ipv6Endpoint::new(ip, tcp_port));
        // An id that names no address at all *and* a usable IPv6 is an
        // IPv6-only source — one representation, shared with the sentinel
        // reader, rather than a Low ID nobody can ever broker.
        let (source, half) = match (ipv6, classic) {
            // The placeholder names no address, so the record's real endpoint
            // is its IPv6 — one representation, shared with the sentinel
            // reader, rather than a Low ID nobody could ever broker.
            (Some(endpoint), PeerSource::LowId { id, .. })
                if id == ClientId::IPV6_ONLY_PLACEHOLDER =>
            {
                (PeerSource::Ipv6(endpoint), None)
            }
            _ => (classic, ipv6),
        };
        let server = match (self.server_ip, self.server_port) {
            // The pair is written together and read together: an address with
            // no port names nothing a Low-ID routing rule could use.
            (Some(raw), Some(port)) if raw != 0 && port != 0 => {
                let octets = raw.to_le_bytes();
                Some(Ipv4Endpoint::new(
                    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
                    port,
                ))
            }
            _ => None,
        };
        SourceExchangeEntry::new(
            SourceSighting::new(source, self.user_hash, self.crypt_options).with_ipv6_half(half),
            server,
        )
    }
}

fn set_first<T>(slot: &mut Option<T>, value: Option<T>) {
    if slot.is_none() {
        *slot = value;
    }
}

/// An integer tag may arrive narrowed to any width — eMule writes the
/// smallest type that holds the value — so every integer read widens back.
const fn widen_uint(value: &TagValue) -> Option<u32> {
    match *value {
        TagValue::U32(word) => Some(word),
        TagValue::U16(short) => Some(short as u32),
        TagValue::U8(byte) => Some(byte as u32),
        TagValue::U64(_) | TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

#[cfg(test)]
mod tests;
