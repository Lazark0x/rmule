//! eD2k tags — the self-describing name/value pairs that carry every optional
//! field in the protocol. Names come in both the numeric-id and the string
//! spelling, values in the integer and string types the wire defines, and
//! decoding is byte-faithful so a round trip re-emits what arrived.

use crate::{Ed2kText, PrimitiveError, Result, WireReader};

/// `TAGTYPE_HASH` — 16 raw bytes with no length prefix. The IPv6 dialect's
/// four address tags all ride it (ADR-0087), and writing one of them as
/// `TAGTYPE_BLOB` instead shifts every later tag in the packet: a reader
/// expecting `HASH` takes `BLOB`'s four length bytes as the start of the
/// address.
const TAGTYPE_HASH: u8 = 0x01;
const TAGTYPE_STRING: u8 = 0x02;
const TAGTYPE_UINT32: u8 = 0x03;
/// `TAGTYPE_UINT64` — aMule `CTagVarInt`'s widened form for an integer past
/// `u32::MAX` (`src/include/tags/TagTypes.h:41`, Fork Pin `ab483654`). Rides
/// `TAG_FILESIZE` on a Kad source publish over 4 GiB.
const TAGTYPE_UINT64: u8 = 0x0B;
const TAGTYPE_UINT16: u8 = 0x08;
const TAGTYPE_UINT8: u8 = 0x09;
// `TAGTYPE_STR1`..`TAGTYPE_STR16` encode short strings whose length
// lives in the type byte itself (no u16 prefix). Lugdunum-era servers
// rely on this compact form for short identity tags (server name,
// CT_NAME, etc.). We decode them as `TagValue::String`; the original
// compact-vs-prefixed encoding is not preserved on re-encode (re-encode
// always emits `TAGTYPE_STRING`), which is semantically lossless.
const TAGTYPE_STR_MIN: u8 = 0x11;
const TAGTYPE_STR_MAX: u8 = 0x20;
// The types [`Tag::skip_prefix`] sizes but no [`TagValue`] models: eMule's
// `CTag` reader (eMuleAI `srchybrid/Packets.cpp:483-511`) and emule-qt's
// (`src/core/protocol/Tag.cpp:172-201`, which adds `BSOB` and compact strings
// to `STR22`).
const TAGTYPE_FLOAT32: u8 = 0x04;
const TAGTYPE_BOOL: u8 = 0x05;
const TAGTYPE_BOOLARRAY: u8 = 0x06;
const TAGTYPE_BLOB: u8 = 0x07;
const TAGTYPE_BSOB: u8 = 0x0A;
const TAGTYPE_STR22: u8 = 0x26;
const NUMERIC_NAME_FLAG: u8 = 0x80;

/// One eD2k tag: a name and a value, kept together because neither is
/// interpretable without the other.
///
/// A tag's *name spelling* is part of its wire identity, not a formatting
/// choice — the same tag written compactly and length-prefixed is different
/// bytes — so both survive a decode/encode round trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    name: TagName,
    value: TagValue,
}

/// How a numeric tag name is written on the wire. Preserved so a re-encode
/// reproduces the counterparty's bytes exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagNameEncoding {
    /// The id rides in the type byte's high bit: two bytes total, no length
    /// prefix. What eMule-family clients emit.
    Compact,
    /// The id is written as a one-byte name behind a `u16` length prefix —
    /// the older, longer spelling Lugdunum-era servers use.
    LengthPrefixed,
}

/// A tag's name: either a numeric id (in one of its two spellings) or a text
/// name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagName {
    kind: TagNameKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TagNameKind {
    Id { id: u8, encoding: TagNameEncoding },
    Text(String),
}

/// A tag's value, in one of the six types this protocol reads.
///
/// The integer width is a wire fact, not a storage choice: eMule narrows every
/// integer to the smallest type that holds it, so a value's width is part of
/// byte-parity (see [`TagValue::compact_uint`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TagValue {
    /// A string, kept as raw bytes. The compact short-string types decode to
    /// this too, and re-encode as the length-prefixed form — different bytes,
    /// same meaning.
    String(Ed2kText),
    /// An eight-byte little-endian integer (`TAGTYPE_UINT64`) — aMule's
    /// `CTagVarInt` widens to this only past `u32::MAX` (see
    /// [`TagValue::compact_uint64`]).
    U64(u64),
    /// A four-byte little-endian integer.
    U32(u32),
    /// A two-byte little-endian integer.
    U16(u16),
    /// A one-byte integer.
    U8(u8),
    /// Sixteen raw bytes, no length prefix — `TAGTYPE_HASH`. Carries a User
    /// Hash where the protocol names one, and an IPv6 address MSB-first in the
    /// IPv6 dialect's four address tags (ADR-0087).
    Hash([u8; HASH_TAG_LEN]),
}

/// How many bytes a [`TagValue::Hash`] carries — the width both a User Hash
/// and an IPv6 address happen to share.
pub const HASH_TAG_LEN: usize = 16;

impl Tag {
    /// A tag from a name and a value.
    pub fn new(name: TagName, value: TagValue) -> Self {
        Self { name, value }
    }

    /// Decode a buffer that must hold exactly one tag.
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidTag`] if anything follows the tag, plus
    /// everything [`Self::decode_prefix`] can raise.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (tag, consumed) = Self::decode_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(PrimitiveError::InvalidTag {
                reason: "trailing tag bytes",
            });
        }
        Ok(tag)
    }

    /// Decode the first tag in `bytes`, returning it and how many bytes it
    /// consumed — how a tag *list* is walked.
    ///
    /// # Errors
    /// [`PrimitiveError::TruncatedTag`] when the buffer stops short,
    /// [`PrimitiveError::UnsupportedTagType`] on a type byte this crate has no
    /// model for (which also ends any walk: the value's width is unknown, so
    /// the next tag's offset is unknowable), [`PrimitiveError::InvalidTag`] on
    /// a name that is not UTF-8.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize)> {
        let mut reader = WireReader::new(bytes);
        let encoded_type = reader.read_u8("tag type")?;
        let (tag_type, name) = if encoded_type & NUMERIC_NAME_FLAG != 0 {
            (
                encoded_type & !NUMERIC_NAME_FLAG,
                TagName::compact_id(reader.read_u8("tag name id")?),
            )
        } else {
            let name_len = reader.read_u16_le("tag name length")? as usize;
            let name_bytes = reader.take(name_len, "tag name")?;
            // Per `docs/reference/notes/tags.md`, a length-prefixed
            // name with `name_len == 1` is *always* a numeric ID, never
            // a 1-character text name (the latter has no use in
            // practice). Route to `length_prefixed_id` so round-trips
            // re-emit the same wire bytes. A caller that hands
            // `TagName::text("X")` to `encode` would NOT round-trip
            // here — `text` accepting 1-byte input is a deliberate
            // permissive constructor for fixture authoring but a
            // by-construction asymmetry; documented for future readers.
            if name_len == 1 {
                (encoded_type, TagName::length_prefixed_id(name_bytes[0]))
            } else {
                // `name_len` came from a `u16` on the wire, so the
                // resulting string is bounded by construction and the
                // `text` validation can't fail here.
                (
                    encoded_type,
                    TagName::text(decode_utf8(name_bytes, "tag name")?)?,
                )
            }
        };

        let value = match tag_type {
            TAGTYPE_STRING => {
                let len = reader.read_u16_le("string tag length")? as usize;
                let value = Ed2kText::from_bytes(reader.take(len, "string tag value")?.to_vec());
                TagValue::String(value)
            }
            TAGTYPE_HASH => {
                let mut hash = [0u8; HASH_TAG_LEN];
                hash.copy_from_slice(reader.take(HASH_TAG_LEN, "hash tag value")?);
                TagValue::Hash(hash)
            }
            TAGTYPE_UINT64 => TagValue::U64(reader.read_u64_le("u64 tag value")?),
            TAGTYPE_UINT32 => TagValue::U32(reader.read_u32_le("u32 tag value")?),
            TAGTYPE_UINT16 => TagValue::U16(reader.read_u16_le("u16 tag value")?),
            TAGTYPE_UINT8 => TagValue::U8(reader.read_u8("u8 tag value")?),
            t if (TAGTYPE_STR_MIN..=TAGTYPE_STR_MAX).contains(&t) => {
                let len = (t - 0x10) as usize;
                let value = Ed2kText::from_bytes(reader.take(len, "string tag value")?.to_vec());
                TagValue::String(value)
            }
            tag_type => return Err(PrimitiveError::UnsupportedTagType { tag_type }),
        };

        Ok((Self { name, value }, reader.position()))
    }

    /// Read the first entry of a tag list, by the rule every tolerant tag-list
    /// reader shares (ADR-0053): the tag when [`TagValue`] models its type, or
    /// `None` when eD2k defines the type but rmule never reads it (`FLOAT32`,
    /// `BOOL`, `BOOLARRAY`, `BLOB`, `BSOB`, `STR17`..`STR22`) or its name is not
    /// UTF-8 — eMule's and aMule's readers parse such a tag and ignore it.
    /// Either way the second value is how many bytes the entry took, so the
    /// walk goes on at the next entry.
    ///
    /// # Errors
    /// [`PrimitiveError::TruncatedTag`] when the buffer stops short, and
    /// [`PrimitiveError::UnsupportedTagType`] on a type byte eD2k does not
    /// define: the two cases that leave the next entry's offset unknowable.
    pub fn decode_or_step_prefix(bytes: &[u8]) -> Result<(Option<Self>, usize)> {
        match Self::decode_prefix(bytes) {
            Ok((tag, used)) => Ok((Some(tag), used)),
            Err(PrimitiveError::UnsupportedTagType { .. } | PrimitiveError::InvalidTag { .. }) => {
                Ok((None, Self::skip_prefix(bytes)?))
            }
            Err(other) => Err(other),
        }
    }

    /// How many bytes the first tag in `bytes` occupies, for every eD2k tag
    /// type — including the ones [`Self::decode_prefix`] has no value model
    /// for (`FLOAT32`, `BOOL`, `BOOLARRAY`, `BLOB`, `BSOB`, `STR17`..`STR22`) and
    /// a name that is not UTF-8. What a reader that promises to skip an
    /// unknown tag (ExtSX's `MODMISC_EXTXS_SKIPTAGS`) walks past one with.
    ///
    /// # Errors
    /// [`PrimitiveError::TruncatedTag`] when the buffer stops short,
    /// [`PrimitiveError::UnsupportedTagType`] on a type byte eD2k does not
    /// define, whose width nobody knows.
    pub fn skip_prefix(bytes: &[u8]) -> Result<usize> {
        let mut reader = WireReader::new(bytes);
        let encoded_type = reader.read_u8("tag type")?;
        let tag_type = if encoded_type & NUMERIC_NAME_FLAG != 0 {
            reader.read_u8("tag name id")?;
            encoded_type & !NUMERIC_NAME_FLAG
        } else {
            let name_len = reader.read_u16_le("tag name length")? as usize;
            reader.take(name_len, "tag name")?;
            encoded_type
        };
        let value_len = match tag_type {
            TAGTYPE_HASH => HASH_TAG_LEN,
            TAGTYPE_STRING => reader.read_u16_le("string tag length")? as usize,
            TAGTYPE_UINT32 | TAGTYPE_FLOAT32 => 4,
            TAGTYPE_UINT8 | TAGTYPE_BOOL => 1,
            // eMule reads `(len / 8) + 1` bytes, not `(len + 7) / 8`.
            TAGTYPE_BOOLARRAY => reader.read_u16_le("bool array length")? as usize / 8 + 1,
            TAGTYPE_BLOB => reader.read_u32_le("blob length")? as usize,
            TAGTYPE_UINT16 => 2,
            TAGTYPE_BSOB => usize::from(reader.read_u8("bsob length")?),
            TAGTYPE_UINT64 => 8,
            t if (TAGTYPE_STR_MIN..=TAGTYPE_STR22).contains(&t) => usize::from(t - 0x10),
            tag_type => return Err(PrimitiveError::UnsupportedTagType { tag_type }),
        };
        reader.take(value_len, "tag value")?;
        Ok(reader.position())
    }

    /// Decode `count` tags off the front of `bytes`, returning them and the
    /// bytes they took. The count is the counterparty's word; the reservation
    /// is bounded by [`Self::block_capacity`], so a count the bytes cannot
    /// hold fails on the first short tag instead of reserving by the count.
    ///
    /// # Errors
    /// Everything [`Self::decode_prefix`] can raise, for the first tag that
    /// fails.
    pub fn decode_block(bytes: &[u8], count: usize) -> Result<(Vec<Self>, usize)> {
        let mut tags = Vec::with_capacity(Self::block_capacity(count, bytes));
        let mut position = 0;
        for _ in 0..count {
            let (tag, consumed) = Self::decode_prefix(&bytes[position..])?;
            position += consumed;
            tags.push(tag);
        }
        Ok((tags, position))
    }

    /// How many slots a reader may reserve for a block of `count` tags read
    /// from `bytes`: no more than the bytes can hold at [`Self::MIN_WIRE_LEN`]
    /// each, however large the count claims to be.
    #[must_use]
    pub const fn block_capacity(count: usize, bytes: &[u8]) -> usize {
        let fits = bytes.len() / Self::MIN_WIRE_LEN;
        if count < fits { count } else { fits }
    }

    /// The fewest bytes one tag takes on the wire: a type byte, a compact
    /// name id and a one-byte value (`UINT8`, `BOOL`, an empty `BSOB`, `STR1`).
    pub const MIN_WIRE_LEN: usize = 3;

    /// Serialize the tag, reproducing the name spelling it carries.
    ///
    /// # Panics
    /// If a text name or string value exceeds 65535 bytes. [`TagName::text`]
    /// rejects over-long names at construction, so only a value built past
    /// that bound can reach it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let tag_type = self.value.tag_type();
        let mut encoded = Vec::new();

        match &self.name.kind {
            TagNameKind::Id { id, encoding } => match encoding {
                TagNameEncoding::Compact => {
                    encoded.push(tag_type | NUMERIC_NAME_FLAG);
                    encoded.push(*id);
                }
                TagNameEncoding::LengthPrefixed => {
                    encoded.push(tag_type);
                    encoded.extend_from_slice(&1_u16.to_le_bytes());
                    encoded.push(*id);
                }
            },
            TagNameKind::Text(name) => {
                encoded.push(tag_type);
                write_len_prefixed_bytes(&mut encoded, name.as_bytes(), "tag name");
            }
        }

        match &self.value {
            TagValue::String(value) => {
                write_len_prefixed_bytes(&mut encoded, value.as_bytes(), "string tag value");
            }
            TagValue::U64(value) => encoded.extend_from_slice(&value.to_le_bytes()),
            TagValue::U32(value) => encoded.extend_from_slice(&value.to_le_bytes()),
            TagValue::U16(value) => encoded.extend_from_slice(&value.to_le_bytes()),
            TagValue::U8(value) => encoded.push(*value),
            TagValue::Hash(value) => encoded.extend_from_slice(value),
        }

        encoded
    }

    /// The tag's name.
    #[must_use]
    pub const fn name(&self) -> &TagName {
        &self.name
    }

    /// The tag's value.
    #[must_use]
    pub const fn value(&self) -> &TagValue {
        &self.value
    }
}

impl TagValue {
    /// The smallest integer variant that holds `value` — eMule/aMule's
    /// `CTag::WriteTagToFile` compaction, which narrows every integer tag to
    /// `TAGTYPE_UINT8`/`_UINT16`/`_UINT32` by magnitude before it hits the wire.
    /// A Kad publish's SOURCES count and FILESIZE ride this (capture-proven: the
    /// aMule `0x43` in `rmule-kad`'s keyword fixture carries SOURCES `0` as a
    /// one-byte `0x09` tag and FILESIZE `65536` as a four-byte `0x03` tag from
    /// the same writer), so a rmule emitter must narrow identically to stay
    /// byte-for-byte with aMule.
    #[must_use]
    pub const fn compact_uint(value: u32) -> Self {
        if value <= u8::MAX as u32 {
            Self::U8(value as u8)
        } else if value <= u16::MAX as u32 {
            Self::U16(value as u16)
        } else {
            Self::U32(value)
        }
    }

    /// The smallest integer variant that holds a 64-bit `value` — aMule's
    /// `CTagVarInt::SizedInit` ladder (`Tag.h:186-195`, Fork Pin `ab483654`):
    /// `<= 0xFF` narrows to `UINT8`, `<= 0xFFFF` to `UINT16`, `<= 0xFFFFFFFF`
    /// to `UINT32`, otherwise `UINT64`. `TAG_FILESIZE` on a Kad source publish
    /// rides this — a file at or under 4 GiB narrows exactly as
    /// [`Self::compact_uint`] would, and only a file over 4 GiB reaches the
    /// `UINT64` rung [`Self::compact_uint`] has no room for.
    #[must_use]
    pub const fn compact_uint64(value: u64) -> Self {
        if value <= u8::MAX as u64 {
            Self::U8(value as u8)
        } else if value <= u16::MAX as u64 {
            Self::U16(value as u16)
        } else if value <= u32::MAX as u64 {
            Self::U32(value as u32)
        } else {
            Self::U64(value)
        }
    }

    const fn tag_type(&self) -> u8 {
        match self {
            Self::String(_) => TAGTYPE_STRING,
            Self::U64(_) => TAGTYPE_UINT64,
            Self::U32(_) => TAGTYPE_UINT32,
            Self::U16(_) => TAGTYPE_UINT16,
            Self::U8(_) => TAGTYPE_UINT8,
            Self::Hash(_) => TAGTYPE_HASH,
        }
    }
}

impl TagName {
    /// A numeric name in the compact spelling — what an emitter should use
    /// unless it is reproducing an older server's bytes.
    #[must_use]
    pub const fn compact_id(id: u8) -> Self {
        Self {
            kind: TagNameKind::Id {
                id,
                encoding: TagNameEncoding::Compact,
            },
        }
    }

    /// A numeric name in the length-prefixed spelling — the form a
    /// Lugdunum-era server writes, and the one a round trip must preserve.
    #[must_use]
    pub const fn length_prefixed_id(id: u8) -> Self {
        Self {
            kind: TagNameKind::Id {
                id,
                encoding: TagNameEncoding::LengthPrefixed,
            },
        }
    }

    /// Construct a length-prefixed text tag name. Rejects names longer
    /// than `u16::MAX` bytes — the wire `name_length` is a `u16`, so
    /// anything longer would silently truncate on encode (the previous
    /// implementation `unwrap`-ped at the encode boundary, panicking
    /// inside `write_len_prefixed_bytes`).
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidTag`] if the name exceeds 65535 bytes.
    pub fn text(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if u16::try_from(name.len()).is_err() {
            return Err(PrimitiveError::InvalidTag {
                reason: "tag name exceeds 65535 bytes",
            });
        }
        Ok(Self {
            kind: TagNameKind::Text(name),
        })
    }

    /// The numeric id, or `None` for a text name.
    #[must_use]
    pub const fn id(&self) -> Option<u8> {
        match &self.kind {
            TagNameKind::Id { id, .. } => Some(*id),
            TagNameKind::Text(_) => None,
        }
    }

    /// The text name, or `None` for a numeric id.
    #[must_use]
    pub fn text_value(&self) -> Option<&str> {
        match &self.kind {
            TagNameKind::Id { .. } => None,
            TagNameKind::Text(name) => Some(name),
        }
    }

    /// Which spelling this name is written in. A text name has only one, so it
    /// reports [`TagNameEncoding::LengthPrefixed`].
    #[must_use]
    pub const fn encoding(&self) -> TagNameEncoding {
        match &self.kind {
            TagNameKind::Id { encoding, .. } => *encoding,
            TagNameKind::Text(_) => TagNameEncoding::LengthPrefixed,
        }
    }
}

fn decode_utf8(bytes: &[u8], reason: &'static str) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| PrimitiveError::InvalidTag { reason })
}

fn write_len_prefixed_bytes(encoded: &mut Vec<u8>, bytes: &[u8], field: &'static str) {
    let len = u16::try_from(bytes.len()).unwrap_or_else(|_| panic!("{field} is too long"));
    encoded.extend_from_slice(&len.to_le_bytes());
    encoded.extend_from_slice(bytes);
}
