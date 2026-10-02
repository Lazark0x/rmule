//! Source-exchange packets — SX1 (ADR-0055) and SX2 (ADR-0055).
//!
//! `OP_REQUESTSOURCES` (`0x81`) / `OP_ANSWERSOURCES` (`0x82`) and
//! `OP_REQUESTSOURCES2` (`0x83`) / `OP_ANSWERSOURCES2` (`0x84`), all under
//! `OP_EMULEPROT`, per `src/include/protocol/ed2k/Client2Client/TCP.h` @ amule
//! `4e8f2b3c` (`KnownFile.cpp::CreateSrcInfoPacket`,
//! `PartFile.cpp::AddClientSources`, `ClientTCPSocket.cpp`,
//! `DownloadClient.cpp`). One version-parameterized entry codec
//! ([`SourceExchangeVersion`], in `entry`) serves both opcode pairs in both
//! directions, validating by aMule's own rules rather than geometry inference.
//!
//! rmule advertises source-exchange nibble **3** + `SupportsSourceEx2` (the
//! ADR-0047 registry) and drives all four opcodes live: it **serves** a peer's
//! `0x81`/`0x83` request (answering `0x82`/`0x84` via the core serve callback)
//! and, as **requester**, asks a SX2-advertising peer with `0x83`
//! (`RequestSources2`, `<ver=4><opts=0><hash>`) — else the bare-hash `0x81` —
//! then consumes the peer's `0x84` (`AnswerSources2`) answer through the very
//! sanity/provenance/cap core `0x82` uses. `PeerPacket::decode` dispatches
//! every one; none park as `Unknown`.
//!
//! Each decoded answer entry retains its declaring server endpoint alongside
//! its [`ExchangedSource`](rmule_primitives::ExchangedSource) provenance (the
//! ADR-0046 model — see [`SourceExchangeEntry`]); the aMule-mirrored sanity
//! filter, Low-ID routing rule and per-file cap that decide which entries the
//! session surfaces live in `admission` ([`sanitize_and_route`]).
//!
//! Layout: `entry` is the per-entry codec (the four wire versions, their
//! strides, the entry model); this file is the four packet framings with
//! their decode-error taxonomies, plus the [`AnswerSourcesSkip`] both answer
//! opcodes share and the serve-side [`ServedSourcesVersion`] pick. Those stay
//! together: one skip taxonomy and one serve negotiation span both opcode
//! pairs, so a per-pair split would cut through both.

mod admission;
mod entry;
mod ext_record;
#[cfg(test)]
mod tests;

use rmule_primitives::{FileHash, Packet};
use thiserror::Error;

pub(crate) use self::admission::sanitize_and_route;
pub use self::entry::{SourceExchangeEntry, SourceExchangeVersion};
use self::entry::{decode_source_entries, encode_source_entry};
pub(crate) use self::ext_record::{EXT_SX_VERSION, decode_ext_records, encode_ext_record};
pub use self::ext_record::{ExtSourceRecordError, ExtSxEmission};
use crate::capability::ModMiscOptions;
use crate::opcode::PeerOpcode;

/// What the *answering* peer claimed about source exchange, read from its
/// hello — the two facts a source answer cannot be decoded without.
///
/// `0x82` carries no version of its own, so its geometry is cross-checked
/// against the answerer's own SX1 nibble (aMule `ClientTCPSocket.cpp`); and an
/// **ExtSX** answer is a tag list rather than a stride, so the only thing that
/// can select the right reader is the answerer's `MODMISC_EXTXS` claim
/// (ADR-0087). Both come from the same hello, so they travel as one value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceExchangeClaim {
    /// The answerer's advertised SX1 nibble (`0` before it identified).
    pub sx1_nibble: u8,
    /// The answerer advertised `MODMISC_EXTXS`, so its answers take the
    /// record form.
    pub ext_sx: bool,
}

/// aMule's `SOURCEEXCHANGE2_VERSION` (`Constants.h` @4e8f2b3c) — the ceiling
/// the serve path clamps an SX2 request's declared version to.
const SOURCEEXCHANGE2_VERSION: u8 = 4;

/// The wire form *and* entry version one source-exchange serve answer takes —
/// the aMule-exact pick (`CKnownFile::CreateSrcInfoPacket`, `KnownFile.cpp#L938`
/// @4e8f2b3c) from the requester's advertised SX capability and the request
/// opcode/version. The session threads this verbatim through the core
/// serve callback (ADR-0055): pools/filters/throttle are core's, the wire form
/// the peer session's — core echoes it back on the answer so the encoder frames
/// the right opcode without re-deriving it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServedSourcesVersion {
    /// `OP_ANSWERSOURCES` (`0x82`) at the requester's own advertised SX1 nibble.
    Sx1(SourceExchangeVersion),
    /// `OP_ANSWERSOURCES2` (`0x84`) at the SX2-negotiated version.
    Sx2(SourceExchangeVersion),
    /// The **ExtSX** record form (ADR-0087) at its pinned version 1, on
    /// whichever opcode the requester's SX2 claim selects. Chosen only for a
    /// requester that advertised `MODMISC_EXTXS`, because nobody else can read
    /// a variable-length record — and chosen *whenever* it did, because it is
    /// the only entry form that can carry an IPv6 source at all.
    Ext {
        /// Frame as `OP_ANSWERSOURCES2` (`0x84`) rather than `0x82` — the
        /// same opcode pick the classic path makes.
        sx2: bool,
        /// Which optional tags the requester's claim permits.
        emission: ExtSxEmission,
    },
}

impl ServedSourcesVersion {
    /// Pick the serve answer's wire form, aMule-exact (`KnownFile.cpp#L938`
    /// @4e8f2b3c): **SX2** (`0x84`) iff the requester advertised
    /// `SupportsSourceEx2` *and* named a requested version `> 0`, at
    /// `min(requested, SOURCEEXCHANGE2_VERSION)`; otherwise **SX1** (`0x82`) at
    /// the requester's own advertised SX1 nibble.
    ///
    /// `requested` is the request's version byte — the `<ver>` an
    /// `OP_REQUESTSOURCES2` / multipacket `Sources2` sub carries, or `0` for a
    /// plain `OP_REQUESTSOURCES` / `Sources` sub (which forces the SX1 path).
    /// A requester SX1 nibble outside `1..=4` degrades to v1 (aMule serves the
    /// lowest common shape rather than refusing).
    #[must_use]
    pub fn negotiate(
        requester_sx1_nibble: u8,
        requester_supports_sx2: bool,
        requested: u8,
        requester_mod_misc: Option<ModMiscOptions>,
    ) -> Self {
        // ExtSX first: it is a record *form*, not a version, and it precedes
        // the version ladder because a classic entry of any version has
        // nowhere to put an IPv6 address (ADR-0087).
        if let Some(claim) = requester_mod_misc
            && claim.supports_ext_sx()
        {
            return Self::Ext {
                sx2: requester_supports_sx2 && requested > 0,
                emission: ExtSxEmission {
                    skip_tags: claim.skips_unknown_ext_sx_tags(),
                },
            };
        }
        if requester_supports_sx2 && requested > 0 {
            let clamped = requested.min(SOURCEEXCHANGE2_VERSION);
            Self::Sx2(SourceExchangeVersion::from_u8(clamped).unwrap_or(SourceExchangeVersion::V4))
        } else {
            Self::Sx1(
                SourceExchangeVersion::from_u8(requester_sx1_nibble)
                    .unwrap_or(SourceExchangeVersion::V1),
            )
        }
    }

    /// The per-entry codec version this answer encodes at — the hybrid-id and
    /// field-width choice both follow it (`SourceExchangeVersion::uses_hybrid_id`
    /// etc.), the ADR-0055 "uniform id rule: hybrid iff `byUsedVersion >= 3`".
    #[must_use]
    pub const fn entry_version(self) -> SourceExchangeVersion {
        match self {
            Self::Sx1(v) | Self::Sx2(v) => v,
            // ExtSX declares version 1 and must not declare more: version 2
            // and above re-enable the classic optional tail, which an ExtSX
            // reader cannot tell from a tag list.
            Self::Ext { .. } => SourceExchangeVersion::V1,
        }
    }
}

/// Why an `OP_REQUESTSOURCES` could not be read.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RequestSourcesDecodeError {
    /// The payload was not exactly one file hash.
    #[error(
        "OP_REQUESTSOURCES payload is {actual} bytes, not the {expected} a bare file hash requires"
    )]
    WrongSize {
        /// What the shape requires.
        expected: usize,
        /// What arrived.
        actual: usize,
    },
}

/// `OP_REQUESTSOURCES` — ask a peer for more sources of `file_hash`. Payload is
/// just `[file_hash 16]`. rmule both sends this (the requester ask) and
/// decodes it to *serve* a peer that asks us (the serve callback answers
/// `OP_ANSWERSOURCES` at the requester's own SX1 nibble, ADR-0055).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSources {
    /// The file sources are wanted for.
    pub file_hash: FileHash,
}

impl RequestSources {
    /// Frame this ask.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::RequestSources.protocol(),
            PeerOpcode::RequestSources.as_u8(),
            self.file_hash.as_bytes().to_vec(),
        )
    }

    /// Read a peer's ask, or say why the payload is not one.
    pub fn decode_packet(packet: &Packet) -> Result<Self, RequestSourcesDecodeError> {
        let payload = packet.payload();
        if payload.len() != FileHash::BYTE_LEN {
            return Err(RequestSourcesDecodeError::WrongSize {
                expected: FileHash::BYTE_LEN,
                actual: payload.len(),
            });
        }
        let mut hash = [0u8; FileHash::BYTE_LEN];
        hash.copy_from_slice(&payload[..FileHash::BYTE_LEN]);
        Ok(Self {
            file_hash: FileHash::from_bytes(hash),
        })
    }
}

/// Why an `OP_ANSWERSOURCES` (`0x82`) could not be read.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AnswerSourcesDecodeError {
    /// The payload ended before the header or the declared entries did.
    #[error("OP_ANSWERSOURCES payload truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the declared geometry requires.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },
    /// The ExtSX record walk refused the body (ADR-0087).
    #[error("OP_ANSWERSOURCES ExtSX records: {source}")]
    ExtRecord {
        #[source]
        /// The record walk's reason.
        source: ExtSourceRecordError,
    },
    /// Count and body length fit no stride the advertised version allows —
    /// `0x82` carries no version of its own, so this cross-check is the only
    /// thing that can reject it.
    #[error(
        "OP_ANSWERSOURCES geometry (count={count}, body={body_len}) does not reconcile with advertised source-exchange version {advertised_version}"
    )]
    AdvertisedVersionMismatch {
        /// What the peer's hello advertised.
        advertised_version: u8,
        /// The entry count the payload declared.
        count: u16,
        /// Bytes actually left for the entries.
        body_len: usize,
    },
}

/// `OP_ANSWERSOURCES` — a peer's source list for `file_hash`. Payload:
/// `[file_hash 16][count u16]` then `count` sources at whichever version the
/// answer resolves to (see [`AnswerSources::decode_packet`]). Each source is
/// a [`SourceExchangeEntry`] — the
/// [`ExchangedSource`](rmule_primitives::ExchangedSource) provenance plus the
/// declaring server the consume-side Low-ID routing rule reads (ADR-0055).
/// Low-ID sources survive here; the High-ID filter is the caller's
/// `as_peer_endpoint` projection (the session's consume path, ADR-0055).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerSources {
    /// The file this list answers for.
    pub file_hash: FileHash,
    /// The entries as decoded — Low-ID rows included, filtering is the
    /// consumer's.
    pub sources: Vec<SourceExchangeEntry>,
}

impl AnswerSources {
    /// Decode `OP_ANSWERSOURCES` by aMule's exact cross-check
    /// (`CPartFile::AddClientSources`'s
    /// `!bSourceExchange2` branch, `PartFile.cpp` @4e8f2b3c): the payload's
    /// geometry must resolve to exactly one of the three SX1 strides, *and*
    /// that geometry-implied version must reconcile with
    /// `advertised_version` — geometry alone is never trusted. A mismatch
    /// drops the whole packet, same as a truncated header (aMule's own
    /// `AddClientSources` treats both as a silent `return;` — a non-terminal
    /// diagnostic in intent; see `resolve_sx1_version` for the exact
    /// branching, including its zero-count corner case).
    ///
    /// `advertised_version` is aMule's `uClientSXVersion`: the *answering
    /// peer's own claimed* SX1 nibble
    /// (`m_client->GetSourceExchange1Version()`, parsed from that peer's
    /// hello — `ClientTCPSocket.cpp` @4e8f2b3c). `PeerPacket::decode` threads
    /// the session's tracked peer capability through to this parameter
    /// (ADR-0055); callers with no session context (e.g. offline
    /// fixture decode) may supply any nibble directly.
    pub fn decode_packet(
        packet: &Packet,
        advertised_version: u8,
    ) -> Result<Self, AnswerSourcesDecodeError> {
        let (file_hash, sources) = decode_answer_sources_entries(packet, advertised_version)?;
        Ok(Self { file_hash, sources })
    }

    /// Encode as `OP_ANSWERSOURCES` at `version` — the version-parameterized
    /// entry codec both directions share (ADR-0055). Each entry's declared
    /// server is not put on the wire: `encode_source_entry` always writes zero
    /// there regardless of what `sources` carries — the same zero-fill
    /// [`AnswerSources2::encode_packet`] applies.
    #[must_use]
    pub fn encode_packet(&self, version: SourceExchangeVersion) -> Packet {
        let stride = version.entry_stride();
        let mut payload = Vec::with_capacity(FileHash::BYTE_LEN + 2 + self.sources.len() * stride);
        payload.extend_from_slice(self.file_hash.as_bytes());
        let (count, sources) = wire_count(&self.sources);
        payload.extend_from_slice(&count.to_le_bytes());
        for src in sources {
            encode_source_entry(&mut payload, src.source(), version);
        }
        Packet::new(
            PeerOpcode::AnswerSources.protocol(),
            PeerOpcode::AnswerSources.as_u8(),
            payload,
        )
    }
}

impl AnswerSources {
    /// Encode as an **ExtSX** `0x82` (ADR-0087): the same
    /// `[file_hash 16][count 2]` header, then variable-length records instead
    /// of a fixed stride. `emission` is what the requester's
    /// `CT_MOD_MISCOPTIONS` claim permits.
    #[must_use]
    pub fn encode_ext_packet(&self, emission: ExtSxEmission) -> Packet {
        let mut payload = Vec::with_capacity(FileHash::BYTE_LEN + 2 + self.sources.len() * 16);
        payload.extend_from_slice(self.file_hash.as_bytes());
        let (count, sources) = wire_count(&self.sources);
        payload.extend_from_slice(&count.to_le_bytes());
        for src in sources {
            encode_ext_record(&mut payload, *src, emission);
        }
        Packet::new(
            PeerOpcode::AnswerSources.protocol(),
            PeerOpcode::AnswerSources.as_u8(),
            payload,
        )
    }

    /// Read an **ExtSX** `0x82`. The classic `count × stride == body` check has
    /// no meaning for a variable-length record, so the guard is the record
    /// walk's own bounds plus the requirement that it consume the whole body.
    ///
    /// # Errors
    /// [`AnswerSourcesDecodeError::Truncated`] when the header is short, and
    /// [`AnswerSourcesDecodeError::ExtRecord`] for anything the record walk
    /// refuses.
    pub fn decode_ext_packet(packet: &Packet) -> Result<Self, AnswerSourcesDecodeError> {
        let payload = packet.payload();
        let header = FileHash::BYTE_LEN + 2;
        if payload.len() < header {
            return Err(AnswerSourcesDecodeError::Truncated {
                needed: header,
                actual: payload.len(),
            });
        }
        let mut hash = [0u8; FileHash::BYTE_LEN];
        hash.copy_from_slice(&payload[..FileHash::BYTE_LEN]);
        let count = u16::from_le_bytes([payload[16], payload[17]]);
        let sources = decode_ext_records(&payload[header..], count)
            .map_err(|source| AnswerSourcesDecodeError::ExtRecord { source })?;
        Ok(Self {
            file_hash: FileHash::from_bytes(hash),
            sources,
        })
    }
}

/// `OP_ANSWERSOURCES`'s header parse, geometry cross-check, and per-entry
/// decode — factored out of [`AnswerSources::decode_packet`] only for
/// readability; it is `AnswerSources`'s sole caller.
fn decode_answer_sources_entries(
    packet: &Packet,
    advertised_version: u8,
) -> Result<(FileHash, Vec<SourceExchangeEntry>), AnswerSourcesDecodeError> {
    let payload = packet.payload();
    let header = FileHash::BYTE_LEN + 2;
    if payload.len() < header {
        return Err(AnswerSourcesDecodeError::Truncated {
            needed: header,
            actual: payload.len(),
        });
    }
    let mut hash = [0u8; FileHash::BYTE_LEN];
    hash.copy_from_slice(&payload[..FileHash::BYTE_LEN]);
    let file_hash = FileHash::from_bytes(hash);
    let count = u16::from_le_bytes([payload[16], payload[17]]);
    let body = &payload[header..];

    let version = resolve_sx1_version(count, body.len(), advertised_version).ok_or(
        AnswerSourcesDecodeError::AdvertisedVersionMismatch {
            advertised_version,
            count,
            body_len: body.len(),
        },
    )?;
    Ok((file_hash, decode_source_entries(body, count, version)))
}

/// aMule-exact SX1 version resolution (`CPartFile::AddClientSources`'s
/// `!bSourceExchange2` branch, `PartFile.cpp` @4e8f2b3c): try each known
/// stride in turn; the first whose `count * stride == body_len` wins, and
/// that geometry-implied version must then reconcile with
/// `advertised_version` — a 28-byte-stride body resolves to v2 only when
/// `advertised_version == 2` exactly, but to v3 for *any* `advertised_version
/// > 2` (aMule's own `else if` catches 4 and above too, not just 3); a
/// 29-byte-stride body requires `advertised_version == 4` exactly.
///
/// A `count` of 0 makes every stride's equation `0 == body_len`
/// simultaneously true when `body_len` is also 0, so it always resolves
/// through the *first* (v1) arm — an empty answer only decodes when
/// `advertised_version == 1`, exactly as aMule's `if`/`else if` chain falls
/// through regardless of what was actually advertised.
fn resolve_sx1_version(
    count: u16,
    body_len: usize,
    advertised_version: u8,
) -> Option<SourceExchangeVersion> {
    let n = count as usize;
    if n * SourceExchangeVersion::V1.entry_stride() == body_len {
        (advertised_version == 1).then_some(SourceExchangeVersion::V1)
    } else if n * SourceExchangeVersion::V2.entry_stride() == body_len {
        match advertised_version {
            2 => Some(SourceExchangeVersion::V2),
            v if v > 2 => Some(SourceExchangeVersion::V3),
            _ => None,
        }
    } else if n * SourceExchangeVersion::V4.entry_stride() == body_len {
        (advertised_version == 4).then_some(SourceExchangeVersion::V4)
    } else {
        None
    }
}

/// Why an `OP_ANSWERSOURCES2` (`0x84`) could not be read.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AnswerSources2DecodeError {
    /// The payload ended before the header or the declared entries did.
    #[error("OP_ANSWERSOURCES2 payload truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes the declared geometry requires.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },
    /// The declared version is outside `1..=4`, the bound aMule enforces
    /// before reading anything after it.
    #[error("OP_ANSWERSOURCES2 declared unsupported source-exchange version {version}")]
    UnsupportedVersion {
        /// The byte that was declared.
        version: u8,
    },
    /// The ExtSX record walk refused the body (ADR-0087).
    #[error("OP_ANSWERSOURCES2 ExtSX records: {source}")]
    ExtRecord {
        #[source]
        /// The record walk's reason.
        source: ExtSourceRecordError,
    },
    /// The body is not exactly `count` entries at the declared version's
    /// stride. No fallback to another version: the declaration is binding.
    #[error(
        "OP_ANSWERSOURCES2 source list is {body_len} bytes, not the exact size version {version} with count {count} requires"
    )]
    WrongGeometry {
        /// The version the answer declared.
        version: u8,
        /// The entry count it declared.
        count: u16,
        /// Bytes actually left for the entries.
        body_len: usize,
    },
}

/// Why an inbound source *answer* was dropped without closing — the reason
/// [`crate::PeerEvent::SourceExchangeAnswerSkipped`] carries. aMule's
/// `CPartFile::AddClientSources` silently `return`s on a malformed answer for
/// both wire forms (`PartFile.cpp` @4e8f2b3c), so a bad `0x82`
/// ([`AnswerSourcesDecodeError`]) or `0x84` ([`AnswerSources2DecodeError`]) is
/// a non-terminal diagnostic, never a protocol-violation close — one skip
/// taxonomy across both opcodes, the ADR-0055 "one semantic core" applied to
/// the consume-error path too.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AnswerSourcesSkip {
    /// A `0x82` answer that would not decode.
    #[error(transparent)]
    Sx1(#[from] AnswerSourcesDecodeError),
    /// A `0x84` answer that would not decode.
    #[error(transparent)]
    Sx2(#[from] AnswerSources2DecodeError),
}

/// `OP_ANSWERSOURCES2` (SX2) — `<version 1><file_hash 16><count 2>` then
/// `count` `version`-strided entries (ADR-0055). Unlike `0x82`, the version
/// travels on the wire, so validation is self-contained: aMule bounds it to
/// `1..=4` then requires *exact* geometry for that declared version
/// (`CPartFile::AddClientSources`'s `bSourceExchange2` branch, `PartFile.cpp`
/// @4e8f2b3c) — no cross-check against anything external, and no fallback to
/// a different version on a size mismatch.
///
/// Each source is a [`SourceExchangeEntry`] — the
/// [`ExchangedSource`](rmule_primitives::ExchangedSource) provenance plus the
/// declaring server every version's entry carries, exactly
/// as [`AnswerSources`] (`0x82`) holds it. aMule reads the same
/// `[srvIP4][srvPort2]` for SX2 as SX1 (`CPartFile::AddClientSources`,
/// `PartFile.cpp` @4e8f2b3c), so the requester-consume path routes a `0x84`'s
/// entries through the one shared sanity/Low-ID/cap core (`sanitize_and_route`)
/// without a second, divergent parse — the "one semantic core" ADR-0055 calls
/// for. The serve/emit path fills the server fields with zero (rmule serves no
/// per-client server endpoint), the same as `0x82`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerSources2 {
    /// The version the answer declared, and the one its geometry had to
    /// match exactly to decode at all.
    pub version: SourceExchangeVersion,
    /// The file this list answers for.
    pub file_hash: FileHash,
    /// The entries, decoded at that version.
    pub sources: Vec<SourceExchangeEntry>,
}

impl AnswerSources2 {
    /// Encode as an **ExtSX** `0x84` (ADR-0087): the version byte pinned at
    /// 1, then the same header and variable-length records as the `0x82` form.
    #[must_use]
    pub fn encode_ext_packet(&self, emission: ExtSxEmission) -> Packet {
        let mut payload = Vec::with_capacity(1 + FileHash::BYTE_LEN + 2 + self.sources.len() * 16);
        payload.push(EXT_SX_VERSION);
        payload.extend_from_slice(self.file_hash.as_bytes());
        let (count, sources) = wire_count(&self.sources);
        payload.extend_from_slice(&count.to_le_bytes());
        for src in sources {
            encode_ext_record(&mut payload, *src, emission);
        }
        Packet::new(
            PeerOpcode::AnswerSources2.protocol(),
            PeerOpcode::AnswerSources2.as_u8(),
            payload,
        )
    }

    /// Read an **ExtSX** `0x84`: the declared version must be exactly the
    /// pinned 1, then the record walk owns the bounds.
    ///
    /// # Errors
    /// [`AnswerSources2DecodeError::Truncated`] on a short header,
    /// [`AnswerSources2DecodeError::UnsupportedVersion`] when the byte is not
    /// the pinned 1, [`AnswerSources2DecodeError::ExtRecord`] for anything
    /// the record walk refuses.
    pub fn decode_ext_packet(packet: &Packet) -> Result<Self, AnswerSources2DecodeError> {
        let payload = packet.payload();
        let header = 1 + FileHash::BYTE_LEN + 2;
        if payload.len() < header {
            return Err(AnswerSources2DecodeError::Truncated {
                needed: header,
                actual: payload.len(),
            });
        }
        if payload[0] != EXT_SX_VERSION {
            return Err(AnswerSources2DecodeError::UnsupportedVersion {
                version: payload[0],
            });
        }
        let mut hash = [0u8; FileHash::BYTE_LEN];
        hash.copy_from_slice(&payload[1..1 + FileHash::BYTE_LEN]);
        let count_at = 1 + FileHash::BYTE_LEN;
        let count = u16::from_le_bytes([payload[count_at], payload[count_at + 1]]);
        let sources = decode_ext_records(&payload[header..], count)
            .map_err(|source| AnswerSources2DecodeError::ExtRecord { source })?;
        Ok(Self {
            version: SourceExchangeVersion::V1,
            file_hash: FileHash::from_bytes(hash),
            sources,
        })
    }

    /// Read a peer's `0x84`: bound the declared version first, then require
    /// its exact geometry.
    pub fn decode_packet(packet: &Packet) -> Result<Self, AnswerSources2DecodeError> {
        let payload = packet.payload();
        if payload.is_empty() {
            return Err(AnswerSources2DecodeError::Truncated {
                needed: 1,
                actual: 0,
            });
        }
        let version = SourceExchangeVersion::from_u8(payload[0]).ok_or(
            AnswerSources2DecodeError::UnsupportedVersion {
                version: payload[0],
            },
        )?;
        let header = 1 + FileHash::BYTE_LEN + 2;
        if payload.len() < header {
            return Err(AnswerSources2DecodeError::Truncated {
                needed: header,
                actual: payload.len(),
            });
        }
        let mut hash = [0u8; FileHash::BYTE_LEN];
        hash.copy_from_slice(&payload[1..1 + FileHash::BYTE_LEN]);
        let file_hash = FileHash::from_bytes(hash);
        let count_at = 1 + FileHash::BYTE_LEN;
        let count = u16::from_le_bytes([payload[count_at], payload[count_at + 1]]);
        let body = &payload[header..];
        let expected = count as usize * version.entry_stride();
        if expected != body.len() {
            return Err(AnswerSources2DecodeError::WrongGeometry {
                version: version.as_u8(),
                count,
                body_len: body.len(),
            });
        }
        let sources = decode_source_entries(body, count, version);
        Ok(Self {
            version,
            file_hash,
            sources,
        })
    }

    /// ## Constraint — the serve side zero-fills server endpoints
    ///
    /// Encoding goes through each entry's client [`source`](
    /// SourceExchangeEntry::source) only: the per-entry *server* endpoint the
    /// consume side may carry is *not* re-emitted (the serve path always
    /// zero-fills it, as captured from aMule). A server-bearing emit would
    /// have to extend `encode_source_entry` — a decode → encode of a
    /// server-bearing `0x84` is lossy by design.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let stride = self.version.entry_stride();
        let mut payload =
            Vec::with_capacity(1 + FileHash::BYTE_LEN + 2 + self.sources.len() * stride);
        payload.push(self.version.as_u8());
        payload.extend_from_slice(self.file_hash.as_bytes());
        let (count, sources) = wire_count(&self.sources);
        payload.extend_from_slice(&count.to_le_bytes());
        for src in sources {
            encode_source_entry(&mut payload, src.source(), self.version);
        }
        Packet::new(
            PeerOpcode::AnswerSources2.protocol(),
            PeerOpcode::AnswerSources2.as_u8(),
            payload,
        )
    }
}

/// The wire count is a `u16`: a list past it writes its first 65535 entries,
/// so the count always matches the records that follow it.
fn wire_count<T>(sources: &[T]) -> (u16, &[T]) {
    let count = u16::try_from(sources.len()).unwrap_or(u16::MAX);
    (count, &sources[..usize::from(count)])
}

/// Why an `OP_REQUESTSOURCES2` could not be read.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RequestSources2DecodeError {
    /// The payload was not the standalone shape's 19 bytes.
    #[error(
        "OP_REQUESTSOURCES2 payload is {actual} bytes, not the {expected} the standalone shape requires"
    )]
    WrongSize {
        /// What the shape requires.
        expected: usize,
        /// What arrived.
        actual: usize,
    },
}

/// `OP_REQUESTSOURCES2` (SX2) — standalone shape
/// `<version 1><options 2><file_hash 16>` (19 bytes;
/// `DownloadClient.cpp::SendFileRequest`/`SendBlockRequests` @4e8f2b3c, both
/// sites write the same triple). `version` is the requester's own SX2
/// ceiling (aMule always sends `SOURCEEXCHANGE2_VERSION`, 4) and `options` is
/// reserved (aMule always sends 0) — both open `u8`/`u16` fields here rather
/// than [`SourceExchangeVersion`], since a *request* is not bounds-checked
/// the way an answer's declared version is.
///
/// aMule's own serve path has a documented defect here: it checks
/// `size != 16` and disconnects every standalone SX2 request
/// (`ClientTCPSocket.cpp` @4e8f2b3c) rather than the 19 bytes this shape
/// actually is — masked in the wild because SX2 requests normally ride
/// inside a multipacket (ADR-0054), not standalone. rmule's own decode does
/// not reproduce that defect; it requires exactly the correct 19 bytes.
///
/// rmule both **serves** this (a peer's `0x83` decodes to the serve callback,
/// its `<ver>` feeding [`ServedSourcesVersion::negotiate`]) and **sends** it as
/// a requester when the peer advertised `SupportsSourceEx2` — the
/// `session`-side pick between `0x83` and the bare-hash `0x81`, aMule-exact
/// (`CUpDownClient::SendFileRequest`, `DownloadClient.cpp` @4e8f2b3c).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSources2 {
    /// The requester's own SX2 ceiling. Left an open byte: a request's
    /// version is not bounds-checked the way an answer's declaration is.
    pub version: u8,
    /// Reserved; aMule always sends 0.
    pub options: u16,
    /// The file sources are wanted for.
    pub file_hash: FileHash,
}

impl RequestSources2 {
    const WIRE_LEN: usize = 1 + 2 + FileHash::BYTE_LEN;

    /// Frame this ask at the standalone 19-byte shape.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(Self::WIRE_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.options.to_le_bytes());
        payload.extend_from_slice(self.file_hash.as_bytes());
        Packet::new(
            PeerOpcode::RequestSources2.protocol(),
            PeerOpcode::RequestSources2.as_u8(),
            payload,
        )
    }

    /// Read a peer's standalone ask, requiring the full 19 bytes rather
    /// than aMule's `size != 16` check (see the type docs).
    pub fn decode_packet(packet: &Packet) -> Result<Self, RequestSources2DecodeError> {
        let payload = packet.payload();
        if payload.len() != Self::WIRE_LEN {
            return Err(RequestSources2DecodeError::WrongSize {
                expected: Self::WIRE_LEN,
                actual: payload.len(),
            });
        }
        let version = payload[0];
        let options = u16::from_le_bytes([payload[1], payload[2]]);
        let mut hash = [0u8; FileHash::BYTE_LEN];
        hash.copy_from_slice(&payload[3..3 + FileHash::BYTE_LEN]);
        Ok(Self {
            version,
            options,
            file_hash: FileHash::from_bytes(hash),
        })
    }
}
