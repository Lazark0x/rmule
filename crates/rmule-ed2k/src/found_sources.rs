//! `OP_FOUNDSOURCES` (0x44) and its obfuscated form: the sources a server
//! answers a lookup with.
//!
//! Each source carries id, TCP port and — in the obfuscated form — a crypt
//! options byte whose top bit says a 16-byte User Hash follows. That bit is a
//! wire-transport flag, not one of the crypt capability bits below it.

use rmule_primitives::{
    FileHash, Packet, PacketProtocol, PeerSource, SourceClaim, SourceCryptOptions, SourceListTail,
};

use crate::source_record::{self, HAS_USER_HASH, RECORD_LEN, RecordForm};
use crate::{Ed2kError, Opcode, Result};

/// Refuse what the wire cannot carry: more than a `u8` count of sources, or a
/// High ID whose packed id is the sentinel (`255.255.255.255`) — written, it
/// would read back as a **Sentinel Source** with no address.
fn check_sources<'a>(
    opcode: Opcode,
    mut sources: impl ExactSizeIterator<Item = &'a PeerSource>,
    too_many: &'static str,
) -> Result<usize> {
    if sources.len() > usize::from(u8::MAX) {
        return Err(Ed2kError::InvalidPayload {
            opcode: opcode.as_u8(),
            reason: too_many,
        });
    }
    let mut sentinels = 0;
    sources.try_for_each(|source| match source {
        PeerSource::Ipv6(_) => {
            sentinels += 1;
            Ok(())
        }
        _ if source.wire_id() == PeerSource::IPV6_SENTINEL => Err(Ed2kError::InvalidPayload {
            opcode: opcode.as_u8(),
            reason: "a High ID of 255.255.255.255 packs to the Sentinel Source id",
        }),
        _ => Ok(()),
    })?;
    Ok(sentinels)
}

/// `OP_FOUNDSOURCES`: the sources a server knows for one file, in the plain
/// form — id and port only, no crypt material, so every one is dialed
/// plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FoundSources {
    file_hash: FileHash,
    sources: Vec<PeerSource>,
    tail: SourceListTail,
}

impl FoundSources {
    /// Construct an `OP_FOUNDSOURCES` body. The wire count field is a
    /// `u8`, so up to 255 entries are permitted; checking here keeps
    /// `encode_packet` infallible.
    pub fn new(file_hash: FileHash, sources: Vec<PeerSource>) -> Result<Self> {
        let sentinels = check_sources(
            Opcode::FoundSources,
            sources.iter(),
            "OP_FOUNDSOURCES source count exceeds u8 wire ceiling (255)",
        )?;
        Ok(Self {
            file_hash,
            sources,
            tail: SourceListTail::Read { sentinels },
        })
    }

    /// The file these sources are for.
    #[must_use]
    pub fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The sources, in the order the server sent them. A **Sentinel Source**
    /// whose inline address is not a usable identity is absent, and so is
    /// every record from the first sentinel on in a malformed list (ADR-0085).
    #[must_use]
    pub fn sources(&self) -> &[PeerSource] {
        &self.sources
    }

    /// How the list measured — the diagnostic a **Malformed Tail** leaves
    /// behind (ADR-0085).
    #[must_use]
    pub fn tail(&self) -> SourceListTail {
        self.tail
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::FoundSources.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_FOUNDSOURCES",
            });
        }
        let payload = packet.payload();
        if payload.len() < FileHash::BYTE_LEN + 1 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_FOUNDSOURCES payload missing file hash or count byte",
            });
        }
        let mut hash_bytes = [0u8; FileHash::BYTE_LEN];
        hash_bytes.copy_from_slice(&payload[..FileHash::BYTE_LEN]);
        let count = usize::from(payload[FileHash::BYTE_LEN]);
        let records =
            source_record::read_exact(&payload[FileHash::BYTE_LEN + 1..], count, RecordForm::Plain)
                .ok_or(Ed2kError::InvalidPayload {
                    opcode,
                    reason: "OP_FOUNDSOURCES declared count does not fit the payload",
                })?;
        Ok(Self {
            file_hash: FileHash::from_bytes(hash_bytes),
            sources: records.records.iter().filter_map(|r| r.source).collect(),
            tail: records.tail,
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let count = u8::try_from(self.sources.len()).expect("FoundSources invariant: len <= 255");
        let mut payload =
            Vec::with_capacity(FileHash::BYTE_LEN + 1 + self.sources.len() * RECORD_LEN);
        payload.extend_from_slice(self.file_hash.as_bytes());
        payload.push(count);
        for source in &self.sources {
            source_record::encode_record(&mut payload, *source, None);
        }
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::FoundSources.as_u8(),
            payload,
        )
    }
}

/// `OP_FOUNDSOURCES_OBFU` (`0x44`): the obfuscation-aware server source reply.
/// Same header as `0x42` (`[file hash 16][count 1]`) but each source item is
/// `[id 4][tcp port 2][crypt-options 1]` and, iff the crypt byte has
/// its `HAS_USER_HASH` bit set, `[user hash 16]` — then, for a **Sentinel
/// Source**, its `[ipv6 16]` last, after both (ADR-0085). That per-source
/// crypt-options + optional User Hash is exactly the `(crypt_options,
/// user_hash)` provenance ADR-0046 threads onto candidates, so each source
/// decodes to a [`SourceClaim`] — the same model the peer source-exchange
/// path produces — which the session's owner states as the server's word
/// (ADR-0085). This *amends* ADR-0042's rule that server-lookup sources can
/// never be obfuscate-dialed: a `0x44` source's crypt side reads through
/// [`SourceClaim::peer_crypt`], the same [`PeerCrypt::outbound`]
/// (ADR-0049) rule every dial meets its peer with.
///
/// [`PeerCrypt::outbound`]: rmule_primitives::PeerCrypt::outbound
///
/// Wire layout from aMule `CPartFile::AddSources(..., bWithObfuscationAndHash)`
/// @ `377ec8d9`. **`[pending]`** until an obfuscation-capable eserver capture
/// confirms it byte-for-byte (ADR-0046 evidence; the counterparty is unproven).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundSourcesObfu {
    file_hash: FileHash,
    sources: Vec<SourceClaim>,
    tail: SourceListTail,
}

impl FoundSourcesObfu {
    /// Construct an `OP_FOUNDSOURCES_OBFU` body. The wire count field is a
    /// `u8`, so up to 255 entries are permitted; checking here keeps
    /// `encode_packet` infallible.
    pub fn new(file_hash: FileHash, sources: Vec<SourceClaim>) -> Result<Self> {
        // A server answers with eD2k records only: a Kad callback row has no
        // record form to put in one.
        let peer_sources: Vec<PeerSource> = sources
            .iter()
            .map(|source| source.peer_source())
            .collect::<Option<_>>()
            .ok_or(Ed2kError::InvalidPayload {
                opcode: Opcode::FoundSourcesObfu.as_u8(),
                reason: "a Kad callback row has no server source record",
            })?;
        let sentinels = check_sources(
            Opcode::FoundSourcesObfu,
            peer_sources.iter(),
            "OP_FOUNDSOURCES_OBFU source count exceeds u8 wire ceiling (255)",
        )?;
        Ok(Self {
            file_hash,
            sources,
            tail: SourceListTail::Read { sentinels },
        })
    }

    /// The file these sources are for.
    #[must_use]
    pub fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The sources, each carrying the crypt material its entry included,
    /// dropped exactly as [`FoundSources::sources`] drops them (ADR-0085).
    #[must_use]
    pub fn sources(&self) -> &[SourceClaim] {
        &self.sources
    }

    /// How the list measured (ADR-0085).
    #[must_use]
    pub fn tail(&self) -> SourceListTail {
        self.tail
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::FoundSourcesObfu.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_FOUNDSOURCES_OBFU",
            });
        }
        let payload = packet.payload();
        if payload.len() < FileHash::BYTE_LEN + 1 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_FOUNDSOURCES_OBFU payload missing file hash or count byte",
            });
        }
        let mut hash_bytes = [0u8; FileHash::BYTE_LEN];
        hash_bytes.copy_from_slice(&payload[..FileHash::BYTE_LEN]);
        let count = usize::from(payload[FileHash::BYTE_LEN]);
        let records = source_record::read_exact(
            &payload[FileHash::BYTE_LEN + 1..],
            count,
            RecordForm::Obfuscated,
        )
        .ok_or(Ed2kError::InvalidPayload {
            opcode,
            reason: "OP_FOUNDSOURCES_OBFU declared count does not fit the payload",
        })?;
        let sources = records
            .records
            .into_iter()
            .filter_map(|record| {
                // Store the capability bits only: HAS_USER_HASH is
                // wire-transport framing (consumed by the walk to gate the
                // hash), not a crypt capability, so leaking it in would split
                // `SourceClaim` dedup against an equivalent
                // source-exchange source. aMule keeps `byCryptOptions & 0x7F`.
                let crypt = record.crypt_byte.unwrap_or(0) & !HAS_USER_HASH;
                Some(SourceClaim::new(
                    record.source?,
                    record.user_hash,
                    Some(SourceCryptOptions::from_byte(crypt)),
                ))
            })
            .collect();
        let tail = records.tail;
        Ok(Self {
            file_hash: FileHash::from_bytes(hash_bytes),
            sources,
            tail,
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let count =
            u8::try_from(self.sources.len()).expect("FoundSourcesObfu invariant: len <= 255");
        let mut payload = Vec::with_capacity(FileHash::BYTE_LEN + 1);
        payload.extend_from_slice(self.file_hash.as_bytes());
        payload.push(count);
        // `new` admitted only claims with a record.
        for (source, record) in self
            .sources
            .iter()
            .filter_map(|source| Some((source, source.peer_source()?)))
        {
            // The wire crypt byte is the source's crypt bits with HAS_USER_HASH
            // forced to match hash presence, so the byte and the hash never
            // disagree — a decode of this encode reproduces the same source.
            let crypt_bits = source
                .crypt_options()
                .map_or(0, SourceCryptOptions::as_byte)
                & !HAS_USER_HASH;
            let crypt_byte = if source.user_hash().is_some() {
                crypt_bits | HAS_USER_HASH
            } else {
                crypt_bits
            };
            source_record::encode_record(
                &mut payload,
                record,
                Some((crypt_byte, source.user_hash())),
            );
        }
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::FoundSourcesObfu.as_u8(),
            payload,
        )
    }
}
