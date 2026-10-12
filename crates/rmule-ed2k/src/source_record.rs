//! The source records `OP_FOUNDSOURCES`, `OP_FOUNDSOURCES_OBFU` and
//! `OP_GLOBFOUNDSOURCES` share, walked record by record with each **Sentinel
//! Source**'s address read inline (ADR-0085).
//!
//! One record is `[id 4][tcp port 2]`, then on `0x44` `[crypt 1]` and, iff the
//! crypt byte's top bit is set, `[user hash 16]`, then — only when the id is
//! `0xFFFFFFFF` — `[ipv6 16]`, always last. That is emule-qt
//! `docs/protocol/ipv6-spec.md:694-703` and its reader
//! `src/core/transfer/DownloadQueue.cpp:786-797` @ `73fff714`. Skipping the
//! sixteen bytes, or looking for them anywhere but inline, shifts every record
//! after the sentinel onto address bytes.
//!
//! A walk that runs short, or a frame-delimited list that leaves bytes over,
//! is a **Malformed Tail**: only the records before the first sentinel are
//! kept, because they sit at the same offsets whatever layout the sender used.
//! A classic list with no sentinel that runs short is a broken frame, exactly
//! as before sentinels existed.

use rmule_primitives::{ClientId, PeerSource, SourceListTail, UserHash, WireReader};

/// The classic part of every record: `[id 4][tcp port 2]`.
pub(crate) const RECORD_LEN: usize = 6;

/// `0x80` in the `OP_FOUNDSOURCES_OBFU` per-source crypt-options byte: a
/// 16-byte User Hash follows this source (aMule `CPartFile::AddSources`,
/// `(byCryptOptions & 0x80) > 0`). A wire-transport flag, not one of the
/// crypt capability bits below it.
pub(crate) const HAS_USER_HASH: u8 = 0x80;

/// Which record shape the list carries.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordForm {
    /// `0x42` / `0x9B`: id and port, plus the sentinel's address.
    Plain,
    /// `0x44`: the plain fields, the crypt byte and the optional User Hash,
    /// then the sentinel's address.
    Obfuscated,
}

/// One record as read. `source` is `None` for a **Sentinel Source** whose
/// inline address is not a usable identity: its bytes were consumed, it names
/// nothing.
pub(crate) struct Record {
    pub(crate) source: Option<PeerSource>,
    /// The `0x44` crypt byte as the wire carried it; `None` on the plain form.
    pub(crate) crypt_byte: Option<u8>,
    pub(crate) user_hash: Option<UserHash>,
}

/// A decoded source list: its records, how it measured, and how many bytes of
/// the frame it occupied.
pub(crate) struct SourceRecords {
    /// The records, in wire order. On a malformed list, only those before the
    /// first sentinel.
    pub(crate) records: Vec<Record>,
    /// How the list measured.
    pub(crate) tail: SourceListTail,
    /// Bytes read. Equal to the whole body when the list is malformed —
    /// nothing sane can follow it.
    pub(crate) consumed: usize,
}

/// Read a list whose frame ends with it (`0x42`, `0x44`): bytes past the last
/// record are unaccounted for.
///
/// `None` when a list with no sentinel does not fit its declared count — a
/// truncated frame.
pub(crate) fn read_exact(body: &[u8], count: usize, form: RecordForm) -> Option<SourceRecords> {
    let walk = walk(body, count, form);
    if walk.short || walk.consumed != body.len() {
        return malformed(walk, body.len());
    }
    Some(read(walk))
}

/// Read a list another packet may follow (`OP_GLOBFOUNDSOURCES`, several to a
/// datagram): whatever follows the last record is left for the next packet.
///
/// `None` when a list with no sentinel does not fit its declared count.
pub(crate) fn read_prefix(body: &[u8], count: usize) -> Option<SourceRecords> {
    let walk = walk(body, count, RecordForm::Plain);
    if walk.short {
        return malformed(walk, body.len());
    }
    Some(read(walk))
}

struct Walk {
    records: Vec<Record>,
    /// How many records were read before the first sentinel.
    before_first_sentinel: usize,
    sentinels: usize,
    /// Bytes the walk read.
    consumed: usize,
    short: bool,
}

fn walk(body: &[u8], count: usize, form: RecordForm) -> Walk {
    let mut walk = Walk {
        // Every record costs at least six bytes, so the body bounds the
        // allocation whatever the count claims.
        records: Vec::with_capacity(count.min(body.len() / RECORD_LEN)),
        before_first_sentinel: 0,
        sentinels: 0,
        consumed: 0,
        short: false,
    };
    let mut reader = WireReader::new(body);
    for _ in 0..count {
        let Some(record) = read_record(&mut reader, form, &mut walk.sentinels) else {
            walk.short = true;
            break;
        };
        if walk.sentinels == 0 {
            walk.before_first_sentinel += 1;
        }
        walk.records.push(record);
    }
    walk.consumed = reader.position();
    walk
}

/// One record at the reader, advancing it; `None` on a short read. Counts the
/// sentinel as soon as its id is read, so a sentinel cut short still marks the
/// list as sentinel-bearing.
fn read_record(
    reader: &mut WireReader<'_>,
    form: RecordForm,
    sentinels: &mut usize,
) -> Option<Record> {
    let id = reader.read_u32_le("source id").ok()?;
    let port = reader.read_u16_le("source port").ok()?;
    let is_sentinel = id == PeerSource::IPV6_SENTINEL;
    if is_sentinel {
        *sentinels += 1;
    }
    let (crypt_byte, user_hash) = match form {
        RecordForm::Plain => (None, None),
        RecordForm::Obfuscated => {
            let crypt = reader.read_u8("source crypt options").ok()?;
            let hash = if crypt & HAS_USER_HASH == 0 {
                None
            } else {
                Some(UserHash::from_bytes(
                    reader
                        .read_array::<{ UserHash::BYTE_LEN }>("source user hash")
                        .ok()?,
                ))
            };
            (Some(crypt), hash)
        }
    };
    let source = if is_sentinel {
        let address = reader
            .read_array::<{ PeerSource::SENTINEL_ADDRESS_LEN }>("sentinel address")
            .ok()?;
        PeerSource::from_sentinel_address(address, port)
    } else {
        PeerSource::from_record(ClientId::from_u32(id), port)
    };
    Some(Record {
        source,
        crypt_byte,
        user_hash,
    })
}

fn read(walk: Walk) -> SourceRecords {
    SourceRecords {
        tail: SourceListTail::Read {
            sentinels: walk.sentinels,
        },
        consumed: walk.consumed,
        records: walk.records,
    }
}

fn malformed(mut walk: Walk, body_len: usize) -> Option<SourceRecords> {
    if walk.short && walk.sentinels == 0 {
        return None;
    }
    walk.records.truncate(walk.before_first_sentinel);
    Some(SourceRecords {
        tail: SourceListTail::Malformed {
            sentinels: walk.sentinels,
            tail_len: body_len - walk.consumed,
        },
        consumed: body_len,
        records: walk.records,
    })
}

/// Append one record in the spec layout. `crypt` is the `0x44` crypt byte and
/// User Hash (the caller keeps the byte's top bit in step with the hash); the
/// sentinel's address goes last, after them.
pub(crate) fn encode_record(
    out: &mut Vec<u8>,
    source: PeerSource,
    crypt: Option<(u8, Option<UserHash>)>,
) {
    out.extend_from_slice(&source.wire_id().to_le_bytes());
    out.extend_from_slice(&source.tcp_port().to_le_bytes());
    if let Some((byte, hash)) = crypt {
        out.push(byte);
        if let Some(hash) = hash {
            out.extend_from_slice(hash.as_bytes());
        }
    }
    if let PeerSource::Ipv6(endpoint) = source {
        out.extend_from_slice(&endpoint.addr_bytes());
    }
}
