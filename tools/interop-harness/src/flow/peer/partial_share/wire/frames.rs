//! The tap reader's frame decoders: one eD2k TCP frame or client-UDP
//! datagram in, what it said out, laid out as aMule's
//! `include/protocol/ed2k/Client2Client/{TCP,UDP}.h` and its writers give
//! them (stock 2.3.3).

use std::collections::HashMap;
use std::io::Read as _;

use super::{HASH_LEN, Hash, Said, Status, Udp};

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_PACKEDPROT: u8 = 0xD4;

const OP_SENDINGPART: u8 = 0x46;
const OP_REQUESTPARTS: u8 = 0x47;
const OP_FILEREQANSNOFIL: u8 = 0x48;
const OP_SETREQFILEID: u8 = 0x4F;
const OP_FILESTATUS: u8 = 0x50;
const OP_HASHSETREQUEST: u8 = 0x51;
const OP_HASHSETANSWER: u8 = 0x52;
const OP_STARTUPLOADREQ: u8 = 0x54;
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
const OP_CANCELTRANSFER: u8 = 0x56;
const OP_OUTOFPARTREQS: u8 = 0x57;
const OP_REQUESTFILENAME: u8 = 0x58;
const OP_REQFILENAMEANSWER: u8 = 0x59;

const OP_COMPRESSEDPART: u8 = 0x40;
const OP_QUEUERANKING: u8 = 0x60;
const OP_REQUESTSOURCES: u8 = 0x81;
const OP_ANSWERSOURCES: u8 = 0x82;
const OP_REQUESTSOURCES2: u8 = 0x83;
const OP_ANSWERSOURCES2: u8 = 0x84;
const OP_MULTIPACKET: u8 = 0x92;
const OP_MULTIPACKETANSWER: u8 = 0x93;
const OP_AICHFILEHASHANS: u8 = 0x9D;
const OP_AICHFILEHASHREQ: u8 = 0x9E;
const OP_COMPRESSEDPART_I64: u8 = 0xA1;
const OP_SENDINGPART_I64: u8 = 0xA2;
const OP_REQUESTPARTS_I64: u8 = 0xA3;
const OP_MULTIPACKET_EXT: u8 = 0xA4;

const OP_REASKFILEPING: u8 = 0x90;
const OP_REASKACK: u8 = 0x91;
const OP_FILENOTFOUND: u8 = 0x92;
const OP_QUEUEFULL: u8 = 0x93;

const AICH_HASH_LEN: usize = 20;

/// A frame's protocol and payload as the receiver reads them: a packed
/// frame inflated and taken as the `0xC5` frame it carries.
pub(super) fn unpacked(protocol: u8, payload: &[u8]) -> Option<(u8, Vec<u8>)> {
    match protocol {
        OP_PACKEDPROT => Some((OP_EMULEPROT, inflate(payload)?)),
        OP_EDONKEYPROT | OP_EMULEPROT => Some((protocol, payload.to_vec())),
        _ => None,
    }
}

/// One link's compressed blocks in flight: by start offset, the packed size
/// a block's fragments add up to and the fragments so far.
#[derive(Default)]
pub(crate) struct Fragments {
    open: HashMap<u64, (usize, Vec<u8>)>,
}

impl Fragments {
    /// Add a fragment of the block at `start`; the inflated block once its
    /// fragments reach `packed`.
    fn add(&mut self, start: u64, packed: usize, fragment: &[u8]) -> Option<Vec<u8>> {
        let entry = self
            .open
            .entry(start)
            .or_insert_with(|| (packed, Vec::new()));
        entry.1.extend_from_slice(fragment);
        if entry.1.len() < entry.0 {
            return None;
        }
        let (_, bytes) = self.open.remove(&start)?;
        inflate(&bytes)
    }
}

/// What one frame said; empty when it is nothing this flow reads.
pub(crate) fn decode(
    protocol: u8,
    opcode: u8,
    body: &[u8],
    from_rmule: bool,
    fragments: &mut Fragments,
) -> Vec<Said> {
    let hash = || hash_at(body, 0);
    let one = |said: Option<Said>| said.into_iter().collect::<Vec<_>>();
    match (protocol, opcode, from_rmule) {
        (OP_EDONKEYPROT, OP_REQFILENAMEANSWER, true) => one(hash().and_then(|hash| {
            let name = string_at(body, HASH_LEN)?.0;
            Some(Said::Name { hash, name })
        })),
        (OP_EDONKEYPROT, OP_FILESTATUS, true) => one(hash().and_then(|hash| {
            let (status, _) = status_at(body, HASH_LEN)?;
            Some(Said::Status { hash, status })
        })),
        (OP_EDONKEYPROT, OP_HASHSETANSWER, true) => one(hash_set(body)),
        (OP_EDONKEYPROT, OP_FILEREQANSNOFIL, true) => one(hash().map(|hash| Said::NoFile { hash })),
        (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ, true) => vec![Said::Accept],
        (OP_EDONKEYPROT, OP_OUTOFPARTREQS, true) => vec![Said::OutOfParts],
        (OP_EMULEPROT, OP_QUEUERANKING, true) => {
            one(u16_at(body, 0).map(|rank| Said::Rank { rank }))
        }
        (OP_EDONKEYPROT, OP_SENDINGPART, true) => one(sending(body, 4)),
        (OP_EMULEPROT, OP_SENDINGPART_I64, true) => one(sending(body, 8)),
        (OP_EMULEPROT, OP_COMPRESSEDPART, true) => one(compressed(body, 4, fragments)),
        (OP_EMULEPROT, OP_COMPRESSEDPART_I64, true) => one(compressed(body, 8, fragments)),
        (OP_EMULEPROT, OP_ANSWERSOURCES, true) => one(sources(body, 0)),
        (OP_EMULEPROT, OP_ANSWERSOURCES2, true) => one(sources(body, 1)),
        (OP_EMULEPROT, OP_MULTIPACKETANSWER, true) => multipacket_answer(body),
        (OP_EDONKEYPROT, OP_REQUESTFILENAME, false) => one(hash().map(|hash| Said::NameAsk {
            hash,
            sources_asked: false,
        })),
        (OP_EDONKEYPROT, OP_SETREQFILEID, false) => {
            one(hash().map(|hash| Said::StatusAsk { hash }))
        }
        (OP_EDONKEYPROT, OP_HASHSETREQUEST, false) => {
            one(hash().map(|hash| Said::HashSetAsk { hash }))
        }
        (OP_EDONKEYPROT, OP_STARTUPLOADREQ, false) => vec![Said::SlotAsk { hash: hash() }],
        (OP_EDONKEYPROT, OP_CANCELTRANSFER, false) => vec![Said::Cancel],
        (OP_EDONKEYPROT, OP_REQUESTPARTS, false) => one(request(body, 4)),
        (OP_EMULEPROT, OP_REQUESTPARTS_I64, false) => one(request(body, 8)),
        (OP_EMULEPROT, OP_REQUESTSOURCES, false) => {
            one(hash().map(|hash| Said::SourcesAsk { hash }))
        }
        (OP_EMULEPROT, OP_REQUESTSOURCES2, false) => {
            one(hash_at(body, 3).map(|hash| Said::SourcesAsk { hash }))
        }
        (OP_EMULEPROT, OP_MULTIPACKET, false) => one(bundle(body, HASH_LEN)),
        (OP_EMULEPROT, OP_MULTIPACKET_EXT, false) => one(bundle(body, HASH_LEN + 8)),
        _ => Vec::new(),
    }
}

/// A peer's file-request bundle: a name ask, and whether it also asked for
/// sources. The name sub carries the asker's own status when it claims
/// extended requests, so the subs after it are found by skipping that
/// status when one is there.
fn bundle(body: &[u8], subs_at: usize) -> Option<Said> {
    let hash = hash_at(body, 0)?;
    let subs = body.get(subs_at..)?;
    let mut at = 0;
    let mut named = false;
    let mut sources_asked = false;
    while let Some(&sub) = subs.get(at) {
        at += 1;
        match sub {
            OP_REQUESTFILENAME => {
                named = true;
                // A status sub follows only when its bitmap fits before the
                // next sub; aMule writes count + bitmap, then optionally the
                // complete-source count.
                if let Some((_, after)) = status_at(subs, at)
                    && subs
                        .get(after)
                        .is_none_or(|next| BUNDLE_SUBS.contains(next))
                {
                    at = after;
                }
            }
            OP_SETREQFILEID | OP_AICHFILEHASHREQ => {}
            OP_REQUESTSOURCES => sources_asked = true,
            OP_REQUESTSOURCES2 => {
                sources_asked = true;
                at += 3;
            }
            _ => break,
        }
    }
    named.then_some(Said::NameAsk {
        hash,
        sources_asked,
    })
}

/// The subs a peer's bundle may hold after its name ask.
const BUNDLE_SUBS: [u8; 5] = [
    OP_REQUESTFILENAME,
    OP_SETREQFILEID,
    OP_REQUESTSOURCES,
    OP_REQUESTSOURCES2,
    OP_AICHFILEHASHREQ,
];

/// rmule's bundled answer: the name, the status and the AICH hash it holds.
fn multipacket_answer(body: &[u8]) -> Vec<Said> {
    let Some(hash) = hash_at(body, 0) else {
        return Vec::new();
    };
    let mut said = Vec::new();
    let mut at = HASH_LEN;
    while let Some(&sub) = body.get(at) {
        at += 1;
        match sub {
            OP_REQFILENAMEANSWER => {
                let Some((name, after)) = string_at(body, at) else {
                    break;
                };
                said.push(Said::Name { hash, name });
                at = after;
            }
            OP_FILESTATUS => {
                let Some((status, after)) = status_at(body, at) else {
                    break;
                };
                said.push(Said::Status { hash, status });
                at = after;
            }
            OP_AICHFILEHASHANS => at += AICH_HASH_LEN,
            _ => break,
        }
    }
    said
}

/// A status at `at`: `<count 2><bitmap (count + 7) / 8>`, and where it ends.
pub(crate) fn status_at(body: &[u8], at: usize) -> Option<(Status, usize)> {
    let count = u16_at(body, at)?;
    let bytes = usize::from(count).div_ceil(8);
    let bitmap = body.get(at + 2..at + 2 + bytes)?;
    let held = (0..u32::from(count))
        .filter(|&part| bitmap[part as usize / 8] & (1 << (part % 8)) != 0)
        .collect();
    Some((Status { count, held }, at + 2 + bytes))
}

fn hash_set(body: &[u8]) -> Option<Said> {
    let hash = hash_at(body, 0)?;
    let count = usize::from(u16_at(body, HASH_LEN)?);
    let parts = (0..count)
        .map(|index| hash_at(body, HASH_LEN + 2 + index * HASH_LEN))
        .collect::<Option<Vec<_>>>()?;
    Some(Said::HashSet { hash, parts })
}

/// `OP_SENDINGPART[_I64]`: `<hash><start><end><data>`, offsets `width` wide.
fn sending(body: &[u8], width: usize) -> Option<Said> {
    let hash = hash_at(body, 0)?;
    let start = uint_at(body, HASH_LEN, width)?;
    let end = uint_at(body, HASH_LEN + width, width)?;
    let bytes = body.get(HASH_LEN + 2 * width..)?.to_vec();
    (end.checked_sub(start)? == bytes.len() as u64).then_some(Said::Block { hash, start, bytes })
}

/// `OP_COMPRESSEDPART[_I64]`: `<hash><start><packed 4><fragment>`.
fn compressed(body: &[u8], width: usize, fragments: &mut Fragments) -> Option<Said> {
    let hash = hash_at(body, 0)?;
    let start = uint_at(body, HASH_LEN, width)?;
    let packed = usize::try_from(uint_at(body, HASH_LEN + width, 4)?).ok()?;
    let fragment = body.get(HASH_LEN + width + 4..)?;
    let bytes = fragments.add(start, packed, fragment)?;
    Some(Said::Block { hash, start, bytes })
}

/// `OP_REQUESTPARTS[_I64]`: three starts then three ends; an empty slot is
/// `0..0`.
fn request(body: &[u8], width: usize) -> Option<Said> {
    let hash = hash_at(body, 0)?;
    let at = |index: usize| uint_at(body, HASH_LEN + index * width, width);
    let ranges = (0..3)
        .map(|slot| Some((at(slot)?, at(slot + 3)?)))
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .filter(|(start, end)| end > start)
        .collect();
    Some(Said::Request { hash, ranges })
}

/// `OP_ANSWERSOURCES` (`lead` 0) or `OP_ANSWERSOURCES2` (`lead` 1, its
/// version byte): `<hash><count 2>` then fixed-stride records whose first
/// four bytes are the source's ID. The stride is what the body's length
/// divides into: 12 (v1), 28 (v2, v3) or 29 (v4).
fn sources(body: &[u8], lead: usize) -> Option<Said> {
    let hash = hash_at(body, lead)?;
    let count = usize::from(u16_at(body, lead + HASH_LEN)?);
    let records = body.get(lead + HASH_LEN + 2..)?;
    let ids = if count == 0 {
        Vec::new()
    } else {
        let stride = records.len() / count;
        if records.len() % count != 0 || ![12, 28, 29].contains(&stride) {
            return None;
        }
        records
            .chunks(stride)
            .map(|record| u32::from_le_bytes([record[0], record[1], record[2], record[3]]))
            .collect()
    };
    Some(Said::Sources { hash, ids })
}

/// One plain eMule client-UDP datagram this flow reads.
pub(crate) fn decode_udp(payload: &[u8], from_rmule: bool) -> Option<Udp> {
    if *payload.first()? != OP_EMULEPROT {
        return None;
    }
    let body = payload.get(2..)?;
    match (payload[1], from_rmule) {
        (OP_REASKFILEPING, false) => hash_at(body, 0).map(|hash| Udp::Ping { hash }),
        (OP_REASKACK, true) => {
            if body.len() == 2 {
                return Some(Udp::Ack {
                    status: None,
                    rank: u16_at(body, 0)?,
                });
            }
            let (status, after) = status_at(body, 0)?;
            (body.len() == after + 2).then_some(Udp::Ack {
                status: Some(status),
                rank: u16_at(body, after)?,
            })
        }
        (OP_FILENOTFOUND, true) => Some(Udp::NotFound),
        (OP_QUEUEFULL, true) => Some(Udp::QueueFull),
        _ => None,
    }
}

fn hash_at(body: &[u8], at: usize) -> Option<Hash> {
    body.get(at..at + HASH_LEN)?.try_into().ok()
}

fn u16_at(body: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(body.get(at..at + 2)?.try_into().ok()?))
}

fn uint_at(body: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = body.get(at..at + width)?;
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}

/// A `<len 2><bytes>` string at `at`, and where it ends.
fn string_at(body: &[u8], at: usize) -> Option<(String, usize)> {
    let len = usize::from(u16_at(body, at)?);
    let bytes = body.get(at + 2..at + 2 + len)?;
    Some((String::from_utf8_lossy(bytes).into_owned(), at + 2 + len))
}

fn inflate(packed: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(packed)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}
