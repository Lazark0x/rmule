//! Bundled file negotiation (ADR-0054): `OP_MULTIPACKET` (`0x92`) /
//! `OP_MULTIPACKET_EXT` (`0xA4`) collapse the request-side quintet into one
//! round trip; `OP_MULTIPACKETANSWER` (`0x93`) bundles the reply.
//!
//! Wire facts, pinned aMule 2.3.3 (`DownloadClient.cpp::SendFileRequest`,
//! `ClientTCPSocket.cpp::ProcessExtPacket` @ `4e8f2b3c`): the frame is
//! `<file_hash 16>` (`0xA4` inserts `<file_size 8>` right after) followed by
//! an **unframed** stream of `<sub_opcode 1><sub_payload…>` items. Each
//! item's payload is identical to the matching standalone packet's payload
//! with its leading `file_hash` stripped — the hash is already carried once,
//! in the frame header. Request-side sub-opcodes: `0x58` (name; the asker's
//! part status follows at extended-requests level 1 — nothing frames it, so
//! only the session's negotiated level tells a reader it is there),
//! `0x4F` (set-req-id, no payload), `0x81`/`0x83` (source request; SX2 adds
//! `<ver 1><opts 2>` — full SX2 serving semantics are ADR-0055's, this walker
//! only routes the sub-opcode), `0x9E` (AICH-root, no payload). Answer-side
//! sub-opcodes: `0x59` (name string), `0x50` (part status), `0x9D` (AICH
//! master hash, itself hash-less in standalone form already).
//!
//! Deliberately not built by re-entering the standalone packet codecs in
//! `file_request`/`source_exchange`/`aich` — the sub shapes differ by the
//! stripped hash, and wrapping synthetic `Packet`s would put wire fiction
//! into the dispatch layer. Fan-in to the session's existing standalone
//! handlers, `0x93` composition from real serve state, and the
//! capability-registry advert flip are the session's — this module is the
//! codec only (walkers, composers, error policy).
//!
//! **Walker error policy**: a truncated frame header is a decode error the
//! caller closes the connection on, mirroring aMule's `CEOFException`
//! disconnect and rmule's house rule for malformed known packets; so is a
//! truncated answer item. A request item cut short is reported as a
//! [`BundleCut`] instead, because aMule gates the bundle on its file before it
//! walks a single sub (`ClientTCPSocket.cpp:1061-1085`) — a cut bundle for a
//! file it does not share is answered not-found, not disconnected. An
//! unrecognized sub-opcode stops the walk, keeps the
//! already-decoded prefix, and reports [`UnknownSub`] so the caller can
//! surface one non-terminal diagnostic and stay connected — the remainder is
//! unparseable by construction (no length framing), so this is a
//! deliberate, capture-invisible divergence from aMule's own behaviour
//! (`ClientTCPSocket.cpp`'s `switch (opcode_in)` has no `default:` case, so
//! an unmatched sub-opcode's payload bytes silently get reinterpreted as
//! further opcodes on the next iteration).

use rmule_primitives::{AichRootHash, Ed2kText, FileHash, MAX_ED2K_FILE_SIZE, Packet};
use thiserror::Error;

use crate::file::PartBitmap;
use crate::file_request::{
    ExtendedRequests, FileSizedStatus, read_file_sized_status, write_part_status,
};
use crate::opcode::PeerOpcode;
use crate::source_exchange::ServedSourcesVersion;

/// `OP_REQUESTSOURCES2` (SX2) sub-opcode byte. Kept as a local const rather
/// than reusing [`PeerOpcode::RequestSources2`] (the standalone frame's
/// opcode): inside the unframed multipacket item
/// stream this byte is a sub-opcode with its own stripped-hash payload shape,
/// not a `(protocol, opcode)` frame — ADR-0055 owns the standalone pair's
/// consume semantics.
const OP_REQUESTSOURCES2: u8 = 0x83;

/// One item inside an unframed `OP_MULTIPACKET`/`OP_MULTIPACKET_EXT` request
/// stream — the standalone packet's payload with its leading `file_hash`
/// stripped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestItem {
    /// `OP_REQUESTFILENAME` (`0x58`) — the asker's part status at
    /// extended-requests level 1, nothing at level 0.
    Name {
        /// The asker's own availability, as `file_request::RequestFileName`
        /// carries it standalone.
        part_status: Option<PartBitmap>,
    },
    /// `OP_SETREQFILEID` (`0x4F`) — no payload.
    SetReqId,
    /// `OP_REQUESTSOURCES` (`0x81`) — source-exchange v1 ask, no payload.
    Sources,
    /// `OP_REQUESTSOURCES2` (`0x83`) — source-exchange v2 ask; payload
    /// `<ver 1><opts 2>`. SX2 serving semantics are ADR-0055's; this walker
    /// only routes the sub-opcode (ADR-0054).
    Sources2 {
        /// The requester's SX2 ceiling.
        version: u8,
        /// Reserved; aMule always sends 0.
        options: u16,
    },
    /// `OP_AICHFILEHASHREQ` (`0x9E`) — no payload.
    AichRoot,
}

/// One sub-ask of a bundle as the serving side answers it: a [`RequestItem`]
/// with the source ask's answer form already picked from the asker's advert.
/// The session hands a bundle's asks to core in one piece, so core can gate
/// the whole bundle on the file first, as aMule does before its sub-opcode
/// loop (stock 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:1061-1085`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundledAsk {
    /// `OP_REQUESTFILENAME` (`0x58`), with the asker's part status when the
    /// session's level carries one and it could be read.
    Name {
        /// The asker's own availability.
        part_status: Option<PartBitmap>,
    },
    /// `OP_SETREQFILEID` (`0x4F`).
    SetReqId,
    /// `OP_AICHFILEHASHREQ` (`0x9E`).
    AichRoot,
    /// `OP_REQUESTSOURCES` / `OP_REQUESTSOURCES2` (`0x81` / `0x83`), answered
    /// out of band in this wire form.
    Sources(ServedSourcesVersion),
}

/// One item inside an unframed `OP_MULTIPACKETANSWER` reply stream — the
/// standalone packet's payload with its leading `file_hash` stripped (the
/// AICH item never carried one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerItem {
    /// `OP_REQFILENAMEANSWER` (`0x59`) — string only.
    Name(Ed2kText),
    /// `OP_FILESTATUS` (`0x50`) — part-count + bitmap.
    Status(PartBitmap),
    /// `OP_AICHFILEHASHANS` (`0x9D`) — master hash.
    AichRoot(AichRootHash),
}

/// One non-terminal diagnostic: the walker met a sub-opcode it does not
/// model and stopped. `items` on the enclosing value still holds the fully
/// valid, already-decoded prefix (ADR-0054's walker error policy: stop, keep
/// prefix, stay open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownSub {
    /// The sub-opcode byte the walker did not recognize.
    pub opcode: u8,
    /// How many bytes remain in the payload after that sub-opcode byte —
    /// unparseable by construction, since sub-items carry no length prefix.
    pub remaining: usize,
}

/// `OP_MULTIPACKET` (`0x92`) / `OP_MULTIPACKET_EXT` (`0xA4`) — a bundled file
/// request. `file_size` is `Some` iff the frame is the `0xA4` (ext) form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiPacketRequest {
    /// The file every item in the bundle is about.
    pub file_hash: FileHash,
    /// The file's size, present only in the `0xA4` form.
    pub file_size: Option<u64>,
    /// The asks, in the order they were framed.
    pub items: Vec<RequestItem>,
    /// The first sub-opcode the walk did not model, when one stopped it early.
    pub unknown_sub: Option<UnknownSub>,
    /// Where the walk ran out of bytes inside a sub, when it did.
    pub cut: Option<BundleCut>,
}

/// A request walk that ran out of bytes inside a sub-ask — a name sub's
/// status or an SX2 sub's trailer. aMule's reader throws there and the packet
/// handler ends the connection (stock 2.3.3 `4e8f2b3c`
/// `ClientTCPSocket.cpp:2018-2047`) — but only once the bundle passed its file
/// gate (`:1061-1085`), so the walker reports the cut instead of failing the
/// packet, and the serving side decides after gating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleCut {
    /// Inside a name sub's status: the status as far as its bytes came —
    /// `None` when not even its count did, as aMule clears it before the read
    /// throws, else each byte's bits set before the next read can throw
    /// (`UploadClient.cpp:400-446`).
    NameStatus(Option<PartBitmap>),
    /// Inside an SX2 sub's `<ver 1><opts 2>` trailer.
    Sources2,
}

/// `OP_MULTIPACKETANSWER` (`0x93`) — a bundled reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiPacketAnswer {
    /// The file every item answers about.
    pub file_hash: FileHash,
    /// The answers, in the order they were framed.
    pub items: Vec<AnswerItem>,
    /// The first sub-opcode the walk did not model, when one stopped it early.
    pub unknown_sub: Option<UnknownSub>,
}

impl MultiPacketRequest {
    /// Read a bundle, stopping at the first sub-opcode this crate does not
    /// model and keeping the prefix already walked. `level` is the session's
    /// negotiated extended-requests level: it alone says whether a part status
    /// follows a `0x58` sub, since the stream frames nothing.
    pub fn decode_packet(
        packet: &Packet,
        level: ExtendedRequests,
    ) -> Result<Self, MultiPacketDecodeError> {
        let has_size = match PeerOpcode::try_from_u8(packet.opcode()) {
            Some(op @ PeerOpcode::MultiPacket) if op.protocol() == packet.protocol() => false,
            Some(op @ PeerOpcode::MultiPacketExt) if op.protocol() == packet.protocol() => true,
            // Dispatch only routes matching (protocol, opcode) here, but this is
            // a public decoder — a direct caller with a mismatched packet gets a
            // typed error, not a panic (the crate's malformed-input convention).
            _ => {
                return Err(MultiPacketDecodeError::UnexpectedOpcode {
                    opcode: packet.opcode(),
                });
            }
        };

        let payload = packet.payload();
        let header_len = FileHash::BYTE_LEN + if has_size { 8 } else { 0 };
        if payload.len() < header_len {
            return Err(MultiPacketDecodeError::Truncated {
                needed: header_len,
                actual: payload.len(),
            });
        }
        let file_hash = read_file_hash(&payload[..FileHash::BYTE_LEN]);
        let mut cursor = FileHash::BYTE_LEN;
        let file_size = if has_size {
            let size = u64::from_le_bytes(
                payload[cursor..cursor + 8]
                    .try_into()
                    .expect("validated length"),
            );
            cursor += 8;
            // The size is the peer's claim and sizes every status read below,
            // so a claim no eD2k file can have ends the bundle here.
            if size > MAX_ED2K_FILE_SIZE {
                return Err(MultiPacketDecodeError::FileSizeOutOfRange { size });
            }
            Some(size)
        } else {
            None
        };

        let mut items = Vec::new();
        let mut unknown_sub = None;
        let mut cut = None;
        while cursor < payload.len() {
            let sub_opcode = payload[cursor];
            cursor += 1;
            match PeerOpcode::try_from_u8(sub_opcode) {
                Some(PeerOpcode::RequestFileName) => {
                    if !level.carries_part_status() {
                        items.push(RequestItem::Name { part_status: None });
                        continue;
                    }
                    match read_name_status(&payload[cursor..], file_size) {
                        NameStatus::Read { status, len } => {
                            cursor += len;
                            items.push(RequestItem::Name {
                                part_status: status,
                            });
                        }
                        NameStatus::Cut(status) => {
                            cut = Some(BundleCut::NameStatus(status));
                            break;
                        }
                    }
                }
                Some(PeerOpcode::SetReqFileId) => items.push(RequestItem::SetReqId),
                Some(PeerOpcode::RequestSources) => items.push(RequestItem::Sources),
                Some(PeerOpcode::AichFileHashReq) => items.push(RequestItem::AichRoot),
                _ if sub_opcode == OP_REQUESTSOURCES2 => {
                    let needed = cursor + 3;
                    if payload.len() < needed {
                        cut = Some(BundleCut::Sources2);
                        break;
                    }
                    let version = payload[cursor];
                    let options = u16::from_le_bytes([payload[cursor + 1], payload[cursor + 2]]);
                    cursor = needed;
                    items.push(RequestItem::Sources2 { version, options });
                }
                // Unknown sub-opcode: stop, keep the prefix, report it — the
                // remainder has no length framing to skip past (ADR-0054).
                _ => {
                    unknown_sub = Some(UnknownSub {
                        opcode: sub_opcode,
                        remaining: payload.len() - cursor,
                    });
                    break;
                }
            }
        }

        Ok(Self {
            file_hash,
            file_size,
            items,
            unknown_sub,
            cut,
        })
    }

    #[must_use]
    /// Frame the bundle, picking the `0x92` or `0xA4` form by whether a file size is carried.
    pub fn encode_packet(&self) -> Packet {
        let opcode = if self.file_size.is_some() {
            PeerOpcode::MultiPacketExt
        } else {
            PeerOpcode::MultiPacket
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(self.file_hash.as_bytes());
        if let Some(size) = self.file_size {
            payload.extend_from_slice(&size.to_le_bytes());
        }
        for item in &self.items {
            match item {
                RequestItem::Name { part_status } => {
                    payload.push(PeerOpcode::RequestFileName.as_u8());
                    if let Some(status) = part_status {
                        write_part_status(&mut payload, status);
                    }
                }
                RequestItem::SetReqId => payload.push(PeerOpcode::SetReqFileId.as_u8()),
                RequestItem::Sources => payload.push(PeerOpcode::RequestSources.as_u8()),
                RequestItem::Sources2 { version, options } => {
                    payload.push(OP_REQUESTSOURCES2);
                    payload.push(*version);
                    payload.extend_from_slice(&options.to_le_bytes());
                }
                RequestItem::AichRoot => payload.push(PeerOpcode::AichFileHashReq.as_u8()),
            }
        }
        Packet::new(opcode.protocol(), opcode.as_u8(), payload)
    }
}

impl MultiPacketAnswer {
    /// Read an answer bundle, with the same stop-and-keep rule as the request.
    pub fn decode_packet(packet: &Packet) -> Result<Self, MultiPacketDecodeError> {
        let payload = packet.payload();
        if payload.len() < FileHash::BYTE_LEN {
            return Err(MultiPacketDecodeError::Truncated {
                needed: FileHash::BYTE_LEN,
                actual: payload.len(),
            });
        }
        let file_hash = read_file_hash(&payload[..FileHash::BYTE_LEN]);
        let mut cursor = FileHash::BYTE_LEN;

        let mut items = Vec::new();
        let mut unknown_sub = None;
        while cursor < payload.len() {
            let sub_opcode = payload[cursor];
            cursor += 1;
            match PeerOpcode::try_from_u8(sub_opcode) {
                Some(PeerOpcode::ReqFileNameAnswer) => {
                    let name = decode_name(payload, &mut cursor)?;
                    items.push(AnswerItem::Name(name));
                }
                Some(PeerOpcode::FileStatus) => {
                    let status = decode_status(payload, &mut cursor)?;
                    items.push(AnswerItem::Status(status));
                }
                Some(PeerOpcode::AichFileHashAns) => {
                    let needed = cursor + AichRootHash::BYTE_LEN;
                    if payload.len() < needed {
                        return Err(MultiPacketDecodeError::Truncated {
                            needed,
                            actual: payload.len(),
                        });
                    }
                    let mut buf = [0u8; AichRootHash::BYTE_LEN];
                    buf.copy_from_slice(&payload[cursor..needed]);
                    cursor = needed;
                    items.push(AnswerItem::AichRoot(AichRootHash::from_bytes(buf)));
                }
                // Unknown sub-opcode: stop, keep the prefix, report it — the
                // remainder has no length framing to skip past (ADR-0054).
                _ => {
                    unknown_sub = Some(UnknownSub {
                        opcode: sub_opcode,
                        remaining: payload.len() - cursor,
                    });
                    break;
                }
            }
        }

        Ok(Self {
            file_hash,
            items,
            unknown_sub,
        })
    }

    #[must_use]
    /// Frame the answer bundle.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.file_hash.as_bytes());
        for item in &self.items {
            match item {
                AnswerItem::Name(name) => {
                    payload.push(PeerOpcode::ReqFileNameAnswer.as_u8());
                    let bytes = name.as_bytes();
                    let len = u16::try_from(bytes.len()).expect("name length exceeds u16");
                    payload.extend_from_slice(&len.to_le_bytes());
                    payload.extend_from_slice(bytes);
                }
                AnswerItem::Status(bitmap) => {
                    payload.push(PeerOpcode::FileStatus.as_u8());
                    let part_count = u16::try_from(bitmap.part_count())
                        .expect("part_count exceeds u16 — wire encoding does not support that");
                    payload.extend_from_slice(&part_count.to_le_bytes());
                    payload.extend_from_slice(&bitmap.encode());
                }
                AnswerItem::AichRoot(root) => {
                    payload.push(PeerOpcode::AichFileHashAns.as_u8());
                    payload.extend_from_slice(root.as_bytes());
                }
            }
        }
        Packet::new(
            PeerOpcode::MultiPacketAnswer.protocol(),
            PeerOpcode::MultiPacketAnswer.as_u8(),
            payload,
        )
    }
}

/// Read the `0x59` sub-item body — `<u16 name_len><name>` — advancing
/// `cursor` past exactly what it consumed (more items may follow).
fn decode_name(payload: &[u8], cursor: &mut usize) -> Result<Ed2kText, MultiPacketDecodeError> {
    let len_end = *cursor + 2;
    if payload.len() < len_end {
        return Err(MultiPacketDecodeError::Truncated {
            needed: len_end,
            actual: payload.len(),
        });
    }
    let name_len = u16::from_le_bytes([payload[*cursor], payload[*cursor + 1]]) as usize;
    let name_start = len_end;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(MultiPacketDecodeError::Truncated {
            needed: usize::MAX,
            actual: payload.len(),
        })?;
    if payload.len() < name_end {
        return Err(MultiPacketDecodeError::Truncated {
            needed: name_end,
            actual: payload.len(),
        });
    }
    *cursor = name_end;
    Ok(Ed2kText::from_bytes(payload[name_start..name_end].to_vec()))
}

/// Read the `0x50` sub-item body — `<u16 part_count><bitmap>` — advancing
/// `cursor` past exactly what it consumed (more items may follow).
fn decode_status(payload: &[u8], cursor: &mut usize) -> Result<PartBitmap, MultiPacketDecodeError> {
    let count_end = *cursor + 2;
    if payload.len() < count_end {
        return Err(MultiPacketDecodeError::Truncated {
            needed: count_end,
            actual: payload.len(),
        });
    }
    let part_count = u16::from_le_bytes([payload[*cursor], payload[*cursor + 1]]) as u32;
    let bitmap_start = count_end;
    let bitmap_len = (part_count as usize).div_ceil(8);
    let bitmap_end = bitmap_start + bitmap_len;
    if payload.len() < bitmap_end {
        return Err(MultiPacketDecodeError::Truncated {
            needed: bitmap_end,
            actual: payload.len(),
        });
    }
    let bitmap = PartBitmap::decode(part_count, &payload[bitmap_start..bitmap_end])
        .expect("slice length matches part_count by construction");
    *cursor = bitmap_end;
    Ok(bitmap)
}

/// What a name sub's status took of the stream.
enum NameStatus {
    /// Read whole, or cleared (`None`), taking `len` bytes.
    Read {
        status: Option<PartBitmap>,
        len: usize,
    },
    /// The stream ended inside it: the bits read, when any.
    Cut(Option<PartBitmap>),
}

/// Read a name sub's status from the front of `rest`. `OP_MULTIPACKET_EXT`
/// carries a size, and its status is read exactly as aMule's
/// `ProcessExtendedInfo` reads it — by that size's part count, a count that is
/// not it cleared after its two bytes and the walk carried on from there
/// (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:414-446`). The size is still the
/// peer's claim here: the decode runs before the serving side compares it to
/// the file's, so the claim is bounded at [`MAX_ED2K_FILE_SIZE`] and the count
/// compared arithmetically, never by building a bitmap the claim sizes. A plain
/// `OP_MULTIPACKET` names no size, so its status is sized by the wire's count
/// and the serving side drops a count that is not the file's (ADR-0055 §Name-ask surface).
fn read_name_status(rest: &[u8], file_size: Option<u64>) -> NameStatus {
    match file_size {
        Some(file_size) => match read_file_sized_status(rest, file_size) {
            FileSizedStatus::Read { status, end } => NameStatus::Read {
                status: Some(status),
                len: end,
            },
            FileSizedStatus::Cleared => NameStatus::Read {
                status: None,
                len: 2,
            },
            FileSizedStatus::Cut(status) => NameStatus::Cut(status),
        },
        None => {
            let mut cursor = 0;
            match decode_status(rest, &mut cursor) {
                Ok(status) => NameStatus::Read {
                    status: Some(status),
                    len: cursor,
                },
                Err(_) => NameStatus::Cut(None),
            }
        }
    }
}

fn read_file_hash(bytes: &[u8]) -> FileHash {
    let mut buf = [0u8; FileHash::BYTE_LEN];
    buf.copy_from_slice(&bytes[..FileHash::BYTE_LEN]);
    FileHash::from_bytes(buf)
}

/// Why a bundle could not be read. An unmodelled sub-opcode is not here:
/// that stops the walk and is reported with the prefix, not as a failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MultiPacketDecodeError {
    /// The bundle ended inside a sub-item's own fields.
    #[error("multipacket payload truncated: needed {needed} bytes, had {actual}")]
    Truncated {
        /// Bytes that sub-item requires.
        needed: usize,
        /// Bytes left in the bundle.
        actual: usize,
    },

    /// The frame is not a bundle at all.
    #[error("multipacket decode called on non-multipacket opcode 0x{opcode:02X}")]
    UnexpectedOpcode {
        /// The opcode that arrived.
        opcode: u8,
    },

    /// `OP_MULTIPACKET_EXT` claimed a file size above eD2k's 256 GiB ceiling.
    #[error("multipacket file size {size} exceeds the eD2k maximum")]
    FileSizeOutOfRange {
        /// The size the bundle claimed.
        size: u64,
    },
}

#[cfg(test)]
mod tests;
