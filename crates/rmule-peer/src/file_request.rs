//! File-probe packet quintet.
//!
//! Opcodes per `src/include/protocol/ed2k/Client2Client/TCP.h` at amule
//! `377ec8d9`:
//!   OP_REQUESTFILENAME   = 0x58 — client asks "what's the name of this hash?"
//!   OP_REQFILENAMEANSWER = 0x59 — peer answers with file name (u16-prefixed)
//!   OP_FILEREQANSNOFIL   = 0x48 — peer answers "I don't have that file"
//!   OP_SETREQFILEID      = 0x4F — client tells peer "this is the file we're talking about"
//!   OP_FILESTATUS        = 0x50 — peer answers part bitmap for the file
//!
//! All five live in `OP_EDONKEYPROT` space. `OP_REQUESTFILENAME` carries the
//! asker's own part status after the hash whenever the session's
//! [`ExtendedRequests`] level is at least 1.

use rmule_primitives::{Ed2kText, FileHash, Packet};
use thiserror::Error;

use crate::file::{PartBitmap, PartBitmapDecodeError};
use crate::opcode::PeerOpcode;

/// The extended-requests level one session speaks: whether a name ask
/// (`0x58`, standalone or a bundle sub) carries the asker's part status.
///
/// aMule's asker writes at the *uploader's* claim (`SendFileRequest`:
/// `if (GetExtendedRequestsVersion() > 0) WritePartStatus`, where the client
/// object is the uploader) and its uploader reads at the *asker's*
/// (`ProcessExtendedInfo`). Taking the lower of rmule's own claim and the
/// peer's satisfies both directions against every claim aMule, eMule and
/// emule-qt send (all `2`), and against an older rmule claiming `0`. Level 2's
/// complete-source count is never spoken: rmule claims `1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtendedRequests(u8);

impl ExtendedRequests {
    /// No part status rides a name ask — the level before a peer identified,
    /// and against a peer that claims none.
    pub const NONE: Self = Self(0);

    /// The level two ends meet at: the lower of `own` and `peer` claims.
    #[must_use]
    pub const fn negotiated(own: u8, peer: u8) -> Self {
        if own < peer { Self(own) } else { Self(peer) }
    }

    /// Whether a name ask carries the asker's part status.
    #[must_use]
    pub const fn carries_part_status(self) -> bool {
        self.0 >= 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_REQUESTFILENAME` (`0x58`) — what do you call this file? Carries the
/// asker's own availability when the session's [`ExtendedRequests`] level
/// says so; aMule's uploader then keeps it for the source-exchange answer.
pub struct RequestFileName {
    /// The file being asked about.
    pub file_hash: FileHash,
    /// Every byte after the hash: the asker's own part status
    /// (`<u16 count><bitmap>`), empty for the bare-hash form.
    pub status: PartStatusTail,
}

/// The bytes a standalone name ask carries after the file hash, left unread
/// by the wire decoder. aMule's uploader sizes the status by the **asked
/// file's** part count, not the count on the wire, and a count that is not
/// the file's clears the status instead of failing the packet (stock 2.3.3
/// `4e8f2b3c` `UploadClient.cpp:414-446`) — so only the side that knows the
/// file can read it, through [`PartStatusTail::read`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartStatusTail(Vec<u8>);

impl PartStatusTail {
    /// The tail a writer puts after the hash for `status`, in aMule's
    /// `WritePartStatus` shape.
    #[must_use]
    pub fn of(status: &PartBitmap) -> Self {
        let mut bytes = Vec::new();
        write_part_status(&mut bytes, status);
        Self(bytes)
    }

    /// The tail as it arrived.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the ask was the hash alone.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The status read against the asked file of `file_size` bytes, as
    /// [`FileSizedStatus`] says — the reader a UDPv4 reask ping shares.
    #[must_use]
    pub fn read(&self, file_size: u64) -> FileSizedStatus {
        read_file_sized_status(&self.0, file_size)
    }
}

/// What aMule's `ProcessExtendedInfo` takes of an asker's part status for the
/// asked file (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:414-446`), whether the
/// status came on a name ask or a UDPv4 reask ping. The claim gate before it
/// and the complete-source count after it are each path's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileSizedStatus {
    /// Read whole: count `0` (a complete copy's, with nothing after it,
    /// `:415-416`) or the file's own count with its bitmap. `end` is how many
    /// bytes of the tail the status took.
    Read {
        /// The status in its wire shape (count `0`, or the file's count).
        status: PartBitmap,
        /// Bytes of the tail consumed.
        end: usize,
    },
    /// A count other than the file's: aMule clears the status and reads
    /// nothing more (`:418-422`) — the ask itself stands.
    Cleared,
    /// Cut short where aMule's reader throws: `None` when not even the count
    /// arrived (`:408-414`), else the status as far as its bytes came, each
    /// byte's bits set before the next read can throw (`:426-446`).
    Cut(Option<PartBitmap>),
}

/// Read a part status from the front of `tail` for a file of `file_size`
/// bytes, as [`FileSizedStatus`] says. The bitmap is sized by the file's real
/// part count (`GetPartCount()`, `:424`) — one short of the wire's count for
/// a size that is an exact multiple of the part size — while the status keeps
/// the wire's count.
#[must_use]
pub(crate) fn read_file_sized_status(tail: &[u8], file_size: u64) -> FileSizedStatus {
    let Some((count, bitmap)) = tail.split_first_chunk::<2>() else {
        return FileSizedStatus::Cut(None);
    };
    let count = u32::from(u16::from_le_bytes(*count));
    if count == 0 {
        return FileSizedStatus::Read {
            status: PartBitmap::decode(0, &[]).expect("an empty bitmap always decodes"),
            end: 2,
        };
    }
    // Compared arithmetically: `file_size` may be the peer's own claim, and
    // building a bitmap to count its parts allocates by that claim.
    if u64::from(count) != file_size / rmule_primitives::ED2K_PART_SIZE + 1 {
        return FileSizedStatus::Cleared;
    }
    let needed = (rmule_primitives::part_count(file_size) as usize).div_ceil(8);
    let read = &bitmap[..needed.min(bitmap.len())];
    let mut bytes = vec![0; (count as usize).div_ceil(8)];
    bytes[..read.len()].copy_from_slice(read);
    let status = PartBitmap::decode(count, &bytes).expect("sized by its own count");
    if read.len() < needed {
        return FileSizedStatus::Cut(Some(status));
    }
    FileSizedStatus::Read {
        status,
        end: 2 + needed,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_REQFILENAMEANSWER` (`0x59`) — the name, and with it the admission that the peer has the file.
pub struct ReqFileNameAnswer {
    /// The file named.
    pub file_hash: FileHash,
    /// What the peer calls it.
    pub file_name: Ed2kText,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_FILEREQANSNOFIL` (`0x48`) — the peer does not have the file.
pub struct FileReqAnsNoFil {
    /// The file it does not have.
    pub file_hash: FileHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_SETREQFILEID` (`0x4F`) — fix the file every later request on this link refers to.
pub struct SetReqFileId {
    /// The file to talk about from here on.
    pub file_hash: FileHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_FILESTATUS` (`0x50`) — which parts of that file the peer holds.
pub struct FileStatus {
    /// The file the bitmap describes.
    pub file_hash: FileHash,
    /// The parts it holds.
    pub bitmap: PartBitmap,
}

impl RequestFileName {
    /// The ask for `file_hash`, followed by `status` when the writer's level
    /// carries one.
    #[must_use]
    pub fn new(file_hash: FileHash, status: Option<&PartBitmap>) -> Self {
        Self {
            file_hash,
            status: status.map(PartStatusTail::of).unwrap_or_default(),
        }
    }

    /// Read the request; the dispatcher matched its opcode already. Whatever
    /// follows the hash is kept unread as the [`PartStatusTail`]: only the
    /// side that knows the asked file can size the status it holds.
    pub fn decode_packet(packet: &Packet) -> Result<Self, FileRequestDecodeError> {
        let payload = packet.payload();
        if payload.len() < FileHash::BYTE_LEN {
            return Err(FileRequestDecodeError::Truncated {
                needed: FileHash::BYTE_LEN,
                actual: payload.len(),
            });
        }
        Ok(Self {
            file_hash: read_file_hash(payload),
            status: PartStatusTail(payload[FileHash::BYTE_LEN..].to_vec()),
        })
    }

    #[must_use]
    /// Frame the request.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = self.file_hash.as_bytes().to_vec();
        payload.extend_from_slice(self.status.as_bytes());
        Packet::new(
            PeerOpcode::RequestFileName.protocol(),
            PeerOpcode::RequestFileName.as_u8(),
            payload,
        )
    }
}

/// Append a name ask's part status: `<u16 part count><bitmap>`, the shape of
/// aMule's `WritePartStatus`.
pub(crate) fn write_part_status(out: &mut Vec<u8>, status: &PartBitmap) {
    let part_count = u16::try_from(status.part_count())
        .expect("part_count exceeds u16 — wire encoding does not support that");
    out.extend_from_slice(&part_count.to_le_bytes());
    out.extend_from_slice(&status.encode());
}

impl SetReqFileId {
    /// Read the answer.
    pub fn decode_packet(packet: &Packet) -> Result<Self, FileRequestDecodeError> {
        let file_hash = decode_only_file_hash(packet)?;
        Ok(Self { file_hash })
    }

    #[must_use]
    /// Frame the answer.
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::SetReqFileId.protocol(),
            PeerOpcode::SetReqFileId.as_u8(),
            self.file_hash.as_bytes().to_vec(),
        )
    }
}

impl FileReqAnsNoFil {
    /// Read the refusal.
    pub fn decode_packet(packet: &Packet) -> Result<Self, FileRequestDecodeError> {
        let file_hash = decode_only_file_hash(packet)?;
        Ok(Self { file_hash })
    }

    #[must_use]
    /// Frame the refusal.
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PeerOpcode::FileReqAnsNoFil.protocol(),
            PeerOpcode::FileReqAnsNoFil.as_u8(),
            self.file_hash.as_bytes().to_vec(),
        )
    }
}

impl ReqFileNameAnswer {
    /// Read the file-id set.
    pub fn decode_packet(packet: &Packet) -> Result<Self, FileRequestDecodeError> {
        let payload = packet.payload();
        if payload.len() < FileHash::BYTE_LEN + 2 {
            return Err(FileRequestDecodeError::Truncated {
                needed: FileHash::BYTE_LEN + 2,
                actual: payload.len(),
            });
        }
        let file_hash = read_file_hash(&payload[..FileHash::BYTE_LEN]);
        let name_len =
            u16::from_le_bytes([payload[FileHash::BYTE_LEN], payload[FileHash::BYTE_LEN + 1]])
                as usize;
        let name_start = FileHash::BYTE_LEN + 2;
        let name_end =
            name_start
                .checked_add(name_len)
                .ok_or(FileRequestDecodeError::Truncated {
                    needed: usize::MAX,
                    actual: payload.len(),
                })?;
        if payload.len() < name_end {
            return Err(FileRequestDecodeError::Truncated {
                needed: name_end,
                actual: payload.len(),
            });
        }
        if payload.len() != name_end {
            return Err(FileRequestDecodeError::TrailingBytes);
        }
        Ok(Self {
            file_hash,
            file_name: Ed2kText::from_bytes(payload[name_start..name_end].to_vec()),
        })
    }

    #[must_use]
    /// Frame the file-id set.
    pub fn encode_packet(&self) -> Packet {
        let name = self.file_name.as_bytes();
        let mut payload = Vec::with_capacity(FileHash::BYTE_LEN + 2 + name.len());
        payload.extend_from_slice(self.file_hash.as_bytes());
        let len = u16::try_from(name.len()).expect("file name length exceeds u16");
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(name);
        Packet::new(
            PeerOpcode::ReqFileNameAnswer.protocol(),
            PeerOpcode::ReqFileNameAnswer.as_u8(),
            payload,
        )
    }
}

impl FileStatus {
    /// Read the status answer, bitmap included.
    pub fn decode_packet(packet: &Packet) -> Result<Self, FileRequestDecodeError> {
        let payload = packet.payload();
        if payload.len() < FileHash::BYTE_LEN + 2 {
            return Err(FileRequestDecodeError::Truncated {
                needed: FileHash::BYTE_LEN + 2,
                actual: payload.len(),
            });
        }
        let file_hash = read_file_hash(&payload[..FileHash::BYTE_LEN]);
        let part_count =
            u16::from_le_bytes([payload[FileHash::BYTE_LEN], payload[FileHash::BYTE_LEN + 1]])
                as u32;
        let bitmap = PartBitmap::decode(part_count, &payload[FileHash::BYTE_LEN + 2..])
            .map_err(FileRequestDecodeError::Bitmap)?;
        Ok(Self { file_hash, bitmap })
    }

    #[must_use]
    /// Frame the status answer.
    pub fn encode_packet(&self) -> Packet {
        let bitmap_bytes = self.bitmap.encode();
        let mut payload = Vec::with_capacity(FileHash::BYTE_LEN + 2 + bitmap_bytes.len());
        payload.extend_from_slice(self.file_hash.as_bytes());
        let part_count = u16::try_from(self.bitmap.part_count())
            .expect("part_count exceeds u16 — wire encoding does not support that");
        payload.extend_from_slice(&part_count.to_le_bytes());
        payload.extend_from_slice(&bitmap_bytes);
        Packet::new(
            PeerOpcode::FileStatus.protocol(),
            PeerOpcode::FileStatus.as_u8(),
            payload,
        )
    }
}

fn decode_only_file_hash(packet: &Packet) -> Result<FileHash, FileRequestDecodeError> {
    let payload = packet.payload();
    if payload.len() != FileHash::BYTE_LEN {
        return Err(FileRequestDecodeError::Truncated {
            needed: FileHash::BYTE_LEN,
            actual: payload.len(),
        });
    }
    Ok(read_file_hash(payload))
}

fn read_file_hash(bytes: &[u8]) -> FileHash {
    let mut buf = [0u8; FileHash::BYTE_LEN];
    buf.copy_from_slice(&bytes[..FileHash::BYTE_LEN]);
    FileHash::from_bytes(buf)
}

/// Why a file-probe packet could not be read.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FileRequestDecodeError {
    #[error("file-request packet payload truncated: needed {needed} bytes, had {actual}")]
    /// The payload ended inside a field the shape requires.
    Truncated {
        /// Bytes the shape requires at that point.
        needed: usize,
        /// Bytes present.
        actual: usize,
    },

    #[error("file-request packet payload has trailing bytes after declared name")]
    /// Bytes remain after the shape ends — the frame was not the packet it
    /// claimed to be, rather than that packet with extras.
    TrailingBytes,

    #[error("file-status bitmap decode failed: {0}")]
    /// The part bitmap inside an `OP_FILESTATUS` did not decode.
    Bitmap(#[from] PartBitmapDecodeError),
}
