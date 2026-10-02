//! `OP_OFFERFILES` (0x15): announcing the files this node shares.
//!
//! The serve side hands over files in domain terms — hash, name, size, and
//! the complete-source hint — and this module turns them into the tagged wire
//! entries, including the high-half size tag a file past 4 GiB needs.

use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Packet, PacketProtocol, Tag, TagName, TagValue,
};

use crate::{Ed2kError, Opcode, Result};

/// aMule file-announce tag IDs (per `docs/reference/notes/tags.md` and the
/// pinned aMule source `377ec8d9`: `src/KnownFile.cpp` / `opcodes.h`).
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILESIZE_HI: u8 = 0x3A;

/// One file to announce, in domain terms. The serve side hands these to
/// `Ed2kCommand::OfferFiles`; the session turns them into wire entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedFile {
    file_hash: FileHash,
    file_size: u64,
    name: Ed2kText,
}

impl OfferedFile {
    /// A file to offer, from the three facts a server indexes it by.
    #[must_use]
    pub const fn new(file_hash: FileHash, file_size: u64, name: Ed2kText) -> Self {
        Self {
            file_hash,
            file_size,
            name,
        }
    }

    /// The file's hash.
    #[must_use]
    pub const fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// Its size in bytes — a size past 4 GiB needs a server that advertised
    /// large-file support.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    /// The name it is offered under, byte-faithful.
    #[must_use]
    pub const fn name(&self) -> &Ed2kText {
        &self.name
    }
}

/// One on-the-wire `OP_OFFERFILES` file entry: the file hash, the
/// complete-source `client_id`/`client_port` hint, and the file's tag list
/// (`FT_FILENAME`, `FT_FILESIZE`, and `FT_FILESIZE_HI` for files > 4 GiB).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferEntry {
    file_hash: FileHash,
    client_id: ClientId,
    client_port: u16,
    tags: Vec<Tag>,
}

impl OfferEntry {
    /// The file's hash.
    #[must_use]
    pub const fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The complete-source id hint the entry carries.
    #[must_use]
    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// The port that goes with the id hint.
    #[must_use]
    pub const fn client_port(&self) -> u16 {
        self.client_port
    }

    /// The entry's tags, in wire order.
    #[must_use]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }
}

/// The `OP_OFFERFILES` packet: a count-prefixed list of [`OfferEntry`].
/// An empty list is the legal "keep-alive" form aMule sends to a silent
/// server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferFiles {
    entries: Vec<OfferEntry>,
}

impl OfferFiles {
    /// Build an announce for `files`, presenting `client_id`/`client_port`
    /// as the complete-source hint on every entry (the High-ID complete
    /// source we are). Files larger than `u32::MAX` split their size into
    /// `FT_FILESIZE` (low 32 bits) + `FT_FILESIZE_HI` (high bits), matching
    /// aMule's large-file wire form.
    #[must_use]
    pub fn announce(client_id: ClientId, client_port: u16, files: &[OfferedFile]) -> Self {
        let entries = files
            .iter()
            .map(|file| {
                let mut tags = Vec::with_capacity(3);
                tags.push(Tag::new(
                    TagName::compact_id(FT_FILENAME),
                    TagValue::String(file.name.clone()),
                ));
                // Low 32 bits of the size (the only size tag for <= 4 GiB).
                tags.push(Tag::new(
                    TagName::compact_id(FT_FILESIZE),
                    TagValue::U32(file.file_size as u32),
                ));
                if file.file_size > u64::from(u32::MAX) {
                    tags.push(Tag::new(
                        TagName::compact_id(FT_FILESIZE_HI),
                        TagValue::U16((file.file_size >> 32) as u16),
                    ));
                }
                OfferEntry {
                    file_hash: file.file_hash,
                    client_id,
                    client_port,
                    tags,
                }
            })
            .collect();
        Self { entries }
    }

    #[must_use]
    /// The offered entries; empty is the legal keep-alive form.
    pub fn entries(&self) -> &[OfferEntry] {
        &self.entries
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::OfferFiles.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_OFFERFILES",
            });
        }
        let payload = packet.payload();
        let mut pos = 0usize;
        let file_count = read_u32(payload, &mut pos, opcode)?;
        let mut entries = Vec::new();
        for _ in 0..file_count {
            let mut hash_bytes = [0u8; FileHash::BYTE_LEN];
            hash_bytes.copy_from_slice(take(payload, &mut pos, FileHash::BYTE_LEN, opcode)?);
            let file_hash = FileHash::from_bytes(hash_bytes);
            let client_id = ClientId::from_u32(read_u32(payload, &mut pos, opcode)?);
            let client_port = read_u16(payload, &mut pos, opcode)?;
            let tag_count = read_u32(payload, &mut pos, opcode)?;
            let mut tags = Vec::new();
            for _ in 0..tag_count {
                let (tag, consumed) = Tag::decode_prefix(&payload[pos..])?;
                pos = pos.checked_add(consumed).ok_or(Ed2kError::InvalidPayload {
                    opcode,
                    reason: "offer tag length overflow",
                })?;
                tags.push(tag);
            }
            entries.push(OfferEntry {
                file_hash,
                client_id,
                client_port,
                tags,
            });
        }
        if pos != payload.len() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "trailing OP_OFFERFILES bytes",
            });
        }
        Ok(Self { entries })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::new();
        let count = u32::try_from(self.entries.len()).expect("offer file count exceeds u32");
        payload.extend_from_slice(&count.to_le_bytes());
        for entry in &self.entries {
            payload.extend_from_slice(entry.file_hash.as_bytes());
            payload.extend_from_slice(&entry.client_id.as_u32().to_le_bytes());
            payload.extend_from_slice(&entry.client_port.to_le_bytes());
            let tag_count = u32::try_from(entry.tags.len()).expect("offer tag count exceeds u32");
            payload.extend_from_slice(&tag_count.to_le_bytes());
            for tag in &entry.tags {
                payload.extend_from_slice(&tag.encode());
            }
        }
        Packet::new(PacketProtocol::Edonkey, Opcode::OfferFiles.as_u8(), payload)
    }
}

/// Read `len` bytes at `*pos`, advancing `*pos`. Bounds-checked: a claimed
/// count that runs past the payload becomes an `InvalidPayload`, never a
/// panic.
fn take<'a>(payload: &'a [u8], pos: &mut usize, len: usize, opcode: u8) -> Result<&'a [u8]> {
    let end = pos.checked_add(len).ok_or(Ed2kError::InvalidPayload {
        opcode,
        reason: "OP_OFFERFILES length overflow",
    })?;
    if end > payload.len() {
        return Err(Ed2kError::InvalidPayload {
            opcode,
            reason: "truncated OP_OFFERFILES payload",
        });
    }
    let slice = &payload[*pos..end];
    *pos = end;
    Ok(slice)
}

fn read_u32(payload: &[u8], pos: &mut usize, opcode: u8) -> Result<u32> {
    let bytes = take(payload, pos, 4, opcode)?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4-byte slice")))
}

fn read_u16(payload: &[u8], pos: &mut usize, opcode: u8) -> Result<u16> {
    let bytes = take(payload, pos, 2, opcode)?;
    Ok(u16::from_le_bytes(bytes.try_into().expect("2-byte slice")))
}
