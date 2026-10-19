//! `OP_OFFERFILES` (0x15): announcing the files this node shares.
//!
//! The serve side hands over files in domain terms — hash, name, size, and
//! whether the file is complete — and this module turns them into the tagged
//! wire entries, including the high-half size tag a file past 4 GiB needs.
//! It also owns the rule for the ID and port each entry carries
//! (aMule `CKnownFile::CreateOfferedFilePacket`, `KnownFile.cpp:1097-1124`).

use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Packet, PacketProtocol, Tag, TagName, TagValue, WireReader,
    WireTruncated,
};

use crate::{Ed2kError, Opcode, Result, ServerGrants};

/// aMule file-announce tag IDs (per `docs/reference/notes/tags.md` and the
/// pinned aMule source `377ec8d9`: `src/KnownFile.cpp` / `opcodes.h`).
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILESIZE_HI: u8 = 0x3A;

/// The ID a compression-flag server reads as "this file is complete"
/// (`FILE_COMPLETE_ID`, `KnownFile.cpp:1100`): not a client at all.
pub const COMPLETE_FILE_ID: u32 = 0xFBFB_FBFB;
/// The port that goes with [`COMPLETE_FILE_ID`] (`FILE_COMPLETE_PORT`).
pub const COMPLETE_FILE_PORT: u16 = 0xFBFB;
/// The ID a compression-flag server reads as "this file is incomplete"
/// (`FILE_INCOMPLETE_ID`, `KnownFile.cpp:1102`).
pub const INCOMPLETE_FILE_ID: u32 = 0xFCFC_FCFC;
/// The port that goes with [`INCOMPLETE_FILE_ID`] (`FILE_INCOMPLETE_PORT`).
pub const INCOMPLETE_FILE_PORT: u16 = 0xFCFC;

/// Whether an offered file is whole on disk, which a compression-flag server
/// reads off the entry's ID and port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileCompleteness {
    /// Every part is held and verified.
    Complete,
    /// A part-file still downloading.
    Incomplete,
}

/// One file to announce, in domain terms. The serve side hands these to
/// `Ed2kCommand::OfferFiles`; the session turns them into wire entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedFile {
    file_hash: FileHash,
    file_size: u64,
    name: Ed2kText,
    completeness: FileCompleteness,
}

impl OfferedFile {
    /// A complete file to offer, from the three facts a server indexes it by.
    #[must_use]
    pub const fn new(file_hash: FileHash, file_size: u64, name: Ed2kText) -> Self {
        Self {
            file_hash,
            file_size,
            name,
            completeness: FileCompleteness::Complete,
        }
    }

    /// The same file, marked `completeness`.
    #[must_use]
    pub const fn with_completeness(mut self, completeness: FileCompleteness) -> Self {
        self.completeness = completeness;
        self
    }

    /// Whether the file is whole.
    #[must_use]
    pub const fn completeness(&self) -> FileCompleteness {
        self.completeness
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
    /// Build an announce for `files` to the server `grants` describes, which
    /// holds `ed2k_id` for us; we present `presented_id` and reach at
    /// `client_port`. Each entry's ID and port follow aMule: a
    /// compression-flag server reads [`COMPLETE_FILE_ID`] or
    /// [`INCOMPLETE_FILE_ID`] off the file's completeness; any other server
    /// gets `presented_id` and `client_port` only while `ed2k_id` is High
    /// (`KnownFile.cpp:1113-1115`), and `0:0` otherwise. A large file
    /// ([`is_large_file`](rmule_primitives::is_large_file)) splits its size into
    /// `FT_FILESIZE` (low 32 bits) + `FT_FILESIZE_HI` (high bits), aMule's
    /// large-file wire form (`KnownFile.cpp:1138-1149`), even when the high
    /// bits are zero.
    #[must_use]
    pub fn announce(
        grants: ServerGrants,
        ed2k_id: ClientId,
        presented_id: ClientId,
        client_port: u16,
        files: &[OfferedFile],
    ) -> Self {
        let entries = files
            .iter()
            .map(|file| {
                let (client_id, client_port) = entry_origin(
                    grants,
                    ed2k_id,
                    presented_id,
                    client_port,
                    file.completeness,
                );
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
                if rmule_primitives::is_large_file(file.file_size) {
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
        let mut reader = WireReader::new(packet.payload());
        let truncated = |error: WireTruncated| Ed2kError::InvalidPayload {
            opcode,
            reason: error.field,
        };
        let file_count = reader
            .read_u32_le("OP_OFFERFILES file count")
            .map_err(truncated)?;
        let mut entries = Vec::new();
        for _ in 0..file_count {
            let file_hash = reader
                .read_file_hash("OP_OFFERFILES file hash")
                .map_err(truncated)?;
            let client_id = ClientId::from_u32(
                reader
                    .read_u32_le("OP_OFFERFILES client id")
                    .map_err(truncated)?,
            );
            let client_port = reader
                .read_u16_le("OP_OFFERFILES client port")
                .map_err(truncated)?;
            let tag_count = reader
                .read_u32_le("OP_OFFERFILES tag count")
                .map_err(truncated)?;
            let mut tags = Vec::new();
            for _ in 0..tag_count {
                let (tag, consumed) = Tag::decode_prefix(reader.remaining_bytes())?;
                reader
                    .skip(consumed, "OP_OFFERFILES tag")
                    .map_err(truncated)?;
                tags.push(tag);
            }
            entries.push(OfferEntry {
                file_hash,
                client_id,
                client_port,
                tags,
            });
        }
        if !reader.is_exhausted() {
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

/// The ID and port one entry carries (`KnownFile.cpp:1097-1124`): the gate
/// reads the eD2k ID, the bytes carry the Presented Client ID.
fn entry_origin(
    grants: ServerGrants,
    ed2k_id: ClientId,
    presented_id: ClientId,
    client_port: u16,
    completeness: FileCompleteness,
) -> (ClientId, u16) {
    if grants.compression {
        match completeness {
            FileCompleteness::Complete => {
                (ClientId::from_u32(COMPLETE_FILE_ID), COMPLETE_FILE_PORT)
            }
            FileCompleteness::Incomplete => {
                (ClientId::from_u32(INCOMPLETE_FILE_ID), INCOMPLETE_FILE_PORT)
            }
        }
    } else if ed2k_id.is_high_id() {
        (presented_id, client_port)
    } else {
        (ClientId::from_u32(0), 0)
    }
}
