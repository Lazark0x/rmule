//! Frames under aMule's experimental tag-based framing, `OP_ED2KV2HEADER`
//! (`0xF4`). aMule writes them only to a client with value-based tags, which
//! rmule never claims, but its reader stands open to anyone
//! (`ClientTCPSocket.cpp:1827-1860`, stock 2.3.3 `4e8f2b3c`): an unknown opcode
//! is ignored, and the two it knows read tags, so a tag cut short throws.

use rmule_primitives::{Packet, WireReader};

use crate::error::WireFault;
use crate::packet::PeerPacket;
use crate::slot::QueueRank;

/// `OP_QUEUERANK` under this framing.
const OP_QUEUERANK: u8 = 0x5C;
/// `OP_REQUESTPARTS` under this framing.
const OP_REQUESTPARTS: u8 = 0x47;

/// Read a frame, as far as aMule's reader goes. A rank takes effect; a block
/// request reads for whether it throws and goes no further, since a peer that
/// asks in tags was never told it may.
pub(crate) fn read(packet: &Packet) -> Result<PeerPacket, WireFault> {
    let mut reader = WireReader::new(packet.payload());
    match packet.opcode() {
        OP_QUEUERANK => {
            reader.read_u8("tag count")?;
            let rank = read_int_tag(&mut reader)? as u16;
            Ok(PeerPacket::QueueRank(QueueRank { rank }))
        }
        OP_REQUESTPARTS => {
            reader.read_file_hash("file hash")?;
            for _ in 0..reader.read_u8("block count")? {
                let start = read_int_tag(&mut reader)?;
                let end = read_int_tag(&mut reader)?.wrapping_add(1);
                if (start != 0 || end != 0) && start > end {
                    return Err(WireFault::EndBeforeStart { start, end });
                }
            }
            Ok(PeerPacket::unknown_from(packet))
        }
        _ => Ok(PeerPacket::unknown_from(packet)),
    }
}

/// `GetIntTagValue` (`SafeFile.cpp:570-597`): a type byte, a name that is
/// skipped, and the value at the type's width. Any other type throws.
fn read_int_tag(reader: &mut WireReader<'_>) -> Result<u64, WireFault> {
    const TAGTYPE_UINT32: u8 = 0x03;
    const TAGTYPE_UINT16: u8 = 0x08;
    const TAGTYPE_UINT8: u8 = 0x09;
    const TAGTYPE_UINT64: u8 = 0x0B;

    let tag_type = reader.read_u8("tag type")?;
    reader.read_len16_bytes("tag name")?;
    Ok(match tag_type {
        TAGTYPE_UINT64 => reader.read_u64_le("tag value")?,
        TAGTYPE_UINT32 => u64::from(reader.read_u32_le("tag value")?),
        TAGTYPE_UINT16 => u64::from(reader.read_u16_le("tag value")?),
        TAGTYPE_UINT8 => u64::from(reader.read_u8("tag value")?),
        value => return Err(WireFault::UnknownState { value }),
    })
}
