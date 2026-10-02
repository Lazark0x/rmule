//! `OP_HELLO` (0x01) and `OP_HELLOANSWER` (0x4C): the one body both carry —
//! user hash, client id, TCP port, tags and connected server — under the two
//! opcodes that differ only in who speaks first.
//!
//! The reader accepts every hello aMule's or eMule's reader accepts
//! (docs/protocol/parity/peer-tcp.md, *Hello read surface*): a tag of a type
//! rmule has no value model for is stepped over by its width, and the word
//! MLDonkey and old eDonkey Hybrid append after the connected server is kept
//! as a [`HelloTrailer`]. What it still refuses, it refuses because no reader
//! could go on: a tag type whose width nobody defines, a tag or field that runs
//! past the frame. Nothing it accepts costs more memory than the frame itself —
//! the declared tag count never sizes an allocation on its own.

use rmule_primitives::{
    ClientId, Ed2kText, Ipv4Endpoint, Packet, PacketProtocol, PrimitiveError, Tag, TagValue,
    UserHash,
};

use crate::error::PeerHelloDecodeError;
use crate::opcode::PeerOpcode;

mod refusal;
pub use refusal::{HelloRefusal, HelloRefusalCode};

// Peer hello opcodes (`OP_HELLO` = 0x01, `OP_HELLOANSWER` = 0x4C) per
// `src/include/protocol/ed2k/Client2Client/TCP.h` at pinned commit
// `377ec8d9`; their bytes now live in `PeerOpcode`.
const FIXED_BODY_LEN: usize = UserHash::BYTE_LEN + 4 + 2 + 4;
const HASH_SIZE_BYTE: u8 = UserHash::BYTE_LEN as u8;
const TRAILER_LEN: usize = 4;

/// Shared body of `OP_HELLO` / `OP_HELLOANSWER`. The two variants differ
/// only by the legacy 1-byte hash-size prefix that `OP_HELLO` carries and
/// `OP_HELLOANSWER` does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHelloBody {
    /// The sender's User Hash — the identity every later credit or proof hangs on.
    pub user_hash: UserHash,
    /// Its Client ID.
    pub client_id: ClientId,
    /// The TCP port it listens on.
    pub tcp_port: u16,
    /// The capability and identity tags, kept in wire order. A tag of a type
    /// with no value model was stepped over and is not here.
    pub tags: Vec<Tag>,
    /// `Ipv4Endpoint(0.0.0.0, 0)` when the sending peer is not connected
    /// to any server. Preserved byte-faithfully through encode/decode.
    pub connected_server: Ipv4Endpoint,
}

/// The four bytes some clients append after the connected server — both
/// references read them only at exactly that length (aMule
/// `BaseClient.cpp:762`, eMule `:565-578`) and ignore a tail of any other.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HelloTrailer {
    /// No four-byte word: nothing followed the server, or a tail no reader
    /// gives a meaning to.
    #[default]
    Absent,
    /// `KDLM` (`0x4B44_4C4D`, wire `4d 4c 44 4b`): MLDonkey.
    MlDonkey,
    /// Any other word: old eDonkey Hybrid, before 1.3 swapped it for a `pr…`
    /// tag.
    Hybrid(u32),
}

impl HelloTrailer {
    const KDLM: u32 = 0x4B44_4C4D;

    fn read(tail: &[u8]) -> Self {
        let Ok(word) = <[u8; TRAILER_LEN]>::try_from(tail) else {
            return Self::Absent;
        };
        match u32::from_le_bytes(word) {
            Self::KDLM => Self::MlDonkey,
            other => Self::Hybrid(other),
        }
    }

    const fn word(self) -> Option<u32> {
        match self {
            Self::Absent => None,
            Self::MlDonkey => Some(Self::KDLM),
            Self::Hybrid(word) => Some(word),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_HELLO` (`0x01`) — the dialer's opening, hash-size prefix included.
pub struct Hello {
    body: PeerHelloBody,
    trailer: HelloTrailer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// `OP_HELLOANSWER` (`0x4C`) — the answer, same body without that prefix.
pub struct HelloAnswer {
    body: PeerHelloBody,
    trailer: HelloTrailer,
}

impl Hello {
    #[must_use]
    /// Wrap a body as the opening hello.
    pub const fn new(body: PeerHelloBody) -> Self {
        Self {
            body,
            trailer: HelloTrailer::Absent,
        }
    }

    #[must_use]
    /// The same hello with `trailer` after the connected server.
    pub const fn with_trailer(mut self, trailer: HelloTrailer) -> Self {
        self.trailer = trailer;
        self
    }

    #[must_use]
    /// The body it carries.
    pub const fn body(&self) -> &PeerHelloBody {
        &self.body
    }

    #[must_use]
    /// What followed the connected server.
    pub const fn trailer(&self) -> HelloTrailer {
        self.trailer
    }

    #[must_use]
    /// Take the body out.
    pub fn into_body(self) -> PeerHelloBody {
        self.body
    }

    /// Read an opening hello, requiring the legacy hash-size prefix.
    pub fn decode_packet(packet: &Packet) -> Result<Self, PeerHelloDecodeError> {
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(PeerHelloDecodeError::UnsupportedProtocol);
        }
        if packet.opcode() != PeerOpcode::Hello.as_u8() {
            return Err(PeerHelloDecodeError::WrongOpcode {
                opcode: packet.opcode(),
            });
        }
        let payload = packet.payload();
        if payload.is_empty() {
            return Err(PeerHelloDecodeError::Truncated {
                needed: 1,
                actual: 0,
            });
        }
        // aMule refuses any other size (`BaseClient.cpp:386-394`): the answer
        // has no size field to echo one with.
        if payload[0] != HASH_SIZE_BYTE {
            return Err(PeerHelloDecodeError::InvalidHashSize {
                expected: HASH_SIZE_BYTE,
                actual: payload[0],
            });
        }
        let (body, trailer) = decode_body(&payload[1..])?;
        Ok(Self { body, trailer })
    }

    #[must_use]
    /// Frame the opening hello, prefix included.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(1 + encoded_body_len(&self.body) + TRAILER_LEN);
        payload.push(HASH_SIZE_BYTE);
        encode_body_into(&mut payload, &self.body, self.trailer);
        Packet::new(
            PeerOpcode::Hello.protocol(),
            PeerOpcode::Hello.as_u8(),
            payload,
        )
    }
}

impl HelloAnswer {
    #[must_use]
    /// Wrap a body as the answer.
    pub const fn new(body: PeerHelloBody) -> Self {
        Self {
            body,
            trailer: HelloTrailer::Absent,
        }
    }

    #[must_use]
    /// The same answer with `trailer` after the connected server.
    pub const fn with_trailer(mut self, trailer: HelloTrailer) -> Self {
        self.trailer = trailer;
        self
    }

    #[must_use]
    /// The body it carries.
    pub const fn body(&self) -> &PeerHelloBody {
        &self.body
    }

    #[must_use]
    /// What followed the connected server.
    pub const fn trailer(&self) -> HelloTrailer {
        self.trailer
    }

    #[must_use]
    /// Take the body out.
    pub fn into_body(self) -> PeerHelloBody {
        self.body
    }

    /// Read an answer, which carries no hash-size prefix.
    pub fn decode_packet(packet: &Packet) -> Result<Self, PeerHelloDecodeError> {
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(PeerHelloDecodeError::UnsupportedProtocol);
        }
        if packet.opcode() != PeerOpcode::HelloAnswer.as_u8() {
            return Err(PeerHelloDecodeError::WrongOpcode {
                opcode: packet.opcode(),
            });
        }
        let (body, trailer) = decode_body(packet.payload())?;
        Ok(Self { body, trailer })
    }

    #[must_use]
    /// Frame the answer.
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(encoded_body_len(&self.body) + TRAILER_LEN);
        encode_body_into(&mut payload, &self.body, self.trailer);
        Packet::new(
            PeerOpcode::HelloAnswer.protocol(),
            PeerOpcode::HelloAnswer.as_u8(),
            payload,
        )
    }
}

fn encoded_body_len(body: &PeerHelloBody) -> usize {
    FIXED_BODY_LEN
        + body.tags.iter().map(|t| t.encode().len()).sum::<usize>()
        + Ipv4Endpoint::WIRE_LEN
}

fn encode_body_into(payload: &mut Vec<u8>, body: &PeerHelloBody, trailer: HelloTrailer) {
    payload.extend_from_slice(body.user_hash.as_bytes());
    payload.extend_from_slice(&body.client_id.as_u32().to_le_bytes());
    payload.extend_from_slice(&body.tcp_port.to_le_bytes());
    payload.extend_from_slice(
        &u32::try_from(body.tags.len())
            .expect("peer hello tag count exceeds u32")
            .to_le_bytes(),
    );
    for tag in &body.tags {
        payload.extend_from_slice(&tag.encode());
    }
    payload.extend_from_slice(&body.connected_server.encode());
    if let Some(word) = trailer.word() {
        payload.extend_from_slice(&word.to_le_bytes());
    }
}

fn decode_body(payload: &[u8]) -> Result<(PeerHelloBody, HelloTrailer), PeerHelloDecodeError> {
    if payload.len() < FIXED_BODY_LEN {
        return Err(PeerHelloDecodeError::Truncated {
            needed: FIXED_BODY_LEN,
            actual: payload.len(),
        });
    }
    let mut hash_bytes = [0u8; UserHash::BYTE_LEN];
    hash_bytes.copy_from_slice(&payload[..UserHash::BYTE_LEN]);
    let user_hash = UserHash::from_bytes(hash_bytes);

    let mut cursor = UserHash::BYTE_LEN;
    let client_id = ClientId::from_u32(u32::from_le_bytes(
        payload[cursor..cursor + 4]
            .try_into()
            .expect("validated client id length"),
    ));
    cursor += 4;
    let tcp_port = u16::from_le_bytes(
        payload[cursor..cursor + 2]
            .try_into()
            .expect("validated tcp port length"),
    );
    cursor += 2;
    let tag_count = u32::from_le_bytes(
        payload[cursor..cursor + 4]
            .try_into()
            .expect("validated tag count length"),
    );
    cursor += 4;
    let tag_count = usize::try_from(tag_count)
        .map_err(|_| PeerHelloDecodeError::TagCountOverflow { count: tag_count })?;

    let block = &payload[cursor..];
    let declared = u32::try_from(tag_count).unwrap_or(u32::MAX);
    let (tags, consumed) = decode_tags(block, tag_count).map_err(|source| {
        refusal::classify_short_count(block, declared).unwrap_or(source.into())
    })?;
    cursor += consumed;

    if payload.len() < cursor + Ipv4Endpoint::WIRE_LEN {
        return Err(refusal::classify_short_count(block, declared).unwrap_or(
            PeerHelloDecodeError::Truncated {
                needed: cursor + Ipv4Endpoint::WIRE_LEN,
                actual: payload.len(),
            },
        ));
    }
    let mut endpoint_bytes = [0u8; Ipv4Endpoint::WIRE_LEN];
    endpoint_bytes.copy_from_slice(&payload[cursor..cursor + Ipv4Endpoint::WIRE_LEN]);
    let connected_server = Ipv4Endpoint::decode(&endpoint_bytes);
    cursor += Ipv4Endpoint::WIRE_LEN;

    let body = PeerHelloBody {
        user_hash,
        client_id,
        tcp_port,
        tags,
        connected_server,
    };
    Ok((body, HelloTrailer::read(&payload[cursor..])))
}

/// Read `count` tags off the front of `bytes`, returning them and the bytes
/// they took. A tag the value model cannot hold — a type both references read
/// but rmule never uses (`FLOAT32`, `BOOL`, `BOOLARRAY`, `BLOB`, `BSOB`,
/// `STR17`–`STR22`), or a name that is not UTF-8 — is stepped over by its width,
/// as the references read and ignore it.
pub(crate) fn decode_tags(bytes: &[u8], count: usize) -> Result<(Vec<Tag>, usize), PrimitiveError> {
    // The frame, not the peer's word, bounds what is reserved.
    let mut tags = Vec::with_capacity(Tag::block_capacity(count, bytes));
    let mut cursor = 0;
    for _ in 0..count {
        let rest = &bytes[cursor..];
        match Tag::decode_prefix(rest) {
            Ok((tag, used)) => {
                tags.push(tag);
                cursor += used;
            }
            Err(PrimitiveError::UnsupportedTagType { .. } | PrimitiveError::InvalidTag { .. }) => {
                cursor += Tag::skip_prefix(rest)?;
            }
            Err(other) => return Err(other),
        }
    }
    Ok((tags, cursor))
}

/// The last integer-valued tag named `id` — both references assign per tag,
/// so a repeated tag's last copy is the one kept, and a copy of the wrong type
/// is passed over (eMule's `IsInt` guard). `UINT8`/`UINT16`/`UINT32` count, as
/// both widen them at decode; `UINT64` does not (eMule `Packets.h:131`).
pub(crate) fn hello_int(tags: &[Tag], id: u8) -> Option<u32> {
    last_value(tags, id, |value| match value {
        TagValue::U32(v) => Some(*v),
        TagValue::U16(v) => Some(u32::from(*v)),
        TagValue::U8(v) => Some(u32::from(*v)),
        _ => None,
    })
}

/// The last string-valued tag named `id`, by the same rule as [`hello_int`].
pub(crate) fn hello_text(tags: &[Tag], id: u8) -> Option<&Ed2kText> {
    last_value(tags, id, |value| match value {
        TagValue::String(text) => Some(text),
        _ => None,
    })
}

fn last_value<'a, T>(
    tags: &'a [Tag],
    id: u8,
    read: impl Fn(&'a TagValue) -> Option<T>,
) -> Option<T> {
    tags.iter()
        .rev()
        .filter(|tag| tag.name().id() == Some(id))
        .find_map(|tag| read(tag.value()))
}
