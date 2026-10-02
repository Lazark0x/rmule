//! The server description exchange (codec ADR-0068, trigger ADR-0052):
//! `OP_SERVER_DESC_REQ` (0xA2) and both `OP_SERVER_DESC_RES` (0xA3) reply
//! dialects — the tagged eserver 16.45+ form and the legacy string form.
//!
//! The request pins the low half of its challenge so the two reply formats
//! stay distinguishable: a legacy `0xA3` carries a string length where the
//! tagged form echoes those two bytes back.

use rmule_primitives::{Ed2kText, Packet, PacketProtocol, Tag, TagValue};

use crate::{Ed2kError, Opcode, Result};

/// `ST_SERVERNAME` (aMule `ServerTags.h`): the server's display name.
const ST_SERVERNAME: u8 = 0x01;
/// `ST_DESCRIPTION` (aMule `ServerTags.h`): the free-text description.
const ST_DESCRIPTION: u8 = 0x0B;
/// `ST_DYNIP` (aMule `ServerTags.h`): the server's dynamic-DNS host name.
const ST_DYNIP: u8 = 0x85;
/// `ST_VERSION` (aMule `ServerTags.h`): the software version, string or
/// packed `u32` (`hi16.lo16`).
const ST_VERSION: u8 = 0x91;
/// `ST_AUXPORTSLIST` (aMule `ServerTags.h`): auxiliary TCP ports, a string.
const ST_AUXPORTSLIST: u8 = 0x93;

/// `OP_SERVER_DESC_REQ` (0xA2): the description request the engine auto-fires
/// after a valid `0x97` status reply (trigger ADR-0052, codec ADR-0068). Body
/// is one `u32 LE` challenge whose **low 16 bits are pinned to
/// [`INV_SERV_DESC_LEN`](Self::INV_SERV_DESC_LEN)** — on the wire those are
/// the first two bytes, and an eserver 16.45+ echoes them back where a legacy
/// `0xA3` carries its first string length, which is how the two reply formats
/// stay distinguishable (aMule `ServerUDPSocket.cpp`: `uDescReqChallenge =
/// (GetRandomUint16() << 16) + INV_SERV_DESC_LEN`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerDescReq {
    challenge: u32,
}

impl ServerDescReq {
    /// `INV_SERV_DESC_LEN` (aMule `ServerUDPSocket.cpp`): a `u16` that is
    /// never a valid legacy string length, pinned into every desc challenge.
    pub const INV_SERV_DESC_LEN: u16 = 0xF0FF;

    /// Mint a challenge from caller-supplied entropy (the high 16 bits), so
    /// the engine's trigger stays deterministic under test.
    #[must_use]
    pub const fn mint(rand16: u16) -> Self {
        Self {
            challenge: ((rand16 as u32) << 16) | Self::INV_SERV_DESC_LEN as u32,
        }
    }

    /// The minted challenge, whose low 16 bits are the pinned marker that
    /// tells the two reply formats apart.
    #[must_use]
    pub const fn challenge(self) -> u32 {
        self.challenge
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::ServerDescReq.as_u8(),
            self.challenge.to_le_bytes().to_vec(),
        )
    }
}

/// The display strings a tagged `0xA3` carries (eserver 16.45+). Every field
/// is optional — the server sends only the tags it has values for, and aMule
/// leaves the others untouched (per-tag setters, no clearing) — so the
/// consumer merges per field instead of replacing the record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerDescTags {
    /// The server's display name.
    pub name: Option<String>,
    /// Its description line.
    pub description: Option<String>,
    /// String form verbatim; a packed-int form is rendered `hi16.lo16` as
    /// aMule displays it (`CFormat("%u.%u") % (v >> 16) % (v & 0xFFFF)`).
    pub version: Option<String>,
    /// The dynamic-DNS name it answers on, when it has one.
    pub dyn_ip: Option<String>,
    /// The extra ports it also listens on, as the server spells the list.
    pub aux_ports_list: Option<String>,
}

/// `OP_SERVER_DESC_RES` (0xA3): the description reply, in one of two wire
/// formats sharing the opcode (ADR-0068). Disambiguated exactly as aMule
/// does (`ServerUDPSocket.cpp`): a body of at least 8 bytes whose first
/// `u16 LE` equals [`ServerDescReq::INV_SERV_DESC_LEN`] is the tagged form
/// `[challenge u32][tag_count u32][tags…]` — the echoed challenge is the
/// consumer's anti-spoof gate; anything else parses as the legacy form
/// `[len u16 LE][string] × 2`. Trailing bytes past either form are ignored,
/// as aMule's reads leave them unconsumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerDescRes {
    /// eserver 16.45+: the challenge echo plus a display-string tag list.
    Tagged {
        /// The echoed challenge — the anti-spoof gate for anything read from
        /// this reply.
        challenge: u32,
        /// The display strings the server sent, each absent unless tagged.
        tags: ServerDescTags,
    },
    /// The pre-16.45 two-string body. aMule 2.3.3 assigns the **first**
    /// string to the server's description and the **second** to its name
    /// (`SetDescription(ReadString)` then `SetListName(ReadString)`) — the
    /// reverse of its own `<name><desc>` opcode comment and of eMule's read
    /// order. rmule mirrors the pinned code path, not the comment.
    Legacy {
        /// The **first** string on the wire, which aMule assigns to the
        /// description.
        description: String,
        /// The **second** string, which aMule assigns to the name.
        name: String,
    },
}

impl ServerDescRes {
    /// Decode an `OP_SERVER_DESC_RES` UDP datagram: `[protocol 0xE3][opcode
    /// 0xA3]` then one of the two bodies (see the type docs). A tag list that
    /// overruns the datagram (tag-bloat) or a legacy string longer than the
    /// remaining bytes is an error — the consumer drops the packet with no
    /// store mutation.
    pub fn decode_udp(bytes: &[u8]) -> Result<Self> {
        let opcode = Opcode::ServerDescRes.as_u8();
        let [protocol, op, body @ ..] = bytes else {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_SERVER_DESC_RES datagram missing header",
            });
        };
        if *protocol != PacketProtocol::Edonkey.as_byte() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if *op != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_SERVER_DESC_RES",
            });
        }
        // aMule peeks the first u16 and requires `size >= 8` before treating
        // the body as tagged; a 0xF0FF prefix on a shorter body falls through
        // to the legacy parse (and fails there, as aMule's read would throw).
        let leading_u16 = (body.len() >= 2)
            .then(|| u16::from_le_bytes(body[..2].try_into().expect("validated 2-byte prefix")));
        if body.len() >= 8 && leading_u16 == Some(ServerDescReq::INV_SERV_DESC_LEN) {
            Self::decode_tagged(body)
        } else {
            Self::decode_legacy(body)
        }
    }

    fn decode_tagged(body: &[u8]) -> Result<Self> {
        let opcode = Opcode::ServerDescRes.as_u8();
        let challenge = u32::from_le_bytes(body[..4].try_into().expect("validated 4-byte field"));
        let tag_count = u32::from_le_bytes(body[4..8].try_into().expect("validated 4-byte field"));
        let mut rest = &body[8..];
        let mut tags = ServerDescTags::default();
        for _ in 0..tag_count {
            let (tag, consumed) =
                Tag::decode_prefix(rest).map_err(|_| Ed2kError::InvalidPayload {
                    opcode,
                    reason: "OP_SERVER_DESC_RES tag list overruns the datagram",
                })?;
            rest = &rest[consumed..];
            let Some(id) = tag.name().id() else {
                continue; // text-named tags are not in the desc vocabulary
            };
            let string = || match tag.value() {
                TagValue::String(text) => Some(text.to_display_string()),
                _ => None,
            };
            match id {
                ST_SERVERNAME => tags.name = string(),
                ST_DESCRIPTION => tags.description = string(),
                ST_DYNIP => tags.dyn_ip = string(),
                ST_AUXPORTSLIST => tags.aux_ports_list = string(),
                ST_VERSION => {
                    tags.version = match tag.value() {
                        TagValue::String(text) => Some(text.to_display_string()),
                        TagValue::U32(v) => Some(format!("{}.{}", v >> 16, v & 0xFFFF)),
                        TagValue::U16(v) => Some(format!("0.{v}")),
                        TagValue::U8(v) => Some(format!("0.{v}")),
                        // A 16-byte hash carries no version, and a version
                        // number never needs 64 bits.
                        TagValue::U64(_) | TagValue::Hash(_) => None,
                    };
                }
                _ => {} // unknown tag: consumed and skipped, as aMule does
            }
        }
        Ok(Self::Tagged { challenge, tags })
    }

    fn decode_legacy(body: &[u8]) -> Result<Self> {
        let (first, rest) = read_len_prefixed_string(body)?;
        let (second, _trailing) = read_len_prefixed_string(rest)?;
        Ok(Self::Legacy {
            description: first,
            name: second,
        })
    }
}

/// One legacy `[len u16 LE][bytes]` string, returning it and the remainder.
fn read_len_prefixed_string(bytes: &[u8]) -> Result<(String, &[u8])> {
    let opcode = Opcode::ServerDescRes.as_u8();
    let error = Ed2kError::InvalidPayload {
        opcode,
        reason: "OP_SERVER_DESC_RES legacy string overruns the datagram",
    };
    let (len_bytes, rest) = bytes.split_at_checked(2).ok_or_else(|| error.clone())?;
    let len = usize::from(u16::from_le_bytes(
        len_bytes.try_into().expect("validated 2-byte length"),
    ));
    let (string_bytes, rest) = rest.split_at_checked(len).ok_or(error)?;
    Ok((
        Ed2kText::from_bytes(string_bytes.to_vec()).to_display_string(),
        rest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_primitives::TagName;

    fn string_tag(id: u8, value: &str) -> Vec<u8> {
        Tag::new(
            TagName::compact_id(id),
            TagValue::String(Ed2kText::from_utf8(value)),
        )
        .encode()
    }

    /// A tagged `0xA3` datagram echoing `challenge`, carrying `tags` raw.
    fn desc_res_tagged_datagram(challenge: u32, tags: &[Vec<u8>]) -> Vec<u8> {
        let mut datagram = vec![0xE3, 0xA3];
        datagram.extend_from_slice(&challenge.to_le_bytes());
        datagram.extend_from_slice(&(u32::try_from(tags.len()).unwrap()).to_le_bytes());
        for tag in tags {
            datagram.extend_from_slice(tag);
        }
        datagram
    }

    #[test]
    fn server_desc_req_mints_the_inv_len_low_half_and_encodes_it() {
        // aMule: `(GetRandomUint16() << 16) + INV_SERV_DESC_LEN` — the pinned
        // low half lands as the datagram's first two body bytes, the exact
        // bytes an eserver 16.45+ echoes and the legacy format cannot start
        // with (0xF0FF is never a valid string length there).
        let request = ServerDescReq::mint(0xABCD);
        assert_eq!(request.challenge(), 0xABCD_F0FF);
        assert_eq!(
            request.encode_packet().encode_udp(),
            vec![0xE3, 0xA2, 0xFF, 0xF0, 0xCD, 0xAB],
            "the golden OP_SERVER_DESC_REQ emit (ADR-0068)"
        );
    }

    #[test]
    fn server_desc_res_decodes_the_tagged_form_and_skips_unknown_tags() {
        let datagram = desc_res_tagged_datagram(
            0xABCD_F0FF,
            &[
                string_tag(0x01, "Lugdunum"),
                string_tag(0x0B, "a test server"),
                string_tag(0x85, "srv.example.org"),
                string_tag(0x91, "17.15"),
                string_tag(0x93, "4665,4672"),
                // An id outside the desc vocabulary: consumed, ignored.
                Tag::new(TagName::compact_id(0x20), TagValue::U32(7)).encode(),
            ],
        );
        let decoded = ServerDescRes::decode_udp(&datagram).expect("tagged form decodes");
        assert_eq!(
            decoded,
            ServerDescRes::Tagged {
                challenge: 0xABCD_F0FF,
                tags: ServerDescTags {
                    name: Some("Lugdunum".into()),
                    description: Some("a test server".into()),
                    version: Some("17.15".into()),
                    dyn_ip: Some("srv.example.org".into()),
                    aux_ports_list: Some("4665,4672".into()),
                },
            }
        );
    }

    #[test]
    fn server_desc_res_renders_a_packed_int_version_as_hi_dot_lo() {
        let datagram = desc_res_tagged_datagram(
            0x0001_F0FF,
            &[Tag::new(TagName::compact_id(0x91), TagValue::U32((17 << 16) | 15)).encode()],
        );
        let ServerDescRes::Tagged { tags, .. } =
            ServerDescRes::decode_udp(&datagram).expect("decodes")
        else {
            panic!("tagged form expected");
        };
        assert_eq!(tags.version.as_deref(), Some("17.15"));
    }

    #[test]
    fn server_desc_res_rejects_a_bloated_tag_count() {
        // The count claims more tags than the datagram holds: the walk runs
        // out of bytes and the packet is undecodable (consumer drops it).
        let datagram = desc_res_tagged_datagram(0x0001_F0FF, &[string_tag(0x01, "x")]);
        let mut bloated = datagram.clone();
        bloated[6..10].copy_from_slice(&1000_u32.to_le_bytes());
        assert!(ServerDescRes::decode_udp(&bloated).is_err());
    }

    #[test]
    fn server_desc_res_decodes_the_legacy_form_with_amules_assignment() {
        // aMule 2.3.3 reads `SetDescription` first, `SetListName` second —
        // the reverse of its own opcode comment; rmule mirrors the code path.
        let mut datagram = vec![0xE3, 0xA3];
        datagram.extend_from_slice(&4_u16.to_le_bytes());
        datagram.extend_from_slice(b"desc");
        datagram.extend_from_slice(&4_u16.to_le_bytes());
        datagram.extend_from_slice(b"name");
        assert_eq!(
            ServerDescRes::decode_udp(&datagram).expect("legacy form decodes"),
            ServerDescRes::Legacy {
                description: "desc".into(),
                name: "name".into(),
            }
        );
    }

    #[test]
    fn server_desc_res_disambiguates_on_the_pinned_prefix_and_min_size() {
        // A 0xF0FF-leading body shorter than 8 bytes is NOT tagged — aMule
        // falls through to the legacy parse, whose 0xF0FF string length then
        // overruns the datagram (a throw-and-drop there, an error here).
        let short = vec![0xE3, 0xA3, 0xFF, 0xF0, 0x01, 0x02];
        assert!(ServerDescRes::decode_udp(&short).is_err());
        // A non-0xF0FF prefix parses as legacy even at 8+ bytes.
        let mut legacy = vec![0xE3, 0xA3];
        legacy.extend_from_slice(&2_u16.to_le_bytes());
        legacy.extend_from_slice(b"ab");
        legacy.extend_from_slice(&2_u16.to_le_bytes());
        legacy.extend_from_slice(b"cd");
        assert!(matches!(
            ServerDescRes::decode_udp(&legacy).expect("legacy"),
            ServerDescRes::Legacy { .. }
        ));
        // A truncated legacy second string is undecodable.
        let mut truncated = vec![0xE3, 0xA3];
        truncated.extend_from_slice(&2_u16.to_le_bytes());
        truncated.extend_from_slice(b"ab");
        truncated.extend_from_slice(&9_u16.to_le_bytes());
        truncated.extend_from_slice(b"cd");
        assert!(ServerDescRes::decode_udp(&truncated).is_err());
    }
}
