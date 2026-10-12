//! Typed codecs for the Kad2 node-maintenance and source-publish messages.
//!
//! Covers the datagrams a **Routing Responder** (see `CONTEXT.md`) exchanges —
//! bootstrap, hello, ping/pong, the `KADEMLIA2_REQ`/`RES` lookup step — plus
//! the **Kad Publisher**/**Kad Storer** pair: `KADEMLIA2_PUBLISH_SOURCE_REQ`
//! (`0x44`), `KADEMLIA2_PUBLISH_RES` (`0x4B`), and the storer-side decode of
//! `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`).
//!
//! ## Provenance
//!
//! The node-maintenance layouts are decoded byte-for-byte from genuine aMule
//! 2.3.3 emissions in the committed captured fixtures
//! (`tests/fixtures/node/captured/private-amule-kad-node-messages-20260707/`
//! and `tests/fixtures/routing/captured/private-amule-kad-distance-20260707/`);
//! `docs/reference/notes/kad-packet-framing.md` records the layouts. Two
//! facts are documentation-backed (link-only aMule source, not captured):
//! the `0x1F` mask on the lookup request's contact count (no capture can
//! prove a mask no real client sets bits in), and the whole publish family —
//! see the framing note's "Source-publish layouts" section. Captured aMule
//! bytes have since corroborated that family (ADR-0043): a storer's `0x3B`
//! (`tests/kad/captured_source_result.rs`), a storer's `0x4B`
//! (`tests/kad/captured_keyword_answers.rs`) and a publisher's `0x44`
//! (`tests/kad/buddy_publish_capture.rs`).
//!
//! Decoding is strict: every field must be present and the payload must end
//! exactly where the message does. aMule enforces exact sizes for the
//! fixed-layout messages, and strictness is the safer posture for the
//! adversarial datagrams the mesh tier scripts.

use rmule_primitives::{Tag, TagName, TagValue, WireReader, WireTruncated};

use crate::KadBuddyContact;

use crate::opcode::Kad2Opcode;
use crate::wire_fields::KadWireFields;
use crate::{KadContact, KadEnvelope, KadId, KadNodeEndpoint};

/// A node's self-description as carried in hello and bootstrap-response
/// headers: `[16B Kad ID][2B TCP port LE][1B version]`.
///
/// `udp_port_tag` is the optional `0xFC` (`TAG_SOURCEUPORT`) hello tag; when
/// absent the receiver falls back to the datagram's UDP source port
/// (capture-proven by `hello_res_min_0x19.bin`).
///
/// `misc_options` is the `0xF2` (`TAG_KADMISCOPTIONS`) hello byte (see the
/// `MISC_OPTIONS_*` bits): firewalled-state and the `0x22` ack-request bit
/// (ADR-0064). `0` means the tag is absent — matching how aMule omits it for an
/// open node with nothing to request; `encode` emits the tag only when non-zero.
/// Bootstrap-response headers carry no tag list, so it is always `0` there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Kad2NodeInfo {
    /// The node's Kad ID.
    pub id: KadId,
    /// The TCP port it serves peers on.
    pub tcp_port: u16,
    /// Its Kad protocol version — what decides which exchanges it can take
    /// part in.
    pub version: u8,
    /// Its Kad UDP port, when the hello tag carried one; `None` means fall
    /// back to the datagram's source port.
    pub udp_port_tag: Option<u16>,
    /// The misc-options bits (firewalled state, ack request). `0` means the
    /// tag was absent.
    pub misc_options: u8,
}

/// One typed Kad2 node-maintenance message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Kad2Message {
    /// `KADEMLIA2_BOOTSTRAP_REQ` (`0x01`) — empty payload.
    BootstrapReq,
    /// `KADEMLIA2_BOOTSTRAP_RES` (`0x09`) — the responder's own info plus a
    /// `u16 LE` count of 25-byte contact rows.
    BootstrapRes {
        /// The responder describing itself.
        sender: Kad2NodeInfo,
        /// The contacts it handed over to seed our table.
        contacts: Vec<KadContact>,
    },
    /// `KADEMLIA2_HELLO_REQ` (`0x11`) — the sender's info + tag list.
    HelloReq(Kad2NodeInfo),
    /// `KADEMLIA2_HELLO_RES` (`0x19`) — the responder's info + tag list.
    HelloRes(Kad2NodeInfo),
    /// `KADEMLIA2_HELLO_RES_ACK` (`0x22`) — the IP-verification ACK: the
    /// sender's own Kad ID and an empty tag list (`<selfID16><tagcnt=0>`),
    /// returned when a `HELLO_RES` requested one (ADR-0064). Consumed only when
    /// tracked, carrying a valid receiver key, with a matching ID and IP.
    HelloResAck {
        /// The acking node's own Kad ID, checked against the contact we asked
        /// to verify.
        id: KadId,
    },
    /// `KADEMLIA2_PING` (`0x60`) — empty payload.
    Ping,
    /// `KADEMLIA2_PONG` (`0x61`) — the UDP source port the ping was observed
    /// to arrive from, `u16 LE`.
    Pong {
        /// The UDP source port the ping was seen to arrive from — how a node
        /// learns its own externally-visible port.
        udp_port: u16,
    },
    /// `KADEMLIA2_REQ` (`0x21`) — `count(1, low 5 bits) target(16) check(16)`,
    /// where `check` must equal the receiver's own Kad ID.
    LookupReq {
        /// How many contacts are wanted, in the low five bits.
        count: u8,
        /// The ID to find contacts near.
        target: KadId,
        /// The receiver's own Kad ID, echoed back so a misrouted or forged
        /// request is detectable.
        check: KadId,
    },
    /// `KADEMLIA2_RES` (`0x29`) — the echoed target and up to `count`
    /// contacts, closest-first.
    LookupRes {
        /// The target the request named, echoed.
        target: KadId,
        /// The contacts, closest first.
        contacts: Vec<KadContact>,
    },
    /// `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`) — `target(16) start(2 LE)
    /// size(8 LE)`, capture-proven layout (kad-source-lookup.md). The
    /// requester sends it; the storer decodes it and answers with re-encoded
    /// `0x3B` rows.
    SearchSourceReq {
        /// The file key being searched.
        target: KadId,
        /// 15-bit result offset; the top bit is masked away on decode. The
        /// requester's single-shot search always sends 0.
        start_position: u16,
        /// The file's size — a storer answers only for a matching size.
        file_size: u64,
    },
    /// `KADEMLIA2_PUBLISH_SOURCE_REQ` (`0x44`) — `file key(16) source ID(16)
    /// tag count(1) tags`. Documentation-backed layout (framing note,
    /// "Source-publish layouts"): the source ID is the publisher's User Hash
    /// per the aMule source, kept as raw bytes until capture-proven.
    PublishSourceReq {
        /// The file key the source is published under.
        file: KadId,
        /// The publisher's identity, kept as raw bytes until a capture proves
        /// what it is.
        source_id: [u8; 16],
        /// The published endpoint description, as far as its tags were
        /// modelled.
        source: KadPublishedSource,
    },
    /// `KADEMLIA2_PUBLISH_RES` (`0x4B`) — `file key(16) load(1)`, sent only
    /// for an accepted publish, optionally followed by a future-use `options`
    /// byte. Bit 0 requests a `KADEMLIA2_PUBLISH_RES_ACK` (`0x4C`) under an
    /// obfuscation key (ADR-0062); aMule 2.3.3's storer leaves it `0`, so
    /// rmule acks with `0` and `encode` emits the byte only when it is
    /// non-zero — byte-identical to aMule while keeping the codec round-trip
    /// faithful.
    PublishRes {
        /// The file key that was published.
        file: KadId,
        /// The storer's self-reported load, 0–100.
        load: u8,
        /// The future-use options byte; bit 0 requests an obfuscated ack.
        /// `0` for every aMule 2.3.3 storer, and the value rmule sends.
        options: u8,
    },
}

/// The publisher's endpoint description carried in a `0x44` tag list,
/// projected to the tags rmule models. Every field is optional at the codec
/// layer — a well-formed publish may omit any tag — and the **Kad Storer**
/// decides what is indexable (e.g. a missing source type or TCP port rejects
/// the entry, mirroring aMule's `AddSources`).
///
/// Unrecognized tags are skipped tolerantly on decode and are **not** carried
/// through to the store: the storer re-encodes only fields it parsed, so its
/// answers can never echo attacker-shaped opaque bytes (stricter than aMule,
/// which passes unknown tags through its index).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct KadPublishedSource {
    /// `TAG_SOURCETYPE` (`0xFF`): 1/4 direct, 3/5 buddy, 6 firewalled-UDP.
    pub source_type: Option<u8>,
    /// `TAG_SOURCEPORT` (`0xFD`): the publisher's eD2k TCP listen port.
    pub tcp_port: Option<u16>,
    /// `TAG_SOURCEUPORT` (`0xFC`): the publisher's Kad UDP port; when absent
    /// the storer falls back to the datagram's observed source port.
    pub udp_port_tag: Option<u16>,
    /// `TAG_FILESIZE` (`0x02`), as a `CTagVarInt` narrows and widens it
    /// `UINT8`/`_UINT16`/`_UINT32` up to 4 GiB, `UINT64` past
    /// it. A missing tag (decode) or field (encode) is a missing size, and
    /// the storer treats a missing size as matches-any-search.
    pub file_size: Option<u64>,
    /// `TAG_ENCRYPTION` (`0xF3`): the publisher's crypt options byte,
    /// preserved verbatim for the future obfuscated-dial channel.
    pub encryption: Option<u8>,
    /// `ip6`: the publisher's own IPv6 (ADR-0087). Emitted only while the
    /// Advertised Endpoints chooser reports a Known address — the tag is the
    /// fact, so publishing one rmule does not hold would invite dials to
    /// nowhere. Kad's own contacts stay IPv4; this rides inside the publish.
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// The publisher's Kad **serving buddy**, from the three tags a type-3/5
    /// publish carries: `TAG_SERVERIP` (`0xFB`), `TAG_SERVERPORT` (`0xFA`) and
    /// `TAG_BUDDYHASH` (`0xF8`), plus the `bi6` string tag (ADR-0087) as the
    /// contact's v6 half. See [`KadBuddyContact`] for the byte orders and
    /// which of them the capture settles.
    pub buddy: Option<KadBuddyContact>,
}

/// Why an envelope could not be decoded into a [`Kad2Message`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kad2MessageDecodeError {
    /// The opcode is not one this codec models. Not necessarily hostile — a
    /// real client may speak opcodes outside rmule's slices.
    UnknownOpcode {
        /// The opcode byte no in-role message uses.
        opcode: u8,
    },
    /// The payload does not parse as the opcode's proven layout. Carries a
    /// static reason for diagnostics; never panics.
    Malformed {
        /// The opcode whose payload did not decode.
        opcode: u8,
        /// Which layout expectation the payload broke.
        reason: &'static str,
    },
}

/// `TAG_SOURCEUPORT` — the hello tag carrying the sender's UDP port.
const TAG_SOURCEUPORT: u8 = 0xFC;
/// `TAG_KADMISCOPTIONS` — the u8 hello tag carrying the misc-options bitfield
/// (capture-observed in `hello_res_0x19.bin` as name `0xF2`, `TAGTYPE_UINT8`).
const TAG_KADMISCOPTIONS: u8 = 0xF2;

/// `TAG_KADMISCOPTIONS` bit 0: this node's UDP port is firewalled. Fed by
/// ADR-0058 `Reachability`; rmule assumes an open node, so it stays `0` until
/// that lands. `[pending]` bit position (documentation-backed, aMule
/// `SendMyDetails`; the byte value is capture-observed, the bit *meanings* are
/// link-only source).
pub const MISC_OPTIONS_UDP_FIREWALLED: u8 = 0x01;
/// `TAG_KADMISCOPTIONS` bit 1: this node's TCP port is firewalled (ADR-0058;
/// `0` until Reachability lands). `[pending]` bit position.
pub const MISC_OPTIONS_TCP_FIREWALLED: u8 = 0x02;
/// `TAG_KADMISCOPTIONS` bit 2: this node requests a `0x22` ACK to verify the
/// peer's IP — set in a `HELLO_RES` when the peer was added/updated without a
/// valid receiver key (ADR-0064). Capture-observed value `0x04` in a real aMule
/// `HELLO_RES` (`hello_res_0x19.bin`).
pub const MISC_OPTIONS_ACK_REQUEST: u8 = 0x04;

impl Kad2Message {
    /// Decode a plain (or already-inflated packed) envelope's payload.
    pub fn decode(envelope: &KadEnvelope) -> Result<Self, Kad2MessageDecodeError> {
        let opcode = envelope.opcode();
        let malformed = |reason| Kad2MessageDecodeError::Malformed { opcode, reason };
        let truncated = |error: WireTruncated| malformed(error.field);
        let mut reader = WireReader::new(envelope.payload());

        let message = match Kad2Opcode::try_from_u8(opcode) {
            Some(Kad2Opcode::BootstrapReq) => Self::BootstrapReq,
            Some(Kad2Opcode::BootstrapRes) => {
                let sender = decode_node_header(&mut reader).map_err(malformed)?;
                let count = reader.read_u16_le("contact count").map_err(truncated)?;
                let contacts =
                    decode_contact_rows(&mut reader, usize::from(count)).map_err(malformed)?;
                Self::BootstrapRes { sender, contacts }
            }
            Some(Kad2Opcode::HelloReq) => {
                Self::HelloReq(decode_hello(&mut reader).map_err(malformed)?)
            }
            Some(Kad2Opcode::HelloRes) => {
                Self::HelloRes(decode_hello(&mut reader).map_err(malformed)?)
            }
            Some(Kad2Opcode::HelloResAck) => {
                let id = reader.read_kad_id("ack sender ID").map_err(truncated)?;
                skip_tag_list(&mut reader, "hello-res-ack").map_err(malformed)?;
                Self::HelloResAck { id }
            }
            Some(Kad2Opcode::Ping) => Self::Ping,
            Some(Kad2Opcode::Pong) => Self::Pong {
                udp_port: reader.read_u16_le("pong udp port").map_err(truncated)?,
            },
            Some(Kad2Opcode::LookupReq) => {
                // aMule masks the requested contact count to the low five bits
                // and drops a request whose masked count is zero
                // (documentation-backed; see the module provenance note).
                let count = reader
                    .read_u8("requested contact count")
                    .map_err(truncated)?
                    & 0x1F;
                if count == 0 {
                    return Err(malformed("requested contact count is zero after masking"));
                }
                Self::LookupReq {
                    count,
                    target: reader.read_kad_id("lookup target").map_err(truncated)?,
                    check: reader.read_kad_id("receiver check ID").map_err(truncated)?,
                }
            }
            Some(Kad2Opcode::LookupRes) => {
                let target = reader.read_kad_id("echoed target").map_err(truncated)?;
                let count = reader.read_u8("contact count").map_err(truncated)?;
                let contacts =
                    decode_contact_rows(&mut reader, usize::from(count)).map_err(malformed)?;
                Self::LookupRes { target, contacts }
            }
            Some(Kad2Opcode::SearchSourceReq) => Self::SearchSourceReq {
                target: reader.read_kad_id("search target").map_err(truncated)?,
                // The receiver masks the top bit away (documentation-backed,
                // aMule listener): the offset is 15-bit on the wire.
                start_position: reader.read_u16_le("start position").map_err(truncated)? & 0x7FFF,
                file_size: reader
                    .read_u64_le("searched file size")
                    .map_err(truncated)?,
            },
            Some(Kad2Opcode::PublishSourceReq) => {
                let file = reader
                    .read_kad_id("published file key")
                    .map_err(truncated)?;
                let source_id = reader
                    .read_array::<16>("published source ID")
                    .map_err(truncated)?;
                let source = decode_published_source(&mut reader).map_err(malformed)?;
                Self::PublishSourceReq {
                    file,
                    source_id,
                    source,
                }
            }
            Some(Kad2Opcode::PublishRes) => {
                let file = reader
                    .read_kad_id("published file key")
                    .map_err(truncated)?;
                let load = reader.read_u8("publish load").map_err(truncated)?;
                // The optional future-use options byte (bit 0 requests the
                // dormant 0x4C ACK); absent ⇒ 0. Anything past it is not the
                // documented layout and trips the trailing-bytes check below.
                let options = if reader.is_exhausted() {
                    0
                } else {
                    reader.read_u8("publish options").map_err(truncated)?
                };
                Self::PublishRes {
                    file,
                    load,
                    options,
                }
            }
            Some(Kad2Opcode::SearchRes) | None => {
                // Search results stay in `decode_source_result`; everything
                // else is unmodelled.
                return Err(Kad2MessageDecodeError::UnknownOpcode { opcode });
            }
        };

        if !reader.is_exhausted() {
            return Err(malformed("trailing bytes after the message"));
        }
        Ok(message)
    }

    /// Serialize into a plain `0xE4` envelope.
    #[must_use]
    pub fn encode(&self) -> KadEnvelope {
        let (opcode, payload) = match self {
            Self::BootstrapReq => (Kad2Opcode::BootstrapReq, Vec::new()),
            Self::BootstrapRes { sender, contacts } => {
                let mut payload = Vec::with_capacity(21 + contacts.len() * CONTACT_ROW_LEN);
                encode_node_header(&mut payload, sender);
                payload.extend_from_slice(
                    &u16::try_from(contacts.len())
                        .expect("more contacts than a u16 row count can carry")
                        .to_le_bytes(),
                );
                encode_contact_rows(&mut payload, contacts);
                (Kad2Opcode::BootstrapRes, payload)
            }
            Self::HelloReq(info) => (Kad2Opcode::HelloReq, encode_hello(info)),
            Self::HelloRes(info) => (Kad2Opcode::HelloRes, encode_hello(info)),
            Self::HelloResAck { id } => {
                // `<selfID16><tagcnt=0>` — the empty-tag-list ACK aMule emits.
                let mut payload = Vec::with_capacity(17);
                payload.extend_from_slice(id.as_bytes());
                payload.push(0);
                (Kad2Opcode::HelloResAck, payload)
            }
            Self::Ping => (Kad2Opcode::Ping, Vec::new()),
            Self::Pong { udp_port } => (Kad2Opcode::Pong, udp_port.to_le_bytes().to_vec()),
            Self::LookupReq {
                count,
                target,
                check,
            } => {
                let mut payload = Vec::with_capacity(33);
                payload.push(count & 0x1F);
                payload.extend_from_slice(target.as_bytes());
                payload.extend_from_slice(check.as_bytes());
                (Kad2Opcode::LookupReq, payload)
            }
            Self::LookupRes { target, contacts } => {
                let mut payload = Vec::with_capacity(17 + contacts.len() * CONTACT_ROW_LEN);
                payload.extend_from_slice(target.as_bytes());
                payload.push(
                    u8::try_from(contacts.len())
                        .expect("more contacts than a u8 row count can carry"),
                );
                encode_contact_rows(&mut payload, contacts);
                (Kad2Opcode::LookupRes, payload)
            }
            Self::SearchSourceReq {
                target,
                start_position,
                file_size,
            } => {
                let mut payload = Vec::with_capacity(26);
                payload.extend_from_slice(target.as_bytes());
                payload.extend_from_slice(&start_position.to_le_bytes());
                payload.extend_from_slice(&file_size.to_le_bytes());
                (Kad2Opcode::SearchSourceReq, payload)
            }
            Self::PublishSourceReq {
                file,
                source_id,
                source,
            } => {
                let mut payload = Vec::with_capacity(33 + 32);
                payload.extend_from_slice(file.as_bytes());
                payload.extend_from_slice(source_id);
                encode_published_source(&mut payload, source);
                (Kad2Opcode::PublishSourceReq, payload)
            }
            Self::PublishRes {
                file,
                load,
                options,
            } => {
                let mut payload = Vec::with_capacity(18);
                payload.extend_from_slice(file.as_bytes());
                payload.push(*load);
                // aMule 2.3.3's storer emits only `file load`; the options byte
                // rides only when something sets it (bit 0 → 0x4C ACK).
                if *options != 0 {
                    payload.push(*options);
                }
                (Kad2Opcode::PublishRes, payload)
            }
        };
        KadEnvelope::plain(opcode.as_u8(), payload)
    }
}

// The Kad source-tag single-byte names a publish carries, in the explicit
// length-prefixed form `[type][01 00][name byte][value]`.
const TAG_FILESIZE: u8 = 0x02;
const TAG_ENCRYPTION: u8 = 0xF3;
const TAG_SOURCEPORT: u8 = 0xFD;
const TAG_SOURCETYPE: u8 = 0xFF;
/// The buddy trio a type-3/5 publish carries — in a *source* publish
/// `TAG_SERVERIP`/`TAG_SERVERPORT` name the **buddy's** endpoint, not any
/// server's (aMule Fork Pin `ab483654`
/// `src/kademlia/kademlia/Search.cpp:848-855`).
const TAG_SERVERPORT: u8 = 0xFA;
const TAG_SERVERIP: u8 = 0xFB;
const TAG_BUDDYHASH: u8 = 0xF8;

/// Decode the `0x44` tag list into the recognized publish fields. First
/// occurrence of a recognized tag wins (aMule's dedupe posture); unknown tags
/// and unexpected value widths are skipped without failing the message.
fn field(error: WireTruncated) -> &'static str {
    error.field
}

fn decode_published_source(
    reader: &mut WireReader<'_>,
) -> Result<KadPublishedSource, &'static str> {
    let tag_count = reader.read_u8("publish tag count").map_err(field)?;
    let mut source = KadPublishedSource::default();
    let (mut buddy_ip, mut buddy_port, mut buddy_id, mut buddy_ipv6) = (None, None, None, None);
    for _ in 0..tag_count {
        let (tag, consumed) = Tag::decode_prefix(reader.remaining_bytes())
            .map_err(|_| "publish tag is truncated or malformed")?;
        reader.advance_clamped(consumed);
        let Some(name) = tag.name().id() else {
            // The IPv6 tags are string-named (ADR-0087), so they never reach
            // the numeric-id match below. Both claims are gated exactly as
            // `source_result::apply_tag` gates a result row's `ip6`: a
            // mapped, link-local, unique-local or loopback address is refused
            // rather than stored, because a scope-less tag cannot tell two of
            // them apart. A refused tag does not claim the slot — a later
            // usable occurrence in the same list still wins it.
            set_first(
                &mut source.ipv6,
                usable_ipv6_tag(&tag, crate::ipv6_tags::TAG_SOURCE_IPV6),
            );
            set_first(
                &mut buddy_ipv6,
                usable_ipv6_tag(&tag, crate::ipv6_tags::TAG_BUDDY_IPV6),
            );
            continue;
        };
        match name {
            TAG_SOURCETYPE => set_first(&mut source.source_type, tag_u8(tag.value())),
            TAG_SOURCEPORT => set_first(&mut source.tcp_port, tag_u16(tag.value())),
            TAG_SOURCEUPORT => set_first(&mut source.udp_port_tag, tag_u16(tag.value())),
            TAG_FILESIZE => set_first(&mut source.file_size, tag_u64(tag.value())),
            TAG_ENCRYPTION => set_first(&mut source.encryption, tag_u8(tag.value())),
            // The buddy trio is collected into scalars first and folded into
            // one contact below — the hash alone decides whether a buddy was
            // named, since a callback needs somewhere to be addressed.
            TAG_SERVERIP => set_first(&mut buddy_ip, tag_u32(tag.value())),
            TAG_SERVERPORT => set_first(&mut buddy_port, tag_u16(tag.value())),
            TAG_BUDDYHASH => set_first(
                &mut buddy_id,
                match tag.value() {
                    TagValue::String(text) => text
                        .try_as_str()
                        .ok()
                        .and_then(crate::source_result::hex_md4)
                        .map(|be| KadId::from_bytes(crate::lookup::kad_wire_id(be))),
                    _ => None,
                },
            ),
            _ => {}
        }
    }
    // The buddy endpoint is gated as the result reader gates it: a storer
    // that indexed a loopback, broadcast or multicast `TAG_SERVERIP` would
    // serve every searcher a datagram aimed at its own host or everyone's.
    // eMuleAI's IPv6-buddy row (`TAG_SERVERIP` = `UINT_MAX`) keeps its port
    // through `buddy_udp_ipv6`, beside the `bi6` it belongs to.
    source.buddy = buddy_id.map(|buddy_id| KadBuddyContact {
        buddy_id,
        buddy_udp: crate::source_result::endpoint(
            buddy_ip,
            buddy_port,
            crate::net::is_claimed_udp_target,
        ),
        buddy_ipv6,
        buddy_udp_ipv6: buddy_ipv6
            .zip(buddy_port.filter(|port| *port != 0))
            .map(|(address, port)| rmule_primitives::Ipv6Endpoint::new(address, port)),
    });
    Ok(source)
}

/// Serialize the publish tag list in aMule's publisher order: SOURCETYPE, then
/// — for a firewalled type-3/5 publish — SERVERIP, SERVERPORT, BUDDYHASH, then
/// SOURCEPORT, SOURCEUPORT, FILESIZE, ENCRYPTION. Absent fields are absent
/// tags, matching how the aMule publisher conditionally emits each one
/// (`src/kademlia/kademlia/Search.cpp:845-884`, Fork Pin `ab483654`).
///
/// **Capture-pinned** against a firewalled stock aMule 2.3.3's own `0x44`
/// (`tests/fixtures/buddy/captured/amule-233-publish-source-req-20260922`):
/// that order exactly, `SOURCETYPE`/`ENCRYPTION` as `UINT8`, `SERVERIP` and
/// `FILESIZE` as `UINT32` (the capture's file is 65 536 bytes), `SERVERPORT`
/// and `SOURCEPORT` as `UINT16`, `BUDDYHASH` as a 32-character upper-case hex
/// string, and no `SOURCEUPORT` at all. aMule builds the three variable-width
/// ones with `CTagVarInt`, so a narrower (or, past 4 GiB, a `UINT64`-wider)
/// value narrows or widens the tag — which is why the reader accepts every
/// width and `FILESIZE` is built through [`TagValue::compact_uint64`]
/// rather than a fixed `TagValue::U32`.
fn encode_published_source(payload: &mut Vec<u8>, source: &KadPublishedSource) {
    let buddy_udp = source.buddy.and_then(|buddy| buddy.buddy_udp);
    // With no IPv4 buddy endpoint, an IPv6 one's port still rides alone, as
    // `encode_source_result` re-serves it: only a reader-built contact has one.
    let buddy_port = buddy_udp.map(|udp| udp.port).or_else(|| {
        source
            .buddy
            .and_then(|buddy| buddy.buddy_udp_ipv6)
            .map(|udp| udp.port)
    });
    let tags = [
        source
            .source_type
            .map(|byte| (TAG_SOURCETYPE, TagValue::U8(byte))),
        buddy_udp.map(|udp| {
            let [a, b, c, d] = udp.ip.octets();
            (
                TAG_SERVERIP,
                TagValue::U32(u32::from_le_bytes([a, b, c, d])),
            )
        }),
        buddy_port.map(|port| (TAG_SERVERPORT, TagValue::U16(port))),
        source.buddy.map(|buddy| {
            (
                TAG_BUDDYHASH,
                TagValue::String(rmule_primitives::Ed2kText::from_utf8(
                    crate::source_result::md4_hex(crate::lookup::kad_wire_id(
                        *buddy.buddy_id.as_bytes(),
                    )),
                )),
            )
        }),
        source
            .tcp_port
            .map(|port| (TAG_SOURCEPORT, TagValue::U16(port))),
        source
            .udp_port_tag
            .map(|port| (TAG_SOURCEUPORT, TagValue::U16(port))),
        source
            .file_size
            .map(|size| (TAG_FILESIZE, TagValue::compact_uint64(size))),
        source
            .encryption
            .map(|options| (TAG_ENCRYPTION, TagValue::U8(options))),
    ];
    let present: Vec<_> = tags.into_iter().flatten().collect();
    // The two IPv6 tags are string-named, so they are built whole rather than
    // by id (ADR-0087); they close the list, `ip6` then `bi6`, after
    // `ENCRYPTION` — eMuleAI's order (`Search.cpp:914-923`, `a2f05dc8`).
    let ipv6_tags: Vec<_> = [
        source
            .ipv6
            .map(|it| crate::ipv6_tags::ipv6_tag(crate::ipv6_tags::TAG_SOURCE_IPV6, it)),
        source
            .buddy
            .and_then(|buddy| buddy.buddy_ipv6)
            .map(|it| crate::ipv6_tags::ipv6_tag(crate::ipv6_tags::TAG_BUDDY_IPV6, it)),
    ]
    .into_iter()
    .flatten()
    .collect();
    payload.push(
        u8::try_from(present.len() + ipv6_tags.len()).expect("publish models at most ten tags"),
    );
    for (name, value) in present {
        payload.extend_from_slice(&Tag::new(TagName::length_prefixed_id(name), value).encode());
    }
    for tag in ipv6_tags {
        payload.extend_from_slice(&tag.encode());
    }
}

/// The address one of Kad's two IPv6 tags carries, or `None` when the tag is
/// not that one, is malformed, or names an address `is_usable_tag_identity`
/// refuses. All three are one outcome for a reader: a refused claim leaves the
/// decoded source where it was, never somewhere worse.
fn usable_ipv6_tag(tag: &Tag, name: &str) -> Option<std::net::Ipv6Addr> {
    crate::ipv6_tags::ipv6_from_tag(tag, name)
        .filter(|address| rmule_primitives::is_usable_tag_identity(*address))
}

fn set_first<T>(slot: &mut Option<T>, value: Option<T>) {
    if slot.is_none() {
        *slot = value;
    }
}

const fn tag_u8(value: &TagValue) -> Option<u8> {
    match *value {
        TagValue::U8(byte) => Some(byte),
        _ => None,
    }
}

/// Ports may arrive narrowed to a u8 by variable-width integer tags. A port
/// never needs `UINT64` — aMule's own port fields are 16-bit — so one arriving
/// narrowed that far is unrecognized, same as a string or hash body.
const fn tag_u16(value: &TagValue) -> Option<u16> {
    match *value {
        TagValue::U16(short) => Some(short),
        TagValue::U8(byte) => Some(byte as u16),
        TagValue::U32(_) | TagValue::U64(_) | TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

/// `TAG_SERVERIP`'s width: a buddy's IPv4 address, which never needs `UINT64`
/// (unlike `TAG_FILESIZE`, whose 64-bit width [`tag_u64`] models).
const fn tag_u32(value: &TagValue) -> Option<u32> {
    match *value {
        TagValue::U32(word) => Some(word),
        TagValue::U16(short) => Some(short as u32),
        TagValue::U8(byte) => Some(byte as u32),
        TagValue::U64(_) | TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

/// `TAG_FILESIZE`'s width: aMule's publisher writes it as a `CTagVarInt`
/// (`Tag.h:186-195`, Fork Pin `ab483654`), which narrows to the smallest of
/// `UINT8`/`_UINT16`/`_UINT32`/`_UINT64` that holds the size — so a reader
/// must widen back from any of the four.
const fn tag_u64(value: &TagValue) -> Option<u64> {
    match *value {
        TagValue::U64(word) => Some(word),
        TagValue::U32(word) => Some(word as u64),
        TagValue::U16(short) => Some(short as u64),
        TagValue::U8(byte) => Some(byte as u64),
        TagValue::String(_) | TagValue::Hash(_) => None,
    }
}

/// `[16B Kad ID][4B IPv4 low-octet-first][2B UDP LE][2B TCP LE][1B version]`.
const CONTACT_ROW_LEN: usize = 25;

fn decode_node_header(reader: &mut WireReader<'_>) -> Result<Kad2NodeInfo, &'static str> {
    Ok(Kad2NodeInfo {
        id: reader.read_kad_id("node ID").map_err(field)?,
        tcp_port: reader.read_u16_le("node TCP port").map_err(field)?,
        version: reader.read_u8("node Kad version").map_err(field)?,
        udp_port_tag: None,
        misc_options: 0,
    })
}

/// Consume a `[count][count × tag]` list, dropping every tag (the tolerant
/// skip the `0x22` ack shares with hello — it carries an empty list, but a
/// future-proof reader must not choke on tags it does not model).
fn skip_tag_list(reader: &mut WireReader<'_>, what: &'static str) -> Result<(), &'static str> {
    let count = reader.read_u8(what).map_err(field)?;
    for _ in 0..count {
        let (_, consumed) = Tag::decode_prefix(reader.remaining_bytes())
            .map_err(|_| "tag is truncated or malformed")?;
        reader.advance_clamped(consumed);
    }
    Ok(())
}

fn encode_node_header(payload: &mut Vec<u8>, info: &Kad2NodeInfo) {
    payload.extend_from_slice(info.id.as_bytes());
    payload.extend_from_slice(&info.tcp_port.to_le_bytes());
    payload.push(info.version);
}

/// Hello payloads append an eD2k tag list to the node header. The `0xFC`
/// UDP-port and `0xF2` misc-options tags are projected; unrecognized tags are
/// skipped without failing the message, matching aMule's tolerant tag loop.
fn decode_hello(reader: &mut WireReader<'_>) -> Result<Kad2NodeInfo, &'static str> {
    let mut info = decode_node_header(reader)?;
    let tag_count = reader.read_u8("hello tag count").map_err(field)?;
    for _ in 0..tag_count {
        let (tag, consumed) = Tag::decode_prefix(reader.remaining_bytes())
            .map_err(|_| "hello tag is truncated or malformed")?;
        reader.advance_clamped(consumed);
        match tag.name().id() {
            Some(TAG_SOURCEUPORT) => {
                info.udp_port_tag = match tag.value() {
                    TagValue::U16(port) => Some(*port),
                    TagValue::U8(port) => Some(u16::from(*port)),
                    _ => None,
                };
            }
            Some(TAG_KADMISCOPTIONS) => {
                if let Some(byte) = tag_u8(tag.value()) {
                    info.misc_options = byte;
                }
            }
            _ => {}
        }
    }
    Ok(info)
}

fn encode_hello(info: &Kad2NodeInfo) -> Vec<u8> {
    let mut payload = Vec::with_capacity(20 + 12);
    encode_node_header(&mut payload, info);
    // aMule's hello tag order (capture-observed in hello_res_0x19.bin):
    // TAG_SOURCEUPORT then TAG_KADMISCOPTIONS. Each is emitted only when it
    // carries information — an absent UDP port or a zero misc-options byte is an
    // absent tag, so a bare hello stays byte-identical to the pre-verification
    // wire (aMule likewise omits a misc-options tag with nothing to convey).
    let tags = [
        info.udp_port_tag
            .map(|port| (TAG_SOURCEUPORT, TagValue::U16(port))),
        (info.misc_options != 0).then_some((TAG_KADMISCOPTIONS, TagValue::U8(info.misc_options))),
    ];
    let present = tags.into_iter().flatten();
    payload.push(u8::try_from(present.clone().count()).expect("a hello models at most two tags"));
    for (name, value) in present {
        payload.extend_from_slice(&Tag::new(TagName::length_prefixed_id(name), value).encode());
    }
    payload
}

fn decode_contact_rows(
    reader: &mut WireReader<'_>,
    count: usize,
) -> Result<Vec<KadContact>, &'static str> {
    // Validate the declared count against the bytes actually present BEFORE
    // allocating, so an absurd count cannot reserve unbounded memory.
    if reader.remaining() != count * CONTACT_ROW_LEN {
        return Err("contact count disagrees with the bytes present");
    }
    let mut contacts = Vec::with_capacity(count);
    for _ in 0..count {
        let id = reader.read_kad_id("contact ID").map_err(field)?;
        let ip = reader
            .read_ipv4_low_octet_first("contact IP")
            .map_err(field)?;
        let udp_port = reader.read_u16_le("contact UDP port").map_err(field)?;
        let tcp_port = reader.read_u16_le("contact TCP port").map_err(field)?;
        let version = reader.read_u8("contact version").map_err(field)?;
        contacts.push(KadContact::new(
            id,
            KadNodeEndpoint::new(ip, udp_port),
            tcp_port,
            version,
        ));
    }
    Ok(contacts)
}

fn encode_contact_rows(payload: &mut Vec<u8>, contacts: &[KadContact]) {
    for contact in contacts {
        payload.extend_from_slice(contact.id().as_bytes());
        let mut octets = contact.endpoint().ip().octets();
        octets.reverse();
        payload.extend_from_slice(&octets);
        payload.extend_from_slice(&contact.endpoint().udp_port().to_le_bytes());
        payload.extend_from_slice(&contact.tcp_port().to_le_bytes());
        payload.push(contact.version());
    }
}
