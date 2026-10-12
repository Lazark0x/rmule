//! The **Rendezvous** signalling codecs (ADR-0091): `OP_RENDEZVOUS` (`0xA0`),
//! `OP_HOLEPUNCH` (`0xA1`) and `OP_NATT_ENDPOINT_HINT` (`0xAA`), all under
//! `OP_EMULEPROT` (`0xC5`) on the client-UDP surface and all sent
//! **unobfuscated on purpose** — a punch that fails to deobfuscate is
//! indistinguishable from one that never arrived.
//!
//! Layouts are eMuleAI v1.6's (`BaseClient.cpp:3148-3190`,
//! `ClientUDPSocket.cpp:1183-1333`), read for facts under ADR-0082. The wire
//! contract these layouts implement is ADR-0091's own "Two Rendezvous
//! coordinators" and "Seams" sections.
//!
//! # Three frames, one body
//!
//! A rendezvous body reaches a node in one of three frames, and **the frame is
//! the direction** (amule#1177 correction 2 — a "this is relayed" bit is a
//! claim by the sender; the frame is a fact):
//!
//! | Frame | Who receives it | Meaning |
//! |---|---|---|
//! | embedded in `OP_REASKCALLBACKUDP` (`0x94`) | the target's buddy | *relay this* |
//! | embedded in `OP_REASKCALLBACKTCP` (`0x9A`) | the target | *relayed to you* (eMuleAI's buddy) |
//! | standalone `0xC5 0xA0` | the target | *relayed to you* (kno's buddy) |
//!
//! The embedded forms are a typed reading of the reask relay's opaque
//! `forwarded` tail: a **null 16-byte hash** where an ordinary reask carries
//! its file hash, then the embedded opcode, then the body. No real file
//! hashes to zero, which is what makes the marker safe.
//!
//! # The greedy file-hash slot
//!
//! The body has no flags and no lengths: every optional block is detected by
//! **bytes remaining**. The 16-byte file-hash test is greedy, so an encoder
//! that omitted the slot would have its endpoint and hint misread as a hash.
//! The slot is therefore **always written** — null when there is no file
//! context — and a reader tests for the null hash, never for presence
//! (correction 8).

use std::net::Ipv4Addr;

use rmule_primitives::{
    FileHash, Ipv4Endpoint, PacketProtocol, UserHash, WireReader, WireTruncated,
};
use thiserror::Error;

use super::caps::{NattConnectOptions, NattTransport};
use crate::peer_udp::{BUDDY_ID_LEN, ClientUdpOpcode, ReaskCallbackUdp};

/// The null hash standing where an ordinary reask carries its file hash — the
/// "custom rendezvous payload" marker of the embedded forms.
const EMBED_MARKER: [u8; 16] = [0; 16];

/// Marker plus the embedded opcode byte.
const EMBED_PREFIX_LEN: usize = EMBED_MARKER.len() + 1;

/// The body's two unconditional fields: requester hash and connect options.
const BODY_MIN_LEN: usize = UserHash::BYTE_LEN + 1;

/// `<ip 4><port 2>` — the claimed endpoint block.
const ENDPOINT_LEN: usize = 6;

/// `NATT_TRANSPORT_UTP` / `NATT_TRANSPORT_QUIC` (`UpdownClient.h:136-141`).
const HINT_UTP: u8 = 1;
const HINT_QUIC: u8 = 2;

/// The fixed `OP_NATT_ENDPOINT_HINT` body width; any other size is dropped.
pub const ENDPOINT_HINT_LEN: usize = 1 + 16 + 16 + 16 + 4 + 2 + 1;

/// The only endpoint-hint version the dialect defines.
pub const ENDPOINT_HINT_VERSION: u8 = 1;

/// The rendezvous body proper — what a requester says about itself to a
/// target it cannot reach.
///
/// Everything here except the hash is a **claim**: rendezvous is the one eD2k
/// path where a node asserts its own address and nothing corrects it
/// (correction 9), so [`claimed_endpoint`](Self::claimed_endpoint) is never a
/// dial target on its own; the precedence rule decides what is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RendezvousBody {
    /// The requester's user hash — the lookup key into peers already known.
    pub requester: UserHash,
    /// The requester's connect-options byte. The embedded emit form always
    /// sets the endpoint-hint request bit; the reader preserves what arrived.
    pub options: NattConnectOptions,
    /// The file the requester wants, or `None` for the null hash. The slot is
    /// on the wire either way.
    pub file_hash: Option<FileHash>,
    /// The endpoint the requester *says* it has. `None` when the block was
    /// absent or null (a zero address or a zero port).
    pub claimed_endpoint: Option<Ipv4Endpoint>,
    /// The transport the requester intends to raise. `None` when absent or a
    /// value the dialect does not define.
    pub transport_hint: Option<NattTransport>,
}

impl RendezvousBody {
    /// Write the body. The file-hash slot and the endpoint block are always
    /// written — null when empty — so every later field sits where the
    /// receiver's bytes-remaining arithmetic expects it.
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.requester.as_bytes());
        out.push(self.options.as_byte());
        match self.file_hash {
            Some(hash) => out.extend_from_slice(hash.as_bytes()),
            None => out.extend_from_slice(&[0; FileHash::BYTE_LEN]),
        }
        let endpoint = self
            .claimed_endpoint
            .unwrap_or(Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0));
        out.extend_from_slice(&endpoint.ip.octets());
        out.extend_from_slice(&endpoint.port.to_le_bytes());
        if let Some(transport) = self.transport_hint {
            out.push(match transport {
                NattTransport::Utp => HINT_UTP,
                NattTransport::Quic => HINT_QUIC,
            });
        }
    }

    /// Read a body by eMuleAI's bytes-remaining rules, in eMuleAI's order.
    /// Surplus bytes are ignored: the dialect has no `remaining == 0` check,
    /// and rejecting a longer body would refuse a future revision that a
    /// stock eMuleAI accepts.
    fn read(body: &[u8]) -> Result<Self, RendezvousDecodeError> {
        let mut reader = WireReader::new(body);
        let requester = UserHash::from_bytes(reader.read_array("requester hash")?);
        if requester.as_bytes() == &[0; UserHash::BYTE_LEN] {
            return Err(RendezvousDecodeError::NullRequester);
        }
        let options = NattConnectOptions::from_byte(reader.read_u8("connect options")?);

        let mut file_hash = None;
        if reader.remaining() >= FileHash::BYTE_LEN {
            let slot = reader.read_array::<{ FileHash::BYTE_LEN }>("file hash")?;
            file_hash = (slot != [0; FileHash::BYTE_LEN]).then(|| FileHash::from_bytes(slot));
        }
        let mut claimed_endpoint = None;
        if reader.remaining() >= ENDPOINT_LEN {
            let ip = Ipv4Addr::from(reader.read_array::<4>("claimed address")?);
            let port = reader.read_u16_le("claimed port")?;
            claimed_endpoint =
                (!ip.is_unspecified() && port != 0).then(|| Ipv4Endpoint::new(ip, port));
        }
        let transport_hint = match reader.remaining_bytes().first() {
            Some(&HINT_UTP) => Some(NattTransport::Utp),
            Some(&HINT_QUIC) => Some(NattTransport::Quic),
            _ => None,
        };
        Ok(Self {
            requester,
            options,
            file_hash,
            claimed_endpoint,
            transport_hint,
        })
    }

    /// The **emit form** (eMuleAI's, and the only one rmule sends): the body
    /// embedded in an `OP_REASKCALLBACKUDP` addressed to the target's serving
    /// buddy. The endpoint-hint request bit is OR-ed in here, exactly where
    /// eMuleAI sets it — this is the one surface where that bit is a request
    /// rather than a collision.
    #[must_use]
    pub fn embed(&self, buddy_id: [u8; BUDDY_ID_LEN]) -> ReaskCallbackUdp {
        let mut forwarded = Vec::with_capacity(EMBED_PREFIX_LEN + BODY_MIN_LEN + 23);
        forwarded.extend_from_slice(&EMBED_MARKER);
        forwarded.push(ClientUdpOpcode::Rendezvous.as_u8());
        Self {
            options: self.options.with_endpoint_hint_request(),
            ..*self
        }
        .write(&mut forwarded);
        ReaskCallbackUdp {
            buddy_id,
            forwarded,
        }
    }

    /// Read a reask relay's `forwarded` tail — the bytes after a `0x94`'s
    /// buddy-ID or a `0x9A`'s injected endpoint — as an embedded rendezvous.
    ///
    /// `None` is the ordinary case: the tail does not open with the null-hash
    /// marker and `0xA0`, so it is a plain reask and none of this module's
    /// business. `Some(Err(_))` is a tail that *claimed* to be a rendezvous
    /// and was malformed — a drop, never a fall-through to the reask path,
    /// which would answer a null file hash.
    #[must_use]
    pub fn from_forwarded(forwarded: &[u8]) -> Option<Result<Self, RendezvousDecodeError>> {
        let body = forwarded.strip_prefix(&EMBED_MARKER)?;
        let body = body.strip_prefix(&[ClientUdpOpcode::Rendezvous.as_u8()])?;
        Some(Self::read(body))
    }

    /// Frame the standalone `0xC5 0xA0` datagram. rmule never *emits* this
    /// toward a buddy (eMuleAI has no standalone writer, and a standalone
    /// relay request cannot name its target); it exists so the accept form has
    /// a round-trip twin and so rmule-as-buddy can forward to a target that
    /// holds no TCP link.
    #[must_use]
    pub fn encode_standalone(&self) -> Vec<u8> {
        let mut datagram = signalling_header(ClientUdpOpcode::Rendezvous);
        self.write(&mut datagram);
        datagram
    }

    /// Decode a standalone `0xC5 0xA0` datagram.
    pub fn decode_standalone(datagram: &[u8]) -> Result<Self, RendezvousDecodeError> {
        Self::read(strip_signalling_header(
            datagram,
            ClientUdpOpcode::Rendezvous,
        )?)
    }
}

/// `OP_HOLEPUNCH` (`0xC5 0xA1`): the punch itself. **The body is empty** — it
/// is purely a trigger that opens the sender's mapping and tells the receiver
/// to try a transport connect.
#[must_use]
pub fn holepunch_datagram() -> Vec<u8> {
    signalling_header(ClientUdpOpcode::Holepunch)
}

/// Whether `datagram` is an `OP_HOLEPUNCH`. A non-empty body is accepted and
/// ignored: a punch is a trigger, and refusing one for carrying bytes would
/// turn a harmless extension into a failed traversal.
#[must_use]
pub fn is_holepunch(datagram: &[u8]) -> bool {
    strip_signalling_header(datagram, ClientUdpOpcode::Holepunch).is_ok()
}

/// `OP_NATT_ENDPOINT_HINT` (`0xC5 0xAA`): a serving buddy's answer to a
/// rendezvous that asked for one — the **target's live endpoint as the buddy
/// sees it**, which is the one address in this exchange a third party
/// observed.
///
/// Decoding proves only that the bytes are well-formed. Whether to *believe*
/// them is [`EndpointHint::is_from`]'s question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointHint {
    /// The target's user hash — the lookup key on the requester's side.
    pub target: UserHash,
    /// The serving buddy's Kad ID, echoing the request's routing key.
    pub buddy_id: [u8; BUDDY_ID_LEN],
    /// The file hash echoed from the request, `None` for the null hash.
    pub file_hash: Option<FileHash>,
    /// The target's live UDP endpoint as its buddy observes it.
    pub target_endpoint: Ipv4Endpoint,
    /// The target's connect options.
    pub options: NattConnectOptions,
}

impl EndpointHint {
    /// Frame the fixed 56-byte hint.
    #[must_use]
    pub fn encode_udp(&self) -> Vec<u8> {
        let mut datagram = signalling_header(ClientUdpOpcode::NattEndpointHint);
        datagram.push(ENDPOINT_HINT_VERSION);
        datagram.extend_from_slice(self.target.as_bytes());
        datagram.extend_from_slice(&self.buddy_id);
        match self.file_hash {
            Some(hash) => datagram.extend_from_slice(hash.as_bytes()),
            None => datagram.extend_from_slice(&[0; FileHash::BYTE_LEN]),
        }
        datagram.extend_from_slice(&self.target_endpoint.ip.octets());
        datagram.extend_from_slice(&self.target_endpoint.port.to_le_bytes());
        datagram.push(self.options.as_byte());
        datagram
    }

    /// Decode a hint. Exactly 56 bytes, version 1, no null target or buddy
    /// hash, no null endpoint — each refusal is eMuleAI's
    /// (`ClientUDPSocket.cpp:1301-1324`). Routability of the endpoint is *not*
    /// tested here: that is a policy about addresses, and it lives with the
    /// precedence rule.
    pub fn decode_udp(datagram: &[u8]) -> Result<Self, RendezvousDecodeError> {
        let body = strip_signalling_header(datagram, ClientUdpOpcode::NattEndpointHint)?;
        if body.len() != ENDPOINT_HINT_LEN {
            return Err(RendezvousDecodeError::HintWidth { actual: body.len() });
        }
        // The width is exact, so no read below can run short; the mapping
        // keeps the reader's failure in this decoder's own error regardless.
        let mut reader = WireReader::new(body);
        let version = reader.read_u8("hint version")?;
        if version != ENDPOINT_HINT_VERSION {
            return Err(RendezvousDecodeError::HintVersion { actual: version });
        }
        let target = reader.read_array::<16>("hint target")?;
        let buddy_id = reader.read_array::<BUDDY_ID_LEN>("hint buddy id")?;
        let file = reader.read_array::<16>("hint file hash")?;
        let ip = Ipv4Addr::from(reader.read_array::<4>("hint address")?);
        let port = reader.read_u16_le("hint port")?;
        if target == [0; 16] || buddy_id == [0; BUDDY_ID_LEN] || ip.is_unspecified() || port == 0 {
            return Err(RendezvousDecodeError::NullHintField);
        }
        Ok(Self {
            target: UserHash::from_bytes(target),
            buddy_id,
            file_hash: (file != [0; 16]).then(|| FileHash::from_bytes(file)),
            target_endpoint: Ipv4Endpoint::new(ip, port),
            options: NattConnectOptions::from_byte(reader.read_u8("hint options")?),
        })
    }

    /// The acceptance rule — **all three must match** what we already hold
    /// for the target: the buddy Kad ID we stored for it, and the datagram's
    /// source address *and* port against that buddy's endpoint. A hint that
    /// fails is "untrusted" and dropped (`ClientUDPSocket.cpp:1325-1330`).
    ///
    /// This is attribution by source address, which is forgeable (kno's audit
    /// finding F3 on amule#1177); the dialect has no nonce to do better. What
    /// it buys is that a hint names an address only for a target whose buddy
    /// we already chose to talk to.
    #[must_use]
    pub fn is_from(
        &self,
        known_buddy_id: &[u8; BUDDY_ID_LEN],
        known_buddy_udp: Ipv4Endpoint,
        observed_source: Ipv4Endpoint,
    ) -> bool {
        &self.buddy_id == known_buddy_id && observed_source == known_buddy_udp
    }
}

fn signalling_header(opcode: ClientUdpOpcode) -> Vec<u8> {
    vec![PacketProtocol::Emule.as_byte(), opcode.as_u8()]
}

fn strip_signalling_header(
    datagram: &[u8],
    expect: ClientUdpOpcode,
) -> Result<&[u8], RendezvousDecodeError> {
    match datagram {
        [protocol, opcode, body @ ..]
            if *protocol == PacketProtocol::Emule.as_byte() && *opcode == expect.as_u8() =>
        {
            Ok(body)
        }
        _ => Err(RendezvousDecodeError::WrongFrame),
    }
}

impl From<WireTruncated> for RendezvousDecodeError {
    fn from(truncated: WireTruncated) -> Self {
        Self::Truncated {
            needed: BODY_MIN_LEN,
            actual: truncated.available,
        }
    }
}

/// Why a rendezvous-family frame could not be read. Every variant is a drop:
/// the dialect has no failure frame to answer with (correction 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RendezvousDecodeError {
    /// Not `0xC5` plus the expected signalling opcode.
    #[error("not the expected NAT-T signalling frame")]
    WrongFrame,
    /// The body is shorter than the requester hash and options byte.
    #[error("rendezvous body is {actual} bytes, needs {needed}")]
    Truncated {
        /// Minimum body width.
        needed: usize,
        /// Bytes that arrived.
        actual: usize,
    },
    /// The requester hash was null — there is no peer to look up.
    #[error("rendezvous names a null requester hash")]
    NullRequester,
    /// The endpoint hint was not the fixed 56 bytes.
    #[error("endpoint hint is {actual} bytes, not 56")]
    HintWidth {
        /// Bytes that arrived.
        actual: usize,
    },
    /// The endpoint hint's version byte was not `1`.
    #[error("endpoint hint version {actual} is not 1")]
    HintVersion {
        /// The version that arrived.
        actual: u8,
    },
    /// A hint field that must be set was null.
    #[error("endpoint hint carries a null hash or endpoint")]
    NullHintField,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requester() -> UserHash {
        UserHash::from_bytes([0x11; 16])
    }

    fn file() -> FileHash {
        FileHash::from_bytes([0x22; 16])
    }

    fn full_body() -> RendezvousBody {
        RendezvousBody {
            requester: requester(),
            options: NattConnectOptions::from_byte(0x83),
            file_hash: Some(file()),
            claimed_endpoint: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 4672)),
            transport_hint: Some(NattTransport::Utp),
        }
    }

    /// eMuleAI's A→R relay request, offset by offset: buddy ID 0, null marker 16,
    /// `0xA0` at 32, requester 33, options 49 (with `0x20` OR-ed in), file
    /// hash 50, IPv4 66 in dotted order, port 70 little-endian, hint 72 —
    /// 73 bytes of body behind the two-byte header.
    #[test]
    fn the_embedded_emit_form_is_emuleais_73_byte_layout() {
        let datagram = full_body().embed([0xBB; 16]).encode_udp();
        assert_eq!(datagram.len(), 2 + 73);
        assert_eq!(&datagram[..2], &[0xC5, 0x94]);
        let body = &datagram[2..];
        assert_eq!(&body[0..16], &[0xBB; 16]);
        assert_eq!(&body[16..32], &[0x00; 16]);
        assert_eq!(body[32], 0xA0);
        assert_eq!(&body[33..49], &[0x11; 16]);
        assert_eq!(body[49], 0x83 | 0x20);
        assert_eq!(&body[50..66], &[0x22; 16]);
        assert_eq!(&body[66..70], &[45, 55, 200, 7]);
        assert_eq!(&body[70..72], &4672u16.to_le_bytes());
        assert_eq!(body[72], 1);
    }

    /// Correction 8, from the receiving side. With no file context the slot
    /// is still written, so eMuleAI's greedy `remaining >= 16` test lands on
    /// sixteen null bytes and the endpoint after it survives. Had the slot
    /// been omitted, the same reader would have eaten the endpoint as a hash.
    #[test]
    fn a_body_without_a_file_still_carries_the_slot_and_keeps_its_endpoint() {
        let body = RendezvousBody {
            file_hash: None,
            ..full_body()
        };
        let forwarded = body.embed([0xBB; 16]).forwarded;
        assert_eq!(forwarded.len(), 17 + 17 + 16 + 6 + 1);
        let read = RendezvousBody::from_forwarded(&forwarded)
            .expect("marker and opcode present")
            .expect("well-formed");
        assert_eq!(read.file_hash, None);
        assert_eq!(read.claimed_endpoint, body.claimed_endpoint);
        assert_eq!(read.transport_hint, Some(NattTransport::Utp));
    }

    /// The greedy hazard itself, pinned so nobody "optimises" the reader: a
    /// foreign encoder that omits the slot and appends 6 + 16 bytes has its
    /// endpoint read as the head of a file hash. rmule reads it the way
    /// eMuleAI does — wrong in the same way — because agreeing with the
    /// population on a malformed body beats being uniquely right about it.
    #[test]
    fn the_reader_is_greedy_in_emuleais_order() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x11; 16]);
        wire.push(0x80);
        wire.extend_from_slice(&[45, 55, 200, 7, 0x40, 0x12]);
        wire.extend_from_slice(&[0x33; 16]);
        let read = RendezvousBody::read(&wire).expect("long enough");
        assert_eq!(
            &read.file_hash.expect("greedy").as_bytes()[..4],
            &[45, 55, 200, 7]
        );
        assert_ne!(
            read.claimed_endpoint,
            Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 7), 0x1240))
        );
    }

    /// An ordinary relayed reask opens with a real file hash, so it is not a
    /// rendezvous; a tail that opens with the marker but a different embedded
    /// opcode is not one either. Both must fall through to the reask path.
    #[test]
    fn an_ordinary_reask_tail_is_not_a_rendezvous() {
        let mut reask = vec![0x22; 16];
        reask.extend_from_slice(&[0x01, 0x00]);
        assert!(RendezvousBody::from_forwarded(&reask).is_none());

        let mut other = vec![0x00; 16];
        other.push(0xA1);
        assert!(RendezvousBody::from_forwarded(&other).is_none());
    }

    /// A tail that claims to be a rendezvous and is not one is a drop — it
    /// must never reach the reask matrix, which would answer a null hash.
    #[test]
    fn a_marked_but_malformed_tail_is_an_error_not_a_reask() {
        let mut tail = vec![0x00; 16];
        tail.push(0xA0);
        tail.extend_from_slice(&[0x11; 10]);
        assert_eq!(
            RendezvousBody::from_forwarded(&tail),
            Some(Err(RendezvousDecodeError::Truncated {
                needed: 17,
                actual: 10
            }))
        );

        let mut null = vec![0x00; 16];
        null.push(0xA0);
        null.extend_from_slice(&[0x00; 17]);
        assert_eq!(
            RendezvousBody::from_forwarded(&null),
            Some(Err(RendezvousDecodeError::NullRequester))
        );
    }

    /// kno's buddy relays in the standalone form; it carries the same body
    /// and leaves the hint-request bit as the sender set it.
    #[test]
    fn the_standalone_form_round_trips_and_does_not_touch_the_options() {
        let datagram = full_body().encode_standalone();
        assert_eq!(&datagram[..2], &[0xC5, 0xA0]);
        assert_eq!(datagram[2 + 16], 0x83);
        assert_eq!(
            RendezvousBody::decode_standalone(&datagram),
            Ok(full_body())
        );
    }

    /// Surplus bytes are ignored, a null endpoint reads as absent, and an
    /// undefined transport value reads as no hint rather than as an error.
    #[test]
    fn surplus_null_and_undefined_fields_are_tolerated() {
        let mut datagram = RendezvousBody {
            claimed_endpoint: None,
            transport_hint: None,
            ..full_body()
        }
        .encode_standalone();
        datagram.extend_from_slice(&[9, 0xFE, 0xFE]);
        let read = RendezvousBody::decode_standalone(&datagram).expect("tolerated");
        assert_eq!(read.claimed_endpoint, None);
        assert_eq!(read.transport_hint, None);
    }

    /// aMule had to be taught that eMuleAI's punch has no body (`c369e3d4`).
    #[test]
    fn a_holepunch_is_two_bytes_and_a_longer_one_still_triggers() {
        assert_eq!(holepunch_datagram(), vec![0xC5, 0xA1]);
        assert!(is_holepunch(&[0xC5, 0xA1]));
        assert!(is_holepunch(&[0xC5, 0xA1, 0x00]));
        assert!(!is_holepunch(&[0xC5, 0xA0]));
        assert!(!is_holepunch(&[0xC5]));
    }

    fn hint() -> EndpointHint {
        EndpointHint {
            target: UserHash::from_bytes([0x44; 16]),
            buddy_id: [0xBB; 16],
            file_hash: Some(file()),
            target_endpoint: Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 5000),
            options: NattConnectOptions::from_byte(0x80),
        }
    }

    /// eMuleAI's endpoint hint: version 0, target 1, buddy 17, file 33, IPv4 49,
    /// port 53, options 55 — 56 bytes, and nothing else is a hint.
    #[test]
    fn the_endpoint_hint_is_the_fixed_56_byte_layout() {
        let datagram = hint().encode_udp();
        assert_eq!(datagram.len(), 2 + 56);
        assert_eq!(&datagram[..3], &[0xC5, 0xAA, 1]);
        assert_eq!(&datagram[2 + 49..2 + 53], &[45, 55, 200, 9]);
        assert_eq!(&datagram[2 + 53..2 + 55], &5000u16.to_le_bytes());
        assert_eq!(EndpointHint::decode_udp(&datagram), Ok(hint()));

        let mut long = datagram.clone();
        long.push(0);
        assert_eq!(
            EndpointHint::decode_udp(&long),
            Err(RendezvousDecodeError::HintWidth { actual: 57 })
        );
        let mut versioned = datagram.clone();
        versioned[2] = 2;
        assert_eq!(
            EndpointHint::decode_udp(&versioned),
            Err(RendezvousDecodeError::HintVersion { actual: 2 })
        );
        let mut portless = datagram;
        portless[2 + 53] = 0;
        portless[2 + 54] = 0;
        assert_eq!(
            EndpointHint::decode_udp(&portless),
            Err(RendezvousDecodeError::NullHintField)
        );
    }

    /// All three, or nothing: the right buddy ID from the wrong port is as
    /// untrusted as the wrong buddy ID from the right one.
    #[test]
    fn a_hint_is_believed_only_from_the_targets_known_buddy() {
        let buddy = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 2), 4672);
        assert!(hint().is_from(&[0xBB; 16], buddy, buddy));
        assert!(!hint().is_from(&[0xBC; 16], buddy, buddy));
        assert!(!hint().is_from(
            &[0xBB; 16],
            buddy,
            Ipv4Endpoint::new(buddy.ip, buddy.port + 1)
        ));
        assert!(!hint().is_from(
            &[0xBB; 16],
            buddy,
            Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 3), buddy.port)
        ));
    }
}
