//! Per-datagram obfuscation crypto primitives for the eMule UDP surfaces
//! (ADR-0046): the stateless RC4-per-packet scheme shared by peer-UDP, Kad-UDP,
//! and server-UDP, distinct from the stream form in [`crate::obfuscation`].
//!
//! Unlike the TCP stream obfuscation (a keyed handshake plus RC4-drop1024), each
//! datagram carries its own 2-byte random key seed in the clear and derives a
//! fresh RC4 key per packet, **without** the 1024-byte keystream discard (aMule
//! skips it on UDP "to save CPU time"). Four key families cover the surfaces:
//!
//! - **ed2k client** — `MD5(user_hash ‖ sender address ‖ MAGICVALUE_UDP ‖
//!   random_key)`, where the address's width follows the datagram's **actual
//!   source family**: 4 bytes and a 23-byte key for IPv4, 16 and a 35-byte key
//!   for IPv6 (ADR-0087).
//! - **Kad NodeID** — `MD5(kad_id ‖ random_key)`.
//! - **Kad verify key** — `MD5(receiver_verify_key ‖ random_key)`.
//! - **server** — `MD5(base_key ‖ direction_magic ‖ random_key)`, keyed on the
//!   `ServerUDPKey` (or crypt-ping challenge) learned from `OP_GLOBSERVSTATRES`.
//!
//! On the wire the client (peer/Kad) families multiplex via the low two bits of
//! the plaintext marker byte (`byte0 & 0x03`); the server pair is dispatched by
//! its own socket. A known-plaintext marker byte bypasses decryption entirely so
//! legacy plaintext datagrams still interoperate at any policy.
//!
//! Every byte layout, magic value, and derivation order below is **source-read**
//! from aMule (`src/EncryptedDatagramSocket.cpp` @`4e8f2b3c`, cite-and-rewrite
//! per ADR-0004) and pinned `[pending]` until a capture confirms it byte-for-byte
//! (the ADR-0046 capture tier). The deterministic tests here lock rmule's scheme
//! as internally consistent (crossed-role loopbacks, direction traps); they do
//! not by themselves prove aMule compatibility — that is the capture's job.

use md5::{Digest, Md5};

use crate::obfuscation::Rc4;
use crate::{PacketProtocol, UserHash};

/// Key-derivation magic mixed into the ed2k client UDP key (`0x5B`).
/// `[pending]` (aMule `EncryptedDatagramSocket.cpp` @`4e8f2b3c`).
pub const MAGICVALUE_UDP: u8 = 0x5B;

/// Server-crypt key magic for the client→server datagram direction (`0x6B`).
/// `[pending]` (aMule `EncryptedDatagramSocket.cpp` @`4e8f2b3c`).
pub const MAGICVALUE_UDP_CLIENTSERVER: u8 = 0x6B;

/// Server-crypt key magic for the server→client datagram direction (`0xA5`).
/// `[pending]` (aMule `EncryptedDatagramSocket.cpp` @`4e8f2b3c`).
pub const MAGICVALUE_UDP_SERVERCLIENT: u8 = 0xA5;

/// The encrypted header sync word identifying a client (peer/Kad) crypt datagram.
/// `[pending]` (aMule `EncryptedDatagramSocket.cpp` @`4e8f2b3c`).
pub const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F_2EC1;

/// The encrypted header sync word identifying a server crypt datagram.
/// `[pending]` (aMule `EncryptedDatagramSocket.cpp` @`4e8f2b3c`).
pub const MAGICVALUE_UDP_SYNC_SERVER: u32 = 0x13EF_24D5;

/// Header bytes before any padding: marker (1) + random key (2) + sync (4) +
/// padding-length (1). aMule's `CRYPT_HEADER_WITHOUTPADDING`.
const CRYPT_HEADER_WITHOUTPADDING: usize = 8;

/// The 8-byte `<receiver_verify_key><sender_verify_key>` trailer Kad datagrams
/// carry inside the encrypted region (ed2k and server datagrams have none).
const KAD_VERIFY_TRAILER_LEN: usize = 8;

/// The most padding a datagram can carry: the pad-length is a single wire byte,
/// so the count saturates at `u8::MAX`. aMule draws `rand() % 16` here (0–15),
/// far under the cap; the framer clamps to this bound so the emitted length
/// byte is a lossless `as u8` that always matches the padding it prefixes.
const MAX_PADDING_LEN: usize = u8::MAX as usize;

/// The sender address that keys an ed2k client datagram, in the family the
/// datagram actually arrived from.
///
/// The layout is **selected, never probed** (ADR-0087). Both widths are valid
/// key material, so guessing wrong does not fail loudly: it derives a key that
/// decrypts to garbage, the sync word does not match, and the datagram is
/// indistinguishable from an unobfuscated peer's. The only thing that can pick
/// correctly is the source family the socket reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramSenderAddress {
    /// An IPv4 sender: four bytes, in the order the capture-proven IPv4 key
    /// already uses.
    V4([u8; 4]),
    /// An IPv6 sender: the sixteen network-order address bytes, giving the
    /// 35-byte layout with its magic at offset 32.
    V6([u8; 16]),
}

impl DatagramSenderAddress {
    /// The sender address as its family's key bytes.
    #[must_use]
    pub fn from_ip(address: std::net::IpAddr) -> Self {
        match address {
            std::net::IpAddr::V4(ip) => Self::V4(ip.octets()),
            std::net::IpAddr::V6(ip) => Self::V6(ip.octets()),
        }
    }

    /// The bytes the key mixes in — four or sixteen, never padded to a common
    /// width: the width *is* the layout.
    #[must_use]
    pub const fn as_key_bytes(&self) -> &[u8] {
        match self {
            Self::V4(bytes) => bytes,
            Self::V6(bytes) => bytes,
        }
    }
}

impl Default for DatagramSenderAddress {
    /// The unspecified IPv4 sender — what a receiver holds before a datagram
    /// has named one. It keys nothing real, which is the honest state.
    fn default() -> Self {
        Self::V4([0; 4])
    }
}

/// Which client (peer/Kad) key family a datagram uses, encoded in the low two
/// bits of the plaintext marker byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramKeyFamily {
    /// Kad, keyed on the receiver's 16-byte KadID (marker bits `0`).
    KadNodeId,
    /// ed2k, keyed on the receiver's user hash + sender IP (marker bits `1`).
    Ed2kUserHash,
    /// Kad, keyed on the receiver's 4-byte UDP verify key (marker bits `2`).
    KadVerifyKey,
}

/// Which direction a server crypt datagram travels, selecting the key magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerCryptDirection {
    /// Client → server (`MAGICVALUE_UDP_CLIENTSERVER`).
    ToServer,
    /// Server → client (`MAGICVALUE_UDP_SERVERCLIENT`).
    FromServer,
}

/// Whether `byte` is a known plaintext UDP protocol marker that bypasses
/// decryption (`OP_EMULEPROT` `0xC5`, `OP_KADEMLIAHEADER` `0xE4`,
/// `OP_KADEMLIAPACKEDPROT` `0xE5`, `OP_PACKEDPROT` `0xD4`, `OP_UDPRESERVEDPROT1`
/// `0xA3`, `OP_UDPRESERVEDPROT2` `0xB2`). A datagram whose first byte is one of
/// these is passed through untouched at any obfuscation policy.
/// `[pending]` (aMule `EncryptedDatagramSocket.cpp` @`4e8f2b3c`).
#[must_use]
pub const fn is_udp_plaintext_marker(byte: u8) -> bool {
    matches!(byte, 0xC5 | 0xE4 | 0xE5 | 0xD4 | 0xA3 | 0xB2)
}

/// The key family a datagram's marker byte selects: `byte0 & 0x03`, with the `3`
/// alias folding onto ed2k (index 1) as aMule does.
#[must_use]
pub const fn marker_family(byte0: u8) -> DatagramKeyFamily {
    match byte0 & 0x03 {
        0 => DatagramKeyFamily::KadNodeId,
        2 => DatagramKeyFamily::KadVerifyKey,
        _ => DatagramKeyFamily::Ed2kUserHash,
    }
}

/// The random inputs a single encrypt draws, injected so tests are deterministic
/// (mirrors the `fn() -> u16` entropy seam the status-ping sweep uses).
#[derive(Clone, Debug)]
pub struct DatagramNonce {
    /// The semi-random plaintext marker byte; its low two bits are overwritten
    /// with the key-family index and it is nudged clear of plaintext markers.
    pub marker_byte: u8,
    /// The 2-byte per-packet key seed, sent in the clear and mixed into the key.
    pub random_key: u16,
    /// Random padding placed (encrypted) between the header and the payload.
    pub padding: Vec<u8>,
}

/// The key material a sender supplies to obfuscate one client (peer/Kad)
/// datagram. The Kad variants also carry the verify-key trailer values.
#[derive(Clone, Debug)]
pub enum ClientEncryptKey<'a> {
    /// ed2k: the receiver's user hash and the sender's own public address, in
    /// the family the datagram will travel over.
    Ed2k {
        /// The receiver's 16-byte user hash.
        user_hash: &'a UserHash,
        /// The sender's own public address, whose width selects the layout.
        sender: DatagramSenderAddress,
    },
    /// Kad, keyed on the receiver's KadID, with the verify-key trailer.
    KadNode {
        /// The receiver's 16-byte KadID.
        kad_id: &'a [u8; 16],
        /// The receiver's verify key echoed in the trailer.
        receiver_verify_key: u32,
        /// The sender's verify key echoed in the trailer.
        sender_verify_key: u32,
    },
    /// Kad, keyed on the receiver's UDP verify key, with the verify-key trailer.
    KadVerify {
        /// The receiver's 4-byte UDP verify key (key basis).
        verify_key: u32,
        /// The receiver's verify key echoed in the trailer.
        receiver_verify_key: u32,
        /// The sender's verify key echoed in the trailer.
        sender_verify_key: u32,
    },
}

/// The candidate key material a receiver holds, tried in marker-bit order to
/// decrypt one client (peer/Kad) datagram. A family whose key is `None` is
/// skipped.
#[derive(Clone, Debug, Default)]
pub struct ClientDecryptKeys<'a> {
    /// This node's own KadID (family `KadNodeId`).
    pub kad_id: Option<&'a [u8; 16]>,
    /// This node's own user hash (family `Ed2kUserHash`).
    pub user_hash: Option<&'a UserHash>,
    /// The datagram sender's address as the socket reported it, mixed into the
    /// ed2k key — and, by its width, selecting that key's layout.
    pub sender: DatagramSenderAddress,
    /// This node's own UDP verify key (family `KadVerifyKey`).
    pub receiver_verify_key: Option<u32>,
}

/// A successfully decrypted client datagram: its family, the recovered payload,
/// and the verify-key trailer (present only for the Kad families).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedDatagram {
    /// The key family whose derivation validated the sync word.
    pub family: DatagramKeyFamily,
    /// The recovered plaintext payload (padding and trailer stripped).
    pub payload: Vec<u8>,
    /// The trailer's receiver verify key (Kad families only).
    pub receiver_verify_key: Option<u32>,
    /// The trailer's sender verify key (Kad families only).
    pub sender_verify_key: Option<u32>,
}

/// Key an RC4 stream from `MD5(parts…)` with **no** keystream discard — the UDP
/// convention (aMule skips the drop-1024 on datagram keys to save CPU).
fn rc4_from_md5_parts(parts: &[&[u8]]) -> Rc4 {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    Rc4::new(&hasher.finalize())
}

/// The exact bytes the ed2k client UDP key is `MD5`'d over — 23 for an IPv4
/// sender, 35 for an IPv6 one (ADR-0087):
///
/// ```text
/// IPv4, 23 bytes: [0..15] user hash | [16..19] address | [20] 0x5B | [21..22] random key
/// IPv6, 35 bytes: [0..15] user hash | [16..31] address | [32] 0x5B | [33..34] random key
/// ```
///
/// The magic sits **after** the address, so it moves with the width — emule-qt's
/// layout (`src/core/net/EncryptedDatagramSocket.cpp:129-134` receive,
/// `:241-246` send, at `73fff714`), the only IPv6 one rmule derives.
///
/// eMuleAI's differs in exactly one byte (`srchybrid/EncryptedDatagramSocket.cpp`
/// `:227-234` receive, `:338-346` send, at `a2f05dc8`): it writes the magic at
/// offset 20, then copies sixteen address bytes over 16..=31 — overwriting it
/// with address byte 4, which is what offset 20 holds here too — and never
/// writes offset 32 of its uninitialised `achKeyData[35]`. So its key agrees
/// with this one only when that stack byte happens to be `0x5B`, and no
/// receiver can derive a byte nobody wrote (ADR-0087's divergence note).
#[must_use]
pub fn ed2k_key_material(
    user_hash: &UserHash,
    sender: DatagramSenderAddress,
    random_key: u16,
) -> Vec<u8> {
    let address = sender.as_key_bytes();
    let mut material = Vec::with_capacity(UserHash::BYTE_LEN + address.len() + 3);
    material.extend_from_slice(user_hash.as_bytes());
    material.extend_from_slice(address);
    material.push(MAGICVALUE_UDP);
    material.extend_from_slice(&random_key.to_le_bytes());
    material
}

/// Derive the ed2k client UDP RC4 key over [`ed2k_key_material`], with no
/// keystream discard.
#[must_use]
pub fn datagram_key_ed2k(
    user_hash: &UserHash,
    sender: DatagramSenderAddress,
    random_key: u16,
) -> Rc4 {
    rc4_from_md5_parts(&[&ed2k_key_material(user_hash, sender, random_key)])
}

/// Derive the Kad-NodeID UDP RC4 key: `RC4(MD5(kad_id ‖ random_key_le))`.
#[must_use]
pub fn datagram_key_kad_node(kad_id: &[u8; 16], random_key: u16) -> Rc4 {
    rc4_from_md5_parts(&[kad_id, &random_key.to_le_bytes()])
}

/// Derive the Kad verify-key UDP RC4 key:
/// `RC4(MD5(verify_key_le ‖ random_key_le))`.
#[must_use]
pub fn datagram_key_kad_verify(verify_key: u32, random_key: u16) -> Rc4 {
    rc4_from_md5_parts(&[&verify_key.to_le_bytes(), &random_key.to_le_bytes()])
}

/// Derive the server UDP RC4 key:
/// `RC4(MD5(base_key_le ‖ direction_magic ‖ random_key_le))`.
#[must_use]
pub fn datagram_key_server(base_key: u32, direction: ServerCryptDirection, random_key: u16) -> Rc4 {
    let magic = match direction {
        ServerCryptDirection::ToServer => MAGICVALUE_UDP_CLIENTSERVER,
        ServerCryptDirection::FromServer => MAGICVALUE_UDP_SERVERCLIENT,
    };
    rc4_from_md5_parts(&[&base_key.to_le_bytes(), &[magic], &random_key.to_le_bytes()])
}

/// The low-two-bits key-family index a marker byte carries on the wire.
const fn family_bits(family: DatagramKeyFamily) -> u8 {
    match family {
        DatagramKeyFamily::KadNodeId => 0,
        DatagramKeyFamily::Ed2kUserHash => 1,
        DatagramKeyFamily::KadVerifyKey => 2,
    }
}

/// The pieces of one obfuscated datagram before RC4 is applied. `marker_step`
/// is added to the marker byte until it clears the plaintext-marker set,
/// preserving whichever low bits the caller pre-set (family index, or none).
struct DatagramFrame<'a> {
    marker: u8,
    marker_step: u8,
    random_key: u16,
    sync: u32,
    padding: &'a [u8],
    trailer: Option<(u32, u32)>,
    payload: &'a [u8],
}

/// Frame one obfuscated datagram: `[marker][random_key_le] ‖ RC4(sync ‖ padlen ‖
/// padding ‖ trailer ‖ payload)`.
fn frame_datagram(frame: &DatagramFrame<'_>, mut cipher: Rc4) -> Vec<u8> {
    let mut marker = frame.marker;
    while is_udp_plaintext_marker(marker) {
        marker = marker.wrapping_add(frame.marker_step);
    }

    // The pad-length is a single wire byte, so clamp to `MAX_PADDING_LEN` and
    // take the count from the *same* slice we emit — the length byte and the
    // padding it prefixes can then never disagree. A bare `len() as u8` would
    // wrap an over-long nonce (e.g. 256 → 0) while still writing every byte,
    // desyncing the decoder's `body_start` and corrupting the payload in a
    // release build. Real nonces sit far under the cap (aMule draws
    // `rand() % 16`); the excess is inert filler the receiver discards anyway.
    let padding = &frame.padding[..frame.padding.len().min(MAX_PADDING_LEN)];

    let mut region =
        Vec::with_capacity(5 + padding.len() + KAD_VERIFY_TRAILER_LEN + frame.payload.len());
    // The sync word is written **little-endian** on the wire: aMule's
    // `EncryptedDatagramSocket` RC4-decrypts four bytes into a native `uint32`
    // and compares to `MAGICVALUE_UDP_SYNC_CLIENT` with an endian-swap that is a
    // no-op on little-endian hosts, so the sync bytes are LE. Framing it BE was
    // self-consistent (every deterministic KAT round-trips) but silently
    // non-interoperable — a genuine aMule Kad crypt capture (flow K)
    // decoded only after this correction.
    region.extend_from_slice(&frame.sync.to_le_bytes());
    region.push(padding.len() as u8);
    region.extend_from_slice(padding);
    if let Some((receiver, sender)) = frame.trailer {
        region.extend_from_slice(&receiver.to_le_bytes());
        region.extend_from_slice(&sender.to_le_bytes());
    }
    region.extend_from_slice(frame.payload);
    cipher.apply(&mut region);

    let mut out = Vec::with_capacity(3 + region.len());
    out.push(marker);
    out.extend_from_slice(&frame.random_key.to_le_bytes());
    out.extend_from_slice(&region);
    out
}

/// Obfuscate one client (peer/Kad) datagram, producing the full on-wire packet
/// (plaintext marker + random key seed, then the RC4-encrypted sync word,
/// padding, optional verify-key trailer, and payload).
#[must_use]
pub fn encrypt_datagram_client(
    payload: &[u8],
    key: &ClientEncryptKey<'_>,
    nonce: &DatagramNonce,
) -> Vec<u8> {
    let (family, cipher, trailer) = match *key {
        ClientEncryptKey::Ed2k { user_hash, sender } => (
            DatagramKeyFamily::Ed2kUserHash,
            datagram_key_ed2k(user_hash, sender, nonce.random_key),
            None,
        ),
        ClientEncryptKey::KadNode {
            kad_id,
            receiver_verify_key,
            sender_verify_key,
        } => (
            DatagramKeyFamily::KadNodeId,
            datagram_key_kad_node(kad_id, nonce.random_key),
            Some((receiver_verify_key, sender_verify_key)),
        ),
        ClientEncryptKey::KadVerify {
            verify_key,
            receiver_verify_key,
            sender_verify_key,
        } => (
            DatagramKeyFamily::KadVerifyKey,
            datagram_key_kad_verify(verify_key, nonce.random_key),
            Some((receiver_verify_key, sender_verify_key)),
        ),
    };
    frame_datagram(
        &DatagramFrame {
            // Both low bits are pinned to the family index. The Kad families
            // match aMule byte for byte (`x & 0xFC` for NodeID,
            // `(x & 0xFE) | 0x02` for the receiver key), but the **ed2k** case is
            // a deliberate narrowing: aMule writes `x | 0x01` and leaves bit 1
            // random, so it emits `..01` *or* `..11`, while rmule always emits
            // `..01`. Both decode identically — a receiver folds the `3` alias
            // onto ed2k ([`marker_family`], aMule's `((b & 0x03) == 3) ? 1 : …`)
            // — but a captured aMule ed2k datagram may carry `..11` where ours
            // never does. `[pending]`: an ADR-0046 capture comparison must read
            // the marker as a *masked* field, not an exact byte.
            marker: (nonce.marker_byte & 0xFC) | family_bits(family),
            // Step by 4 so the family bits survive any nudge off a marker.
            marker_step: 4,
            random_key: nonce.random_key,
            sync: MAGICVALUE_UDP_SYNC_CLIENT,
            padding: &nonce.padding,
            trailer,
            payload,
        },
        cipher,
    )
}

/// The recovered contents of one RC4-decrypted region.
struct Unframed {
    payload: Vec<u8>,
    trailer: Option<(u32, u32)>,
}

/// Strip an RC4-decrypted region: validate the `sync` word, then drop the
/// padding-length byte + padding (+ the 8-byte verify-key trailer for Kad).
/// Returns `None` on a sync mismatch / malformed body.
fn unframe_region(region: &[u8], sync: u32, has_trailer: bool) -> Option<Unframed> {
    if region.len() < 5 || u32::from_le_bytes(region[..4].try_into().ok()?) != sync {
        return None;
    }
    let body_start = 5 + region[4] as usize;
    let trailer_len = if has_trailer {
        KAD_VERIFY_TRAILER_LEN
    } else {
        0
    };
    if region.len() < body_start + trailer_len {
        return None;
    }
    let trailer = has_trailer.then(|| {
        let receiver = u32::from_le_bytes(region[body_start..body_start + 4].try_into().unwrap());
        let sender = u32::from_le_bytes(region[body_start + 4..body_start + 8].try_into().unwrap());
        (receiver, sender)
    });
    Some(Unframed {
        payload: region[body_start + trailer_len..].to_vec(),
        trailer,
    })
}

/// Dual-path receive for one client (peer/Kad) datagram. Returns `None` if the
/// first byte is a plaintext marker (caller handles it plainly), the datagram is
/// too short, or no held key validates the sync word (garbage / not for us).
#[must_use]
pub fn decrypt_datagram_client(
    datagram: &[u8],
    keys: &ClientDecryptKeys<'_>,
) -> Option<DecryptedDatagram> {
    if datagram.len() < CRYPT_HEADER_WITHOUTPADDING || is_udp_plaintext_marker(datagram[0]) {
        return None;
    }
    let random_key = u16::from_le_bytes([datagram[1], datagram[2]]);
    let primary = marker_family(datagram[0]);
    let every = [
        DatagramKeyFamily::KadNodeId,
        DatagramKeyFamily::Ed2kUserHash,
        DatagramKeyFamily::KadVerifyKey,
    ];
    // Try the marker-indicated family first, then the rest.
    for family in std::iter::once(primary).chain(every.into_iter().filter(|&f| f != primary)) {
        let cipher = match family {
            DatagramKeyFamily::KadNodeId => {
                keys.kad_id.map(|id| datagram_key_kad_node(id, random_key))
            }
            DatagramKeyFamily::Ed2kUserHash => keys
                .user_hash
                .map(|uh| datagram_key_ed2k(uh, keys.sender, random_key)),
            DatagramKeyFamily::KadVerifyKey => keys
                .receiver_verify_key
                .map(|vk| datagram_key_kad_verify(vk, random_key)),
        };
        let Some(mut cipher) = cipher else { continue };
        let mut region = datagram[3..].to_vec();
        cipher.apply(&mut region);
        let has_trailer = family != DatagramKeyFamily::Ed2kUserHash;
        if let Some(unframed) = unframe_region(&region, MAGICVALUE_UDP_SYNC_CLIENT, has_trailer) {
            let (receiver_verify_key, sender_verify_key) = match unframed.trailer {
                Some((r, s)) => (Some(r), Some(s)),
                None => (None, None),
            };
            return Some(DecryptedDatagram {
                family,
                payload: unframed.payload,
                receiver_verify_key,
                sender_verify_key,
            });
        }
    }
    None
}

/// Obfuscate one server datagram (no verify-key trailer; server sync word).
#[must_use]
pub fn encrypt_datagram_server(
    payload: &[u8],
    base_key: u32,
    direction: ServerCryptDirection,
    nonce: &DatagramNonce,
) -> Vec<u8> {
    // The server pair is dispatched by socket, not marker bits, so the marker
    // carries no family index — nudge it off plaintext markers by a bare step.
    // A server takes a datagram that leads with `OP_EDONKEYPROT` as plaintext,
    // so the marker clears that byte too (aMule `EncryptSendServer`).
    let mut marker = nonce.marker_byte;
    while marker == PacketProtocol::Edonkey.as_byte() || is_udp_plaintext_marker(marker) {
        marker = marker.wrapping_add(1);
    }
    frame_datagram(
        &DatagramFrame {
            marker,
            marker_step: 1,
            random_key: nonce.random_key,
            sync: MAGICVALUE_UDP_SYNC_SERVER,
            padding: &nonce.padding,
            trailer: None,
            payload,
        },
        datagram_key_server(base_key, direction, nonce.random_key),
    )
}

/// Decrypt one server datagram keyed on `base_key` for the given direction.
/// Returns `None` on a short datagram or a sync-word mismatch.
#[must_use]
pub fn decrypt_datagram_server(
    datagram: &[u8],
    base_key: u32,
    direction: ServerCryptDirection,
) -> Option<Vec<u8>> {
    if datagram.len() < CRYPT_HEADER_WITHOUTPADDING {
        return None;
    }
    let random_key = u16::from_le_bytes([datagram[1], datagram[2]]);
    let mut cipher = datagram_key_server(base_key, direction, random_key);
    let mut region = datagram[3..].to_vec();
    cipher.apply(&mut region);
    unframe_region(&region, MAGICVALUE_UDP_SYNC_SERVER, false).map(|unframed| unframed.payload)
}

#[cfg(test)]
mod tests;

/// The IPv6 key against both counterparties' source, byte for byte (ADR-0087's divergence note):
/// which derivation rmule accepts, and what an
/// eMuleAI datagram's fate is.
#[cfg(test)]
mod ipv6_key_kat {
    use super::*;

    /// emule-qt's own IPv6 test address, `2001:db8::1234:5678`
    /// (`tests/tst_EncryptedDatagram.cpp:91-93` at `73fff714`).
    const ADDRESS: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56,
        0x78,
    ];
    const HASH: [u8; 16] = [0x11; 16];
    const RANDOM_KEY: u16 = 0xBEEF;

    /// emule-qt `src/core/net/EncryptedDatagramSocket.cpp:129-134`:
    /// `md4cpy(keyData, userHash); memcpy(&keyData[16], ip6, 16);
    /// keyData[32] = kMagicValueUDP; pokeUInt16(&keyData[33], randomKeyPart);`
    fn emule_qt_material() -> [u8; 35] {
        let mut key = [0u8; 35];
        key[..16].copy_from_slice(&HASH);
        key[16..32].copy_from_slice(&ADDRESS);
        key[32] = 0x5B;
        key[33..].copy_from_slice(&RANDOM_KEY.to_le_bytes());
        key
    }

    /// eMuleAI `srchybrid/EncryptedDatagramSocket.cpp:227-234`, in its
    /// statement order, with `stack` standing for the byte it never writes.
    fn emuleai_material(stack: u8) -> [u8; 35] {
        let mut key = [stack; 35];
        key[..16].copy_from_slice(&HASH); // md4cpy(achKeyData, hash)
        key[20] = MAGICVALUE_UDP; // achKeyData[20] = MAGICVALUE_UDP
        key[16..32].copy_from_slice(&ADDRESS); // memcpy(achKeyData + 16, ip6, 16)
        key[33..].copy_from_slice(&RANDOM_KEY.to_le_bytes()); // memcpy(+ 33, rand, 2)
        key
    }

    /// One ed2k datagram obfuscated under raw key `material`, framed exactly as
    /// [`encrypt_datagram_client`] frames one.
    fn sealed_under(material: &[u8], payload: &[u8]) -> Vec<u8> {
        frame_datagram(
            &DatagramFrame {
                marker: 0x41,
                marker_step: 4,
                random_key: RANDOM_KEY,
                sync: MAGICVALUE_UDP_SYNC_CLIENT,
                padding: &[],
                trailer: None,
                payload,
            },
            rc4_from_md5_parts(&[material]),
        )
    }

    /// The only IPv6 derivation rmule holds is emule-qt's: the material is its
    /// 35 bytes and the key is `RC4(MD5(them))` with no discard.
    #[test]
    fn the_ipv6_key_is_emule_qts_35_bytes() {
        let sender = DatagramSenderAddress::V6(ADDRESS);
        let user_hash = UserHash::from_bytes(HASH);
        assert_eq!(
            ed2k_key_material(&user_hash, sender, RANDOM_KEY),
            emule_qt_material()
        );
        let mut ours = [0u8; 32];
        datagram_key_ed2k(&user_hash, sender, RANDOM_KEY).apply(&mut ours);
        let mut theirs = [0u8; 32];
        Rc4::new(&Md5::digest(emule_qt_material())).apply(&mut theirs);
        assert_eq!(ours, theirs);
    }

    /// eMuleAI's key differs from emule-qt's at offset 32 alone, and rmule
    /// opens its datagram for exactly one value of that unwritten byte — the
    /// one that happens to equal the magic. Every other value misses the sync
    /// word, which is the drop core counts.
    #[test]
    fn an_emuleai_ipv6_datagram_opens_only_when_its_unwritten_byte_is_the_magic() {
        let user_hash = UserHash::from_bytes(HASH);
        let keys = ClientDecryptKeys {
            user_hash: Some(&user_hash),
            sender: DatagramSenderAddress::V6(ADDRESS),
            ..Default::default()
        };
        let payload = [0xC5, 0x90, 0x01];
        for stack in 0..=u8::MAX {
            let material = emuleai_material(stack);
            let differing: Vec<usize> = (0..35)
                .filter(|&at| material[at] != emule_qt_material()[at])
                .collect();
            let opened = decrypt_datagram_client(&sealed_under(&material, &payload), &keys);
            if stack == MAGICVALUE_UDP {
                assert!(differing.is_empty());
                assert_eq!(opened.expect("the layouts coincide").payload, payload);
            } else {
                assert_eq!(differing, [32], "stack byte {stack:#04x}");
                assert!(opened.is_none(), "stack byte {stack:#04x} opened");
            }
        }
    }
}
