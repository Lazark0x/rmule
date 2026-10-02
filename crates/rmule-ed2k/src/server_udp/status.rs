//! The server status chain (ADR-0052): the `OP_GLOBSERVSTATREQ` (0x96)
//! challenge ping, the `OP_GLOBSERVSTATRES` (0x97) progressive-body reply
//! whose length alone says how far a server's dialect reaches, and the
//! capability flags it advertises.
//!
//! The echoed challenge is the anti-spoof gate for every capability fact
//! injected from a datagram. The obfuscated crypt-ping variant is encoded in
//! ADR-0046's layer; only the padding rule its minters must not drift on
//! lives here.

use rmule_primitives::{Packet, PacketProtocol, ServerUdpFlags};

use crate::{Ed2kError, Opcode, Result};

/// `OP_GLOBSERVSTATREQ` (0x96): the plain status ping, client → server. Body is
/// one `u32 LE` challenge minted as `0x55AA0000 + rand16` (aMule
/// `ServerList.cpp` — `challenge = 0x55AA0000 + (uint16)rand()`); the server
/// echoes it as the first field of its `0x97` reply, which is rmule's
/// anti-spoof gate for injected capability state (ADR-0052). The obfuscated
/// crypt-ping variant is ADR-0046's, not encoded here — only the one rule its
/// minters must not drift on, [`crypt_ping_padding_len`], lives alongside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GlobServStatReq {
    challenge: u32,
}

impl GlobServStatReq {
    /// The fixed high half every status challenge carries.
    pub const CHALLENGE_BASE: u32 = 0x55AA_0000;

    /// Mint a challenge from caller-supplied entropy (the low 16 bits), so
    /// sweeps stay deterministic under test: `0x55AA0000 + rand16`.
    #[must_use]
    pub const fn mint(rand16: u16) -> Self {
        Self {
            challenge: Self::CHALLENGE_BASE + rand16 as u32,
        }
    }

    /// The minted challenge value, which the reply must echo.
    #[must_use]
    pub const fn challenge(self) -> u32 {
        self.challenge
    }

    /// The ping as a packet, ready for a UDP send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::GlobServStatReq.as_u8(),
            self.challenge.to_le_bytes().to_vec(),
        )
    }

    /// Decode an `OP_GLOBSERVSTATREQ` UDP datagram (the server's view of the
    /// ping, exercised by a deterministic fake server). The frame is
    /// `[protocol 0xE3][opcode 0x96]` then the fixed body `[challenge u32 LE]`.
    pub fn decode_udp(bytes: &[u8]) -> Result<Self> {
        let opcode = Opcode::GlobServStatReq.as_u8();
        let [protocol, op, body @ ..] = bytes else {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBSERVSTATREQ datagram missing header",
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
                reason: "wrong opcode for OP_GLOBSERVSTATREQ",
            });
        }
        let challenge: [u8; 4] = body.try_into().map_err(|_| Ed2kError::InvalidPayload {
            opcode,
            reason: "OP_GLOBSERVSTATREQ payload must be [challenge u32]",
        })?;
        Ok(Self {
            challenge: u32::from_le_bytes(challenge),
        })
    }
}

/// Padding length one obfuscated crypt-ping draws for `seed` — aMule's
/// `rand() % 16` narrowed to the sub-range every observed server accepts.
///
/// The crypt-ping (ADR-0046) is the raw `[challenge u32 LE][padding]`
/// datagram sent unencrypted to a server's obfuscation UDP port (TCP+12); the
/// padding carries no meaning — it only varies the datagram's size — so its
/// length is free to be clamped. Two counterparty acceptance windows constrain
/// it, and only their intersection is universally deliverable:
///
/// - the **eserver family** (Lugdunum, eNode) admits an obfuscated ping of
///   `4..=18` bytes;
/// - **ed2k-server** (`andrey23127/ed2k-server` @`eacf7f1`) reads that same
///   `4..=18` arm, but its pre-flight drops anything shorter than 10 bytes
///   before the arm is reached — an effective `10..=18` window.
///
/// `4 + 6..=4 + 14` = `10..=18` total sits inside both, so no server drops the
/// ping silently — which on the wire is indistinguishable from "the server
/// never answered", and cost a single-shot probe ~1 run in 16 before the clamp.
/// The wire form is unchanged: aMule mints paddings across this range too, so a
/// clamped ping is still an aMule-legal ping.
///
/// Both minters call this — the sweep engine's production nonce
/// (`rmule-core`'s `os_crypt_ping_nonce`) and the hand-run probe
/// (`rmule-tools ed2k server probe`) — so the window cannot drift between the
/// emitter a capture ratifies and the emitter that solicited it.
#[must_use]
pub const fn crypt_ping_padding_len(seed: u8) -> usize {
    const MIN: usize = 6;
    const MAX: usize = 14;
    // The modulo's slight bias across the nine lengths is immaterial: the
    // padding exists to vary the datagram's size, and the server ignores it.
    MIN + (seed as usize) % (MAX - MIN + 1)
}

/// Crypt-ping challenge for `raw` — aMule's non-zero rule plus the one value a
/// server's datagram dispatcher cannot read as a challenge.
///
/// The challenge leads the datagram in little-endian order, so its low byte is
/// the first byte on the wire — the same position a plain eD2k datagram carries
/// its `0xE3` protocol marker. A dispatcher branches there before any
/// obfuscation is considered (ed2k-server @`eacf7f1` `udp.rs:180`
/// `if data[0] == PROTO_EDONKEY`), so a challenge ending `0xE3` is parsed as a
/// malformed plain frame and answered by nothing — 1 ping in 256, and
/// indistinguishable on the wire from a server that does not implement the
/// crypt-ping at all. Flipping the low bit moves that byte out of collision
/// while keeping the challenge inside the space aMule mints (any non-zero
/// `u32`), so the ping stays aMule-legal.
#[must_use]
pub const fn crypt_ping_challenge(raw: u32) -> u32 {
    let candidate = if raw.to_le_bytes()[0] == PacketProtocol::Edonkey.as_byte() {
        raw ^ 1
    } else {
        raw
    };
    // aMule's `if (dwChallenge == 0) dwChallenge++` (ServerList.cpp @4e8f2b3c).
    if candidate == 0 { 1 } else { candidate }
}

/// `OP_GLOBSERVSTATRES` (0x97): the status-ping reply, server → client. The
/// body is **progressive** — older/newer servers stop at different lengths,
/// and every boundary is a valid reply (aMule `ServerUDPSocket.cpp` reads by
/// `size >=` thresholds):
///
/// | offset | field | present when |
/// |---|---|---|
/// | 0 | `challenge u32` | always (size ≥ 12) |
/// | 4 | `users u32` | always |
/// | 8 | `files u32` | always |
/// | 12 | `max_users u32` | size ≥ 16 |
/// | 16 | `soft_files u32` + `hard_files u32` | size ≥ 24 |
/// | 24 | `udp_flags u32` | size ≥ 28 |
/// | 28 | `low_id_users u32` | size ≥ 32 |
/// | 32 | `obf_udp_port u16` + `obf_tcp_port u16` + `server_udp_key u32` | size ≥ 40 |
///
/// Bytes beyond offset 40 are ignored, as aMule does. The challenge is the
/// anti-spoof echo — the consumer accepts the reply only when it matches the
/// outstanding ping to that server (ADR-0052).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobServStatRes {
    challenge: u32,
    users: u32,
    files: u32,
    max_users: Option<u32>,
    soft_files: Option<u32>,
    hard_files: Option<u32>,
    udp_flags: Option<ServerUdpFlags>,
    low_id_users: Option<u32>,
    obfuscation_udp_port: Option<u16>,
    obfuscation_tcp_port: Option<u16>,
    server_udp_key: Option<u32>,
}

impl GlobServStatRes {
    /// The echoed challenge — a reply whose challenge does not match the outstanding ping is not this server's answer.
    #[must_use]
    pub const fn challenge(&self) -> u32 {
        self.challenge
    }

    /// Users the server reports logged in.
    #[must_use]
    pub const fn users(&self) -> u32 {
        self.users
    }

    /// Files it reports those users offer.
    #[must_use]
    pub const fn files(&self) -> u32 {
        self.files
    }

    /// Its user ceiling, when the reply reached that length.
    #[must_use]
    pub const fn max_users(&self) -> Option<u32> {
        self.max_users
    }

    /// The file count past which it starts dropping the least-wanted entries.
    #[must_use]
    pub const fn soft_files(&self) -> Option<u32> {
        self.soft_files
    }

    /// The file count it will not index past at all.
    #[must_use]
    pub const fn hard_files(&self) -> Option<u32> {
        self.hard_files
    }

    /// Its advertised UDP capabilities, when the reply reached that length.
    #[must_use]
    pub const fn udp_flags(&self) -> Option<ServerUdpFlags> {
        self.udp_flags
    }

    /// How many of its users are Low ID — the share of its sources that need a callback.
    #[must_use]
    pub const fn low_id_users(&self) -> Option<u32> {
        self.low_id_users
    }

    /// Its obfuscated UDP port, when advertised.
    #[must_use]
    pub const fn obfuscation_udp_port(&self) -> Option<u16> {
        self.obfuscation_udp_port
    }

    /// Its obfuscated TCP port, when advertised.
    #[must_use]
    pub const fn obfuscation_tcp_port(&self) -> Option<u16> {
        self.obfuscation_tcp_port
    }

    /// The key our obfuscated datagrams to it must carry.
    #[must_use]
    pub const fn server_udp_key(&self) -> Option<u32> {
        self.server_udp_key
    }

    /// Decode an `OP_GLOBSERVSTATRES` UDP datagram: `[protocol 0xE3][opcode
    /// 0x97]` then the progressive body (see the type docs). A body shorter
    /// than 12 bytes is invalid; a length between boundaries yields the fields
    /// whose threshold it clears (aMule's `size >=` reads); trailing bytes
    /// beyond the deepest field are ignored.
    pub fn decode_udp(bytes: &[u8]) -> Result<Self> {
        let opcode = Opcode::GlobServStatRes.as_u8();
        let [protocol, op, body @ ..] = bytes else {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBSERVSTATRES datagram missing header",
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
                reason: "wrong opcode for OP_GLOBSERVSTATRES",
            });
        }
        // aMule's `size >=` thresholds measure the body: `OnPacketReceived`
        // hands `ProcessPacket` a `CMemFile(pBuffer + 2, nPayLoadLen - 2)`,
        // so its `size < 12` minimum is challenge + users + files.
        if body.len() < 12 {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_GLOBSERVSTATRES body shorter than challenge + users + files",
            });
        }
        let read_u32 = |offset: usize| {
            u32::from_le_bytes(
                body[offset..offset + 4]
                    .try_into()
                    .expect("validated 4-byte field"),
            )
        };
        let read_u16 = |offset: usize| {
            u16::from_le_bytes(
                body[offset..offset + 2]
                    .try_into()
                    .expect("validated 2-byte field"),
            )
        };
        let max_users = (body.len() >= 16).then(|| read_u32(12));
        let (soft_files, hard_files) = if body.len() >= 24 {
            (Some(read_u32(16)), Some(read_u32(20)))
        } else {
            (None, None)
        };
        let udp_flags = (body.len() >= 28).then(|| ServerUdpFlags::from_bits(read_u32(24)));
        let low_id_users = (body.len() >= 32).then(|| read_u32(28));
        let (obfuscation_udp_port, obfuscation_tcp_port, server_udp_key) = if body.len() >= 40 {
            (Some(read_u16(32)), Some(read_u16(34)), Some(read_u32(36)))
        } else {
            (None, None, None)
        };
        Ok(Self {
            challenge: read_u32(0),
            users: read_u32(4),
            files: read_u32(8),
            max_users,
            soft_files,
            hard_files,
            udp_flags,
            low_id_users,
            obfuscation_udp_port,
            obfuscation_tcp_port,
            server_udp_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full 38-byte `0x97` body (aMule size 40 counting the 2-byte UDP
    /// header): every progressive field populated with a distinct value, so
    /// boundary slices prove exactly which fields each length yields.
    fn full_stat_res_body() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x55AA_0102_u32.to_le_bytes()); // challenge
        body.extend_from_slice(&1000_u32.to_le_bytes()); // users
        body.extend_from_slice(&2000_u32.to_le_bytes()); // files
        body.extend_from_slice(&3000_u32.to_le_bytes()); // max_users
        body.extend_from_slice(&4000_u32.to_le_bytes()); // soft_files
        body.extend_from_slice(&5000_u32.to_le_bytes()); // hard_files
        body.extend_from_slice(&0x0000_0723_u32.to_le_bytes()); // udp_flags
        body.extend_from_slice(&42_u32.to_le_bytes()); // low_id_users
        body.extend_from_slice(&4672_u16.to_le_bytes()); // obf udp port
        body.extend_from_slice(&4665_u16.to_le_bytes()); // obf tcp port
        body.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes()); // server udp key
        body
    }

    /// A `0x97` datagram whose body is truncated to aMule's `size` (the body
    /// length — `OnPacketReceived` strips the 2-byte header before the
    /// threshold ladder).
    fn stat_res_datagram(body_len: usize) -> Vec<u8> {
        let mut datagram = vec![
            PacketProtocol::Edonkey.as_byte(),
            Opcode::GlobServStatRes.as_u8(),
        ];
        datagram.extend_from_slice(&full_stat_res_body()[..body_len]);
        datagram
    }

    #[test]
    fn glob_serv_stat_req_mints_and_encodes_the_challenge_datagram() {
        let ping = GlobServStatReq::mint(0x0102);
        assert_eq!(ping.challenge(), 0x55AA_0102);
        // [protocol 0xE3][opcode 0x96][challenge u32 LE] — no length prefix.
        assert_eq!(
            ping.encode_packet().encode_udp(),
            vec![0xE3, 0x96, 0x02, 0x01, 0xAA, 0x55]
        );
    }

    #[test]
    fn glob_serv_stat_req_round_trips_through_the_fake_server_view() {
        let ping = GlobServStatReq::mint(0xBEEF);
        let decoded =
            GlobServStatReq::decode_udp(&ping.encode_packet().encode_udp()).expect("decodes");
        assert_eq!(decoded, ping);
        assert!(
            GlobServStatReq::decode_udp(&[0xE3, 0x96, 0x01, 0x02]).is_err(),
            "a short challenge is rejected"
        );
    }

    /// Exhaustive over every seed a minter can draw: the crypt-ping datagram
    /// `[challenge 4][padding]` must never leave the window *both* server
    /// families accept — the eserver arm's `4..=18` intersected with
    /// ed2k-server's `>= 10` pre-flight, i.e. `10..=18`. An out-of-window ping is
    /// dropped without a reply, which is indistinguishable on the wire from a
    /// server that does not implement the leg at all — the failure this clamp
    /// exists to remove.
    #[test]
    fn every_crypt_ping_seed_mints_a_length_both_servers_accept() {
        let lengths: std::collections::BTreeSet<usize> = (0..=u8::MAX)
            // `+ 4` for the challenge the padding trails.
            .map(|seed| 4 + crypt_ping_padding_len(seed))
            .collect();
        assert_eq!(lengths.first().copied(), Some(10), "shortest datagram");
        assert_eq!(lengths.last().copied(), Some(18), "longest datagram");
    }

    #[test]
    fn no_crypt_ping_challenge_opens_with_the_plain_protocol_marker() {
        // Sweep every low byte (the first byte on the wire) against a fixed
        // high half, plus the all-zero word aMule's non-zero rule catches.
        for low in 0..=u8::MAX {
            let raw = u32::from_le_bytes([low, 0x4D, 0x1F, 0xA0]);
            let minted = crypt_ping_challenge(raw);
            assert_ne!(
                minted.to_le_bytes()[0],
                PacketProtocol::Edonkey.as_byte(),
                "challenge {raw:#010x} would be dispatched as a plain frame"
            );
            assert_ne!(minted, 0, "challenge {raw:#010x} must stay non-zero");
        }
        assert_eq!(crypt_ping_challenge(0), 1, "aMule's zero bump");
        // The 255 non-colliding low bytes pass through untouched — the rule
        // narrows the space by exactly one byte value, nothing else.
        let untouched = u32::from_le_bytes([0x2A, 0x4D, 0x1F, 0xA0]);
        assert_eq!(crypt_ping_challenge(untouched), untouched);
    }

    #[test]
    fn glob_serv_stat_res_decodes_each_progressive_boundary() {
        // (aMule size, max_users, soft/hard, flags, low_id, obf trio) — every
        // boundary from ServerUDPSocket.cpp's `size >=` ladder, plus 20 (a
        // between-boundaries length yields only the thresholds it clears) and
        // 44 (bytes past the deepest field are ignored).
        let cases: [(usize, bool, bool, bool, bool, bool); 8] = [
            (12, false, false, false, false, false),
            (16, true, false, false, false, false),
            (20, true, false, false, false, false),
            (24, true, true, false, false, false),
            (28, true, true, true, false, false),
            (32, true, true, true, true, false),
            (40, true, true, true, true, true),
            (44, true, true, true, true, true),
        ];
        for (amule_size, max, soft_hard, flags, low_id, obf) in cases {
            let mut datagram = stat_res_datagram(amule_size.min(40));
            if amule_size > 40 {
                datagram.extend_from_slice(&[0xFF; 4]);
            }
            let decoded = GlobServStatRes::decode_udp(&datagram).expect("boundary decodes");
            assert_eq!(decoded.challenge(), 0x55AA_0102, "size {amule_size}");
            assert_eq!(decoded.users(), 1000, "size {amule_size}");
            assert_eq!(decoded.files(), 2000, "size {amule_size}");
            assert_eq!(
                decoded.max_users(),
                max.then_some(3000),
                "size {amule_size}"
            );
            assert_eq!(
                decoded.soft_files(),
                soft_hard.then_some(4000),
                "size {amule_size}"
            );
            assert_eq!(
                decoded.hard_files(),
                soft_hard.then_some(5000),
                "size {amule_size}"
            );
            assert_eq!(
                decoded.udp_flags(),
                flags.then_some(ServerUdpFlags::from_bits(0x0000_0723)),
                "size {amule_size}"
            );
            assert_eq!(
                decoded.low_id_users(),
                low_id.then_some(42),
                "size {amule_size}"
            );
            assert_eq!(
                decoded.obfuscation_udp_port(),
                obf.then_some(4672),
                "size {amule_size}"
            );
            assert_eq!(
                decoded.obfuscation_tcp_port(),
                obf.then_some(4665),
                "size {amule_size}"
            );
            assert_eq!(
                decoded.server_udp_key(),
                obf.then_some(0xDEAD_BEEF),
                "size {amule_size}"
            );
        }
    }

    /// `SRV_UDPFLG_IPV6` is the same `0x4000` bit as the TCP word's, stated
    /// independently on the UDP surface (ADR-0087 §4.2). The only *measured*
    /// IPv6-capable word is the TCP one (`0x000045DD`, amule#1177 →
    /// ed2k-server#12); this UDP word is this file's `0x0723` golden with the
    /// bit added, so the assertion is that the bit reads and shadows nothing —
    /// not that a server sent these bytes.
    ///
    /// Evidence: **deterministic tier, awaiting a pinned IPv6 server.**
    #[test]
    fn the_ipv6_extension_bit_is_read_from_the_udp_flag_word() {
        let flags = ServerUdpFlags::from_bits(0x0000_4723);
        assert!(flags.supports_ipv6());
        assert!(flags.supports_ext_get_sources());
        assert!(flags.supports_udp_obfuscation());
        assert!(flags.supports_tcp_obfuscation());
        assert!(!ServerUdpFlags::from_bits(0x0000_0723).supports_ipv6());
    }

    #[test]
    fn glob_serv_stat_res_full_reply_reads_the_advertised_flags() {
        let decoded = GlobServStatRes::decode_udp(&stat_res_datagram(40)).expect("decodes");
        let flags = decoded.udp_flags().expect("size 40 carries flags");
        // 0x0723 = TCPOBFUSCATION | UDPOBFUSCATION | LARGEFILES |
        // EXT_GETSOURCES2 | EXT_GETFILES | EXT_GETSOURCES.
        assert!(flags.supports_ext_get_sources());
        assert!(flags.supports_ext_get_files());
        assert!(flags.supports_ext_get_sources2());
        assert!(flags.supports_large_files());
        assert!(flags.supports_udp_obfuscation());
        assert!(flags.supports_tcp_obfuscation());
        assert!(!flags.supports_new_tags());
        assert!(!flags.supports_unicode());
    }

    #[test]
    fn glob_serv_stat_res_rejects_a_body_below_the_minimum() {
        // aMule: `if (size < 12) throw` — 11 total bytes is one short.
        let datagram = stat_res_datagram(12);
        assert!(GlobServStatRes::decode_udp(&datagram[..datagram.len() - 1]).is_err());
        assert!(GlobServStatRes::decode_udp(&[0xE3, 0x97]).is_err());
        // Wrong opcode and wrong protocol are not a status reply.
        let mut wrong_opcode = stat_res_datagram(12);
        wrong_opcode[1] = Opcode::GlobFoundSources.as_u8();
        assert!(GlobServStatRes::decode_udp(&wrong_opcode).is_err());
        let mut wrong_protocol = stat_res_datagram(12);
        wrong_protocol[0] = 0xE5;
        assert!(GlobServStatRes::decode_udp(&wrong_protocol).is_err());
    }
}
