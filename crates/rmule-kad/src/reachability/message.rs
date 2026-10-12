//! The firewall-check wire codecs (ADR-0058): the `0x50`/`0x53` TCP-check
//! requests and their `0x58`/`0x59` responses as one round-trippable
//! [`FirewallMessage`], plus the UDP-check pair — the `0x62` result a helper
//! reports and the `0xA7` peer-TCP request that recruits it. Opcode bytes and
//! size gates are aMule's; the `0x58` body is the capture-pinned low-octet-first
//! requester IP (see the module docs of [`super`]).

use std::net::Ipv4Addr;

use rmule_primitives::{UserHash, WireReader, WireTruncated};

use crate::KadEnvelope;

/// `KADEMLIA_FIREWALLED_REQ` (`0x50`): legacy (v≤6) TCP firewall check —
/// `<tcpport 2>`.
pub const KADEMLIA_FIREWALLED_REQ: u8 = 0x50;
/// `KADEMLIA_FIREWALLED2_REQ` (`0x53`): v7+ TCP firewall check —
/// `<tcpport 2><userhash 16><connectoptions 1>`. The user hash is written with
/// aMule's `WriteUInt128` (`KademliaUDPListener.cpp:181`): four little-endian
/// words, each four-byte group of the MD4 hash reversed. The helper reads it
/// back with `ReadUInt128` and keys its obfuscated dial-back on the result, so
/// a hash sent in raw MD4 order keys the dial-back on another hash and our
/// responder cannot authenticate it (bench-proven).
pub const KADEMLIA_FIREWALLED2_REQ: u8 = 0x53;
/// `KADEMLIA_FIREWALLED_RES` (`0x58`): firewall check response — `<ip 4>`, the
/// requester's observed external IP.
pub const KADEMLIA_FIREWALLED_RES: u8 = 0x58;
/// `KADEMLIA_FIREWALLED_ACK_RES` (`0x59`): legacy UDP connect-back ack — empty
/// body.
pub const KADEMLIA_FIREWALLED_ACK_RES: u8 = 0x59;

/// The `0x53` request's minimum length: `<tcpport 2><userhash 16><connectoptions
/// 1>` (aMule's `>= 19` gate); trailing bytes are tolerated.
const FIREWALLED2_REQ_MIN_LEN: usize = 2 + UserHash::BYTE_LEN + 1;

/// Whether `opcode` is a firewall-check **request** the responder answers —
/// the node's dispatch gate. Responses (`0x58`/`0x59`) are requester-consumed
/// and routed by [`is_firewall_check_res`] instead.
pub(crate) fn is_firewall_check_req(opcode: u8) -> bool {
    matches!(opcode, KADEMLIA_FIREWALLED_REQ | KADEMLIA_FIREWALLED2_REQ)
}

/// Whether `opcode` is a firewall-check **response** the requester consumes —
/// the `0x58` observed-IP reply and the `0x59` legacy UDP connect-back ack. The
/// node routes these to its [`FirewallSelfCheck`](super::FirewallSelfCheck) only while its own check is
/// enabled; unrouted otherwise (byte-for-byte aMule, which never processes a
/// firewall response it did not request).
pub(crate) fn is_firewall_check_res(opcode: u8) -> bool {
    matches!(
        opcode,
        KADEMLIA_FIREWALLED_RES | KADEMLIA_FIREWALLED_ACK_RES
    )
}

/// One typed Kad2 firewall self-check message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FirewallMessage {
    /// `0x50` — a legacy check advertising the requester's TCP port.
    FirewalledReq { tcp_port: u16 },
    /// `0x53` — a v7+ check advertising the TCP port, the requester's User
    /// Hash, and its connect-options (which crypt the dial-back should use).
    Firewalled2Req {
        tcp_port: u16,
        user_hash: UserHash,
        connect_options: u8,
    },
    /// `0x58` — the response carrying the requester's observed external IP.
    FirewalledRes { ip: Ipv4Addr },
    /// `0x59` — the legacy UDP connect-back ack (empty body).
    FirewalledAck,
}

/// Why a firewall-check envelope could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FirewallDecodeError {
    /// The opcode is not one of the four firewall-check rows.
    UnknownOpcode {
        /// The opcode byte no firewall-check message uses.
        opcode: u8,
    },
    /// The payload does not match the opcode's fixed layout (`0x50` is exactly
    /// two bytes; `0x53` is at least nineteen; `0x58` is exactly four; `0x59`
    /// is empty). Never panics.
    Malformed {
        /// The opcode whose payload did not decode.
        opcode: u8,
        /// Which layout expectation the payload broke.
        reason: &'static str,
    },
}

impl FirewallMessage {
    /// Decode a plain firewall-check envelope, enforcing aMule's size gates.
    pub(crate) fn decode(envelope: &KadEnvelope) -> Result<Self, FirewallDecodeError> {
        let opcode = envelope.opcode();
        let payload = envelope.payload();
        let malformed = |reason| FirewallDecodeError::Malformed { opcode, reason };
        match opcode {
            KADEMLIA_FIREWALLED_REQ => {
                // aMule's exact `== 2` gate: a legacy check is only its TCP port.
                let [lo, hi] = payload else {
                    return Err(malformed("0x50 is not exactly a two-byte TCP port"));
                };
                Ok(Self::FirewalledReq {
                    tcp_port: u16::from_le_bytes([*lo, *hi]),
                })
            }
            KADEMLIA_FIREWALLED2_REQ => {
                // aMule's `>= 19` gate: port + user hash + connect-options, with
                // trailing bytes tolerated.
                if payload.len() < FIREWALLED2_REQ_MIN_LEN {
                    return Err(malformed("0x53 is shorter than its 19-byte minimum"));
                }
                let short =
                    |_: WireTruncated| malformed("0x53 is shorter than its 19-byte minimum");
                let mut reader = WireReader::new(payload);
                let tcp_port = reader.read_u16_le("TCP port").map_err(short)?;
                let hash = reader.read_array("user hash").map_err(short)?;
                Ok(Self::Firewalled2Req {
                    tcp_port,
                    user_hash: UserHash::from_bytes(crate::lookup::kad_wire_id(hash)),
                    connect_options: reader.read_u8("connect options").map_err(short)?,
                })
            }
            KADEMLIA_FIREWALLED_RES => {
                let [a, b, c, d] = payload else {
                    return Err(malformed("0x58 is not exactly a four-byte IP"));
                };
                // Low-octet-first on the wire (aMule `WriteUInt32`): the observed
                // IP is written reversed, so read it back reversed (see `encode`).
                Ok(Self::FirewalledRes {
                    ip: Ipv4Addr::new(*d, *c, *b, *a),
                })
            }
            KADEMLIA_FIREWALLED_ACK_RES => {
                if !payload.is_empty() {
                    return Err(malformed("0x59 ack carries no body"));
                }
                Ok(Self::FirewalledAck)
            }
            _ => Err(FirewallDecodeError::UnknownOpcode { opcode }),
        }
    }

    /// Serialize into a plain (`0xE4`) firewall-check envelope.
    pub(crate) fn encode(&self) -> KadEnvelope {
        match self {
            Self::FirewalledReq { tcp_port } => {
                KadEnvelope::plain(KADEMLIA_FIREWALLED_REQ, tcp_port.to_le_bytes().to_vec())
            }
            Self::Firewalled2Req {
                tcp_port,
                user_hash,
                connect_options,
            } => {
                let mut payload = Vec::with_capacity(FIREWALLED2_REQ_MIN_LEN);
                payload.extend_from_slice(&tcp_port.to_le_bytes());
                payload.extend_from_slice(&crate::lookup::kad_wire_id(*user_hash.as_bytes()));
                payload.push(*connect_options);
                KadEnvelope::plain(KADEMLIA_FIREWALLED2_REQ, payload)
            }
            // The observed IP as aMule's `WriteUInt32` renders it: LOW-OCTET-FIRST
            // (reversed dotted octets), the same convention rmule's Kad contact
            // codec uses (`messages.rs` `read_ipv4_low_octet_first` /
            // `octets.reverse()`). Capture-pinned: aMule's genuine `0x58` for
            // 203.0.113.3 is `03 71 00 cb`
            // (fixtures/firewalled/captured/amule-233-firewall-selfcheck-requester).
            Self::FirewalledRes { ip } => {
                let mut octets = ip.octets();
                octets.reverse();
                KadEnvelope::plain(KADEMLIA_FIREWALLED_RES, octets.to_vec())
            }
            Self::FirewalledAck => KadEnvelope::plain(KADEMLIA_FIREWALLED_ACK_RES, Vec::new()),
        }
    }
}

/// `KADEMLIA2_FIREWALLUDP` (`0x62`): a helper's UDP firewall-check **result**,
/// the reply the UDP tester consumes. Layout `<errorcode 1><tested UDP port 2>`
/// (`src/include/protocol/kad2/Client2Client/UDP.h`).
pub const KADEMLIA2_FIREWALLUDP: u8 = 0x62;

/// `OP_FWCHECKUDPREQ` (`0xA7`): the peer-**TCP** request the UDP tester dials to
/// each helper (`OP_EMULEPROT`, `src/include/protocol/kad2/Client2Client/TCP.h`,
/// support required for Kad version ≥ 6). Layout
/// `<intern UDP port 2><extern UDP port 2><sender key 4>`. Not a Kad UDP
/// envelope — the node originates this payload and core packs it onto the
/// brokered peer dial (the seam the orchestrator wires live); the codec lives
/// here so the tester's request bytes are provable beside the `0x62` it answers.
pub const OP_FWCHECKUDPREQ: u8 = 0xA7;

/// The minimum `0x62` result length: `<errorcode 1><port 2>` (aMule's
/// `CHECK_PACKET_MIN_SIZE(3)` in `Process2FirewallUDP`); trailing bytes are
/// tolerated, matching aMule's `PeekUInt8`/`PeekUInt16` reads.
const FIREWALLUDP_MIN_LEN: usize = 1 + 2;

/// The exact `OP_FWCHECKUDPREQ` payload length: `<intern 2><extern 2><key 4>`.
const FWCHECKUDPREQ_LEN: usize = 2 + 2 + 4;

/// A decoded `0x62 KADEMLIA2_FIREWALLUDP` result: a helper reporting whether it
/// could reach the UDP port it was asked to test (aMule `Process2FirewallUDP`).
///
/// `error_code` is aMule's `errorAlreadyKnown` byte: `0` is a clean result, any
/// nonzero value flags a **biased** helper (it had transfer/chat state with us,
/// or our IP was already in its routing zone) whose result the tester must
/// discard. `tested_port` is the UDP port the helper reached us on — our intern
/// or extern Kad port, which the tester matches to decide the open-port
/// preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FirewallUdpResult {
    pub(crate) error_code: u8,
    pub(crate) tested_port: u16,
}

impl FirewallUdpResult {
    /// Whether the helper flagged a biased result (nonzero errorcode); the
    /// tester counts such a result as **cancelled**, not a failure — aMule
    /// `Process2FirewallUDP`'s `errorCode != 0` branch.
    pub(crate) fn is_biased(&self) -> bool {
        self.error_code != 0
    }

    /// Decode a plain `0x62` envelope, enforcing aMule's `>= 3` size gate.
    pub(crate) fn decode(envelope: &KadEnvelope) -> Result<Self, FirewallDecodeError> {
        let opcode = envelope.opcode();
        if opcode != KADEMLIA2_FIREWALLUDP {
            return Err(FirewallDecodeError::UnknownOpcode { opcode });
        }
        let payload = envelope.payload();
        if payload.len() < FIREWALLUDP_MIN_LEN {
            return Err(FirewallDecodeError::Malformed {
                opcode,
                reason: "0x62 is shorter than its three-byte minimum",
            });
        }
        let short = |_: WireTruncated| FirewallDecodeError::Malformed {
            opcode,
            reason: "0x62 is shorter than its three-byte minimum",
        };
        let mut reader = WireReader::new(payload);
        Ok(Self {
            error_code: reader.read_u8("error code").map_err(short)?,
            // The tested port as aMule's `WriteUInt16`/`PeekUInt16` render it:
            // little-endian (`ENDIAN_SWAP_16` is a no-op on the LE wire).
            tested_port: reader.read_u16_le("tested port").map_err(short)?,
        })
    }

    /// Serialize into a plain (`0xE4`) `0x62` envelope — the helper-side encode,
    /// exercised by the round-trip KAT and the responder half the orchestrator
    /// drives live.
    pub(crate) fn encode(&self) -> KadEnvelope {
        let mut payload = Vec::with_capacity(FIREWALLUDP_MIN_LEN);
        payload.push(self.error_code);
        payload.extend_from_slice(&self.tested_port.to_le_bytes());
        KadEnvelope::plain(KADEMLIA2_FIREWALLUDP, payload)
    }
}

/// The `OP_FWCHECKUDPREQ` (`0xA7`) request body the tester sends a helper over
/// peer-TCP (aMule `SendFirewallCheckUDPRequest`): the two UDP ports the helper
/// should try to reach us on and the sender key that ties its `0x62` reply back
/// to this request.
///
/// `intern_port` is our forwarded/listen Kad UDP port, `extern_port` our
/// NAT-observed port (the 0x60/0x61 residual discovers it; `0` or equal to
/// `intern_port` means "no distinct PAT port", and aMule then tests only the
/// intern port). `sender_key` is aMule's `GetUDPVerifyKey(helperIP)` — the
/// per-helper verify key (ADR-0046); the node supplies it, the live derivation
/// is the crypt seam's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FwCheckUdpRequest {
    pub(crate) intern_port: u16,
    pub(crate) extern_port: u16,
    pub(crate) sender_key: u32,
}

impl FwCheckUdpRequest {
    /// Serialize the peer-TCP request payload: `<intern 2><extern 2><key 4>`,
    /// every field little-endian (aMule `CMemFile::WriteUInt16`/`WriteUInt32`).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(FWCHECKUDPREQ_LEN);
        payload.extend_from_slice(&self.intern_port.to_le_bytes());
        payload.extend_from_slice(&self.extern_port.to_le_bytes());
        payload.extend_from_slice(&self.sender_key.to_le_bytes());
        payload
    }

    /// Decode the request payload (the helper/responder side, aMule
    /// `ProcessFirewallCheckUDPRequest`): exactly eight bytes. Trailing or short
    /// payloads are rejected — the responder round-trip KAT and the live helper
    /// leg both read exactly what [`encode`](Self::encode) wrote.
    pub(crate) fn decode(payload: &[u8]) -> Result<Self, FirewallDecodeError> {
        let malformed = || FirewallDecodeError::Malformed {
            opcode: OP_FWCHECKUDPREQ,
            reason: "OP_FWCHECKUDPREQ is not exactly eight bytes",
        };
        if payload.len() != FWCHECKUDPREQ_LEN {
            return Err(malformed());
        }
        let mut reader = WireReader::new(payload);
        Ok(Self {
            intern_port: reader.read_u16_le("intern port").map_err(|_| malformed())?,
            extern_port: reader.read_u16_le("extern port").map_err(|_| malformed())?,
            sender_key: reader.read_u32_le("sender key").map_err(|_| malformed())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sixteen distinct bytes, so the `WriteUInt128` word order shows.
    fn user_hash() -> UserHash {
        UserHash::from_bytes(std::array::from_fn(|i| i as u8))
    }

    #[test]
    fn the_legacy_request_round_trips_through_its_exact_two_bytes() {
        // KAT: a 0x50 is `[opcode][port LE]` and nothing else.
        let message = FirewallMessage::FirewalledReq { tcp_port: 4662 };
        let envelope = message.encode();
        assert_eq!(envelope.opcode(), KADEMLIA_FIREWALLED_REQ);
        assert_eq!(envelope.payload(), 4662u16.to_le_bytes());
        assert_eq!(FirewallMessage::decode(&envelope), Ok(message));

        // A trailing byte breaks the exact-2 gate.
        let overlong = KadEnvelope::plain(KADEMLIA_FIREWALLED_REQ, vec![0x36, 0x12, 0x00]);
        assert!(matches!(
            FirewallMessage::decode(&overlong),
            Err(FirewallDecodeError::Malformed { .. })
        ));
    }

    #[test]
    fn the_v7_request_carries_port_hash_options_and_tolerates_trailing() {
        // KAT: 0x53 layout is `<port 2><userhash 16><connectoptions 1>`.
        let message = FirewallMessage::Firewalled2Req {
            tcp_port: 5000,
            user_hash: user_hash(),
            connect_options: 0x03,
        };
        let envelope = message.encode();
        assert_eq!(envelope.opcode(), KADEMLIA_FIREWALLED2_REQ);
        assert_eq!(envelope.payload().len(), FIREWALLED2_REQ_MIN_LEN);
        assert_eq!(&envelope.payload()[0..2], 5000u16.to_le_bytes());
        assert_eq!(
            &envelope.payload()[2..18],
            &[3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12],
            "aMule's WriteUInt128: each four-byte group reversed"
        );
        assert_eq!(envelope.payload()[18], 0x03);
        assert_eq!(FirewallMessage::decode(&envelope), Ok(message));

        // Trailing bytes past the 19-byte minimum are tolerated (aMule `>= 19`).
        let mut trailing = envelope.payload().to_vec();
        trailing.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(
            FirewallMessage::decode(&KadEnvelope::plain(KADEMLIA_FIREWALLED2_REQ, trailing)),
            Ok(message)
        );

        // One byte short of 19 fails the gate.
        let short = KadEnvelope::plain(
            KADEMLIA_FIREWALLED2_REQ,
            vec![0u8; FIREWALLED2_REQ_MIN_LEN - 1],
        );
        assert!(matches!(
            FirewallMessage::decode(&short),
            Err(FirewallDecodeError::Malformed { .. })
        ));
    }

    #[test]
    fn the_response_and_ack_round_trip() {
        // KAT: 0x58 carries the IP low-octet-first (reversed dotted octets, aMule's WriteUInt32 —
        // capture-pinned); 0x59 is empty.
        let res = FirewallMessage::FirewalledRes {
            ip: Ipv4Addr::new(203, 0, 113, 7),
        };
        let res_envelope = res.encode();
        assert_eq!(res_envelope.opcode(), KADEMLIA_FIREWALLED_RES);
        assert_eq!(res_envelope.payload(), [7, 113, 0, 203]);
        assert_eq!(FirewallMessage::decode(&res_envelope), Ok(res));

        let ack = FirewallMessage::FirewalledAck;
        let ack_envelope = ack.encode();
        assert_eq!(ack_envelope.opcode(), KADEMLIA_FIREWALLED_ACK_RES);
        assert!(ack_envelope.payload().is_empty());
        assert_eq!(FirewallMessage::decode(&ack_envelope), Ok(ack));

        // A 0x59 with a body is not the empty ack.
        assert!(matches!(
            FirewallMessage::decode(&KadEnvelope::plain(KADEMLIA_FIREWALLED_ACK_RES, vec![0x00])),
            Err(FirewallDecodeError::Malformed { .. })
        ));
    }

    #[test]
    fn the_udp_result_round_trips_and_pins_the_0x62_wire_layout() {
        // KAT: a 0x62 is `[errorcode 1][tested port 2 LE]`. A clean result on our
        // Kad UDP port 4672 (0x1240) is body `00 40 12` — capture-faithful to
        // aMule's WriteUInt8(errorcode) + WriteUInt16(port), little-endian.
        let result = FirewallUdpResult {
            error_code: 0,
            tested_port: 4672,
        };
        let envelope = result.encode();
        assert_eq!(envelope.opcode(), KADEMLIA2_FIREWALLUDP);
        assert_eq!(envelope.payload(), [0x00, 0x40, 0x12]);
        assert_eq!(FirewallUdpResult::decode(&envelope), Ok(result));
        assert!(!result.is_biased());

        // A biased result (errorcode 1) round-trips and reads biased.
        let biased = FirewallUdpResult {
            error_code: 1,
            tested_port: 4672,
        };
        assert_eq!(biased.encode().payload(), [0x01, 0x40, 0x12]);
        assert!(biased.is_biased());
    }

    #[test]
    fn a_short_0x62_is_malformed_and_a_trailing_one_is_tolerated() {
        // Under three bytes fails aMule's CHECK_PACKET_MIN_SIZE(3).
        assert!(matches!(
            FirewallUdpResult::decode(&KadEnvelope::plain(KADEMLIA2_FIREWALLUDP, vec![0x00, 0x40])),
            Err(FirewallDecodeError::Malformed { .. })
        ));
        // Trailing bytes past the three-byte minimum are tolerated (aMule Peeks
        // the first three and ignores the rest).
        assert_eq!(
            FirewallUdpResult::decode(&KadEnvelope::plain(
                KADEMLIA2_FIREWALLUDP,
                vec![0x00, 0x40, 0x12, 0xFF]
            )),
            Ok(FirewallUdpResult {
                error_code: 0,
                tested_port: 4672,
            })
        );
        // A non-0x62 opcode is not a UDP result.
        assert!(matches!(
            FirewallUdpResult::decode(&KadEnvelope::plain(KADEMLIA_FIREWALLED_RES, vec![0, 0, 0])),
            Err(FirewallDecodeError::UnknownOpcode { opcode: 0x58 })
        ));
    }

    #[test]
    fn the_udp_request_round_trips_and_pins_its_eight_byte_layout() {
        // KAT: OP_FWCHECKUDPREQ is `<intern 2 LE><extern 2 LE><senderkey 4 LE>`.
        // intern 4672 (0x1240), extern 5000 (0x1388), key 0xDEADBEEF.
        let request = FwCheckUdpRequest {
            intern_port: 4672,
            extern_port: 5000,
            sender_key: 0xDEAD_BEEF,
        };
        let payload = request.encode();
        assert_eq!(
            payload,
            [0x40, 0x12, 0x88, 0x13, 0xEF, 0xBE, 0xAD, 0xDE],
            "little-endian ports then key, aMule CMemFile order"
        );
        assert_eq!(FwCheckUdpRequest::decode(&payload), Ok(request));

        // A wrong length (short or trailing) is malformed — the request is fixed.
        assert!(matches!(
            FwCheckUdpRequest::decode(&payload[..7]),
            Err(FirewallDecodeError::Malformed { .. })
        ));
        let mut overlong = payload.clone();
        overlong.push(0x00);
        assert!(matches!(
            FwCheckUdpRequest::decode(&overlong),
            Err(FirewallDecodeError::Malformed { .. })
        ));
    }

    #[test]
    fn requests_and_responses_route_to_their_own_halves() {
        // The responder answers only the two requests; the requester consumes
        // only the two responses. No opcode is in both sets.
        assert!(is_firewall_check_req(KADEMLIA_FIREWALLED_REQ));
        assert!(is_firewall_check_req(KADEMLIA_FIREWALLED2_REQ));
        assert!(!is_firewall_check_req(KADEMLIA_FIREWALLED_RES));
        assert!(!is_firewall_check_req(KADEMLIA_FIREWALLED_ACK_RES));

        assert!(is_firewall_check_res(KADEMLIA_FIREWALLED_RES));
        assert!(is_firewall_check_res(KADEMLIA_FIREWALLED_ACK_RES));
        assert!(!is_firewall_check_res(KADEMLIA_FIREWALLED_REQ));
        assert!(!is_firewall_check_res(KADEMLIA_FIREWALLED2_REQ));
    }

    /// The size-gated layouts, each cut at every byte: only the whole
    /// (or, for the `>=` gates, longer) payload decodes.
    #[test]
    fn firewall_payloads_cut_at_every_byte_are_rejected() {
        let req2 = FirewallMessage::Firewalled2Req {
            tcp_port: 4662,
            user_hash: user_hash(),
            connect_options: 0x83,
        }
        .encode();
        for cut in 0..req2.payload().len() {
            let short = KadEnvelope::plain(req2.opcode(), req2.payload()[..cut].to_vec());
            assert!(
                FirewallMessage::decode(&short).is_err(),
                "0x53 cut to {cut}"
            );
        }
        assert!(FirewallMessage::decode(&req2).is_ok());

        let udp = FirewallUdpResult {
            error_code: 0,
            tested_port: 4672,
        }
        .encode();
        for cut in 0..udp.payload().len() {
            let short = KadEnvelope::plain(udp.opcode(), udp.payload()[..cut].to_vec());
            assert!(
                FirewallUdpResult::decode(&short).is_err(),
                "0x62 cut to {cut}"
            );
        }
        assert!(FirewallUdpResult::decode(&udp).is_ok());

        let request = FwCheckUdpRequest {
            intern_port: 4672,
            extern_port: 4673,
            sender_key: 0x0102_0304,
        }
        .encode();
        for cut in 0..request.len() {
            assert!(
                FwCheckUdpRequest::decode(&request[..cut]).is_err(),
                "OP_FWCHECKUDPREQ cut to {cut}"
            );
        }
        assert!(FwCheckUdpRequest::decode(&request).is_ok());
    }
}
