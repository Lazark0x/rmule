//! The Kad-UDP **buddy / callback** wire codecs (ADR-0061): `0x51`
//! `KADEMLIA_FINDBUDDY_REQ`, `0x5A` `KADEMLIA_FINDBUDDY_RES`, and `0x52`
//! `KADEMLIA_CALLBACK_REQ`. Sans-I/O, the sibling of the [`reachability`] firewall
//! codecs — the KadNode emits and consumes these three; the *decisions* they feed
//! (the open-node buddy slot, the callback route chooser) live core-side.
//!
//! Layouts pinned to aMule 2.3.3
//! `src/kademlia/net/KademliaUDPListener.cpp` (`ProcessFindBuddyRequest` L1425,
//! `ProcessFindBuddyResponse` L1461, `ProcessCallbackRequest` L1487):
//!
//! - `0x51` `<buddyID 16><requesterHash 16><requesterTcpPort 2>` — min 34; the
//!   firewalled recruiter's search converges and asks the found node to be its
//!   buddy. `buddyID` is the search target `~recruiterKadID` (`Search.cpp` L775
//!   `WriteUInt128(m_target)`), the value the responder echoes and the recruiter
//!   XOR-verifies its `0x5A` against.
//! - `0x5A` `<buddyID 16><responderHash 16><responderTcpPort 2>[connectOptions 1]`
//!   — min 34; the accepting open node's answer, echoing `buddyID` and carrying
//!   its own client hash + advertised TCP port. The trailing `connectOptions`
//!   byte is present only on the v7+ (crypt) form (aMule writes it only when the
//!   sender key is non-empty). The recruiter accepts the answer iff
//!   `~buddyID == ourKadID` (`ProcessFindBuddyResponse`: `check ^= CUInt128(true)`
//!   — `CUInt128(true)` is all-ones — `if GetKadID() == check`).
//! - `0x52` `<buddyID 16><fileHash 16><requesterTcpPort 2>` — min 34; a peer asks
//!   our firewalled buddy (addressed by `buddyID`) to dial it back for `fileHash`.
//!   The open node relays it as `OP_CALLBACK 0x99` over the buddy's TCP link.
//!
//! All multi-byte scalars little-endian (`CMemFile::WriteUInt16`).
//!
//! # The user-hash field is word-swapped, and that is not decoration
//!
//! aMule writes every 128-bit field here through `CFileDataIO::WriteUInt128`
//! (`src/SafeFile.cpp:292`), which emits the value as **four little-endian
//! 32-bit chunks** of a big-endian-loaded hash
//! (`CPrefs::CPrefs`: `m_clientHash.SetValueBE(thePrefs::GetUserHash().GetHash())`,
//! `src/kademlia/kademlia/Prefs.cpp:86`). The net wire form is therefore the
//! raw MD4 user hash **with each 32-bit word's bytes reversed** — the same
//! self-inverse [`kad_wire_id`] transform the source-lookup target and the
//! published source ID already go through.
//!
//! For `buddy_id` that swap is invisible: a Kad ID is only ever echoed and
//! self-compared, and every rmule [`KadId`] holds the wire order, so both ends
//! of every comparison are in the same order (`source_result`'s `TAG_BUDDYHASH`
//! is the one place a Kad ID is *printed* as an eD2k hash, and it swaps there).
//!
//! The **user hash** and the **file hash** are different — they are the two
//! fields in this cluster that cross namespaces. ADR-0061's open-node attach
//! matches the user hash against the one an **eD2k `OP_HELLO`** reports, and
//! the `0x52` relay's file hash is matched against our shared files and
//! download queue on the firewalled end (aMule `ReadUInt128` then
//! `fileid.ToByteArray()`, `ClientTCPSocket.cpp:1755-1758`; eMule
//! `ListenSocket.cpp:1378-1381`); a hash read in the wrong order can never
//! match one read in the right order. So the codec normalises both on the way
//! in and denormalises them on the way out, and callers upstream hold only the
//! raw MD4 form.
//!
//! **This changes no relayed byte.** aMule's own `0x52`→`0x99` relay is a
//! `ReadUInt128`/`WriteUInt128` round trip on both 128-bit fields
//! (`KademliaUDPListener.cpp:1783-1794` at the pinned `amule-kno` tree;
//! eMule `KademliaUDPListener.cpp:1776-1790`), so the relayed `OP_CALLBACK`
//! carries the `0x52`'s bytes unchanged and the un-swap happens at the
//! firewalled *reader*. rmule normalises at this codec and denormalises again
//! in `rmule_peer::Callback`'s `0x99` framing, which composes to the same
//! pass-through — with the file hash a true [`FileHash`] in between, so the
//! firewalled end's "do we know this file" gate can answer.
//!
//! Capture-proven, flow M run `1790077497`: the firewalled aMule's
//! `0x51` carried `34 d7 97 01 c5 74 0e 13 a0 a1 ff c7 28 6f ef b1`, and the
//! `OP_HELLO` it sent moments later up the buddy link it dialed carried
//! `01 97 d7 34 13 0e 74 c5 c7 ff a1 a0 b1 ef 6f 28` — the same hash, word by
//! word reversed. Reading it raw is why the buddy link was never held.
//!
//! [`reachability`]: crate::reachability
//! [`kad_wire_id`]: crate::lookup::kad_wire_id

use rmule_primitives::{FileHash, UserHash, WireReader, WireTruncated};

use crate::envelope::KadEnvelope;
use crate::id::KadId;
use crate::wire_fields::KadWireFields;

/// `KADEMLIA_FINDBUDDY_REQ` (`0x51`): a firewalled node asks the found node to be
/// its buddy — `<buddyID 16><requesterHash 16><requesterTcpPort 2>`.
pub const KADEMLIA_FINDBUDDY_REQ: u8 = 0x51;
/// `KADEMLIA_FINDBUDDY_RES` (`0x5A`): the open node's accept —
/// `<buddyID 16><responderHash 16><responderTcpPort 2>[connectOptions 1]`.
pub const KADEMLIA_FINDBUDDY_RES: u8 = 0x5A;
/// `KADEMLIA_CALLBACK_REQ` (`0x52`): a peer asks our buddy to dial it back —
/// `<buddyID 16><fileHash 16><requesterTcpPort 2>`.
pub const KADEMLIA_CALLBACK_REQ: u8 = 0x52;

/// aMule's `CHECK_PACKET_MIN_SIZE(34)` for all three opcodes: two 16-byte IDs
/// plus a two-byte TCP port. Trailing bytes are tolerated (aMule reads fixed
/// fields with `ReadUInt128`/`ReadUInt16`); `0x5A`'s extra byte is the only
/// meaningful trailer.
const BUDDY_MIN_LEN: usize = KadId::BYTE_LEN + UserHash::BYTE_LEN + 2;

/// Whether `opcode` is one of the three Kad-UDP buddy/callback rows the node
/// dispatches to this codec.
pub(crate) fn is_buddy_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        KADEMLIA_FINDBUDDY_REQ | KADEMLIA_FINDBUDDY_RES | KADEMLIA_CALLBACK_REQ
    )
}

/// Why a buddy/callback envelope could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuddyDecodeError {
    /// The opcode is not `0x51`/`0x5A`/`0x52`.
    UnknownOpcode {
        /// The opcode byte no buddy message uses.
        opcode: u8,
    },
    /// The payload is shorter than aMule's 34-byte minimum.
    Malformed {
        /// The opcode whose payload did not decode.
        opcode: u8,
        /// Which layout expectation the payload broke.
        reason: &'static str,
    },
}

/// One decoded Kad-UDP buddy/callback message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum BuddyMessage {
    /// `0x51`: a firewalled peer's recruitment ask.
    FindBuddyReq {
        /// The search target `~recruiterKadID`, echoed into the `0x5A` answer.
        buddy_id: KadId,
        /// The recruiter's own client/user hash.
        requester_hash: UserHash,
        /// The recruiter's advertised TCP port — the buddy link we would open.
        requester_tcp_port: u16,
    },
    /// `0x5A`: the open node's accept.
    FindBuddyRes {
        /// The echoed target; the recruiter accepts iff `~buddy_id == ourKadID`.
        buddy_id: KadId,
        /// The responder's client/user hash.
        responder_hash: UserHash,
        /// The responder's advertised TCP port (its buddy link).
        responder_tcp_port: u16,
        /// The v7+ connect-options byte, present only on the crypt form.
        connect_options: Option<u8>,
    },
    /// `0x52`: a peer wanting our firewalled buddy to dial it back.
    CallbackReq {
        /// The buddy the peer addressed — verified against our slot before relay.
        buddy_id: KadId,
        /// The file the callback is for.
        file_hash: FileHash,
        /// The requesting peer's TCP port (relayed to the buddy).
        requester_tcp_port: u16,
    },
}

impl BuddyMessage {
    /// Decode a plain buddy/callback envelope, enforcing aMule's 34-byte gate.
    pub(crate) fn decode(envelope: &KadEnvelope) -> Result<Self, BuddyDecodeError> {
        let opcode = envelope.opcode();
        let payload = envelope.payload();
        if !is_buddy_opcode(opcode) {
            return Err(BuddyDecodeError::UnknownOpcode { opcode });
        }
        if payload.len() < BUDDY_MIN_LEN {
            return Err(BuddyDecodeError::Malformed {
                opcode,
                reason: "buddy/callback payload is shorter than its 34-byte minimum",
            });
        }
        // Field cuts shared by all three layouts: <id 16><id/hash 16><port 2>.
        let malformed = |truncated: WireTruncated| BuddyDecodeError::Malformed {
            opcode,
            reason: truncated.field,
        };
        let mut reader = WireReader::new(payload);
        let first = reader.read_kad_id("buddy ID").map_err(malformed)?;
        let second = reader.read_array("requester hash").map_err(malformed)?;
        let tcp_port = reader.read_u16_le("TCP port").map_err(malformed)?;
        match opcode {
            KADEMLIA_FINDBUDDY_REQ => Ok(Self::FindBuddyReq {
                buddy_id: first,
                requester_hash: read_user_hash(second),
                requester_tcp_port: tcp_port,
            }),
            KADEMLIA_FINDBUDDY_RES => Ok(Self::FindBuddyRes {
                buddy_id: first,
                responder_hash: read_user_hash(second),
                responder_tcp_port: tcp_port,
                // aMule's `if (lenPacket > 34)` connect-options read.
                connect_options: reader.read_u8("connect options").ok(),
            }),
            KADEMLIA_CALLBACK_REQ => Ok(Self::CallbackReq {
                buddy_id: first,
                file_hash: read_file_hash(second),
                requester_tcp_port: tcp_port,
            }),
            _ => unreachable!("is_buddy_opcode admits only the three rows"),
        }
    }

    /// Serialize into a plain (`0xE4`) buddy/callback envelope.
    pub(crate) fn encode(&self) -> KadEnvelope {
        match self {
            Self::FindBuddyReq {
                buddy_id,
                requester_hash,
                requester_tcp_port,
            } => KadEnvelope::plain(
                KADEMLIA_FINDBUDDY_REQ,
                buddy_body(
                    buddy_id,
                    &user_hash_wire(*requester_hash),
                    *requester_tcp_port,
                    None,
                ),
            ),
            Self::FindBuddyRes {
                buddy_id,
                responder_hash,
                responder_tcp_port,
                connect_options,
            } => KadEnvelope::plain(
                KADEMLIA_FINDBUDDY_RES,
                buddy_body(
                    buddy_id,
                    &user_hash_wire(*responder_hash),
                    *responder_tcp_port,
                    *connect_options,
                ),
            ),
            Self::CallbackReq {
                buddy_id,
                file_hash,
                requester_tcp_port,
            } => KadEnvelope::plain(
                KADEMLIA_CALLBACK_REQ,
                buddy_body(
                    buddy_id,
                    &file_hash_wire(*file_hash),
                    *requester_tcp_port,
                    None,
                ),
            ),
        }
    }
}

/// Whether a `0x5A`'s echoed `buddy_id` confirms it answers *our* recruitment
/// (aMule `ProcessFindBuddyResponse`: `check ^= CUInt128(true); GetKadID() == check`).
/// The bitwise-NOT of the echoed target must equal our own Kad ID — a
/// byte-order-independent check, so it needs no wire-order care.
pub(crate) fn confirms_recruitment(buddy_id: KadId, own_id: KadId) -> bool {
    buddy_id
        .as_bytes()
        .iter()
        .zip(own_id.as_bytes().iter())
        .all(|(echoed, ours)| *echoed == !*ours)
}

/// The Kad ID a recruiter searches toward (aMule's FindBuddy target): the bitwise
/// inverse of its own Kad ID, so the found node sits at the far end of the
/// keyspace and the `0x5A` echo XOR-verifies back.
pub(crate) fn recruitment_target(own_id: KadId) -> KadId {
    let mut inverted = *own_id.as_bytes();
    for byte in &mut inverted {
        *byte = !*byte;
    }
    KadId::from_bytes(inverted)
}

/// Build the shared `<id 16><id/hash 16><port 2>[extra 1]` body.
fn buddy_body(id: &KadId, second: &[u8; 16], tcp_port: u16, extra: Option<u8>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(BUDDY_MIN_LEN + usize::from(extra.is_some()));
    payload.extend_from_slice(id.as_bytes());
    payload.extend_from_slice(second);
    payload.extend_from_slice(&tcp_port.to_le_bytes());
    if let Some(extra) = extra {
        payload.push(extra);
    }
    payload
}

/// The user-hash field, read out of aMule's `WriteUInt128` word order into the
/// raw MD4 form the eD2k hello reports (see the module doc).
fn read_user_hash(wire: [u8; 16]) -> UserHash {
    UserHash::from_bytes(crate::lookup::kad_wire_id(wire))
}

/// The inverse of [`read_user_hash`] — the swap is its own inverse, so this is
/// the same transform under the name that says which direction it serves.
fn user_hash_wire(hash: UserHash) -> [u8; 16] {
    crate::lookup::kad_wire_id(*hash.as_bytes())
}

/// The `0x52` file-hash field, read out of aMule's `WriteUInt128` word order
/// into the raw MD4 form every other rmule surface holds a [`FileHash`] in
/// (see the module doc).
fn read_file_hash(wire: [u8; 16]) -> FileHash {
    FileHash::from_bytes(crate::lookup::kad_wire_id(wire))
}

/// The inverse of [`read_file_hash`], under the name that says which direction
/// it serves.
fn file_hash_wire(hash: FileHash) -> [u8; 16] {
    crate::lookup::kad_wire_id(*hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kad_id(byte: u8) -> KadId {
        KadId::from_bytes([byte; KadId::BYTE_LEN])
    }

    /// The user hash the firewalled aMule of flow M run `1790077497` put in its
    /// `0x51`, and the one its `OP_HELLO` reported up the buddy link it then
    /// dialed. Two readings of one identity, and ADR-0061's open-node attach
    /// only holds the link when they meet.
    const CAPTURED_0X51_HASH_FIELD: [u8; 16] = [
        0x34, 0xd7, 0x97, 0x01, 0xc5, 0x74, 0x0e, 0x13, 0xa0, 0xa1, 0xff, 0xc7, 0x28, 0x6f, 0xef,
        0xb1,
    ];
    const CAPTURED_HELLO_USER_HASH: [u8; 16] = [
        0x01, 0x97, 0xd7, 0x34, 0x13, 0x0e, 0x74, 0xc5, 0xc7, 0xff, 0xa1, 0xa0, 0xb1, 0xef, 0x6f,
        0x28,
    ];

    #[test]
    fn findbuddy_req_round_trips_its_pinned_34_byte_layout() {
        // buddyID = 0x11..., an asymmetric requester hash (a palindromic one
        // would pass whatever byte order the field used), port 4662 (0x1236 LE).
        let message = BuddyMessage::FindBuddyReq {
            buddy_id: kad_id(0x11),
            requester_hash: UserHash::from_bytes(CAPTURED_HELLO_USER_HASH),
            requester_tcp_port: 4662,
        };
        let envelope = message.encode();
        assert_eq!(envelope.opcode(), KADEMLIA_FINDBUDDY_REQ);
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&CAPTURED_0X51_HASH_FIELD);
        expected.extend_from_slice(&[0x36, 0x12]);
        assert_eq!(envelope.payload(), expected.as_slice());
        assert_eq!(BuddyMessage::decode(&envelope), Ok(message));
    }

    /// The measured defect: the recruiter's user hash reaches the
    /// open-node attach in the raw MD4 form an `OP_HELLO` reports, never in
    /// aMule's `WriteUInt128` word order. Pinned to the run `1790077497`
    /// capture — the `0x51` field and the hello hash beside it.
    #[test]
    fn the_recruiters_user_hash_decodes_into_the_form_the_hello_reports() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0xCC; 16]);
        payload.extend_from_slice(&CAPTURED_0X51_HASH_FIELD);
        payload.extend_from_slice(&[0x36, 0x12]);
        let envelope = KadEnvelope::plain(KADEMLIA_FINDBUDDY_REQ, payload);

        let Ok(BuddyMessage::FindBuddyReq { requester_hash, .. }) = BuddyMessage::decode(&envelope)
        else {
            panic!("the captured 0x51 decodes as a recruitment ask");
        };
        assert_eq!(
            requester_hash,
            UserHash::from_bytes(CAPTURED_HELLO_USER_HASH),
            "the 0x51's hash field is the hello's user hash, word-swapped"
        );

        // The same field on the way out: what we answer a recruiter with is
        // what aMule reads back as our client hash.
        let res = BuddyMessage::FindBuddyRes {
            buddy_id: kad_id(0xCC),
            responder_hash: UserHash::from_bytes(CAPTURED_HELLO_USER_HASH),
            responder_tcp_port: 4662,
            connect_options: None,
        };
        assert_eq!(
            &res.encode().payload()[KadId::BYTE_LEN..KadId::BYTE_LEN + UserHash::BYTE_LEN],
            CAPTURED_0X51_HASH_FIELD,
        );
    }

    #[test]
    fn findbuddy_res_carries_connect_options_only_on_the_crypt_form() {
        // Legacy form (no connect-options): exactly 34 bytes, `None` on decode.
        let legacy = BuddyMessage::FindBuddyRes {
            buddy_id: kad_id(0xAA),
            responder_hash: UserHash::from_bytes([0xBB; 16]),
            responder_tcp_port: 4672,
            connect_options: None,
        };
        let legacy_env = legacy.encode();
        assert_eq!(legacy_env.payload().len(), BUDDY_MIN_LEN);
        assert_eq!(BuddyMessage::decode(&legacy_env), Ok(legacy));

        // v7+ form: the trailing connect-options byte round-trips as `Some`.
        let crypt = BuddyMessage::FindBuddyRes {
            buddy_id: kad_id(0xAA),
            responder_hash: UserHash::from_bytes([0xBB; 16]),
            responder_tcp_port: 4672,
            connect_options: Some(0x03),
        };
        let crypt_env = crypt.encode();
        assert_eq!(crypt_env.payload().len(), BUDDY_MIN_LEN + 1);
        assert_eq!(crypt_env.payload()[BUDDY_MIN_LEN], 0x03);
        assert_eq!(BuddyMessage::decode(&crypt_env), Ok(crypt));
    }

    /// aMule's own `0x52`, off the buddy's tap (run `1790185890`):
    /// a stock requester's `BaseClient.cpp:2133-2141` emit toward the
    /// buddy a type-3 row named. Provenance in the fixture's `meta.toml`.
    const CAPTURED_CALLBACK_REQ: &[u8] = include_bytes!(
        "../tests/fixtures/buddy/captured/amule-233-callback-req-20260923/callback_req_0x52.bin"
    );

    /// The file the requester downloaded, as its ed2k link names it.
    const CAPTURED_FILE_MD4: &str = "009D91607B0D86D64FAFF631E02ED864";

    /// Pinned from aMule's bytes: both 128-bit fields ride
    /// `WriteUInt128`. `buddyID` is `CUInt128(GetBuddyID())` — the row's
    /// `TAG_BUDDYHASH` (`CCDDEEFF…`, loaded `SetValueBE`) — so on the wire it is
    /// the buddy's own Kad ID in the wire order every rmule [`KadId`] holds, and
    /// it decodes raw. `fileID` is `CUInt128(GetFileHash())`, word-swapped, so
    /// the codec hands callers the eD2k hash and writes the Kad order back.
    /// aMule's other `0x52` writer: the `FINDSOURCE` search's, sent to the
    /// contact that answered a walk toward an ID-only row's buddy (run `1790190646`,
    /// `Search.cpp:1092-1100`). Provenance in the
    /// fixture's `meta.toml`.
    const CAPTURED_FINDSOURCE_CALLBACK_REQ: &[u8] = include_bytes!(
        "../tests/fixtures/buddy/captured/amule-233-callback-req-findsource-20260923/callback_req_0x52.bin"
    );

    /// Both captures' row and link: the rmule buddy's ID in wire order, the
    /// synthetic file, the requester's listener.
    fn captured_callback_message() -> BuddyMessage {
        BuddyMessage::CallbackReq {
            buddy_id: KadId::from_bytes([
                0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00,
            ]),
            file_hash: FileHash::from_hex(CAPTURED_FILE_MD4).unwrap(),
            requester_tcp_port: 4662,
        }
    }

    fn decode_captured_callback(datagram: &[u8]) -> Result<BuddyMessage, BuddyDecodeError> {
        let (&[proto, opcode], payload) = datagram.split_at(2) else {
            unreachable!("a 36-byte datagram");
        };
        assert_eq!((proto, opcode), (0xE4, KADEMLIA_CALLBACK_REQ));
        BuddyMessage::decode(&KadEnvelope::plain(KADEMLIA_CALLBACK_REQ, payload.to_vec()))
    }

    #[test]
    fn amules_captured_callback_decodes_to_the_rows_buddy_and_the_links_file() {
        let message = captured_callback_message();
        assert_eq!(decode_captured_callback(CAPTURED_CALLBACK_REQ), Ok(message));
        assert_eq!(
            message.encode().payload(),
            &CAPTURED_CALLBACK_REQ[2..],
            "rmule writes aMule's 0x52 byte for byte"
        );
    }

    /// The `FINDSOURCE` writer spells every field as the endpoint branch does,
    /// so the one decoder reads both.
    #[test]
    fn amules_findsource_callback_decodes_as_its_endpoint_branch_callback() {
        assert_eq!(
            decode_captured_callback(CAPTURED_FINDSOURCE_CALLBACK_REQ),
            Ok(captured_callback_message())
        );
        assert_eq!(CAPTURED_FINDSOURCE_CALLBACK_REQ, CAPTURED_CALLBACK_REQ);
    }

    #[test]
    fn the_findbuddy_response_verifies_by_xor_inversion_against_our_kad_id() {
        // aMule accepts the answer iff the echoed target is the bitwise inverse of
        // our own Kad ID — the recruiter searched for `~ownID`, so a compliant
        // responder echoes exactly that.
        let own = kad_id(0x55);
        assert_eq!(recruitment_target(own), kad_id(0xAA), "~0x55 == 0xAA");
        assert!(
            confirms_recruitment(recruitment_target(own), own),
            "the echoed inverse target confirms our recruitment"
        );
        // A responder echoing any other value fails the XOR guard (a stale or
        // misrouted 0x5A the tracked-packet window already narrowed).
        assert!(!confirms_recruitment(kad_id(0x55), own));
        assert!(!confirms_recruitment(kad_id(0x12), own));
    }

    #[test]
    fn a_short_or_unknown_buddy_envelope_is_rejected_never_panics() {
        // 33 bytes — one short of the 34-byte minimum.
        let short = KadEnvelope::plain(KADEMLIA_FINDBUDDY_REQ, vec![0u8; 33]);
        assert_eq!(
            BuddyMessage::decode(&short),
            Err(BuddyDecodeError::Malformed {
                opcode: KADEMLIA_FINDBUDDY_REQ,
                reason: "buddy/callback payload is shorter than its 34-byte minimum",
            })
        );
        // A non-buddy opcode is not this codec's row.
        assert_eq!(
            BuddyMessage::decode(&KadEnvelope::plain(0x40, vec![0u8; 34])),
            Err(BuddyDecodeError::UnknownOpcode { opcode: 0x40 })
        );
        assert!(is_buddy_opcode(KADEMLIA_FINDBUDDY_REQ));
        assert!(is_buddy_opcode(KADEMLIA_FINDBUDDY_RES));
        assert!(is_buddy_opcode(KADEMLIA_CALLBACK_REQ));
        assert!(!is_buddy_opcode(0x40));
    }

    /// Every layout cut at every byte below its 34-byte minimum is rejected;
    /// the bytes past the minimum are the optional connect-options byte only.
    #[test]
    fn a_buddy_envelope_cut_at_every_byte_below_its_minimum_is_rejected() {
        let id = kad_id(0x11);
        let messages = [
            BuddyMessage::FindBuddyReq {
                buddy_id: id,
                requester_hash: UserHash::from_bytes([0x22; 16]),
                requester_tcp_port: 4662,
            },
            BuddyMessage::FindBuddyRes {
                buddy_id: id,
                responder_hash: UserHash::from_bytes([0x33; 16]),
                responder_tcp_port: 4662,
                connect_options: Some(0x03),
            },
            captured_callback_message(),
        ];
        for message in messages {
            let whole = message.encode();
            assert_eq!(BuddyMessage::decode(&whole), Ok(message));
            for cut in 0..BUDDY_MIN_LEN {
                let cut_envelope =
                    KadEnvelope::plain(whole.opcode(), whole.payload()[..cut].to_vec());
                assert!(
                    BuddyMessage::decode(&cut_envelope).is_err(),
                    "opcode 0x{:02X} cut to {cut} bytes decoded",
                    whole.opcode()
                );
            }
        }
    }
}
