//! The peer opcode table: every byte matches the wire spec, the extended
//! opcodes qualify by protocol rather than by byte alone, and the byte ↔
//! opcode conversion round-trips.

use rmule_peer::PeerOpcode;
use rmule_primitives::PacketProtocol;

#[test]
fn bytes_match_the_wire_spec() {
    // Standard-protocol opcodes.
    assert_eq!(PeerOpcode::Hello.as_u8(), 0x01);
    assert_eq!(PeerOpcode::HelloAnswer.as_u8(), 0x4C);
    assert_eq!(PeerOpcode::RequestFileName.as_u8(), 0x58);
    assert_eq!(PeerOpcode::ReqFileNameAnswer.as_u8(), 0x59);
    assert_eq!(PeerOpcode::FileReqAnsNoFil.as_u8(), 0x48);
    assert_eq!(PeerOpcode::SetReqFileId.as_u8(), 0x4F);
    assert_eq!(PeerOpcode::FileStatus.as_u8(), 0x50);
    assert_eq!(PeerOpcode::HashSetRequest.as_u8(), 0x51);
    assert_eq!(PeerOpcode::HashSetAnswer.as_u8(), 0x52);
    assert_eq!(PeerOpcode::RequestSources.as_u8(), 0x81);
    assert_eq!(PeerOpcode::AnswerSources.as_u8(), 0x82);
    assert_eq!(PeerOpcode::RequestSources2.as_u8(), 0x83);
    assert_eq!(PeerOpcode::AnswerSources2.as_u8(), 0x84);
    assert_eq!(PeerOpcode::StartUploadReq.as_u8(), 0x54);
    assert_eq!(PeerOpcode::AcceptUploadReq.as_u8(), 0x55);
    assert_eq!(PeerOpcode::OutOfPartReqs.as_u8(), 0x57);
    assert_eq!(PeerOpcode::RequestParts.as_u8(), 0x47);
    assert_eq!(PeerOpcode::SendingPart.as_u8(), 0x46);
    // Extended-protocol opcodes.
    assert_eq!(PeerOpcode::QueueRanking.as_u8(), 0x60);
    assert_eq!(PeerOpcode::RequestPartsI64.as_u8(), 0xA3);
    assert_eq!(PeerOpcode::SendingPartI64.as_u8(), 0xA2);
}

#[test]
fn protocol_qualifies_extended_opcodes() {
    assert_eq!(PeerOpcode::QueueRanking.protocol(), PacketProtocol::Emule);
    assert_eq!(
        PeerOpcode::RequestPartsI64.protocol(),
        PacketProtocol::Emule
    );
    assert_eq!(PeerOpcode::SendingPartI64.protocol(), PacketProtocol::Emule);
    assert_eq!(PeerOpcode::AnswerSources.protocol(), PacketProtocol::Emule);
    assert_eq!(
        PeerOpcode::RequestSources2.protocol(),
        PacketProtocol::Emule
    );
    assert_eq!(PeerOpcode::AnswerSources2.protocol(), PacketProtocol::Emule);
    assert_eq!(PeerOpcode::Hello.protocol(), PacketProtocol::Edonkey);
    assert_eq!(PeerOpcode::RequestParts.protocol(), PacketProtocol::Edonkey);
}

#[test]
fn try_from_u8_round_trips() {
    assert_eq!(PeerOpcode::try_from_u8(0x4C), Some(PeerOpcode::HelloAnswer));
    assert_eq!(
        PeerOpcode::try_from_u8(0x60),
        Some(PeerOpcode::QueueRanking)
    );
    assert_eq!(PeerOpcode::try_from_u8(0x00), None);
}
