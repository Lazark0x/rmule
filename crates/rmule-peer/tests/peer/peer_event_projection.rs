//! `PeerEvent::from_peer_packet` is the state-independent packet→event
//! projection (mirrors `Ed2kEvent::from_server_packet`). These tests pin
//! the field mapping (a wrong field — e.g. `end` vs `start` for the part
//! offset — is a real bug class) and the projection boundary: packets
//! whose event depends on session state must return `None`, leaving them
//! to `PeerSession::dispatch`.
use rmule_peer::{
    AcceptUploadReq, FileProbeStatus, FileReqAnsNoFil, HashSetAnswer, NoticeEvent, PeerEvent,
    PeerPacket, QueueRanking, RequesterEvent, SendingPart, SideEvent,
};
use rmule_primitives::{FileHash, PacketProtocol, PartHash};

#[test]
fn sending_part_projects_start_offset_and_verbatim_bytes() {
    let file_hash = FileHash::from_bytes([0x11; 16]);
    let packet = PeerPacket::SendingPart(SendingPart {
        file_hash,
        start: 0x4000,
        end: 0x8000,
        data: vec![0xAB, 0xCD, 0xEF],
    });
    match PeerEvent::from_peer_packet(&packet) {
        Some(PeerEvent::Requester(RequesterEvent::PartReceived {
            file_hash: fh,
            offset,
            bytes,
        })) => {
            assert_eq!(fh, file_hash);
            assert_eq!(offset, 0x4000, "offset must be `start`, never `end`");
            assert_eq!(bytes, vec![0xAB, 0xCD, 0xEF]);
        }
        other => panic!("expected PartReceived, got {other:?}"),
    }
}

#[test]
fn hash_set_answer_projects_hashes_losslessly() {
    let file_hash = FileHash::from_bytes([0x22; 16]);
    let hashes = vec![
        PartHash::from_bytes([0xDD; 16]),
        PartHash::from_bytes([0xEE; 16]),
    ];
    let packet = PeerPacket::HashSetAnswer(HashSetAnswer {
        file_hash,
        part_hashes: hashes.clone(),
    });
    match PeerEvent::from_peer_packet(&packet) {
        Some(PeerEvent::Requester(RequesterEvent::HashSetReceived {
            file_hash: fh,
            part_hashes,
        })) => {
            assert_eq!(fh, file_hash);
            assert_eq!(part_hashes, hashes);
        }
        other => panic!("expected HashSetReceived, got {other:?}"),
    }
}

#[test]
fn no_file_answer_projects_to_not_available_probe() {
    let file_hash = FileHash::from_bytes([0x33; 16]);
    let packet = PeerPacket::FileReqAnsNoFil(FileReqAnsNoFil { file_hash });
    match PeerEvent::from_peer_packet(&packet) {
        Some(PeerEvent::Requester(RequesterEvent::FileProbed {
            file_hash: fh,
            status,
        })) => {
            assert_eq!(fh, file_hash);
            assert_eq!(status, FileProbeStatus::NotAvailable);
        }
        other => panic!("expected FileProbed NotAvailable, got {other:?}"),
    }
}

#[test]
fn unknown_packet_projects_payload_length_not_bytes() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let packet = PeerPacket::Unknown {
        protocol: PacketProtocol::Emule,
        opcode: 0x99,
        payload: payload.clone(),
    };
    match PeerEvent::from_peer_packet(&packet) {
        Some(PeerEvent::Notice(NoticeEvent::UnknownPacket {
            protocol,
            opcode,
            payload_len,
        })) => {
            assert_eq!(protocol, PacketProtocol::Emule);
            assert_eq!(opcode, 0x99);
            assert_eq!(payload_len, payload.len());
        }
        other => panic!("expected UnknownPacket, got {other:?}"),
    }
}

#[test]
fn state_dependent_packets_are_not_projected() {
    // These carry events only `PeerSession::dispatch` can decide — they
    // read `active_slot` / `last_rank` — so the pure projection declines
    // them. A regression that accidentally projected one would corrupt the
    // slot state machine.
    assert!(PeerEvent::from_peer_packet(&PeerPacket::AcceptUploadReq(AcceptUploadReq)).is_none());
    assert!(
        PeerEvent::from_peer_packet(&PeerPacket::QueueRanking(QueueRanking { rank: 5 })).is_none()
    );
}

#[test]
fn kad_firewall_ack_projects_to_the_reachability_signal() {
    // 0xA8 is state-independent: its meaning is entirely its arrival on the
    // link, so the pure projection emits the event and core bridges it to the
    // Kad window guard (ADR-0058 requester).
    assert!(matches!(
        PeerEvent::from_peer_packet(&PeerPacket::KadFirewallAck),
        Some(PeerEvent::Side(SideEvent::KadFirewallCheckAck))
    ));
}
