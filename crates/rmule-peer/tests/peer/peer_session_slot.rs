//! The upload slot a requester chases: the probe and hash-set gates
//! `RequestParts` auto-issues, the single-active-slot rule, queue rank
//! progress, and the cancel/release paths that hand the slot back.

use rmule_peer::{PartRanges, PeerCommand, PeerError, PeerEvent, SlotReleaseReason};
use rmule_primitives::session::drain;
use rmule_primitives::{ED2K_PART_SIZE, Packet, PartHash};
use rmule_testkit::peer_session::*;

#[test]
fn request_parts_auto_issues_probe_and_hashset_before_startuploadreq() {
    let h = file_hash(0xC1);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    let immediate = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&immediate).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x58, 0x4F, 0x51],
        "REQUESTFILENAME, SETREQFILEID, HASHSETREQUEST pipelined immediately"
    );

    // Peer answers probe + status + hashset; only THEN does session send STARTUPLOADREQ.
    session.handle_bytes(&reqfilename_answer(h, "c.bin"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    let after_probe = drain(|| session.poll_output());
    assert!(
        writes(&after_probe).is_empty(),
        "no STARTUPLOADREQ until HASHSETANSWER arrives"
    );

    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0xDD; 16])]));
    let after_hashset = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&after_hashset).iter().map(Packet::opcode).collect();
    assert_eq!(opcodes, vec![0x54], "STARTUPLOADREQ now fires");
    assert!(events(&after_hashset).iter().any(|e| matches!(
        e,
        PeerEvent::HashSetReceived { file_hash, .. } if *file_hash == h
    )));
}

#[test]
fn request_parts_for_sub_part_file_skips_hashset_gate_before_startuploadreq() {
    let h = file_hash(0xC2);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: ED2K_PART_SIZE - 1,
        ranges,
    });
    let immediate = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&immediate).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x58],
        "sub-part files use the whole-file hash as authority and need neither \
         HASHSETREQUEST nor SETREQFILEID (aMule SendFileRequest bundles \
         OP_SETREQFILEID only for a multi-part file)"
    );

    session.handle_bytes(&reqfilename_answer(h, "c.bin"));
    session.handle_bytes(&file_status(h, 0, &[]));
    let after_probe = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&after_probe).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x54],
        "STARTUPLOADREQ must fire once the probe completes"
    );
    assert!(events(&after_probe).iter().any(|e| matches!(
        e,
        PeerEvent::FileProbed { file_hash, .. } if *file_hash == h
    )));
}

#[test]
fn second_request_parts_while_slot_active_is_rejected_with_slotbusy() {
    let d = file_hash(0xD1);
    let e = file_hash(0xE1);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: d,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    let _ = drain(|| session.poll_output());

    // Active slot context for D; E is denied.
    session.handle_command(PeerCommand::RequestParts {
        file_hash: e,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::CommandRejected {
            reason: PeerError::SlotBusy
        }
    )));
}

#[test]
fn queueranking_dedups_identical_ranks_and_emits_progress_on_improvement() {
    let h = file_hash(0xF1);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    let _ = drain(|| session.poll_output());

    // Walk through the probe + hashset so STARTUPLOADREQ goes out and
    // active_slot is set.
    session.handle_bytes(&reqfilename_answer(h, "f.bin"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&queueranking(10));
    session.handle_bytes(&queueranking(10));
    session.handle_bytes(&queueranking(10));
    let after_repeats = drain(|| session.poll_output());
    let ranked_count = events(&after_repeats)
        .iter()
        .filter(|e| matches!(e, PeerEvent::QueueRanked { rank: 10, .. }))
        .count();
    assert_eq!(ranked_count, 1, "identical ranks deduped");

    session.handle_bytes(&queueranking(7));
    let progress = drain(|| session.poll_output());
    assert!(events(&progress).iter().any(|e| matches!(
        e,
        PeerEvent::QueueProgress {
            previous_rank: 10,
            new_rank: 7,
            ..
        }
    )));

    session.handle_bytes(&queueranking(7));
    let nooop = drain(|| session.poll_output());
    assert!(events(&nooop).is_empty(), "same rank twice is silent");
}

#[test]
fn outofpartreqs_emits_queue_rejected_and_clears_active_slot() {
    let f = file_hash(0x71);
    let g = file_hash(0x72);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: f,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(f, "f"));
    session.handle_bytes(&file_status(f, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(f, &[PartHash::from_bytes([0; 16])]));
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&outofpartreqs());
    let out = drain(|| session.poll_output());
    let evs = events(&out);
    assert!(evs.iter().any(|e| matches!(
        e,
        PeerEvent::QueueRejected { file_hash } if *file_hash == f
    )));
    assert!(evs.iter().any(|e| matches!(
        e,
        PeerEvent::SlotReleased { file_hash, reason: SlotReleaseReason::QueueRejected } if *file_hash == f
    )));

    // Slot context is clear: a new RequestParts for G proceeds.
    session.handle_command(PeerCommand::RequestParts {
        file_hash: g,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    let out_g = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&out_g).iter().map(Packet::opcode).collect();
    assert_eq!(opcodes, vec![0x58, 0x4F, 0x51]);
    assert!(!events(&out_g).iter().any(|e| matches!(
        e,
        PeerEvent::CommandRejected {
            reason: PeerError::SlotBusy
        }
    )));
}

#[test]
fn slot_grant_then_part_download_completes() {
    let h = file_hash(0x88);
    let mut session = identified_session();
    let part_len: u32 = 32;
    let ranges = PartRanges::new([(0, part_len as u64), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "x"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&acceptuploadreq());
    let after_accept = drain(|| session.poll_output());
    assert!(events(&after_accept).iter().any(|e| matches!(
        e,
        PeerEvent::SlotGranted { file_hash } if *file_hash == h
    )));
    // Session must send OP_REQUESTPARTS once accepted.
    let req_opcodes: Vec<u8> = writes(&after_accept).iter().map(Packet::opcode).collect();
    assert!(
        req_opcodes.contains(&0x47),
        "OP_REQUESTPARTS sent after accept, got {req_opcodes:?}"
    );

    // Feed the part data in two halves.
    let half: Vec<u8> = (0..part_len as u8 / 2).collect();
    session.handle_bytes(&sendingpart(h, 0, &half));
    let half_out = drain(|| session.poll_output());
    assert!(events(&half_out).iter().any(|e| matches!(
        e,
        PeerEvent::PartReceived { file_hash, offset: 0, bytes } if *file_hash == h && bytes == &half
    )));
    // Not complete yet.
    assert!(!events(&half_out).iter().any(|e| matches!(
        e,
        PeerEvent::SlotReleased {
            reason: SlotReleaseReason::DownloadComplete,
            ..
        }
    )));

    let second_half: Vec<u8> = (16..32u8).collect();
    session.handle_bytes(&sendingpart(h, 16, &second_half));
    let done_out = drain(|| session.poll_output());
    // The slot is HELD: receiving the requested bytes does not release it.
    // The session cannot know the whole-part size, so it keeps the slot
    // across block requests until the worker explicitly releases.
    assert!(
        !events(&done_out)
            .iter()
            .any(|e| matches!(e, PeerEvent::SlotReleased { .. }))
    );

    // The worker explicitly releases when it has the whole part.
    session.handle_command(PeerCommand::ReleaseSlot { file_hash: h });
    let released = drain(|| session.poll_output());
    assert!(events(&released).iter().any(|e| matches!(
        e,
        PeerEvent::SlotReleased { file_hash, reason: SlotReleaseReason::DownloadComplete } if *file_hash == h
    )));

    // active_slot cleared: a new RequestParts for a different file succeeds.
    let h2 = file_hash(0x89);
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h2,
        file_size: 1_000_000,
        ranges,
    });
    let out_h2 = drain(|| session.poll_output());
    assert!(!events(&out_h2).iter().any(|e| matches!(
        e,
        PeerEvent::CommandRejected {
            reason: PeerError::SlotBusy
        }
    )));
}

#[test]
fn release_slot_for_unheld_file_is_a_noop() {
    let mut session = identified_session();
    // No active slot: ReleaseSlot must not emit a release or panic.
    session.handle_command(PeerCommand::ReleaseSlot {
        file_hash: file_hash(0x01),
    });
    let out = drain(|| session.poll_output());
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::SlotReleased { .. }))
    );
}

#[test]
fn cancel_transfer_writes_op_canceltransfer_and_releases_the_active_slot() {
    let h = file_hash(0xC5);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "c"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    let _ = drain(|| session.poll_output());
    // Slot granted (active and holding): a worker torn down now for a local
    // reason (CancelDownload/PauseDownload/complete-overshoot, ADR-0056)
    // sends OP_CANCELTRANSFER before releasing.
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output());

    session.handle_command(PeerCommand::CancelTransfer { file_hash: h });
    let out = drain(|| session.poll_output());
    let sent = writes(&out);
    assert_eq!(sent.len(), 1, "exactly one frame written, got {sent:?}");
    assert_eq!(sent[0].opcode(), 0x56);
    assert_eq!(sent[0].payload(), &[] as &[u8]);
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::SlotReleased {
            file_hash,
            reason: SlotReleaseReason::Cancelled
        } if *file_hash == h
    )));

    // Latch: active_slot is already clear, so a second CancelTransfer for the
    // same file is a no-op — at most one 0x56 per ask-cycle (ADR-0056).
    session.handle_command(PeerCommand::CancelTransfer { file_hash: h });
    let second = drain(|| session.poll_output());
    assert!(writes(&second).is_empty());
    assert!(
        !events(&second)
            .iter()
            .any(|e| matches!(e, PeerEvent::SlotReleased { .. }))
    );

    // active_slot cleared: a new RequestParts for a different file succeeds.
    let h2 = file_hash(0xC6);
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h2,
        file_size: ED2K_PART_SIZE + 1,
        ranges,
    });
    let out2 = drain(|| session.poll_output());
    assert!(!events(&out2).iter().any(|e| matches!(
        e,
        PeerEvent::CommandRejected {
            reason: PeerError::SlotBusy
        }
    )));
}

#[test]
fn cancel_transfer_for_unheld_file_is_a_noop() {
    let mut session = identified_session();
    session.handle_command(PeerCommand::CancelTransfer {
        file_hash: file_hash(0x02),
    });
    let out = drain(|| session.poll_output());
    assert!(writes(&out).is_empty());
    assert!(
        !events(&out)
            .iter()
            .any(|e| matches!(e, PeerEvent::SlotReleased { .. }))
    );
}

#[test]
fn additional_request_parts_under_held_slot_sends_requestparts_without_startuploadreq() {
    let h = file_hash(0x90);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    });
    session.handle_bytes(&reqfilename_answer(h, "x"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(h, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    let _ = drain(|| session.poll_output()); // first STARTUPLOADREQ + REQUESTPARTS

    // Second block request for the SAME file while the slot is held.
    let next = PartRanges::new([(4, 8), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges: next,
    });
    let out = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&out).iter().map(Packet::opcode).collect();
    assert_eq!(
        opcodes,
        vec![0x47],
        "only OP_REQUESTPARTS, no new STARTUPLOADREQ"
    );
    assert!(
        !events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::CommandRejected {
                reason: PeerError::SlotBusy
            }
        )),
        "same-file request under a held slot is not SlotBusy"
    );
}

#[test]
fn request_parts_with_mismatched_file_size_is_rejected() {
    let h = file_hash(0xCC);
    let mut session = identified_session();
    session.handle_command(PeerCommand::ProbeFile {
        file_hash: h,
        file_size: 1_000_000,
        own_status: rmule_peer::PartBitmap::downloader_empty(1_000_000),
    });
    session.handle_bytes(&reqfilename_answer(h, "x"));
    session.handle_bytes(&file_status(h, 1, &[0x01]));
    let _ = drain(|| session.poll_output());

    // First RequestParts confirms the size the probe already recorded.
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 1_000_000,
        ranges,
    });
    let _ = drain(|| session.poll_output());

    // Drain slot terminal so active_slot clears.
    session.signal_slot_stale();
    let _ = drain(|| session.poll_output());

    // Re-request the same file with a different size.
    session.handle_command(PeerCommand::RequestParts {
        file_hash: h,
        file_size: 2_000_000,
        ranges,
    });
    let out = drain(|| session.poll_output());
    assert!(events(&out).iter().any(|e| matches!(
        e,
        PeerEvent::CommandRejected {
            reason: PeerError::FileSizeMismatch {
                requested: 2_000_000,
                known: 1_000_000
            }
        }
    )));
}
