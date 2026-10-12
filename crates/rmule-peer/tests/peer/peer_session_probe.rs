//! Probing a file on a peer: the name/status/no-file answers a probe
//! resolves to, how unrelated probes interleave on one connection
//! (ADR-0025), and the hash-set cache that keeps a second download from
//! re-asking.

use rmule_peer::{
    ConnectionEvent, FileProbeStatus, PartBitmap, PartRanges, PeerCloseReason, PeerCommand,
    PeerEvent, PeerOutput, RequesterCommand, RequesterEvent,
};
use rmule_primitives::session::drain;
use rmule_primitives::{ED2K_PART_SIZE, FileHash, Packet, PartHash};
use rmule_testkit::peer_session::*;

#[test]
fn probe_happy_path_emits_writes_and_available_status() {
    let h = file_hash(0xAA);
    let mut session = identified_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: h,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    }));
    let out1 = drain(|| session.poll_output());
    let probe_writes = writes(&out1);
    assert_eq!(probe_writes.len(), 2);
    assert_eq!(probe_writes[0].opcode(), 0x58); // OP_REQUESTFILENAME
    assert_eq!(probe_writes[1].opcode(), 0x4F); // OP_SETREQFILEID

    session.handle_bytes(&reqfilename_answer(h, "shared.bin"));
    session.handle_bytes(&file_status(h, 3, &[0x07]));
    let out2 = drain(|| session.poll_output());
    let probed = events(&out2)
        .into_iter()
        .find_map(|e| match e {
            PeerEvent::Requester(RequesterEvent::FileProbed { file_hash, status })
                if *file_hash == h =>
            {
                Some(status)
            }
            _ => None,
        })
        .expect("FileProbed emitted");
    match probed {
        FileProbeStatus::Available {
            file_name,
            bitmap,
            complete,
        } => {
            assert_eq!(file_name.as_bytes(), b"shared.bin");
            assert_eq!(bitmap.part_count(), 3);
            // Every one of the three parts spelled out is a part file whose last
            // part arrived, not a complete source: aMule and eMule count only
            // the part-count-0 sentinel (ADR-0108).
            assert!(bitmap.is_complete());
            assert!(!complete);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn probe_not_available_caches_and_replays_on_reprobe() {
    let h = file_hash(0xBB);
    let mut session = identified_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: h,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    }));
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&filereqansnofil(h));
    let first = drain(|| session.poll_output());
    assert!(events(&first).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::FileProbed {
            status: FileProbeStatus::NotAvailable,
            ..
        })
    )));

    // Re-probing the same hash hits the cache: no new wire writes,
    // event replayed immediately.
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: h,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    }));
    let second = drain(|| session.poll_output());
    assert!(
        writes(&second).is_empty(),
        "cached NotAvailable: no rewrite"
    );
    assert!(events(&second).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::FileProbed {
            status: FileProbeStatus::NotAvailable,
            ..
        })
    )));
}

#[test]
fn interleaved_probes_demux_by_file_hash() {
    let a = file_hash(0xA1);
    let b = file_hash(0xB1);
    let mut session = identified_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: a,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    }));
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: b,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    }));
    let _ = drain(|| session.poll_output());

    // Responses arrive in B-then-A order.
    session.handle_bytes(&reqfilename_answer(b, "b.bin"));
    session.handle_bytes(&file_status(b, 3, &[0x01]));
    session.handle_bytes(&reqfilename_answer(a, "a.bin"));
    session.handle_bytes(&file_status(a, 3, &[0x01]));

    let out = drain(|| session.poll_output());
    let probed: Vec<FileHash> = events(&out)
        .into_iter()
        .filter_map(|e| match e {
            PeerEvent::Requester(RequesterEvent::FileProbed { file_hash, .. }) => Some(*file_hash),
            _ => None,
        })
        .collect();
    assert_eq!(probed, vec![b, a]);
}

#[test]
fn hashset_caching_skips_rerequest_on_second_download() {
    // Walk through a full download for D, then RequestParts again with
    // the same file_hash. No second HASHSETREQUEST should hit the wire.
    let d = file_hash(0xDD);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: d,
        file_size: 1_000_000,
        ranges,
    }));
    // One-part file: the fallback probe is the name ask alone, so
    // no OP_FILESTATUS answer is solicited or expected — the name answer
    // alone completes the probe (bitmap prefilled complete). aMule can
    // still answer a complete-file status to the standalone `0x4F` it was
    // sent on an earlier probe of this hash, or send one unprompted;
    // arriving after the probe is already `Available`, it must merge into
    // the bitmap (a no-op here — identical to the prefilled one) rather
    // than reopen the probe and stall the slot.
    session.handle_bytes(&reqfilename_answer(d, "d"));
    session.handle_bytes(&file_status(d, 1, &[0x01]));
    session.handle_bytes(&hashset_answer(d, &[PartHash::from_bytes([0; 16])]));
    session.handle_bytes(&acceptuploadreq());
    session.handle_bytes(&sendingpart(d, 0, &[1, 2, 3, 4]));
    let _ = drain(|| session.poll_output());

    // The slot is now held; the worker releases it once it has the part.
    // The cached hash set must survive the release so the next download
    // skips OP_HASHSETREQUEST.
    session.handle_command(PeerCommand::Requester(RequesterCommand::ReleaseSlot {
        file_hash: d,
    }));
    let _ = drain(|| session.poll_output());

    // Second RequestParts for the same file.
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: d,
        file_size: 1_000_000,
        ranges,
    }));
    let out = drain(|| session.poll_output());
    let opcodes: Vec<u8> = writes(&out).iter().map(Packet::opcode).collect();
    assert!(
        !opcodes.contains(&0x51),
        "no fresh OP_HASHSETREQUEST: opcodes were {opcodes:?}"
    );
    // STARTUPLOADREQ goes out immediately because probe+hashset both cached.
    assert!(opcodes.contains(&0x54));
}

#[test]
fn a_complete_source_sentinel_status_expands_to_a_full_bitmap_of_the_files_real_part_count() {
    // aMule's `nED2KPartCount == 0` "complete source" sentinel
    // (`ProcessFileStatus`, `DownloadClient.cpp:388-458`, kno `ab483654`)
    // means the peer holds every part, not zero parts. The fold expands it
    // using the file size `RequestParts` already gave this flow:
    // 20,000,000 bytes is 3 ED2K parts.
    let h = file_hash(0xEE);
    let mut session = identified_session();
    let ranges = PartRanges::new([(0, 4), (0, 0), (0, 0)]).unwrap();
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestParts {
        file_hash: h,
        file_size: 20_000_000,
        ranges,
    }));
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&reqfilename_answer(h, "shared.bin"));
    session.handle_bytes(&file_status(h, 0, &[]));
    let out = drain(|| session.poll_output());
    let probed = events(&out)
        .into_iter()
        .find_map(|e| match e {
            PeerEvent::Requester(RequesterEvent::FileProbed { file_hash, status })
                if *file_hash == h =>
            {
                Some(status)
            }
            _ => None,
        })
        .expect("FileProbed emitted");
    match probed {
        FileProbeStatus::Available {
            bitmap, complete, ..
        } => {
            assert_eq!(*bitmap, PartBitmap::all_present(3));
            assert!(complete, "the sentinel is a complete source");
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn a_complete_source_sentinel_status_expands_to_a_full_bitmap_on_a_bare_probe_too() {
    // `ProbeFile` now carries the file size, so a status
    // answering a bare probe — with no `RequestParts`/`RequestFile` in the
    // same flow — has just as much to expand the sentinel against as one
    // that opened through those commands: 20,000,000 bytes is 3 ED2K parts.
    let h = file_hash(0xEF);
    let mut session = identified_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: h,
        file_size: 20_000_000,
        own_status: PartBitmap::downloader_empty(20_000_000),
    }));
    let _ = drain(|| session.poll_output());

    session.handle_bytes(&reqfilename_answer(h, "shared.bin"));
    session.handle_bytes(&file_status(h, 0, &[]));
    let out = drain(|| session.poll_output());
    let probed = events(&out)
        .into_iter()
        .find_map(|e| match e {
            PeerEvent::Requester(RequesterEvent::FileProbed { file_hash, status })
                if *file_hash == h =>
            {
                Some(status)
            }
            _ => None,
        })
        .expect("FileProbed emitted");
    match probed {
        FileProbeStatus::Available {
            bitmap, complete, ..
        } => {
            assert_eq!(*bitmap, PartBitmap::all_present(3));
            assert!(complete, "the sentinel is a complete source");
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

/// The Advertised Parts a probe of a `file_size`-byte file reads off one
/// status frame, or the session's last two outputs when the frame closed it.
fn probe_with_status(file_size: u64, status: &[u8]) -> Result<PartBitmap, Vec<PeerOutput>> {
    let h = file_hash(0x5E);
    let mut session = identified_session();
    session.handle_command(PeerCommand::Requester(RequesterCommand::ProbeFile {
        file_hash: h,
        file_size,
        own_status: PartBitmap::downloader_empty(file_size),
    }));
    let _ = drain(|| session.poll_output());
    session.handle_bytes(&reqfilename_answer(h, "exact.bin"));
    session.handle_bytes(status);
    let mut out = drain(|| session.poll_output());
    let probed = events(&out).into_iter().find_map(|e| match e {
        PeerEvent::Requester(RequesterEvent::FileProbed {
            status: FileProbeStatus::Available { bitmap, .. },
            ..
        }) => Some(bitmap.clone()),
        _ => None,
    });
    probed.ok_or_else(|| out.split_off(out.len().saturating_sub(2)))
}

/// aMule's reader (stock 2.3.3 `DownloadClient.cpp:404-449`) on a file of
/// exactly two parts: the sentinel and the `size / PARTSIZE + 1` = 3 count
/// both read as the two real parts — the phantom third bit is never read.
#[test]
fn an_exact_multiples_sentinel_and_counted_status_read_as_the_same_parts() {
    let size = 2 * ED2K_PART_SIZE;
    let h = file_hash(0x5E);
    let sentinel = probe_with_status(size, &file_status(h, 0, &[])).unwrap();
    let counted = probe_with_status(size, &file_status(h, 3, &[0b111])).unwrap();
    assert_eq!(sentinel, counted);
    assert_eq!(counted, PartBitmap::all_present(2));
}

/// Any count but `0` and `size / PARTSIZE + 1` is aMule's "wrong part number"
/// throw, and the connection drops (`DownloadClient.cpp:417-425`): the real
/// part count of an exact multiple, one too many, and a one-part claim.
#[test]
fn a_status_counting_other_parts_than_the_file_has_closes_the_session() {
    let size = 2 * ED2K_PART_SIZE;
    let h = file_hash(0x5E);
    for (count, bitmap) in [(2, vec![0b11]), (4, vec![0b1111]), (1, vec![0b1])] {
        let closed = probe_with_status(size, &file_status(h, count, &bitmap))
            .expect_err("a wrong count is refused, never probed");
        assert!(
            matches!(
                closed.as_slice(),
                [
                    PeerOutput::Event(PeerEvent::Connection(ConnectionEvent::Disconnected {
                        reason: PeerCloseReason::ProtocolViolation,
                    })),
                    PeerOutput::Close(PeerCloseReason::ProtocolViolation),
                ]
            ),
            "count {count}: {closed:?}"
        );
    }
}
