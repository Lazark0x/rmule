//! Asks about a download (ADR-0113 §"What each ask is answered"): a Served
//! Download answers probes from its start and offers nothing until its
//! Verified Range holds a part; a Partial Share is offered from its range; a
//! registry row of the same hash wins; a running download's askers are kept
//! as candidates; nothing is AICH.

use std::path::PathBuf;

use rmule_peer::ReaskAck;

use super::*;
use crate::DownloadId;
use crate::VerifiedPartRecord;
use crate::served_downloads::{BytesAt, Served, VerifiedRange, WholeSet};

mod exchange;

/// Three whole parts: the writer counts four, the phantom always held, and
/// the whole set has four hashes, the empty fourth part's included.
pub(super) const SIZE: u64 = 3 * ED2K_PART_SIZE;

fn set() -> Vec<PartHash> {
    (0..4)
        .map(|part| PartHash::from_bytes([0x40 + part; 16]))
        .collect()
}

/// A Served Download of [`SIZE`] bytes, its whole set held when `whole`, the
/// parts `verified` recorded against it, its run taking askers when
/// `running`.
pub(super) fn download(whole: bool, verified: &[u32], running: bool) -> ServedLook {
    let hashes = set();
    let set = whole.then(|| WholeSet::of(SIZE, &hashes).expect("the whole set"));
    let records: Vec<VerifiedPartRecord> = verified
        .iter()
        .map(|&part_index| VerifiedPartRecord {
            part_index,
            offset: u64::from(part_index) * ED2K_PART_SIZE,
            len: ED2K_PART_SIZE,
            part_hash: hashes[part_index as usize],
        })
        .collect();
    let range = VerifiedRange::of_records(set.as_ref(), &records);
    ServedLook {
        offered: set.is_some() && range.holds_a_part(),
        served: Served {
            download_id: DownloadId::from_u64(1),
            file_size: SIZE,
            name: Ed2kText::from_utf8("download.bin"),
            part_path: PathBuf::from("/temp/download.bin.part"),
            final_path: PathBuf::from("/downloads/download.bin"),
            bytes_at: BytesAt::PartFile,
            set,
            range,
            identity: None,
            pool: Default::default(),
        },
        takes_askers: running,
    }
}

/// A state serving `rows` and the Served Downloads `downloads`, through one
/// slot, the share trigger fired once.
pub(super) fn state_of(
    rows: Vec<SharedFileEntry>,
    downloads: Vec<(FileHash, ServedLook)>,
) -> ServeState {
    let mut state = ServeState::new(UploadSlotQueue::new(1, 8));
    state.on_served(downloads.into_iter().collect());
    let _ = state.on_share_set(rows, Instant::now(), &no_modifiers());
    state
}

fn ask(state: &mut ServeState, p: PeerEndpoint, request: ServerEvent) -> Vec<ServeDecision> {
    state.on_conn_event(
        Instant::now(),
        p,
        ServeInput::Server(request),
        &no_modifiers(),
    )
}

fn name_ask(file_hash: FileHash) -> ServerEvent {
    ServerEvent::FileRequested {
        file_hash,
        status: PartStatusTail::of(&PartBitmap::downloader_empty(SIZE)),
    }
}

/// The status a writer states for a file of [`SIZE`] holding `parts`, the
/// phantom fourth part held.
fn holding(parts: &[u32]) -> PartBitmap {
    let bits = parts.iter().fold(1u8 << 3, |bits, part| bits | 1 << part);
    PartBitmap::decode(4, &[bits]).unwrap()
}

/// What the run is handed for an asker at `link` identified by [`identify`]:
/// its coordinate, as the word of the party at `link` (ADR-0085).
fn kept(file_hash: FileHash, link: PeerEndpoint, user_hash: UserHash) -> ServeDecision {
    let identity = hello_facts(user_hash, 0, 0, 2).identity();
    ServeDecision::KeepAsker {
        file_hash,
        sighting: identity.source_coordinate(link),
    }
}

#[test]
fn a_download_before_its_first_verified_part_answers_probes_and_moves_nobody() {
    let (row, file) = (hash(0x01), hash(0x02));
    let mut state = state_of(
        vec![entry(row, 1_000, "row.bin")],
        vec![(file, download(false, &[], false))],
    );
    let t = Instant::now();
    // A waiter of the row asks about the download.
    let _ = slot_request(&mut state, peer(4000), row, t);
    let p = peer(4001);
    identify(&mut state, p, user(0x0B), t);
    assert!(matches!(
        slot_request(&mut state, p, row, t).as_slice(),
        [
            _,
            _,
            ServeDecision::Emit(ServeEvent::PeerQueued { rank: 1, .. })
        ]
    ));

    assert_eq!(
        ask(&mut state, p, name_ask(file)),
        [send(
            p,
            ServerCommand::AnswerFileName {
                file_hash: file,
                file_name: Ed2kText::from_utf8("download.bin"),
            },
        )],
        "named, and the waiter stays queued for the row"
    );
    assert_eq!(
        ask(&mut state, p, ServerEvent::FileIdSet { file_hash: file }),
        [send(
            p,
            ServerCommand::AnswerFileStatus {
                file_hash: file,
                bitmap: PartBitmap::downloader_empty(SIZE),
            },
        )],
        "the empty bitmap, phantom part held"
    );
    assert_eq!(
        ask(
            &mut state,
            p,
            ServerEvent::HashSetRequested { file_hash: file }
        ),
        [send(
            p,
            ServerCommand::AnswerFileNotFound { file_hash: file }
        )],
        "no set held"
    );
    assert_eq!(
        slot_request(&mut state, p, file, t),
        [],
        "a slot ask is silent"
    );
    assert_eq!(state.queue.waiting_file(p), Some(row), "it moved no waiter");
}

#[test]
fn a_download_with_its_whole_set_and_no_part_answers_the_set_and_offers_nothing() {
    let file = hash(0x02);
    let mut state = state_of(Vec::new(), vec![(file, download(true, &[], false))]);
    let p = peer(4001);
    assert_eq!(
        ask(
            &mut state,
            p,
            ServerEvent::HashSetRequested { file_hash: file }
        ),
        [send(
            p,
            ServerCommand::AnswerHashSet {
                file_hash: file,
                part_hashes: set(),
            },
        )]
    );
    assert_eq!(slot_request(&mut state, p, file, Instant::now()), []);
}

#[test]
fn a_partial_share_queues_a_slot_ask_and_states_its_verified_range() {
    let file = hash(0x02);
    let mut state = state_of(Vec::new(), vec![(file, download(true, &[0, 2], false))]);
    let t = Instant::now();
    let holder = peer(4000);
    assert!(matches!(
        slot_request(&mut state, holder, file, t).as_slice(),
        [
            ServeDecision::CountUploadRequest { .. },
            ServeDecision::Send {
                command: ServerCommand::GrantSlot { .. },
                ..
            },
            ServeDecision::Emit(ServeEvent::UploadSlotGranted { .. }),
        ]
    ));
    let waiter = peer(4001);
    assert!(matches!(
        slot_request(&mut state, waiter, file, t).as_slice(),
        [
            ServeDecision::CountUploadRequest { .. },
            ServeDecision::Send {
                command: ServerCommand::SetQueueRank { rank: 1 },
                ..
            },
            ServeDecision::Emit(ServeEvent::PeerQueued { rank: 1, .. }),
        ]
    ));
    assert_eq!(
        ask(
            &mut state,
            waiter,
            ServerEvent::FileIdSet { file_hash: file }
        ),
        [send(
            waiter,
            ServerCommand::AnswerFileStatus {
                file_hash: file,
                bitmap: holding(&[0, 2]),
            },
        )]
    );
}

#[test]
fn a_waiters_udp_reask_carries_a_partial_shares_range_and_a_whole_files_count_zero() {
    let (row, partial, whole) = (hash(0x01), hash(0x02), hash(0x03));
    let mut state = state_of(
        vec![entry(row, SIZE, "row.bin")],
        vec![
            (partial, download(true, &[1], false)),
            (whole, download(true, &[0, 1, 2], false)),
        ],
    );
    let t = Instant::now();
    // A holder takes the one slot; each waiter after it queues.
    let _ = slot_request(&mut state, peer_at([10, 0, 0, 1], 4000), row, t);
    for (file, ip, status) in [
        (row, [10, 0, 0, 2], PartBitmap::complete_source_sentinel()),
        (partial, [10, 0, 0, 3], holding(&[1])),
        (whole, [10, 0, 0, 4], PartBitmap::complete_source_sentinel()),
    ] {
        let waiter = peer_at(ip, 4662);
        identify_udp(&mut state, waiter, user(ip[3]), 4672, 4, t);
        let _ = slot_request(&mut state, waiter, file, t);
        let rank = state.queue.waiting_len() as u16;
        assert_eq!(
            state.on_reask_ping(t, udp(ip, 4672), &reask_ping(file)),
            [ServeDecision::SendClientUdp {
                to: udp(ip, 4672),
                datagram: ReaskAck {
                    part_status: Some(status),
                    rank,
                }
                .encode_udp(),
                crypt_target: target_of(user(ip[3])),
            }],
            "file {file:?}"
        );
    }
}

#[test]
fn a_registry_row_and_a_served_download_of_one_hash_the_row_answers() {
    let file = hash(0x02);
    let mut state = state_of(
        vec![entry(file, SIZE, "row.bin")],
        vec![(file, download(true, &[0], true))],
    );
    let p = peer(4001);
    identify(&mut state, p, user(0x0B), Instant::now());
    let named = ask(&mut state, p, name_ask(file));
    assert_eq!(
        named,
        [send(
            p,
            ServerCommand::AnswerFileName {
                file_hash: file,
                file_name: Ed2kText::from_utf8("row.bin"),
            },
        )],
        "the row's name, and no asker kept for the download"
    );
    assert_eq!(
        ask(&mut state, p, ServerEvent::FileIdSet { file_hash: file }),
        [send(
            p,
            ServerCommand::AnswerFileStatus {
                file_hash: file,
                bitmap: super::super::reask::full_bitmap(SIZE),
            },
        )]
    );
}

#[test]
fn a_running_downloads_asker_is_kept_and_a_paused_ones_is_answered_only() {
    let (running, paused) = (hash(0x02), hash(0x03));
    let mut state = state_of(
        Vec::new(),
        vec![
            (running, download(true, &[0], true)),
            (paused, download(true, &[0], false)),
        ],
    );
    let p = peer(4001);
    identify(&mut state, p, user(0x0B), Instant::now());
    let name = |file| {
        send(
            p,
            ServerCommand::AnswerFileName {
                file_hash: file,
                file_name: Ed2kText::from_utf8("download.bin"),
            },
        )
    };
    assert_eq!(
        ask(&mut state, p, name_ask(running)),
        [name(running), kept(running, p, user(0x0B))]
    );
    assert_eq!(ask(&mut state, p, name_ask(paused)), [name(paused)]);
    // A bundle keeps its asker past the file gate too.
    let bundle = ServerEvent::FileBundleRequested {
        file_hash: running,
        file_size: Some(SIZE),
        asks: vec![BundledAsk::SetReqId],
        cut: None,
    };
    assert_eq!(
        ask(&mut state, p, bundle),
        [
            kept(running, p, user(0x0B)),
            send(
                p,
                ServerCommand::AnswerFileStatus {
                    file_hash: running,
                    bitmap: holding(&[0]),
                },
            ),
        ]
    );
}

/// The source the run is handed for an asker at `link` whose hello claims
/// `claimed`.
fn kept_at(link: PeerEndpoint, claimed: ClientId) -> Option<PeerSource> {
    let running = hash(0x02);
    let mut state = state_of(Vec::new(), vec![(running, download(true, &[0], true))]);
    let hello = HelloFacts {
        client_id: claimed,
        ..hello_facts(user(0x0B), 0, 0, 2)
    };
    let _ = state.on_conn_event(Instant::now(), link, hello.identified(), &no_modifiers());
    ask(&mut state, link, name_ask(running))
        .into_iter()
        .find_map(|decision| match decision {
            ServeDecision::KeepAsker { sighting, .. } => sighting.peer_source(),
            _ => None,
        })
}

#[test]
fn an_asker_is_a_source_at_the_address_its_link_came_from_whatever_high_id_it_claims() {
    // aMule takes the socket's address as a High-ID client's (BaseClient.cpp
    // `:661`, `:678-680`) and dials that (`:1620`), the hello's port beside it.
    let link = peer_at([172, 18, 0, 6], 36126);
    let socket = PeerSource::HighId(rmule_primitives::Ipv4Endpoint::new(
        Ipv4Addr::new(172, 18, 0, 6),
        4662,
    ));
    for claimed in [0x1000_0001, 0, u32::from_le_bytes([172, 18, 0, 6])] {
        assert_eq!(kept_at(link, ClientId::from_u32(claimed)), Some(socket));
    }
    // A Low ID stays the callback it names: the socket is not where a dial
    // reaches it.
    assert_eq!(
        kept_at(link, ClientId::from_u32(77)),
        Some(PeerSource::LowId {
            id: ClientId::from_u32(77),
            port: 4662
        })
    );
}

#[test]
fn an_ipv6_asker_is_a_source_at_its_links_address_whatever_id_it_claims() {
    // kno takes the socket's address as the client's on either family
    // (`BaseClient.cpp:812-813`); an IPv4 claim no link checks names nothing,
    // so a download of the asker meets the link it came on (ADR-0107).
    let address = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x66);
    let link = PeerEndpoint::V6(rmule_primitives::Ipv6Endpoint::new(address, 36126));
    let socket = PeerSource::Ipv6(rmule_primitives::Ipv6Endpoint::new(address, 4662));
    for claimed in [u32::from_le_bytes([192, 0, 2, 9]), 0, 77] {
        assert_eq!(kept_at(link, ClientId::from_u32(claimed)), Some(socket));
    }
}

#[test]
fn an_aich_ask_for_a_served_download_decides_nothing() {
    let file = hash(0x02);
    let mut state = state_of(Vec::new(), vec![(file, download(true, &[0], true))]);
    let p = peer(4001);
    let root = rmule_primitives::AichRootHash::from_bytes([7; 20]);
    for request in [
        ServerEvent::AichRequested {
            file_hash: file,
            part: 0,
            root,
        },
        ServerEvent::AichFileHashRequested { file_hash: file },
    ] {
        assert_eq!(ask(&mut state, p, request), []);
    }
}

#[test]
fn a_partial_share_the_cell_dropped_answers_until_the_next_share_trigger() {
    let file = hash(0x02);
    let mut state = state_of(Vec::new(), vec![(file, download(true, &[0], false))]);
    let t = Instant::now();
    let _ = slot_request(&mut state, peer(4000), file, t);
    let waiter = peer(4001);
    let _ = slot_request(&mut state, waiter, file, t);

    // The download ended; the cell no longer holds it.
    state.on_served(HashMap::new());
    assert!(matches!(
        ask(
            &mut state,
            waiter,
            ServerEvent::FileIdSet { file_hash: file }
        )
        .as_slice(),
        [ServeDecision::Send {
            command: ServerCommand::AnswerFileStatus { .. },
            ..
        }]
    ));
    let purged = state.on_purge(t, Duration::from_secs(3600), &no_modifiers());
    assert_eq!(purged, [], "its waiter is still waiting for a shared file");

    let decisions = state.on_share_set(Vec::new(), t, &no_modifiers());
    assert!(
        decisions.contains(&send(
            waiter,
            ServerCommand::AnswerFileNotFound { file_hash: file }
        )),
        "the trigger stops serving it: {decisions:?}"
    );
    assert_eq!(
        ask(
            &mut state,
            waiter,
            ServerEvent::FileIdSet { file_hash: file }
        ),
        [send(
            waiter,
            ServerCommand::AnswerFileNotFound { file_hash: file }
        )]
    );
}

/// One `OP_OFFERFILES` to a server granting compression names a row with
/// the complete marker and a Partial Share with the incomplete one
/// (`KnownFile.cpp:1097-1107`), each under its own name and size.
#[test]
fn a_compression_server_reads_a_row_complete_and_a_partial_share_incomplete_in_one_announce() {
    use rmule_ed2k::{OfferFiles, ServerGrants};
    use rmule_primitives::ClientId;

    let (row, partial) = (hash(0x01), hash(0x02));
    let mut state = ServeState::new(UploadSlotQueue::new(1, 8));
    state.on_served([(partial, download(true, &[0], false))].into());
    let decisions = state.on_share_set(vec![entry(row, 42, "r")], Instant::now(), &no_modifiers());
    let Some(ServeDecision::Announce(files)) = decisions.last() else {
        panic!("an announce: {decisions:?}");
    };
    let grants = ServerGrants {
        compression: true,
        ..ServerGrants::default()
    };
    let id = ClientId::from_u32(0x0403_0201);
    let packet = OfferFiles::announce(grants, id, id, 4662, files).encode_packet();
    let expected: &[u8] = &[
        0x02, 0x00, 0x00, 0x00, // file_count = 2
        // The row: its hash, 251.251.251.251:0xFBFB, two tags.
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, // file_hash
        0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, // complete marker
        0x02, 0x00, 0x00, 0x00, // tag_count = 2
        0x82, 0x01, 0x01, 0x00, b'r', // FT_FILENAME "r"
        0x83, 0x02, 0x2A, 0x00, 0x00, 0x00, // FT_FILESIZE = 42
        // The Partial Share: its hash, 252.252.252.252:0xFCFC, its
        // download's name and size.
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, // file_hash
        0xFC, 0xFC, 0xFC, 0xFC, 0xFC, 0xFC, // incomplete marker
        0x02, 0x00, 0x00, 0x00, // tag_count = 2
        0x82, 0x01, 0x0C, 0x00, b'd', b'o', b'w', b'n', b'l', b'o', b'a', b'd', b'.', b'b', b'i',
        b'n', // FT_FILENAME "download.bin"
        0x83, 0x02, 0x00, 0x50, 0xBD, 0x01, // FT_FILESIZE = 29_184_000
    ];
    assert_eq!(packet.payload(), expected);
}
