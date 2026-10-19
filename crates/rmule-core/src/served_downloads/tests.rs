//! The Served Downloads cell on its own: who is a member, one writer per
//! entry, when an entry is offered, and what each look reports.

use rmule_primitives::{Ed2kFileLink, Ed2kText};

use super::*;
use crate::DownloadPaths;
use crate::download::RunNumber;
use crate::file_key::FileKey;
use crate::storage::DownloadRepository;
use crate::store::download::DurableDownloadRepository;

/// Two whole parts and five bytes: three hashes, three parts.
const SIZE: u64 = 2 * ED2K_PART_SIZE + 5;

fn link(seed: u8, size: u64) -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("served.bin"),
        size,
        file_hash: FileHash::from_bytes([seed; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// A download row of `size` bytes for file `seed`, moved to `lifecycle`.
fn record(
    store: &DurableDownloadRepository,
    seed: u8,
    size: u64,
    lifecycle: DownloadLifecycle,
) -> DurableDownloadRecord {
    let paths = DownloadPaths::from_final_path(PathBuf::from(format!("/downloads/{seed}.bin")));
    let id = store
        .create_download(&link(seed, size), None, &paths, None)
        .unwrap()
        .id();
    let steps: &[DownloadLifecycle] = match lifecycle {
        DownloadLifecycle::Queued => &[],
        DownloadLifecycle::Active => &[DownloadLifecycle::Active],
        DownloadLifecycle::Completed => &[
            DownloadLifecycle::Active,
            DownloadLifecycle::Completing,
            DownloadLifecycle::Completed,
        ],
        later => &[DownloadLifecycle::Active, later],
    };
    for &step in steps {
        store.set_lifecycle(id, step).unwrap();
    }
    store.load_download(id).unwrap()
}

fn store() -> DurableDownloadRepository {
    DurableDownloadRepository::new(rmule_testkit::memory_store())
}

fn hashes(seed: u8) -> Vec<PartHash> {
    (0..3)
        .map(|part| PartHash::from_bytes([seed.wrapping_add(part); 16]))
        .collect()
}

fn verified(part_index: u32, part_hash: PartHash) -> VerifiedPartRecord {
    VerifiedPartRecord {
        part_index,
        offset: u64::from(part_index) * ED2K_PART_SIZE,
        len: ED2K_PART_SIZE,
        part_hash,
    }
}

#[test]
fn only_a_queued_running_completing_or_paused_download_larger_than_one_part_is_served() {
    let store = store();
    let cell = ServedDownloads::default();
    for (seed, size, lifecycle, served) in [
        (1, SIZE, DownloadLifecycle::Queued, true),
        (2, SIZE, DownloadLifecycle::Active, true),
        (3, SIZE, DownloadLifecycle::Paused, true),
        (4, SIZE, DownloadLifecycle::Failed, false),
        (5, SIZE, DownloadLifecycle::Completed, false),
        (8, SIZE, DownloadLifecycle::Completing, true),
        (6, ED2K_PART_SIZE, DownloadLifecycle::Queued, false),
        (7, 1_000, DownloadLifecycle::Active, false),
    ] {
        let row = record(&store, seed, size, lifecycle);
        assert_eq!(
            cell.install(&row, &[]),
            served,
            "{lifecycle:?} of {size} bytes"
        );
        assert_eq!(cell.served(row.file_hash()).is_some(), served);
    }
}

#[test]
fn one_writer_holds_an_entry_at_every_instant() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Queued);
    let file = row.file_hash();
    assert!(cell.install(&row, &hashes(1)));
    assert!(!cell.install(&row, &hashes(1)), "one entry per file");

    let first = cell
        .hand_to_run(file, RunNumber::new(1))
        .expect("the actor holds it at install");
    assert!(
        cell.hand_to_run(file, RunNumber::new(2)).is_none(),
        "a run holds it"
    );
    assert!(
        !cell.end(row.id(), PartialEnd::Ended),
        "the actor ends only what it holds"
    );
    assert!(first.record_range(&hashes(1), &[verified(0, hashes(1)[0])]));

    cell.take_back(file, RunNumber::new(1));
    assert!(
        !first.record_range(&hashes(1), &[]),
        "a run the lease was taken back from writes nothing"
    );
    let second = cell
        .hand_to_run(file, RunNumber::new(2))
        .expect("the actor holds it again");
    cell.take_back(file, RunNumber::new(1));
    assert!(
        !first.record_range(&hashes(1), &[]),
        "an earlier run's take-back leaves the later run its lease"
    );
    assert!(second.record_range(&hashes(1), &[]));
    assert!(!cell.served(file).unwrap().range.holds_a_part());

    cell.take_back(file, RunNumber::new(2));
    assert!(cell.end(row.id(), PartialEnd::Ended));
    assert!(cell.served(file).is_none());
}

#[test]
fn offered_once_a_part_meets_the_whole_set_and_not_while_held_back() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Queued);
    let file = row.file_hash();
    assert!(cell.install(&row, &[]));
    let lease = cell.hand_to_run(file, RunNumber::new(1)).unwrap();
    let mut offers = cell.offer_changes();
    let set = hashes(1);

    // A part written while no set was held is checked by nothing yet.
    lease.record_range(&[], &[verified(0, set[0])]);
    assert!(cell.offered().is_empty());
    // A set short of a hash is no set.
    lease.record_range(&set[..2], &[verified(0, set[0])]);
    assert!(cell.offered().is_empty());
    // A part whose recorded hash the set disproves is outside the range.
    lease.record_range(&set, &[verified(0, PartHash::from_bytes([0xEE; 16]))]);
    assert!(cell.offered().is_empty());
    assert!(!offers.has_changed().unwrap(), "nothing offered yet");

    lease.record_range(&set, &[verified(0, set[0])]);
    assert_eq!(cell.offered(), [file]);
    assert!(
        offers.has_changed().unwrap(),
        "the offer bumps the generation"
    );
    offers.mark_unchanged();
    lease.record_range(&set, &[verified(0, set[0]), verified(1, set[1])]);
    assert!(
        !offers.has_changed().unwrap(),
        "a range that grows changes no offer"
    );

    cell.hold_back(file, true);
    assert!(cell.offered().is_empty());
    cell.hold_back(file, false);
    assert_eq!(cell.offered(), [file]);
}

#[test]
fn each_look_says_each_change_once_with_its_cause() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Queued);
    let file = row.file_hash();
    let set = hashes(1);
    cell.install(&row, &set);
    assert_eq!(cell.look(), [OfferChange::Joined(file)]);
    assert_eq!(cell.look(), []);

    let lease = cell.hand_to_run(file, RunNumber::new(1)).unwrap();
    lease.record_range(&set, &[verified(2, set[2])]);
    assert_eq!(cell.look(), [OfferChange::Offered(file)]);

    cell.hold_back(file, true);
    assert_eq!(
        cell.look(),
        [OfferChange::Withdrawn(file, PartialEnd::HeldBack)]
    );
    cell.hold_back(file, false);
    assert_eq!(cell.look(), [OfferChange::Offered(file)]);

    lease.record_range(&set, &[]);
    assert_eq!(
        cell.look(),
        [OfferChange::Withdrawn(file, PartialEnd::Changed)],
        "the run's part file lost what the range named"
    );
    lease.record_range(&set, &[verified(2, set[2])]);
    assert_eq!(cell.look(), [OfferChange::Offered(file)]);

    cell.take_back(file, RunNumber::new(1));
    cell.end(row.id(), PartialEnd::Completed);
    assert_eq!(
        cell.look(),
        [
            OfferChange::Withdrawn(file, PartialEnd::Completed),
            OfferChange::Left(file)
        ]
    );
    assert_eq!(cell.look(), []);
}

#[test]
fn an_offer_that_comes_and_goes_between_two_looks_is_said_both_ways() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Queued);
    let file = row.file_hash();
    let set = hashes(1);
    cell.install(&row, &set);
    assert_eq!(cell.look(), [OfferChange::Joined(file)]);
    let lease = cell.hand_to_run(file, RunNumber::new(1)).unwrap();

    lease.record_range(&set, &[verified(0, set[0])]);
    lease.record_range(&set, &[]);
    assert_eq!(
        cell.look(),
        [
            OfferChange::Offered(file),
            OfferChange::Withdrawn(file, PartialEnd::Changed)
        ]
    );

    lease.record_range(&set, &[verified(0, set[0])]);
    assert_eq!(cell.look(), [OfferChange::Offered(file)]);
    lease.record_range(&set, &[]);
    lease.record_range(&set, &[verified(0, set[0])]);
    assert_eq!(
        cell.look(),
        [
            OfferChange::Withdrawn(file, PartialEnd::Changed),
            OfferChange::Offered(file)
        ]
    );
    assert_eq!(cell.look(), []);
}

#[test]
fn only_the_run_holding_an_entry_takes_its_askers_and_a_full_inbox_drops_one() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Queued);
    let file = row.file_hash();
    cell.install(&row, &hashes(1));
    let asker = |n: u8| {
        SourceSighting::plain(
            rmule_primitives::PeerSource::new(
                rmule_primitives::ClientId::from_u32(u32::from_le_bytes([10, 0, 0, n])),
                4662,
            ),
            rmule_primitives::Informant::Own,
        )
    };
    let takes_askers =
        |cell: &ServedDownloads| cell.read_since(0).unwrap().entries[&file].takes_askers;

    assert!(!cell.sight(file, asker(1)), "the actor holds it: no run");
    assert!(!takes_askers(&cell));

    let lease = cell.hand_to_run(file, RunNumber::new(1)).unwrap();
    let mut inbox = lease.take_askers().expect("the run holds it");
    assert!(takes_askers(&cell));
    for n in 0..ASKER_INBOX {
        assert!(cell.sight(file, asker(u8::try_from(n).unwrap())));
    }
    assert!(
        !cell.sight(file, asker(0xFF)),
        "a full inbox drops the asker"
    );
    assert_eq!(inbox.try_recv().ok(), Some(asker(0)));

    cell.take_back(file, RunNumber::new(1));
    assert!(
        !cell.sight(file, asker(1)),
        "the inbox closed with the lease"
    );
    assert!(!takes_askers(&cell));
    assert!(
        lease.take_askers().is_none(),
        "a run without the lease opens none"
    );
}

fn identity(file: u64) -> PartFileIdentity {
    PartFileIdentity {
        key: FileKey { volume: 1, file },
        at_rest: None,
    }
}

#[test]
fn a_read_that_found_the_file_changed_empties_the_range_until_a_holder_reads_the_file_again() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Queued);
    let file = row.file_hash();
    let set = hashes(1);
    cell.install(&row, &set);
    let lease = cell.hand_to_run(file, RunNumber::new(1)).unwrap();
    lease.record_identity(identity(7));
    lease.record_range(&set, &[verified(0, set[0])]);
    cell.look();

    assert!(
        !cell.empty_range(file, Some(identity(8)), PartialEnd::Changed),
        "a read checked against a file the entry no longer names empties nothing"
    );
    assert_eq!(cell.offered(), [file]);
    let offers = cell.offer_changes();
    assert!(cell.empty_range(file, Some(identity(7)), PartialEnd::Unreadable));
    assert!(offers.has_changed().unwrap(), "the actor is woken");
    assert_eq!(
        cell.look(),
        [OfferChange::Withdrawn(file, PartialEnd::Unreadable)]
    );
    assert_eq!(cell.served(file).unwrap().range, VerifiedRange::default());

    lease.record_range(&set, &[verified(0, set[0])]);
    assert!(
        cell.offered().is_empty(),
        "the run's next ruling keeps it empty"
    );
    lease.record_identity(identity(9));
    lease.record_range(&set, &[verified(0, set[0])]);
    assert_eq!(cell.offered(), [file], "a file read again is ruled again");
}

#[test]
fn the_offer_check_writes_only_an_entry_the_actor_holds() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Paused);
    let file = row.file_hash();
    let set = hashes(1);
    cell.install(&row, &set);
    let held = [verified(1, set[1])];

    let lease = cell.hand_to_run(file, RunNumber::new(1)).unwrap();
    assert!(!cell.held_by_actor(file, row.id()));
    assert!(!cell.offer_checked(file, row.id(), &held, identity(7)));
    drop(lease);
    cell.take_back(file, RunNumber::new(1));
    assert!(!cell.offer_checked(file, DownloadId::from_u64(99), &held, identity(7)));

    assert!(cell.held_by_actor(file, row.id()));
    assert!(cell.offer_checked(file, row.id(), &held, identity(7)));
    let served = cell.served(file).unwrap();
    assert!(served.range.holds(1) && !served.range.holds(0));
    assert_eq!(served.identity, Some(identity(7)));
    assert_eq!(
        cell.look(),
        [OfferChange::Joined(file), OfferChange::Offered(file)]
    );
}

/// A Served Download is offered under the download's own name, which its
/// destination's file name differs from once a safe-filename rewrite or the
/// completion move's free name chose another (ADR-0113), from install
/// through the move.
#[test]
fn a_served_download_is_offered_under_the_downloads_name_not_its_paths() {
    let store = store();
    let cell = ServedDownloads::default();
    let row = record(&store, 1, SIZE, DownloadLifecycle::Active);
    let file = row.file_hash();
    assert!(cell.install(&row, &hashes(1)));
    let served = Ed2kText::from_utf8("served.bin");
    assert_eq!(cell.served(file).unwrap().name, served);

    let lease = cell
        .hand_to_run(file, RunNumber::new(1))
        .expect("the actor holds it");
    assert!(lease.bytes_in_place(std::path::Path::new("/downloads/1 (1).bin"), None));
    assert_eq!(cell.served(file).unwrap().name, served);
}
