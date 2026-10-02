//! A rename against a scripted directory (ADR-0100, "A rename carries its
//! hash when the file's identity proves it"): carried unread when identity,
//! size and time all match, and read, as before, in each case the model
//! refuses.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use rmule_primitives::FileHashSummary;

use super::super::scripted::{ROOT, Scripted, known, row};
use super::super::{
    Consent, FileIdentity, Known, Memory, PassEnd, ProgressCell, ScanReport, SpareCopy, run_pass,
};
use crate::registry::SharedFileEntry;

fn pass_knowing(dir: &Scripted, known: &Known) -> (PassEnd, Vec<ScanReport>) {
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let mut reports = Vec::new();
    let end = run_pass(
        dir,
        Path::new(ROOT),
        known,
        Consent::Given,
        &AtomicBool::new(false),
        &progress,
        &mut Memory::default(),
        &mut |report| reports.push(report),
    );
    (end, reports)
}

/// A shared film at `/dl/film.mkv` with identity inode 7, born at second 1.
fn film(dir: &mut Scripted) -> (SharedFileEntry, FileIdentity) {
    let stamp = dir.file("/dl/film.mkv", b"the film", 5);
    let identity = dir.identify("/dl/film.mkv", 7, 1);
    let mut entry = row("/dl/film.mkv", stamp, 0);
    entry.file_hash = FileHashSummary::digest_bytes(b"the film").file_hash();
    (entry, identity)
}

fn knowing(row: &SharedFileEntry, identity: Option<FileIdentity>) -> Known {
    Known {
        identities: identity
            .map(|identity| HashMap::from([(row.file_hash, identity)]))
            .unwrap_or_default(),
        ..known(std::slice::from_ref(row))
    }
}

fn moved(reports: &[ScanReport]) -> bool {
    reports
        .iter()
        .any(|report| matches!(report, ScanReport::Moved { .. }))
}

#[test]
fn a_rename_while_rmule_was_off_is_carried_unread() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    dir.dir("/dl/watched");
    dir.rename("/dl/film.mkv", "/dl/watched/film.mkv");
    let (end, reports) = pass_knowing(&dir, &knowing(&shared, Some(identity)));
    assert_eq!(
        reports,
        [ScanReport::Moved {
            file_hash: shared.file_hash,
            from: shared.path.clone(),
            to: SpareCopy {
                path: "/dl/watched/film.mkv".into(),
                file_hash: shared.file_hash,
                stamp: dir.files[Path::new("/dl/watched/film.mkv")].0,
                identity: Some(identity),
            },
        }],
        "moved, never held, gone or read"
    );
    assert_eq!(dir.opens(), 0);
    assert!(matches!(end, PassEnd::Finished(s) if s.carried == 1 && s.hashed == 0));
}

/// Each refusal reads the file, as the scan always did.
fn assert_read(dir: &Scripted, reports: &[ScanReport]) {
    assert_eq!(dir.opens(), 1, "{reports:?}");
    assert!(!moved(reports), "nothing carried: {reports:?}");
}

#[test]
fn a_filesystem_with_no_stable_identity_is_read() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    dir.rename("/dl/film.mkv", "/dl/renamed.mkv");
    // FAT, a network mount, tmpfs, a file with no birth time: no identity.
    dir.identities.clear();
    let (_, reports) = pass_knowing(&dir, &knowing(&shared, Some(identity)));
    assert_read(&dir, &reports);
}

#[test]
fn a_move_to_another_filesystem_is_read() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    dir.rename("/dl/film.mkv", "/dl/mounted/film.mkv");
    let elsewhere = FileIdentity {
        device: 2,
        ..identity
    };
    dir.identities
        .insert(PathBuf::from("/dl/mounted/film.mkv"), elsewhere);
    dir.dir("/dl/mounted");
    let (_, reports) = pass_knowing(&dir, &knowing(&shared, Some(identity)));
    assert_read(&dir, &reports);
}

#[test]
fn an_inode_reused_after_a_delete_is_read() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    // The film is deleted; a new file of the same size and time is created
    // and handed the freed inode. Its birth time is its own.
    dir.remove("/dl/film.mkv");
    dir.file("/dl/other.mkv", b"not film", 5);
    dir.identify("/dl/other.mkv", 7, 2);
    let (_, reports) = pass_knowing(&dir, &knowing(&shared, Some(identity)));
    assert_read(&dir, &reports);
}

#[test]
fn a_file_touched_after_its_rename_is_read_and_its_identity_never_looked_at() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    dir.rename("/dl/film.mkv", "/dl/renamed.mkv");
    dir.file("/dl/renamed.mkv", b"the film", 6);
    let looks = dir.identity_looks();
    let (_, reports) = pass_knowing(&dir, &knowing(&shared, Some(identity)));
    assert_read(&dir, &reports);
    assert_eq!(
        dir.identity_looks() - looks,
        1,
        "only the hashed file's own identity, after the read"
    );
}

#[test]
fn a_row_with_no_recorded_identity_is_read() {
    let mut dir = Scripted::new();
    let (shared, _) = film(&mut dir);
    dir.rename("/dl/film.mkv", "/dl/renamed.mkv");
    let (_, reports) = pass_knowing(&dir, &knowing(&shared, None));
    assert_read(&dir, &reports);
}

#[test]
fn a_hard_link_to_a_shared_file_becomes_a_spare_unread() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    let stamp = dir.file("/dl/link.mkv", b"the film", 5);
    dir.identities
        .insert(PathBuf::from("/dl/link.mkv"), identity);
    let (_, reports) = pass_knowing(&dir, &knowing(&shared, Some(identity)));
    assert_eq!(
        reports,
        [ScanReport::Spare(SpareCopy {
            path: "/dl/link.mkv".into(),
            file_hash: shared.file_hash,
            stamp,
            identity: Some(identity),
        })]
    );
    assert_eq!(dir.opens(), 0);
}

#[test]
fn a_renamed_spare_copy_is_carried_unread() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    let stamp = dir.file("/dl/copy.mkv", b"the film", 8);
    let copy_identity = dir.identify("/dl/copy.mkv", 9, 3);
    let recorded = SpareCopy {
        path: "/dl/copy.mkv".into(),
        file_hash: shared.file_hash,
        stamp,
        identity: Some(copy_identity),
    };
    dir.rename("/dl/copy.mkv", "/dl/copy2.mkv");
    let (_, reports) = pass_knowing(
        &dir,
        &Known {
            spares: vec![recorded.clone()],
            ..knowing(&shared, Some(identity))
        },
    );
    assert_eq!(
        reports,
        [
            ScanReport::SpareLeft("/dl/copy.mkv".into()),
            ScanReport::Spare(SpareCopy {
                path: "/dl/copy2.mkv".into(),
                ..recorded
            }),
        ]
    );
    assert_eq!(dir.opens(), 0);
}

#[test]
fn a_trusted_row_with_no_identity_is_given_one_once() {
    let mut dir = Scripted::new();
    let (shared, identity) = film(&mut dir);
    let (_, reports) = pass_knowing(&dir, &knowing(&shared, None));
    assert_eq!(
        reports,
        [ScanReport::Identified {
            file_hash: shared.file_hash,
            path: shared.path.clone(),
            identity,
        }]
    );
    let (_, again) = pass_knowing(&dir, &knowing(&shared, Some(identity)));
    assert!(again.is_empty());
    assert_eq!(dir.opens(), 0);
}
