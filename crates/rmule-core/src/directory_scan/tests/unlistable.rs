//! A subfolder the pass cannot list (ADR-0106, "One look, five answers"):
//! what it hides is looked at path by path, and a row that cannot be looked
//! at is withheld as unreadable, never gone.

use super::*;

fn hash(tag: u8) -> FileHash {
    FileHash::from_bytes([tag; FileHash::BYTE_LEN])
}

fn ruled_gone(reports: &[ScanReport], tag: u8) -> bool {
    reports.iter().any(|report| match report {
        ScanReport::Gone { file_hash, .. }
        | ScanReport::Held { file_hash, .. }
        | ScanReport::Unshare(file_hash) => *file_hash == hash(tag),
        _ => false,
    })
}

#[test]
fn a_row_under_a_folder_that_cannot_be_opened_is_withheld_never_gone() {
    let mut dir = Scripted::new();
    dir.dir("/dl/Movies");
    let film = dir.file("/dl/Movies/film.mkv", b"film", 1);
    let gone = dir.file("/dl/gone.bin", b"gone", 1);
    dir.remove("/dl/gone.bin");
    dir.sealed.insert(PathBuf::from("/dl/Movies"));
    let outcome = pass(
        &dir,
        &[
            row("/dl/Movies/film.mkv", film, 1),
            row("/dl/gone.bin", gone, 2),
        ],
    );
    assert!(outcome.reports.contains(&ScanReport::Unreadable {
        file_hash: hash(1),
        path: PathBuf::from("/dl/Movies/film.mkv"),
        kind: io::ErrorKind::PermissionDenied,
    }));
    assert!(!ruled_gone(&outcome.reports, 1), "{:?}", outcome.reports);
    assert!(ruled_gone(&outcome.reports, 2), "the pass still rules");
}

#[test]
fn a_folder_that_only_refuses_its_listing_keeps_its_rows_by_their_own_looks() {
    let mut dir = Scripted::new();
    dir.dir("/dl/Movies");
    let film = dir.file("/dl/Movies/film.mkv", b"film", 1);
    let gone = dir.file("/dl/Movies/gone.mkv", b"gone", 1);
    dir.remove("/dl/Movies/gone.mkv");
    dir.unlistable.insert(PathBuf::from("/dl/Movies"));
    let outcome = pass(
        &dir,
        &[
            row("/dl/Movies/film.mkv", film, 1),
            row("/dl/Movies/gone.mkv", gone, 2),
        ],
    );
    assert!(!ruled_gone(&outcome.reports, 1), "{:?}", outcome.reports);
    assert!(
        !outcome
            .reports
            .iter()
            .any(|report| matches!(report, ScanReport::Unreadable { .. })),
    );
    assert!(ruled_gone(&outcome.reports, 2), "{:?}", outcome.reports);
    assert!(matches!(outcome.end, PassEnd::Finished(s) if s.trusted == 1));
}
