//! Set-aside rows and the add's confirm against a scripted directory
//! (ADR-0101, "Shared Directories"): a directory added again reads nothing
//! its set-aside rows still describe, and an add asks even when nothing
//! would be read.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use rmule_primitives::{FileHashSummary, PartHash};

use super::super::scripted::{ROOT, Scripted, row};
use super::super::{
    Consent, DirectoryOffer, Known, Memory, PassEnd, ProgressCell, ScanReport, SetAside, run_pass,
};
use super::shared_paths;

fn pass_knowing(dir: &Scripted, known: &Known, consent: Consent) -> (PassEnd, Vec<ScanReport>) {
    let progress: ProgressCell = Arc::new(Mutex::new(None));
    let mut reports = Vec::new();
    let end = run_pass(
        dir,
        Path::new(ROOT),
        &mut || Some(known.clone()),
        consent,
        &AtomicBool::new(false),
        &progress,
        &mut Memory::default(),
        &mut |report| reports.push(report),
    );
    (end, reports)
}

/// The set-aside row a remove left for `bytes` at `path`, its part hash set
/// one no read could produce, so a share of it proves nothing was read.
fn set_aside(dir: &mut Scripted, path: &str, bytes: &[u8], modified: u64) -> SetAside {
    let stamp = dir.file(path, bytes, modified);
    let mut entry = row(path, stamp, 0);
    entry.file_hash = FileHashSummary::digest_bytes(bytes).file_hash();
    entry.name = Path::new(path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    entry.part_hashes = vec![PartHash::from_bytes([
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1,
        0xF0,
    ])];
    SetAside {
        entry,
        identity: None,
    }
}

fn knowing(asides: &[SetAside]) -> Known {
    Known {
        set_aside: asides
            .iter()
            .map(|aside| (aside.entry.path.clone(), aside.clone()))
            .collect(),
        ..Known::default()
    }
}

#[test]
fn a_directory_added_again_shares_its_set_aside_rows_unread() {
    let mut dir = Scripted::new();
    let film = set_aside(&mut dir, "/dl/film.mkv", b"film bytes", 11);
    dir.dir("/dl/music");
    let song = set_aside(&mut dir, "/dl/music/song.ogg", b"song bytes", 12);
    let known = knowing(&[film.clone(), song.clone()]);
    let asked = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&asked);
    let (end, reports) = pass_knowing(
        &dir,
        &known,
        Consent::Confirm(Box::new(move |offer| {
            *seen.lock().unwrap() = Some(offer);
            true
        })),
    );
    assert_eq!(dir.opens(), 0, "nothing read");
    assert_eq!(
        *asked.lock().unwrap(),
        Some(DirectoryOffer {
            files: 2,
            bytes: 20,
            unread: 2
        })
    );
    assert!(matches!(end, PassEnd::Finished(s) if s.trusted == 2 && s.hashed == 0));
    let shared: Vec<_> = reports
        .iter()
        .filter_map(|report| match report {
            ScanReport::Share(entry) => Some(entry.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(shared, [film.entry, song.entry]);
}

#[test]
fn a_set_aside_row_the_file_no_longer_matches_is_dropped_and_the_file_read() {
    let mut dir = Scripted::new();
    let old = set_aside(&mut dir, "/dl/film.mkv", b"film bytes", 11);
    dir.file("/dl/film.mkv", b"film bytes, recut", 13);
    let (_, reports) = pass_knowing(&dir, &knowing(&[old]), Consent::Given);
    assert!(reports.contains(&ScanReport::SetAsideLeft(PathBuf::from("/dl/film.mkv"))));
    assert_eq!(dir.opens(), 1);
    assert_eq!(shared_paths(&reports), [PathBuf::from("/dl/film.mkv")]);
}

#[test]
fn an_added_directory_is_asked_about_even_when_it_would_read_nothing() {
    let dir = Scripted::new();
    let asked = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&asked);
    let (end, _) = pass_knowing(
        &dir,
        &Known::default(),
        Consent::Confirm(Box::new(move |offer| {
            *seen.lock().unwrap() = Some(offer);
            false
        })),
    );
    assert_eq!(*asked.lock().unwrap(), Some(DirectoryOffer::default()));
    assert_eq!(end, PassEnd::Declined);
}
