//! The add's and the download directory's guards against a real filesystem,
//! which entries cover which, and which files a refused entry holds back.

use std::path::{Path, PathBuf};

use super::{DirectoryRefusal, ShareGuards, admit, covering, guard_in_place};

fn dirs(root: &Path, names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|name| {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::canonicalize(dir).unwrap()
        })
        .collect()
}

#[test]
fn an_add_answers_the_canonical_path_whatever_the_spelling() {
    let tmp = tempfile::tempdir().unwrap();
    let made = dirs(tmp.path(), &["films"]);
    let spelled = tmp.path().join("films/./../films");
    assert_eq!(
        admit(&spelled, &[], &ShareGuards::default()),
        Ok(made[0].clone())
    );
}

#[test]
fn the_guards_refuse_home_root_data_and_what_is_already_shared() {
    let tmp = tempfile::tempdir().unwrap();
    let made = dirs(
        tmp.path(),
        &[
            "home",
            "home/rmule-data",
            "home/rmule-data/sub",
            "media",
            "media/films",
        ],
    );
    let (home, data, inside_data, media, films) =
        (&made[0], &made[1], &made[2], &made[3], &made[4]);
    let guards = ShareGuards {
        home: Some(home.clone()),
        data_dir: Some(data.clone()),
    };
    let refused = |path: &Path, listed: &[PathBuf]| admit(path, listed, &guards).unwrap_err();
    assert_eq!(refused(home, &[]), DirectoryRefusal::HomeDirectory);
    assert_eq!(
        refused(Path::new("/"), &[]),
        DirectoryRefusal::FilesystemRoot
    );
    assert_eq!(refused(data, &[]), DirectoryRefusal::DataDirectory);
    assert_eq!(refused(inside_data, &[]), DirectoryRefusal::DataDirectory);
    assert_eq!(
        admit(
            &tmp.path().canonicalize().unwrap(),
            &[],
            &ShareGuards {
                home: None,
                data_dir: Some(data.clone()),
            }
        )
        .unwrap_err(),
        DirectoryRefusal::HoldsDataDirectory
    );
    assert_eq!(
        refused(media, std::slice::from_ref(media)),
        DirectoryRefusal::AlreadyShared
    );
    assert_eq!(
        refused(films, std::slice::from_ref(media)),
        DirectoryRefusal::InsideShared {
            parent: media.clone()
        }
    );
    assert_eq!(
        refused(&tmp.path().join("nothing here"), &[]),
        DirectoryRefusal::NotADirectory
    );
    // A parent of a listed entry is admitted: it replaces the entry.
    assert_eq!(
        admit(media, std::slice::from_ref(films), &guards),
        Ok(media.clone())
    );
}

/// The download directory need not be there yet, but one not made is judged
/// where it would be made, through a spelling that is not canonical: the
/// temporary directory itself lies behind a symlink on macOS.
#[test]
fn the_download_dir_is_guarded_where_it_would_be_made() {
    let tmp = tempfile::tempdir().unwrap();
    let made = dirs(tmp.path(), &["home", "home/rmule-data", "home/films"]);
    let guards = ShareGuards {
        home: Some(made[0].clone()),
        data_dir: Some(made[1].clone()),
    };
    let spelled = |name: &str| tmp.path().join(name);
    assert_eq!(
        guard_in_place(&spelled("home"), &guards),
        Err(DirectoryRefusal::HomeDirectory)
    );
    assert_eq!(
        guard_in_place(&spelled("home/rmule-data/incoming/new"), &guards),
        Err(DirectoryRefusal::DataDirectory)
    );
    assert_eq!(guard_in_place(&spelled("home/films"), &guards), Ok(()));
    assert_eq!(
        guard_in_place(&spelled("home/films/not-yet"), &guards),
        Ok(())
    );
}

#[test]
fn a_file_is_no_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("film.mkv");
    std::fs::write(&file, b"not a directory").unwrap();
    assert_eq!(
        admit(&file, &[], &ShareGuards::default()),
        Err(DirectoryRefusal::NotADirectory)
    );
}

#[test]
fn only_the_outermost_entries_are_scanned() {
    let entries = [
        PathBuf::from("/home/op/Downloads/rmule"),
        PathBuf::from("/srv/music"),
        PathBuf::from("/home/op/Downloads"),
    ];
    assert_eq!(
        covering(&entries),
        [
            (
                PathBuf::from("/home/op/Downloads/rmule"),
                Some(PathBuf::from("/home/op/Downloads"))
            ),
            (PathBuf::from("/srv/music"), None),
            (PathBuf::from("/home/op/Downloads"), None),
        ]
    );
}

/// Either reading of a path refusing it refuses it: a link under a refused
/// entry that leads out of it still lies in it by its name, while a passing
/// entry inside a refused one, reached through a link, shares its own files.
#[cfg(unix)]
#[test]
fn a_refused_entry_holds_back_every_spelling_of_what_lies_in_it() {
    let tmp = tempfile::tempdir().unwrap();
    let made = dirs(tmp.path(), &["home", "home/films", "elsewhere"]);
    let (home, films, elsewhere) = (&made[0], &made[1], &made[2]);
    std::os::unix::fs::symlink(elsewhere, home.join("out")).unwrap();
    std::os::unix::fs::symlink(films, tmp.path().join("to-films")).unwrap();
    let refused = super::RefusedFolders::read([(home.as_path(), true), (films.as_path(), false)]);

    assert!(refused.refuses(&home.join("out/a.bin")), "named under home");
    assert!(!refused.refuses(&elsewhere.join("a.bin")));
    assert!(!refused.refuses(&tmp.path().join("to-films/a.bin")));
    assert!(!refused.refuses(&films.join("a.bin")));
}
