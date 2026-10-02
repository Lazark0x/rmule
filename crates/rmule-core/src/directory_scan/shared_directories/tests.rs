//! The add's guards against a real filesystem, and which entries cover which.

use std::path::{Path, PathBuf};

use super::{DirectoryRefusal, ShareGuards, admit, covering};

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
