//! Unit tests for Preview: the Player Command's words, the arguments a
//! launch hands the player, the Preview Ready reading and a launch's notes.

use std::path::{Path, PathBuf};

use super::*;
use crate::fixture::{diag, download_id, preview_ready, rooted};

fn args(command: &str, path: &Path) -> Vec<OsString> {
    argv(&split(command).expect("splits"), path)
}

fn os(text: &str) -> OsString {
    OsString::from(text)
}

#[test]
fn a_text_splits_by_posix_rules_with_nothing_expanded() {
    assert_eq!(
        split(r#"'/opt/my player/mpv' --title="a b" \$HOME *.mkv # rest"#),
        Ok(vec![
            "/opt/my player/mpv".to_string(),
            "--title=a b".to_string(),
            "$HOME".to_string(),
            "*.mkv".to_string(),
        ])
    );
}

#[test]
fn an_open_quote_or_a_lone_backslash_is_refused() {
    assert_eq!(split(r#"mpv "--title=a"#), Err(Unsplittable::OpenQuote));
    assert_eq!(split(r"mpv \"), Err(Unsplittable::OpenQuote));
}

#[test]
fn a_first_word_that_is_the_file_or_no_word_at_all_is_refused() {
    assert_eq!(split("%PARTFILE --fs"), Err(Unsplittable::NoProgram));
    assert_eq!(split("x%PARTFILE"), Err(Unsplittable::NoProgram));
    assert_eq!(split("# only a comment"), Err(Unsplittable::NoProgram));
}

/// `path` as one word of a Player Command.
fn word(path: &Path) -> String {
    let path = path.to_str().expect("a temp path is UTF-8");
    shlex::try_quote(path).expect("quotes").into_owned()
}

/// A folder named `name` in a fresh temp dir, which is kept while it lives.
fn folder(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let folder = dir.path().join(name);
    std::fs::create_dir(&folder).expect("folder");
    (dir, folder)
}

#[test]
fn a_first_word_naming_a_folder_is_refused_and_a_path_not_there_yet_is_taken() {
    let (dir, player) = folder("player");
    assert_eq!(
        split(&format!("{} --fs", word(&player))),
        Err(Unsplittable::Folder)
    );
    let missing = dir.path().join("mpv");
    assert_eq!(
        split(&word(&missing)),
        Ok(vec![missing.display().to_string()]),
        "a player may be installed after it is set"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn a_folder_named_app_is_only_a_folder_off_macos() {
    let (_dir, bundle) = folder("IINA.app");
    assert_eq!(split(&word(&bundle)), Err(Unsplittable::Folder));
}

#[cfg(target_os = "macos")]
#[test]
fn a_macos_app_bundle_opens_through_launch_services_with_the_app_named() {
    let (_dir, bundle) = folder("IINA.app");
    let named = bundle.to_str().expect("a temp path is UTF-8");
    let file = Path::new("/films/a.mkv.part");
    let opened = |words: &[&str]| {
        [os("/usr/bin/open"), os("-a")]
            .into_iter()
            .chain(words.iter().copied().map(os))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        args(&word(&bundle), file),
        opened(&[named, "/films/a.mkv.part"])
    );
    assert_eq!(
        args(&format!("{} -n", word(&bundle)), file),
        opened(&[named, "-n", "/films/a.mkv.part"]),
        "the other words are open's own, and the file goes last"
    );
    assert_eq!(
        args(&format!("{} %PARTFILE --args --fs", word(&bundle)), file),
        opened(&[named, "/films/a.mkv.part", "--args", "--fs"]),
        "placed before --args, the file is opened, not handed to the app's main"
    );
    let completed = format!("{named}/");
    assert_eq!(
        args(&shlex::try_quote(&completed).expect("quotes"), file),
        opened(&[&completed, "/films/a.mkv.part"]),
        "a shell's completion ends the bundle in a slash"
    );
}

#[test]
fn the_placeholder_is_replaced_in_every_word_that_holds_it_and_the_path_goes_last_without_one() {
    let path = Path::new("/films/a.mkv.part");
    assert_eq!(
        args("mpv %PARTFILE --fs", path),
        [os("mpv"), os("/films/a.mkv.part"), os("--fs")]
    );
    assert_eq!(
        args("mpv --sub-file=%PARTFILE.srt", path),
        [os("mpv"), os("--sub-file=/films/a.mkv.part.srt")],
        "inside a word, the word stays one argument and the path is not appended"
    );
    assert_eq!(
        args("mpv %PARTFILE --x=%PARTFILE%PARTFILE", path),
        [
            os("mpv"),
            os("/films/a.mkv.part"),
            os("--x=/films/a.mkv.part/films/a.mkv.part"),
        ]
    );
    assert_eq!(
        args("mpv --fs", path),
        [os("mpv"), os("--fs"), os("/films/a.mkv.part")]
    );
}

#[test]
fn a_single_quoted_windows_program_stays_literal() {
    assert_eq!(
        args(
            r"'C:\Program Files\vlc.exe' --fullscreen",
            Path::new("D:/a.mkv.part")
        ),
        [
            os(r"C:\Program Files\vlc.exe"),
            os("--fullscreen"),
            os("D:/a.mkv.part"),
        ]
    );
}

/// The path enters no shell and no split: whatever it holds, it is one
/// argument, as is a word it is placed into.
#[test]
fn a_path_holding_shell_syntax_is_one_argument() {
    let path = PathBuf::from("/films/a \"b\"; $(rm -rf ~)\nc.mkv.part");
    assert_eq!(
        args("mpv", &path),
        [os("mpv"), path.clone().into_os_string()]
    );
    let mut word = os("--file=");
    word.push(path.as_os_str());
    assert_eq!(args("mpv --file=%PARTFILE", &path), [os("mpv"), word]);
}

#[cfg(unix)]
#[test]
fn a_path_whose_bytes_are_not_utf8_reaches_the_player_unchanged() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let path = Path::new(std::ffi::OsStr::from_bytes(b"/films/\xff\xfe.mkv.part"));
    let argv = args("mpv --file=%PARTFILE", path);
    assert_eq!(
        argv[1].clone().into_vec(),
        b"--file=/films/\xff\xfe.mkv.part".to_vec()
    );
}

#[test]
fn a_ready_download_hands_over_its_published_path_and_the_command() {
    let state = preview_ready();
    let target = preview_target(&state, download_id(1)).expect("ready");
    assert_eq!(target.path, rooted("films/film.mkv.part"));
    assert_eq!(target.player, Player::Command("mpv --fs"));
}

#[test]
fn without_a_player_command_a_ready_download_goes_to_the_default_app_for_its_names_extension() {
    let mut state = preview_ready();
    state.preferences.player_command = None;
    let target = preview_target(&state, download_id(1)).expect("ready");
    assert_eq!(target.path, rooted("films/film.mkv.part"));
    assert_eq!(target.player, Player::DefaultApp("mkv"));
}

#[test]
fn the_extension_is_the_names_last_dot_on_and_a_stem_that_is_not_utf8_keeps_it() {
    assert_eq!(extension(b"film.part.mkv"), Some("mkv"));
    assert_eq!(extension(b"\xff\xfe film.MKV"), Some("MKV"));
    assert_eq!(extension(b"film"), None);
    assert_eq!(extension(b".mkv"), None, "a leading dot names no extension");
    assert_eq!(extension(b"film."), None);
    assert_eq!(
        extension(b"film.\xff"),
        None,
        "an extension that is not UTF-8 names no type"
    );
}

/// Each block is the one shown when it is the first that holds, even with
/// every later one holding too.
#[test]
fn each_block_is_shown_when_it_is_the_first_that_holds() {
    let id = download_id(1);
    let block = |change: &dyn Fn(&mut UiState)| {
        let mut state = preview_ready();
        change(&mut state);
        preview_target(&state, id).err()
    };
    let no_part_map = |state: &mut UiState| {
        state.diagnostics.downloads.remove(&download_id(1));
    };
    let not_previewable = |state: &mut UiState| {
        let row = state.downloads.get_mut(&download_id(1)).expect("row");
        row.metadata.as_mut().expect("metadata").name =
            rmule_primitives::Ed2kText::from_utf8("notes.txt");
        no_part_map(state);
    };
    assert_eq!(
        block(&|state| {
            not_previewable(state);
            state.downloads.get_mut(&id).expect("row").file_path = None;
        }),
        Some(PreviewBlock::DetailsUnknown)
    );
    assert_eq!(
        block(&|state| state.downloads.get_mut(&id).expect("row").metadata = None),
        Some(PreviewBlock::DetailsUnknown)
    );
    assert_eq!(
        block(&|state| {
            state.downloads.remove(&id);
        }),
        Some(PreviewBlock::DetailsUnknown)
    );
    assert_eq!(block(&not_previewable), Some(PreviewBlock::NotPreviewable));
    assert_eq!(block(&no_part_map), Some(PreviewBlock::NoPartMap));
    assert_eq!(
        block(&|state| {
            state
                .diagnostics
                .downloads
                .insert(id, diag(id, 0x4D, "IV", 0, vec![]));
        }),
        Some(PreviewBlock::HeadNotVerified)
    );
}

/// A completed download is ready on its finished file whatever its part map
/// says, and a resting failed one is ready on its `.part` once part 0 holds.
#[test]
fn a_completed_download_is_ready_whatever_its_parts_and_a_failed_one_by_its_first_part() {
    let id = download_id(1);
    let mut state = preview_ready();
    let row = state.downloads.get_mut(&id).expect("row");
    row.status = DownloadStatus::Completed;
    row.file_path = Some(rooted("films/film.mkv"));
    state
        .diagnostics
        .downloads
        .insert(id, diag(id, 0x4D, "MM", 0, vec![]));
    assert_eq!(
        preview_target(&state, id).map(|target| target.path),
        Ok(rooted("films/film.mkv").as_path())
    );

    let mut state = preview_ready();
    state.downloads.get_mut(&id).expect("row").status = DownloadStatus::Failed;
    assert!(preview_target(&state, id).is_ok());
}

/// A completion move hands Preview the `.part` while the `.part` still holds
/// the bytes, and the finished file once core says the file is in place:
/// waiting for the store follows a rename that took the `.part` away.
#[test]
fn a_move_past_its_swap_hands_preview_the_finished_file() {
    use rmule_core::{CompletionStep, CoreEvent, DownloadEvent};

    let id = download_id(1);
    let mut state = preview_ready();
    let to = rooted("films/film (1).mkv");
    let completing = |step| {
        CoreEvent::Download(DownloadEvent::Completing {
            download_id: id,
            to: to.clone(),
            step,
        })
    };
    crate::state::fold(&mut state, completing(CompletionStep::WaitingForRelease));
    assert_eq!(
        preview_target(&state, id).map(|target| target.path),
        Ok(rooted("films/film.mkv.part").as_path()),
        "the rename has not happened"
    );
    crate::state::fold(&mut state, completing(CompletionStep::WaitingForStore));
    assert_eq!(
        preview_target(&state, id).map(|target| target.path),
        Ok(to.as_path())
    );
}

/// The exit status of a Unix process `code` ended with, or Windows' own.
fn exited(code: i32) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        std::os::unix::process::ExitStatusExt::from_raw(code << 8)
    }
    #[cfg(windows)]
    {
        std::os::windows::process::ExitStatusExt::from_raw(code as u32)
    }
}

#[test]
fn a_clean_exit_says_nothing_and_any_other_names_the_download_and_its_status() {
    use crate::words::player::exit_note;
    assert_eq!(exit_note("film.mkv", exited(0)), None);
    assert_eq!(
        exit_note("film.mkv", exited(2))
            .as_ref()
            .map(|note| note.as_str()),
        Some("preview of film.mkv: the player ended with status 2")
    );
}

#[cfg(unix)]
#[test]
fn a_player_stopped_by_a_signal_says_so() {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        crate::words::player::exit_note("film.mkv", std::process::ExitStatus::from_raw(9))
            .as_ref()
            .map(|note| note.as_str()),
        Some("preview of film.mkv: the player was stopped by a signal")
    );
}

#[test]
fn a_refused_spawn_names_the_download_and_the_cause_in_the_operators_words() {
    assert_eq!(
        crate::words::player::spawn_refused("film.mkv", std::io::ErrorKind::NotFound).as_str(),
        "preview of film.mkv: the player could not start: it is not there"
    );
    assert_eq!(
        crate::words::player::spawn_refused("film.mkv", std::io::ErrorKind::PermissionDenied)
            .as_str(),
        "preview of film.mkv: the player could not start: the program is not executable"
    );
}

#[test]
fn a_type_with_no_default_app_says_so_and_points_to_the_player_setting() {
    assert_eq!(
        crate::words::player::no_app("film.mkv", "mkv").as_str(),
        "preview of film.mkv: no app opens .mkv files here — set a player in Settings"
    );
    assert_eq!(
        crate::words::player::lookup_failed("film.mkv", "mkv", std::io::ErrorKind::NotFound)
            .as_str(),
        "preview of film.mkv: the app for .mkv files could not be looked up: it is not there"
    );
}
