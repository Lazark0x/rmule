//! Unit tests for the Default App: the arguments each road builds from a
//! looked-up app, and the freedesktop reading over directories of the test's
//! own. No test starts a process.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use super::DefaultApp;
use super::freedesktop::{Dirs, lookup};

fn os(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

#[test]
fn each_road_names_the_app_and_hands_it_the_file_as_one_argument() {
    let file = Path::new("/films/a film.mkv.part");
    assert_eq!(
        DefaultApp::Bundle("/Applications/IINA.app".into()).argv(file),
        os(&[
            "/usr/bin/open",
            "-a",
            "/Applications/IINA.app",
            "/films/a film.mkv.part"
        ])
    );
    assert_eq!(
        DefaultApp::Program(r"C:\Program Files\VideoLAN\VLC\vlc.exe".into()).argv(file),
        os(&[
            r"C:\Program Files\VideoLAN\VLC\vlc.exe",
            "/films/a film.mkv.part"
        ])
    );
    assert_eq!(
        DefaultApp::DesktopEntry("/usr/share/applications/vlc.desktop".into()).argv(file),
        os(&[
            "gio",
            "launch",
            "/usr/share/applications/vlc.desktop",
            "/films/a film.mkv.part"
        ])
    );
}

/// A freedesktop tree: a config directory, then a user and a system data
/// directory, on a GNOME desktop.
fn tree() -> (tempfile::TempDir, Dirs) {
    let root = tempfile::tempdir().expect("temp dir");
    let dirs = Dirs {
        config: vec![root.path().join("config")],
        data: vec![root.path().join("user"), root.path().join("system")],
        desktops: vec!["gnome".to_string()],
    };
    (root, dirs)
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("a parent")).expect("dirs");
    fs::write(path, text).expect("file");
}

fn entry(dirs: &Dirs, name: &str) -> PathBuf {
    let path = dirs.data[1].join("applications").join(name);
    write(&path, "[Desktop Entry]\nType=Application\n");
    path
}

#[test]
fn the_heaviest_glob_names_the_type_case_folded_unless_it_is_marked_cs() {
    let (_root, dirs) = tree();
    write(
        &dirs.data[1].join("mime/globs2"),
        "# shared-mime-info\n50:video/x-matroska:*.mkv\n",
    );
    write(
        &dirs.data[0].join("mime/globs2"),
        "80:video/x-shouting:*.MKV:cs\n10:video/x-light:*.mkv\n",
    );
    write(
        &dirs.config[0].join("mimeapps.list"),
        "[Default Applications]\nvideo/x-matroska=vlc.desktop\nvideo/x-shouting=loud.desktop\nvideo/x-light=light.desktop\n",
    );
    let vlc = entry(&dirs, "vlc.desktop");
    let loud = entry(&dirs, "loud.desktop");
    entry(&dirs, "light.desktop");
    assert_eq!(lookup(&dirs, "mkv").expect("reads"), Some(vlc.clone()));
    assert_eq!(lookup(&dirs, "Mkv").expect("reads"), Some(vlc));
    assert_eq!(lookup(&dirs, "MKV").expect("reads"), Some(loud));
    assert_eq!(
        lookup(&dirs, "webm").expect("reads"),
        None,
        "no glob, no type"
    );
}

#[test]
fn the_first_installed_default_in_the_specs_order_wins_and_an_association_stands_in_for_none() {
    let (_root, dirs) = tree();
    write(
        &dirs.data[1].join("mime/globs2"),
        "50:video/mp4:*.mp4\n50:audio/flac:*.flac\n50:audio/ogg:*.ogg\n50:audio/x-none:*.none\n",
    );
    write(
        &dirs.config[0].join("gnome-mimeapps.list"),
        "[Default Applications]\nvideo/mp4=gone.desktop;kde-mpv.desktop;\n",
    );
    write(
        &dirs.config[0].join("mimeapps.list"),
        "[Default Applications]\nvideo/mp4=vlc.desktop\n\n[Added Associations]\naudio/flac=removed.desktop;vlc.desktop;\n\n[Removed Associations]\naudio/flac=removed.desktop;\n",
    );
    write(
        &dirs.data[1].join("applications/mimeinfo.cache"),
        "[MIME Cache]\naudio/ogg=vlc.desktop;\n",
    );
    let vlc = entry(&dirs, "vlc.desktop");
    let mpv = entry(&dirs, "kde/mpv.desktop");
    entry(&dirs, "removed.desktop");
    assert_eq!(
        lookup(&dirs, "mp4").expect("reads"),
        Some(mpv),
        "the desktop's own list first, an entry not installed passed over, a dash read as a folder"
    );
    assert_eq!(lookup(&dirs, "flac").expect("reads"), Some(vlc.clone()));
    assert_eq!(lookup(&dirs, "ogg").expect("reads"), Some(vlc));
    assert_eq!(
        lookup(&dirs, "none").expect("reads"),
        None,
        "a type no app opens"
    );
}

#[cfg(unix)]
#[test]
fn the_directories_fall_back_to_the_specs_defaults_and_drop_a_relative_one() {
    let dirs = Dirs::from_vars(|name| {
        match name {
            "HOME" => Some("/home/op"),
            "XDG_CONFIG_HOME" => Some(""),
            "XDG_DATA_DIRS" => Some("/opt/share:relative/share"),
            "XDG_CURRENT_DESKTOP" => Some("ubuntu:GNOME"),
            _ => None,
        }
        .map(OsString::from)
    });
    assert_eq!(
        dirs,
        Dirs {
            config: vec!["/home/op/.config".into(), "/etc/xdg".into()],
            data: vec!["/home/op/.local/share".into(), "/opt/share".into()],
            desktops: vec!["ubuntu".to_string(), "gnome".to_string()],
        }
    );
}
