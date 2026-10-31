//! A file name from the network, cleaned so it can be joined to a local
//! directory and still name a file inside it. Links, search rows and peers
//! all carry a name the counterparty chose; `Path::join` with an absolute
//! name replaces the base, and a `..` component leaves it.
//!
//! One portable policy, the same on every platform: a name is cleaned for
//! the strictest file system rmule runs on, Windows, wherever rmule itself
//! runs. A file fetched on Linux is often copied to a Windows machine
//! afterwards, the name a download is stored under never depends on where
//! it was added, and the rules are tested on every host alike. Windows
//! refuses the characters dropped here, drops a trailing dot or space when
//! it creates the file (so the file would not be found under the name
//! asked for), and opens a device for a reserved name such as `CON` or
//! `NUL.txt`, whatever its case or extension.

use std::path::{Path, PathBuf};

use icu_normalizer::ComposingNormalizerBorrowed;

use crate::{Ed2kFileLink, FileHash};

/// A remote file name, cleaned to one path component.
///
/// Cleaned the way aMule's `DoCleanup` cleans the name of a completed file
/// (`src/libs/common/Path.cpp:112-145`, called with spaces kept from
/// `ThreadTasks.cpp:444`): every `/` and every character below U+0020 is
/// dropped, and so are `" * < > ? | \ :`. aMule drops that second set only
/// on a file system that cannot hold them; rmule drops it on every one, so a
/// name never carries the other platform's separator or a drive prefix.
/// Trailing dots and spaces are dropped next. A name that cleans to nothing
/// (dots or spaces alone) names no file inside the directory, and the file's
/// hash stands in for it. Last, a name whose part before its first dot is a
/// Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`, `LPT1` and the
/// rest; any case, trailing spaces ignored) gains a leading `_`, so
/// `nul.txt` is kept as `_nul.txt`. A name past [`Self::MAX_BYTES`] keeps its
/// extension and a stem cut on a character boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeFileName(String);

impl SafeFileName {
    /// The bytes a name keeps, so every file made from it fits the strictest
    /// volume, 255 bytes (ext4), which also bounds the 255 UTF-16 units of
    /// exFAT and NTFS: the part file `<name> (n).part`, the Hole Probe's
    /// `.<name> (n).part.holeprobe` and the Completion Copy's
    /// `.<name> (n).completing`, the number up to five digits (ADR-0115).
    pub const MAX_BYTES: usize = 230;

    /// The cleaned name of the file `link` names.
    #[must_use]
    pub fn of_link(link: &Ed2kFileLink) -> Self {
        Self::clean(&link.name.to_display_string(), &link.file_hash)
    }

    /// `name` cleaned, or the upper-case hex of `hash` when nothing usable is
    /// left of it.
    #[must_use]
    pub fn clean(name: &str, hash: &FileHash) -> Self {
        let kept: String = name.chars().filter(|&c| !is_dropped(c)).collect();
        let cleaned = kept.trim_end_matches(['.', ' ']);
        if cleaned.is_empty() {
            return Self(hash.to_hex_upper());
        }
        if names_a_device(cleaned) {
            return Self(shortened(&format!("_{cleaned}")));
        }
        Self(shortened(cleaned))
    }

    /// The cleaned name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path of this file inside `dir`: always a direct child of it.
    #[must_use]
    pub fn path_in(&self, dir: &Path) -> PathBuf {
        dir.join(&self.0)
    }
}

/// `text` as the strictest volume compares a name: NFC, then lowered character
/// by character, with final sigma as sigma. A name that comes from a peer can
/// spell another's file (ADR-0115). Measured on exFAT: `Я` is `я`, `Ω` is `ω`,
/// NFC is NFD, and `ß` and `ı` stay themselves, as lowering leaves them.
#[must_use]
pub fn fold_as_a_volume(text: &str) -> String {
    ComposingNormalizerBorrowed::new_nfc()
        .normalize(text)
        .chars()
        .flat_map(char::to_lowercase)
        .map(|c| if c == '\u{3c2}' { '\u{3c3}' } else { c })
        .collect()
}

/// The longest extension a shortened name keeps: past it the tail of a long
/// name is no extension.
const MAX_KEPT_EXTENSION_BYTES: usize = 32;

/// `name` within [`SafeFileName::MAX_BYTES`]: its stem cut on a character
/// boundary, its extension kept, no trailing dot or space left by the cut.
fn shortened(name: &str) -> String {
    if name.len() <= SafeFileName::MAX_BYTES {
        return name.to_owned();
    }
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 && name.len() - dot <= MAX_KEPT_EXTENSION_BYTES => name.split_at(dot),
        _ => (name, ""),
    };
    let mut end = SafeFileName::MAX_BYTES - extension.len();
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    let stem = stem[..end].trim_end_matches(['.', ' ']);
    format!("{stem}{extension}")
}

fn is_dropped(c: char) -> bool {
    c < ' ' || matches!(c, '/' | '\\' | '"' | '*' | '<' | '>' | '?' | '|' | ':')
}

/// The names Windows opens as a device rather than a file, with or without
/// an extension: the console (and its two handles), the printer, the
/// auxiliary port, the null device, and the serial and parallel ports,
/// numbered 0 to 9 or with a superscript 1 to 3.
const RESERVED_DEVICE_NAMES: [&str; 32] = [
    "CON",
    "CONIN$",
    "CONOUT$",
    "PRN",
    "AUX",
    "NUL",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// Whether Windows would open `name` as a device: the part before its first
/// dot, trailing spaces dropped, is a reserved name in any case.
fn names_a_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    RESERVED_DEVICE_NAMES
        .iter()
        .any(|device| device.eq_ignore_ascii_case(stem))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> FileHash {
        FileHash::from_hex("31D6CFE0D16AE931B73C59D7E0C089C0").unwrap()
    }

    fn joined(name: &str) -> PathBuf {
        SafeFileName::clean(name, &hash()).path_in(Path::new("/dl"))
    }

    fn cleaned(name: &str) -> String {
        SafeFileName::clean(name, &hash()).as_str().to_owned()
    }

    #[test]
    fn a_parent_walk_stays_inside_the_directory() {
        assert_eq!(joined("../../etc/passwd"), Path::new("/dl/....etcpasswd"));
    }

    #[test]
    fn an_absolute_name_does_not_replace_the_directory() {
        assert_eq!(joined("/abs/path.bin"), Path::new("/dl/abspath.bin"));
    }

    #[test]
    fn a_windows_path_loses_its_drive_and_separators() {
        assert_eq!(joined(r"C:\Windows\x.dll"), Path::new("/dl/CWindowsx.dll"));
    }

    #[test]
    fn nul_and_control_characters_are_dropped_and_spaces_kept() {
        assert_eq!(joined("a\0b\tc d.avi"), Path::new("/dl/abc d.avi"));
    }

    #[test]
    fn every_character_windows_refuses_is_dropped() {
        assert_eq!(
            cleaned("a<b>c:d\"e/f\\g|h?i*j\u{1f}k.bin"),
            "abcdefghijk.bin"
        );
    }

    #[test]
    fn trailing_dots_and_spaces_are_dropped() {
        for (name, kept) in [
            ("movie.avi.", "movie.avi"),
            ("movie.avi ", "movie.avi"),
            ("movie.avi. . ", "movie.avi"),
            ("archive..", "archive"),
            (" leading kept", " leading kept"),
            (".hidden", ".hidden"),
            ("a . b", "a . b"),
        ] {
            assert_eq!(cleaned(name), kept, "{name:?}");
        }
    }

    #[test]
    fn a_device_name_alone_gains_a_leading_underscore_in_any_case() {
        for name in [
            "CON",
            "con",
            "Prn",
            "aux",
            "NUL",
            "COM0",
            "com1",
            "COM9",
            "lpt0",
            "LPT9",
            "COM\u{b9}",
            "lpt\u{b3}",
            "CONIN$",
            "conout$",
        ] {
            assert_eq!(cleaned(name), format!("_{name}"), "{name:?}");
        }
    }

    #[test]
    fn a_device_name_with_an_extension_is_still_a_device() {
        for (name, kept) in [
            ("NUL.txt", "_NUL.txt"),
            ("con.tar.gz", "_con.tar.gz"),
            ("Aux .avi", "_Aux .avi"),
            ("com3..log", "_com3..log"),
            ("lpt1.", "_lpt1"),
            ("PRN ", "_PRN"),
        ] {
            assert_eq!(cleaned(name), kept, "{name:?}");
        }
    }

    #[test]
    fn a_name_that_only_starts_like_a_device_is_kept() {
        for name in [
            "CONSOLE.txt",
            "COM10",
            "LPT",
            "nul_device.bin",
            "a.CON",
            "my con.txt",
            " NUL.txt",
        ] {
            assert_eq!(cleaned(name), name, "{name:?}");
        }
    }

    #[test]
    fn a_name_of_dots_alone_takes_the_hash() {
        for name in ["..", ".", "", "/../", "\0", " ", ". .", "... "] {
            assert_eq!(
                joined(name),
                Path::new("/dl/31D6CFE0D16AE931B73C59D7E0C089C0"),
                "{name:?}"
            );
        }
    }

    #[test]
    fn every_cleaned_name_is_one_component_inside_the_directory() {
        for name in ["../x", "/x", r"..\x", "a/../../b", "C:x", "x/..", "..."] {
            let path = joined(name);
            assert_eq!(
                path.parent(),
                Some(Path::new("/dl")),
                "{name:?} gave {path:?}"
            );
            assert!(
                path.components()
                    .all(|c| !matches!(c, std::path::Component::ParentDir)),
                "{name:?} gave {path:?}"
            );
        }
    }

    /// A name past the cap keeps its extension and a stem cut on a character
    /// boundary, so every file made from it fits a volume's 255 bytes.
    #[test]
    fn a_name_past_the_cap_is_shortened_and_keeps_its_extension() {
        let hash = FileHash::from_bytes([1; FileHash::BYTE_LEN]);
        let long = format!("{}.mkv", "\u{6f22}".repeat(100));
        let name = SafeFileName::clean(&long, &hash);
        assert!(name.as_str().len() <= SafeFileName::MAX_BYTES);
        assert!(name.as_str().ends_with("\u{6f22}.mkv"), "{}", name.as_str());

        let no_extension = "a".repeat(300);
        assert_eq!(
            SafeFileName::clean(&no_extension, &hash).as_str().len(),
            SafeFileName::MAX_BYTES
        );

        let cut_before_a_space = format!("{}  b{}.iso", "a".repeat(224), "c".repeat(50));
        assert_eq!(
            SafeFileName::clean(&cut_before_a_space, &hash).as_str(),
            format!("{}.iso", "a".repeat(224))
        );

        let fits = format!("{}.mkv", "a".repeat(SafeFileName::MAX_BYTES - 4));
        assert_eq!(SafeFileName::clean(&fits, &hash).as_str(), fits);
    }

    #[test]
    fn what_a_volume_folds_is_one_name_and_what_it_keeps_is_two() {
        let one = |a: &str, b: &str| fold_as_a_volume(a) == fold_as_a_volume(b);
        assert!(one("Film", "film"));
        assert!(one("\u{42f}", "\u{44f}"), "Я is я");
        assert!(one("\u{3a9}", "\u{3c9}"), "Ω is ω");
        assert!(one("\u{3a3}", "\u{3c2}"), "Σ is ς");
        assert!(one("caf\u{e9}", "cafe\u{301}"), "NFC is NFD");
        assert!(!one("stra\u{df}e", "strasse"), "ß stays itself");
        assert!(!one("\u{131}", "i"), "ı stays itself");
    }
}
