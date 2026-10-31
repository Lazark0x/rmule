//! The line beside each part file that lets it outlive the store (ADR-0083):
//! `.<name>.part.link`, the file's canonical ed2k link, with its Part Hash Set
//! once one is known. The store's row is the only other link from a `.part`
//! to its hash and size, so losing the store would otherwise orphan every
//! partial for good. Plain text, so an operator can read it by hand.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rmule_primitives::{Ed2kFileLink, Ed2kLink};

use super::dot_sibling;

/// The suffix past the part file's own name.
const SUFFIX: &str = ".link";

/// Where the line for `part_path` lies.
pub(crate) fn beside(part_path: &Path) -> Option<PathBuf> {
    dot_sibling(part_path, SUFFIX)
}

/// Keep `link` beside `part_path`, written whole under another name so a
/// line that stands is a whole one.
///
/// # Errors
/// What the file system said.
pub(crate) fn keep(part_path: &Path, link: &str) -> io::Result<()> {
    let (Some(line), Some(partial)) = (beside(part_path), dot_sibling(part_path, ".link.new"))
    else {
        return Ok(());
    };
    let mut file = std::fs::File::create(&partial)?;
    writeln!(file, "{link}")?;
    file.sync_all()?;
    std::fs::rename(partial, line)
}

/// A part file and the link beside it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LinkedPart {
    /// The part file, which stands.
    pub part_path: PathBuf,
    /// What its line says.
    pub link: Ed2kFileLink,
}

/// Every part file in `temp_dir` with a readable line beside it. A line whose
/// part file is gone is the leftover of a finished download and is removed;
/// one that does not read is left for the operator's eyes.
pub(crate) fn linked_parts(temp_dir: &Path) -> Vec<LinkedPart> {
    let Ok(entries) = std::fs::read_dir(temp_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let part = name.to_str()?.strip_prefix('.')?.strip_suffix(SUFFIX)?;
            let part_path = temp_dir.join(part);
            if !part_path.is_file() {
                if let Err(error) = std::fs::remove_file(entry.path()) {
                    tracing::warn!(%error, "a part file's leftover line could not be removed");
                }
                return None;
            }
            let line = std::fs::read_to_string(entry.path()).ok()?;
            match Ed2kLink::parse(line.trim()) {
                Ok(Ed2kLink::File(link)) => Some(LinkedPart { part_path, link }),
                _ => {
                    tracing::warn!("a part file's line is no file link");
                    None
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_reads_back_and_one_left_by_a_gone_part_file_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let link = rmule_testkit::file_link("kept.bin", &[0x6D; 64]);
        let kept = dir.path().join("kept.bin.part");
        std::fs::write(&kept, b"bytes").unwrap();
        keep(&kept, &Ed2kLink::File(link.clone()).to_string()).unwrap();
        let gone = dir.path().join("gone.bin.part");
        keep(&gone, "ed2k://|nothing|/").unwrap();

        assert_eq!(
            linked_parts(dir.path()),
            vec![LinkedPart {
                part_path: kept,
                link
            }]
        );
        assert!(!beside(&gone).unwrap().exists());
    }
}
