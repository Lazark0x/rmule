//! The **free name** a file takes when its own is taken (ADR-0115): the
//! numbered `stem (n).ext` beside it, `n` counting from one, the first for
//! which nothing stands. A placement and a completion move choose by the same
//! rule, so a download that found its name taken at either end reads the
//! same.

use std::path::{Path, PathBuf};

/// `name` as the `n`th numbered name: `stem (n).ext`, or `name (n)` for a
/// name with no extension. Only a space, parentheses and digits are added,
/// so a cleaned name stays one path component.
pub(crate) fn numbered(name: &str, n: u32) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

/// `path` itself when `taken` says it is free, or the first numbered name
/// beside it that `taken` leaves free. A path with no file name is answered
/// as it is.
pub(crate) fn first_free(path: &Path, taken: impl Fn(&Path) -> bool) -> PathBuf {
    if !taken(path) {
        return path.to_path_buf();
    }
    let Some(name) = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return path.to_path_buf();
    };
    (1..)
        .map(|n| path.with_file_name(numbered(&name, n)))
        .find(|candidate| !taken(candidate))
        .expect("an unbounded range finds a free name")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    use super::first_free;

    #[test]
    fn a_taken_name_takes_the_first_numbered_name_beside_it_left_free() {
        let taken: HashSet<PathBuf> = ["/dl/film.mkv", "/dl/film (1).mkv", "/dl/notes"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let is_taken = |path: &Path| taken.contains(path);
        assert_eq!(
            first_free(Path::new("/dl/film.mkv"), is_taken),
            Path::new("/dl/film (2).mkv")
        );
        assert_eq!(
            first_free(Path::new("/dl/notes"), is_taken),
            Path::new("/dl/notes (1)")
        );
        assert_eq!(
            first_free(Path::new("/dl/.hidden"), |path| path
                == Path::new("/dl/.hidden")),
            Path::new("/dl/.hidden (1)")
        );
        assert_eq!(
            first_free(Path::new("/dl/free.iso"), is_taken),
            Path::new("/dl/free.iso")
        );
    }
}
