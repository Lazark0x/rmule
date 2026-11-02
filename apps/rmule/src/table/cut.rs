//! Free text in a cell that cannot hold it: cut in the middle, by display
//! width, on grapheme boundaries, keeping a file's extension (ADR-0119).
//!
//! The start of a name and its end are what tell two files apart, and the
//! extension says what the file is, so the cut falls between them. The ends
//! are measured in cells and walked by grapheme cluster, so a wide glyph is
//! never halved and a combining mark never leaves its letter.

use unicode_segmentation::UnicodeSegmentation;

use crate::wrap::display_width;

/// What stands in for the text a cut took out.
const CUT: &str = "…";

/// The widest extension a cut keeps, its dot included: `.torrent` fits, and
/// anything longer is more likely a word after a dot than a file type.
const EXTENSION_MAX: usize = 10;

/// `text` in at most `width` cells: whole when it fits, else its start and
/// end around `…`. The end keeps the extension, when a name has one and the
/// width leaves the start at least as many cells as the end.
pub(crate) fn cut_middle(text: &str, width: usize) -> String {
    if display_width(text) <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let room = width - 1;
    let tail_room = extension(text)
        .map(display_width)
        .filter(|cells| *cells * 2 <= room)
        .unwrap_or(0)
        .max(room / 3);
    let tail = last_cells(text, tail_room);
    let head = first_cells(text, room - display_width(tail));
    format!("{head}{CUT}{tail}")
}

/// The end of `name` from its last dot, when that reads as a file type: short,
/// and letters and digits only.
fn extension(name: &str) -> Option<&str> {
    let at = name.rfind('.').filter(|at| *at > 0)?;
    let tail = &name[at..];
    let word = &tail[1..];
    (!word.is_empty()
        && display_width(tail) <= EXTENSION_MAX
        && word.chars().all(char::is_alphanumeric))
    .then_some(tail)
}

/// The start of `text` that fits `width` cells, whole graphemes only.
fn first_cells(text: &str, width: usize) -> &str {
    let mut cells = 0usize;
    let mut end = 0usize;
    for (at, grapheme) in text.grapheme_indices(true) {
        cells += display_width(grapheme);
        if cells > width {
            break;
        }
        end = at + grapheme.len();
    }
    &text[..end]
}

/// The end of `text` that fits `width` cells, whole graphemes only.
fn last_cells(text: &str, width: usize) -> &str {
    let mut cells = 0usize;
    let mut start = text.len();
    for (at, grapheme) in text.grapheme_indices(true).rev() {
        cells += display_width(grapheme);
        if cells > width {
            break;
        }
        start = at;
    }
    &text[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_that_fits_stays_whole() {
        assert_eq!(cut_middle("ubuntu.iso", 10), "ubuntu.iso");
    }

    #[test]
    fn a_long_name_keeps_its_start_and_its_extension() {
        let cut = cut_middle("(2007)Wiley-Advanced.Rust.Programming.Boot.up.pdf", 20);
        assert_eq!(cut, "(2007)Wiley-A…up.pdf");
        assert_eq!(display_width(&cut), 20);
    }

    #[test]
    fn a_dot_inside_a_sentence_is_no_extension() {
        let cut = cut_middle("!! Sharing-Devils No.1 !!", 12);
        assert_eq!(cut, "!! Shari… !!");
    }

    /// A wide glyph that would straddle the edge goes whole: the cell stays
    /// short of the width rather than holding half a glyph.
    #[test]
    fn a_wide_glyph_is_never_halved() {
        let name = "東京物語の完全版ディスク.mkv";
        for width in 1..display_width(name) {
            let cut = cut_middle(name, width);
            assert!(display_width(&cut) <= width, "{width}: {cut}");
            assert!(cut.chars().all(|c| name.contains(c) || c == '…'), "{cut}");
        }
        assert!(cut_middle(name, 14).ends_with(".mkv"));
    }

    /// `e` and its combining acute are one grapheme: a cut keeps both or
    /// neither, and never leaves a mark on the `…`.
    #[test]
    fn a_combining_mark_stays_with_its_letter() {
        let name = "cafe\u{301}cafe\u{301}cafe\u{301}cafe\u{301}.flac";
        for width in 1..display_width(name) {
            let cut = cut_middle(name, width);
            assert!(display_width(&cut) <= width, "{width}: {cut}");
            assert!(!cut.starts_with('\u{301}'));
            assert!(!cut.contains("…\u{301}"), "{cut}");
            assert!(!cut.contains("e…\u{301}"), "{cut}");
        }
    }

    #[test]
    fn a_cell_too_small_for_the_extension_cuts_it_too() {
        assert_eq!(cut_middle("archive-of-everything.tar", 5), "arc…r");
        assert_eq!(cut_middle("archive.tar", 1), "…");
        assert_eq!(cut_middle("archive.tar", 0), "");
    }
}
