//! TestBackend golden harness (spec §2): glyph-level render snapshots under
//! `tests/goldens/`, the spine every view's goldens build on.
//!
//! Compare is glyph-exact with trailing whitespace trimmed per line; bless or
//! re-bless a golden by running the test with `UPDATE_GOLDENS=1`.

use std::fs;
use std::path::PathBuf;

use ratatui::backend::TestBackend;
use ratatui::{Frame, Terminal};

/// Render one frame at `width`×`height` and return its glyphs, one line per
/// buffer row, trailing whitespace trimmed, trailing newline present.
pub(crate) fn render_to_lines(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(draw).expect("draw frame");
    let buffer = terminal.backend().buffer();
    let area = buffer.area;
    let mut out = String::new();
    for y in area.top()..area.bottom() {
        let line: String = (area.left()..area.right())
            .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
            .collect();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Compare a render against `tests/goldens/<name>.txt`, or (re-)bless it when
/// `UPDATE_GOLDENS=1` is set.
pub(crate) fn assert_golden(name: &str, width: u16, height: u16, draw: impl FnOnce(&mut Frame)) {
    let actual = render_to_lines(width, height, draw);
    // Goldens are written with `/` separators. A fixture path joined on
    // Windows mixes them (`/srv/rmule\Temp`) while the layout under test is
    // the same, so a golden never holds a literal backslash.
    #[cfg(windows)]
    let actual = actual.replace('\\', "/");
    let raw = raw_forms(&actual);
    assert!(
        raw.is_empty(),
        "golden '{name}' draws code, not words: {raw:?}"
    );
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "goldens",
        &format!("{name}.txt"),
    ]
    .iter()
    .collect();
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        let dir = path.parent().expect("goldens dir");
        fs::create_dir_all(dir).expect("create goldens dir");
        fs::write(&path, &actual).expect("write golden");
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing golden {}; bless it with UPDATE_GOLDENS=1",
            path.display()
        )
    });
    assert_eq!(
        actual, expected,
        "golden '{name}' drifted; re-bless with UPDATE_GOLDENS=1 if intended"
    );
}

/// What in a rendered frame reads as code rather than words: an
/// `Option` (`Some(`, `None`), a struct's braces (` { `), a path (`::`, but not
/// an IPv6 address), or a byte array (`[` then digits and commas).
pub(crate) fn raw_forms(rendered: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in rendered.lines() {
        if line.contains("Some(") {
            found.push(format!("Some( in {line:?}"));
        }
        if line.contains(" { ") {
            found.push(format!("braces in {line:?}"));
        }
        for word in line.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if word == "None" {
                found.push(format!("None in {line:?}"));
            }
        }
        for token in line.split_whitespace() {
            if token.contains("::") && !is_ipv6_address(token) {
                found.push(format!(":: in {line:?}"));
            }
        }
        if has_byte_array(line) {
            found.push(format!("byte array in {line:?}"));
        }
    }
    found
}

/// Whether `token`, stripped of the punctuation a sentence puts around it, is
/// an IPv6 address or an `[address]:port`.
fn is_ipv6_address(token: &str) -> bool {
    let bare = token.trim_matches(|c: char| matches!(c, '(' | ')' | ',' | ';' | '.' | '…'));
    bare.parse::<std::net::Ipv6Addr>().is_ok() || bare.parse::<std::net::SocketAddrV6>().is_ok()
}

/// Whether `line` holds `[` followed by digits, a comma and more digits.
fn has_byte_array(line: &str) -> bool {
    line.match_indices('[').any(|(at, _)| {
        let rest = &line[at + 1..];
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        digits > 0
            && rest[digits..].starts_with(',')
            && rest[digits + 1..]
                .trim_start()
                .starts_with(|c: char| c.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use ratatui::text::Text;
    use ratatui::widgets::{Block, Paragraph};

    use super::*;

    #[test]
    fn renders_glyphs_row_by_row_with_trailing_space_trimmed() {
        let lines = render_to_lines(6, 2, |frame| {
            frame.render_widget(Text::raw("hi"), frame.area());
        });
        assert_eq!(lines, "hi\n\n");
    }

    #[test]
    fn checked_in_golden_round_trips_through_the_file_harness() {
        assert_golden("harness_smoke", 20, 4, |frame| {
            let block = Block::bordered().title("rmule");
            frame.render_widget(Paragraph::new("seam + spine").block(block), frame.area());
        });
    }

    /// No checked-in golden draws code rather than words: every one
    /// is scanned, including any blessed before the scan ran at render time.
    #[test]
    fn no_golden_draws_code() {
        let dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "goldens"]
            .iter()
            .collect();
        let mut scanned = 0;
        for entry in fs::read_dir(&dir).expect("goldens dir") {
            let path = entry.expect("golden entry").path();
            let text = fs::read_to_string(&path).expect("golden text");
            let raw = raw_forms(&text);
            assert!(raw.is_empty(), "{}: {raw:?}", path.display());
            scanned += 1;
        }
        assert!(scanned > 0, "no goldens found under {}", dir.display());
    }

    /// The scan finds each raw form the operator met — the
    /// `PeerReachRouted` line among them — and passes an IPv6 address.
    #[test]
    fn the_raw_forms_are_found_and_an_ipv6_address_is_not_one() {
        let met =
            "peer 1.2.3.4:4662 reach via Buddy { buddy_id: KadId([143, 0, 91]), emitted_to: None }";
        let raw = raw_forms(met);
        assert!(
            raw.iter().any(|found| found.starts_with("braces")),
            "{raw:?}"
        );
        assert!(raw.iter().any(|found| found.starts_with("None")), "{raw:?}");
        assert!(
            raw.iter().any(|found| found.starts_with("byte array")),
            "{raw:?}"
        );
        assert!(!raw_forms("x: Some(3)").is_empty());
        assert!(!raw_forms("rmule_core::PeerReachRoute").is_empty());
        assert!(raw_forms("peer [2001:db8::1]:4662 selected, fe80::1 too").is_empty());
    }
}
