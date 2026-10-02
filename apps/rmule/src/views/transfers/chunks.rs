//! The positional chunk map a download row renders as its progress cell
//! (ADR-0079).
//!
//! The snapshot's per-index part vector is bucketed to the cell's width, so a
//! part shows at its own position rather than as an aggregate count. A row
//! whose part map has not landed — an empty vector, core saying *unknown*
//! rather than *nothing done* — keeps the flat dim rendering.

use ratatui::style::Style;
use ratatui::text::Span;
use rmule_core::diagnostics::PartState;

use crate::theme::Theme;

/// The positional chunk bar (spec §3.2, ADR-0079): glyph *i* of `width` shows
/// the file region `[i·n/W, (i+1)·n/W)` of the `n`-entry part map — grey
/// `█` have, green `▓` downloading, dark `░` not yet — so the left of the bar
/// is the head of the file, the way every eD2k client draws it.
///
/// The bar is a fixed-width *visualization*, not text: it is sized to its
/// column and never wraps (the wrap policy covers user data, and losing a
/// glyph here loses no fact — the map is downsampled by definition).
///
/// An empty map (`n == 0`: core has opened the row but not settled the
/// scheduler yet, so part status is *unknown*) renders flat dim, the same
/// "nothing to say" the cell showed before any part fact existed.
pub(super) fn chunk_bar(parts: &[PartState], width: usize, theme: &Theme) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }
    if parts.is_empty() {
        return vec![Span::styled("░".repeat(width), theme.dim_text())];
    }

    // Run-length the buckets so a 200-cell bar is a handful of spans.
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut run: Option<(PartState, usize)> = None;
    for index in 0..width {
        let state = bucket_state(parts, index, width);
        match run {
            Some((current, ref mut len)) if current == state => *len += 1,
            Some((current, len)) => {
                spans.push(bucket_span(current, len, theme));
                run = Some((state, 1));
            }
            None => run = Some((state, 1)),
        }
    }
    if let Some((state, len)) = run {
        spans.push(bucket_span(state, len, theme));
    }
    spans
}

/// The status glyph column `index` of `width` reports for the part map.
///
/// The column covers `parts[floor(i·n/W) .. floor((i+1)·n/W))`, always at
/// least one part — so a bar wider than the file has parts stretches each
/// part across several glyphs instead of leaving dead cells, and a bar
/// narrower than the file aggregates.
///
/// **Bucket rule: `Verified` needs unanimity, then activity wins.** A bucket
/// reads *have* only if every part in it is verified — a partly-done region
/// must never claim to be done. Among the rest, any in-flight part paints the
/// bucket green, because "work is happening in this region" is the fact a
/// chunk map is read for; only a region with nothing held and nothing being
/// fetched reads missing.
fn bucket_state(parts: &[PartState], index: usize, width: usize) -> PartState {
    let n = parts.len();
    let start = index * n / width;
    let end = ((index + 1) * n / width).max(start + 1).min(n);
    let bucket = &parts[start..end];
    if bucket.iter().all(|part| *part == PartState::Verified) {
        PartState::Verified
    } else if bucket.contains(&PartState::InFlight) {
        PartState::InFlight
    } else {
        PartState::Missing
    }
}

fn bucket_span(state: PartState, len: usize, theme: &Theme) -> Span<'static> {
    let (glyph, color) = match state {
        // have → grey full blocks
        PartState::Verified => ("█", theme.dim),
        // downloading → green
        PartState::InFlight => ("▓", theme.good),
        // missing → dark (panel tone: barely there, i.e. "not yet")
        PartState::Missing => ("░", theme.panel),
    };
    Span::styled(glyph.repeat(len), Style::new().fg(color))
}

#[cfg(test)]
mod tests {

    use crate::fixture::part_map;

    use super::*;

    /// The glyphs a bar of `width` draws for `parts`, concatenated.
    fn bar_text(parts: &[PartState], width: usize, theme: &Theme) -> String {
        chunk_bar(parts, width, theme)
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    /// The Progress cell is a chunk *map*: glyph position is file
    /// position, at every ratio of parts to cells.
    #[test]
    fn the_progress_cell_places_each_part_at_its_own_position() {
        let theme = Theme::default_dark();
        // 1:1 — ten parts across ten cells: the bar *is* the map. A
        // proportional bar of the same counts would read "████▓▓░░░░".
        assert_eq!(bar_text(&part_map("VVMVIMVIMM"), 10, &theme), "██░█▓░█▓░░");
        // Wider than the file has parts: each part stretches across its own
        // span of cells rather than leaving the tail of the bar dead.
        assert_eq!(bar_text(&part_map("VIM"), 9, &theme), "███▓▓▓░░░");
        // Narrower: two parts per bucket. A bucket reads `have` only when
        // every part in it is verified (bucket 2 mixes M+V → not have), and
        // among the rest any in-flight part wins (bucket 3 is I+M → green).
        assert_eq!(bar_text(&part_map("VVVVMVIMVM"), 5, &theme), "██░▓░");
        // An unknown map is not a 0%-complete file: flat dim, nothing claimed.
        assert_eq!(bar_text(&[], 6, &theme), "░░░░░░");
    }

    /// A download paused before its hash set arrived: its size
    /// fixes its part count, so core's row already holds every part missing,
    /// and the bar draws them in the missing tone — not the flat dim bar of
    /// a picture nobody has.
    #[test]
    fn golden_a_download_paused_before_its_hash_set_draws_every_part_missing() {
        use rmule_core::diagnostics::DiagnosticsState;
        use rmule_primitives::ED2K_PART_SIZE;

        use crate::fixture::{GOLDEN_H, GOLDEN_W, download_id, download_row, file_hash, now};
        use crate::golden::assert_golden;
        use crate::state::{DownloadStatus, UiState};
        use crate::views::transfers::TransfersView;

        let metadata = crate::fixture::metadata(
            "early.iso",
            3 * ED2K_PART_SIZE + 1,
            rmule_core::DownloadMetadataOrigin::Link,
        );
        // The run opens and is paused before anything settles.
        let core = DiagnosticsState::new();
        core.ensure_download(download_id(1), file_hash(1), metadata.clone());
        core.end_run(download_id(1), false);

        let mut state = UiState::default();
        let mut row = download_row(DownloadStatus::Paused, 1, 0);
        row.part_count = None; // no hash set
        row.metadata = Some(metadata);
        state.downloads.insert(download_id(1), row);
        state.diagnostics = core.snapshot();
        let parts = &state.diagnostics.downloads[&download_id(1)].parts;
        assert_eq!(parts, &vec![PartState::Missing; 4]);

        let theme = Theme::default_dark();
        let tones: Vec<_> = chunk_bar(parts, 10, &theme)
            .iter()
            .map(|span| (span.content.to_string(), span.style.fg))
            .collect();
        assert_eq!(tones, vec![("░".repeat(10), Some(theme.panel))]);

        let mut view = TransfersView::new();
        assert_golden(
            "transfers_paused_before_hash_set",
            GOLDEN_W,
            GOLDEN_H,
            |frame| view.draw(frame, frame.area(), &state, &theme, now()),
        );
    }

    /// The three tones stay attached to the three states, one span per run
    /// (a 200-cell modal bar must not become 200 spans).
    #[test]
    fn each_part_state_keeps_its_own_tone() {
        let theme = Theme::default_dark();
        let spans = chunk_bar(&part_map("VVIMM"), 5, &theme);
        let tones: Vec<_> = spans
            .iter()
            .map(|span| (span.content.as_ref(), span.style.fg))
            .collect();
        assert_eq!(
            tones,
            vec![
                ("██", Some(theme.dim)),
                ("▓", Some(theme.good)),
                ("░░", Some(theme.panel)),
            ],
        );
    }
}
