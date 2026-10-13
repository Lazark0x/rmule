//! The file-details modal: the full facts of the selected download, laid out
//! as label/value rows that wrap rather than truncate.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use rmule_core::DownloadId;
use rmule_primitives::FileHash;

use super::chunks::chunk_bar;
use super::downloads::{diag_counts, diag_parts, origin_label, source_counts};
use super::sort::DownloadLine;
use super::{Overlay, TransfersView, selected_id};
use crate::rates::format_rate;
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::Modal;
use crate::words::download::{on_disk, source_wait_words};
use crate::wrap::labeled_lines;

/// Width of the details modal's label column (`" {label:<8}"`).
const DETAIL_LABEL_W: usize = 8;

/// One details-modal key-value row, wrapped: continuation lines hang under the
/// value column so a 32-hex hash reads as one row at any width.
fn detail_rows(label: &str, value: &str, value_w: usize, theme: &Theme) -> Vec<Line<'static>> {
    labeled_lines(
        Span::styled(format!(" {label:<DETAIL_LABEL_W$}"), theme.dim_text()),
        value,
        Style::new().fg(theme.fg),
        value_w,
    )
}

impl TransfersView {
    pub(super) fn handle_details(&mut self, key: KeyEvent) -> ViewOutcome {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
                ViewOutcome::Redraw
            }
            _ => ViewOutcome::Redraw,
        }
    }

    pub(super) fn draw_details(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        ids: &[DownloadId],
    ) {
        let Some(id) = selected_id(ids, &self.table_state) else {
            return;
        };
        let row = state.downloads.get(&id);
        let diag = state.diagnostics.downloads.get(&id);
        let hash = row.and_then(|r| r.file_hash);
        let metadata = row.and_then(|r| r.metadata.as_ref());
        let bps = state.download_speed(id);
        let counts = diag_counts(diag);
        let total_parts = counts.total();

        let line = DownloadLine::new(id, state);
        let name = line.name.clone();
        let size = line.size_cell();
        let origin =
            metadata.map_or_else(|| "—".to_string(), |m| origin_label(m.origin).to_string());
        let percent_done = line.done_cell();
        let done = if total_parts == 0 {
            percent_done
        } else {
            format!("{percent_done}  ({}/{total_parts} parts)", counts.verified)
        };
        let sources = source_counts(diag).map_or_else(
            || "— (not running)".to_string(),
            |(known, sending)| format!("{known} known, {sending} sending"),
        );

        // Key-value rows wrap under their value column: the full hash
        // is 32 hex digits, so a narrow frame must grow the modal, not cut it.
        let width = 52u16.min(area.width);
        let inner_w = usize::from(width).saturating_sub(2).max(1);
        let value_w = inner_w.saturating_sub(DETAIL_LABEL_W + 1).max(1);
        let mut lines: Vec<Line<'static>> = [
            ("name", name),
            (
                "hash",
                hash.map_or_else(|| "—".to_string(), FileHash::to_hex_upper),
            ),
            ("size", size),
            ("origin", origin),
            ("done", done),
            ("speed", format_rate(bps)),
            ("sources", sources),
            // The one place the Allocated Bytes and the Hole Verdict show
            // (ADR-0111, "What the operator reads").
            (
                "on disk",
                on_disk(
                    diag.and_then(|d| d.allocated_bytes),
                    diag.and_then(|d| d.hole_verdict),
                ),
            ),
        ]
        .into_iter()
        .flat_map(|(label, value)| detail_rows(label, &value, value_w, theme))
        .collect();
        // A failed row says why — or that why was not kept (ADR-0094).
        if let Some(row) = row
            && row.status == crate::state::DownloadStatus::Failed
        {
            let why = row.failure.as_ref().map_or_else(
                || crate::state::FAILURE_NOT_RECORDED.to_string(),
                crate::state::download_failure_words,
            );
            lines.extend(detail_rows("failed", &why, value_w, theme));
        }
        // A row whose run waits says on what (ADR-0051's amendment).
        if let Some(row) = row {
            let wait = match (row.status, row.source_wait) {
                (_, Some(reason)) => Some(source_wait_words(reason)),
                (crate::state::DownloadStatus::NoConnection, None) => {
                    Some(crate::state::NO_NETWORK_WAIT)
                }
                _ => None,
            };
            if let Some(wait) = wait {
                lines.extend(detail_rows("waiting", wait, value_w, theme));
            }
        }
        lines.push(Line::raw(""));
        // The modal's wider budget buckets the same map more finely than the
        // table cell does — same fact, more resolution (ADR-0079).
        lines.push(Line::from(chunk_bar(diag_parts(diag), inner_w, theme)));

        Modal::new(" File details ", theme)
            .flash_title(theme)
            .draw(frame, area, width, theme, lines);
    }
}

#[cfg(test)]
mod tests {

    use rmule_core::HoleVerdict;
    use rmule_primitives::ED2K_PART_SIZE;

    use crate::golden::assert_golden;

    use super::*;
    use crate::fixture::*;

    /// A row that failed before rmule kept why says so in words (ADR-0094).
    #[test]
    fn a_failed_row_with_no_reason_says_the_reason_was_not_recorded() {
        let mut view = TransfersView::new();
        let mut state = three_downloads();
        for row in state.downloads.values_mut() {
            row.status = crate::state::DownloadStatus::Failed;
            row.failure = None;
        }
        view.overlay = Overlay::Details;
        let screen = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        assert!(screen.contains("not recorded"), "{screen}");
    }

    /// A row whose run waits with no server session says on what, in words.
    #[test]
    fn a_waiting_row_says_what_it_waits_on() {
        let mut view = TransfersView::new();
        view.overlay = Overlay::Details;
        let state = waiting_downloads();
        let screen = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        assert!(screen.contains("no source left to try"), "{screen}");
    }

    /// The details modal over the active download, its On disk levels set.
    fn assert_on_disk_golden(name: &str, allocated: Option<u64>, verdict: Option<HoleVerdict>) {
        let mut view = TransfersView::new();
        view.overlay = Overlay::Details;
        let mut state = three_downloads();
        let diag = state
            .diagnostics
            .downloads
            .get_mut(&download_id(1))
            .expect("the active download's row");
        diag.allocated_bytes = allocated;
        diag.hole_verdict = verdict;
        assert_golden(name, GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }

    /// A disk that holds holes: the part file takes its verified parts and
    /// a probe's slack, and the row says what the verdict means.
    #[test]
    fn golden_details_on_disk_holds_holes() {
        assert_on_disk_golden(
            "transfers_details_on_disk_holds_holes",
            Some(4 * ED2K_PART_SIZE + 4096),
            Some(HoleVerdict::HoldsHoles),
        );
    }

    /// A disk that holds no holes: the part file takes its length up to its
    /// last verified part, part 6.
    #[test]
    fn golden_details_on_disk_hole_less() {
        assert_on_disk_golden(
            "transfers_details_on_disk_hole_less",
            Some(7 * ED2K_PART_SIZE),
            Some(HoleVerdict::HoleLess),
        );
    }

    /// A probe that failed says the disk was not measured, and why.
    #[test]
    fn golden_details_on_disk_unknown() {
        assert_on_disk_golden(
            "transfers_details_on_disk_unknown",
            Some(4 * ED2K_PART_SIZE + 4096),
            Some(HoleVerdict::Unknown(std::io::ErrorKind::PermissionDenied)),
        );
    }

    /// A reading above the file's 87.7 MB shows as read, and a verdict not
    /// yet taken is a dash.
    #[test]
    fn golden_details_on_disk_above_the_files_length() {
        assert_on_disk_golden(
            "transfers_details_on_disk_above_length",
            Some(100_000_000),
            None,
        );
    }

    #[test]
    fn golden_details_modal() {
        let mut view = TransfersView::new();
        view.overlay = Overlay::Details;
        let state = three_downloads();
        assert_golden("transfers_details_modal", GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }
}
