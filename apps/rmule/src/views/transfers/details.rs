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
use super::downloads::{diag_counts, diag_parts, origin_label, swarm_exhausted};
use super::sort::DownloadLine;
use super::{Overlay, TransfersView, selected_id};
use crate::state::UiState;
use crate::table::widest;
use crate::table_sort::RowMove;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::views::modal::Modal;
use crate::words::download::{
    completion_progress, no_needed_parts_words, on_disk, part_check_progress,
    source_activity_words, source_wait_words, volume_stop_words,
};
use crate::words::units::rate;
use crate::words::{absent, transfers as words};
use crate::wrap::labeled_lines;

/// Width of the details modal's label column (`" {label:<8}"`).
fn label_w() -> usize {
    widest(&words::DETAIL_LABELS)
}

/// One details-modal key-value row, wrapped: continuation lines hang under the
/// value column so a 32-hex hash reads as one row at any width.
fn detail_rows(label: &str, value: &str, value_w: usize, theme: &Theme) -> Vec<Line<'static>> {
    labeled_lines(
        Span::styled(format!(" {label:<w$}", w = label_w()), theme.dim_text()),
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
            // A frame too short for every line scrolls them.
            code => {
                if let Some(movement) = RowMove::of(code) {
                    self.details_viewport.get_mut().scroll(movement);
                }
                ViewOutcome::Redraw
            }
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
        let Some(id) = selected_id(ids, self.selected) else {
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
        let origin = metadata.map_or_else(
            || absent::UNKNOWN.to_string(),
            |m| origin_label(m.origin).to_string(),
        );
        let percent_done = line.done_cell();
        let done = if total_parts == 0 {
            percent_done
        } else {
            words::done_of_parts(&percent_done, counts.verified.into(), total_parts.into())
        };
        let sources = diag.map_or_else(
            || absent::NOT_RUNNING.to_string(),
            |diag| source_activity_words(diag.known_sources, diag.source_activity),
        );

        // Key-value rows wrap under their value column: the full hash
        // is 32 hex digits, so a narrow frame must grow the modal, not cut it.
        let width = 52u16.min(area.width);
        let lines = |width: u16| -> Vec<Line<'static>> {
            let inner_w = usize::from(width).saturating_sub(2).max(1);
            let value_w = inner_w.saturating_sub(label_w() + 1).max(1);
            let mut lines: Vec<Line<'static>> = [
                (words::NAME, name.clone()),
                (
                    words::HASH,
                    hash.map_or_else(|| absent::UNKNOWN.to_string(), FileHash::to_hex_upper),
                ),
                (words::SIZE, size.clone()),
                (words::ORIGIN, origin.clone()),
                (words::DONE, done.clone()),
                (words::SPEED, rate(bps)),
                (words::SOURCES, sources.clone()),
                // The one place the Allocated Bytes and the Hole Verdict show
                // (ADR-0111, "What the operator reads").
                (
                    words::ON_DISK,
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
                lines.extend(detail_rows(words::FAILED, &why, value_w, theme));
            }
            // A row whose run waits says on what (ADR-0051's amendment); one
            // no known source can feed says that first.
            if let Some(row) = row {
                let wait = match (row.status, row.source_wait) {
                    (status, _) if swarm_exhausted(status, diag) => {
                        Some(no_needed_parts_words(counts.verified, total_parts))
                    }
                    (_, Some(reason)) => Some(source_wait_words(reason).to_string()),
                    (crate::state::DownloadStatus::NoConnection, None) => {
                        Some(crate::state::NO_NETWORK_WAIT.to_string())
                    }
                    _ => None,
                };
                if let Some(wait) = wait {
                    lines.extend(detail_rows(words::WAITING, &wait, value_w, theme));
                }
            }
            // A row the volume stopped says what the volume did, and a run
            // reading its parts back says how far it is.
            if let Some(stopped) = row.and_then(|row| row.volume_stop.as_ref()) {
                let why = volume_stop_words(&stopped.directory, stopped.stop);
                lines.extend(detail_rows(words::STOPPED, &why, value_w, theme));
            }
            if let Some(level) = diag.and_then(|d| d.part_check) {
                let doing = part_check_progress(level.checked, level.of);
                lines.extend(detail_rows(words::CHECKING, &doing, value_w, theme));
            }
            // A completing row says what its move does, and what its copy has
            // written (ADR-0115).
            if let Some(progress) = diag.and_then(|d| d.completion)
                && row.is_some_and(|row| row.status == crate::state::DownloadStatus::Completing)
            {
                let size = metadata.map(|m| m.size);
                let doing = completion_progress(progress.step, progress.copied, size);
                lines.extend(detail_rows(words::MOVE, &doing, value_w, theme));
            }
            lines.push(Line::raw(""));
            // The modal's wider budget buckets the same map more finely than the
            // table cell does — same fact, more resolution (ADR-0079).
            lines.push(Line::from(chunk_bar(diag_parts(diag), inner_w, theme)));
            lines
        };
        Modal::new(words::DETAILS_TITLE, theme)
            .flash_title(theme)
            .closes()
            .draw_scrolled(frame, area, width, theme, &self.details_viewport, lines);
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
        let mut view = TransfersView::by_name();
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
        let mut view = TransfersView::by_name();
        view.overlay = Overlay::Details;
        let state = waiting_downloads();
        let screen = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        assert!(screen.contains("no source left to try"), "{screen}");
    }

    /// Every source of the active run retired holding nothing it lacks: the
    /// status cell and the details say so, with the parts held and total,
    /// whatever the run last waited on.
    #[test]
    fn golden_every_source_holds_no_needed_part() {
        let mut view = TransfersView::by_name();
        let mut state = three_downloads();
        let diag = state
            .diagnostics
            .downloads
            .get_mut(&download_id(1))
            .expect("the active download's row");
        diag.known_sources = 3;
        diag.source_activity = rmule_core::diagnostics::SourceActivity {
            queued: 3,
            needing_nothing: 3,
            ..Default::default()
        };
        state
            .downloads
            .get_mut(&download_id(1))
            .expect("the active download's row")
            .source_wait = Some(rmule_core::SourceWait::OnStanding);
        assert_golden("transfers_no_needed_parts", GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        view.overlay = Overlay::Details;
        assert_golden(
            "transfers_no_needed_parts_details",
            GOLDEN_W,
            GOLDEN_H,
            |frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now());
            },
        );
    }

    /// One source still able to feed the file leaves the row its own status.
    #[test]
    fn one_source_that_may_hold_a_needed_part_keeps_the_rows_status() {
        let mut view = TransfersView::by_name();
        let mut state = three_downloads();
        let diag = state
            .diagnostics
            .downloads
            .get_mut(&download_id(1))
            .expect("the active download's row");
        diag.known_sources = 3;
        diag.source_activity = rmule_core::diagnostics::SourceActivity {
            queued: 3,
            needing_nothing: 2,
            ..Default::default()
        };
        let screen = crate::golden::render_to_lines(GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
        assert!(!screen.contains("No parts"), "{screen}");
    }

    /// The details modal over the active download, its On disk levels set.
    fn assert_on_disk_golden(name: &str, allocated: Option<u64>, verdict: Option<HoleVerdict>) {
        let mut view = TransfersView::by_name();
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

    /// The details modal over the active download, its completion move at
    /// `step` with `copied` bytes written.
    fn assert_completing_golden(name: &str, step: rmule_core::CompletionStep, copied: u64) {
        let mut view = TransfersView::by_name();
        view.overlay = Overlay::Details;
        let mut state = three_downloads();
        state
            .downloads
            .get_mut(&download_id(1))
            .expect("the active download")
            .status = crate::state::DownloadStatus::Completing;
        let diag = state
            .diagnostics
            .downloads
            .get_mut(&download_id(1))
            .expect("the active download's row");
        // Every part verified: only then does a move begin.
        diag.parts = part_map("VVVVVVVVVV");
        diag.workers.clear();
        diag.known_sources = 0;
        diag.completion = Some(rmule_core::diagnostics::CompletionProgress { step, copied });
        assert_golden(name, GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }

    #[test]
    fn golden_details_completing_at_each_step() {
        use rmule_core::CompletionStep as Step;
        for (name, step, copied) in [
            ("transfers_details_completing_moving", Step::Moving, 0),
            (
                "transfers_details_completing_queued",
                Step::QueuedForCopy,
                0,
            ),
            (
                "transfers_details_completing_copying",
                Step::Copying,
                46_000_000,
            ),
            (
                "transfers_details_completing_held",
                Step::WaitingForRelease,
                0,
            ),
            (
                "transfers_details_completing_store",
                Step::WaitingForStore,
                92_000_000,
            ),
        ] {
            assert_completing_golden(name, step, copied);
        }
    }

    /// A frame too short for the details: `j` scrolls them, and the border
    /// counts the last line on screen.
    #[test]
    fn golden_details_overflow_a_short_frame() {
        let mut view = TransfersView::by_name();
        view.overlay = Overlay::Details;
        let state = three_downloads();
        let draw = |view: &mut TransfersView| {
            crate::golden::render_to_lines(GOLDEN_W, 9, |frame| {
                let area = frame.area();
                view.draw(frame, area, &state, &Theme::default_dark(), now());
            })
        };
        draw(&mut view);
        for _ in 0..3 {
            view.handle_key(press(KeyCode::Char('j')), &state);
        }
        assert_golden("transfers_details_overflow", GOLDEN_W, 9, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }

    #[test]
    fn golden_details_modal() {
        let mut view = TransfersView::by_name();
        view.overlay = Overlay::Details;
        let state = three_downloads();
        assert_golden("transfers_details_modal", GOLDEN_W, GOLDEN_H, |frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &Theme::default_dark(), now());
        });
    }
}
