//! The shared directories strip (ADR-0101, "Shared Directories"): a
//! read-only line per listed directory above the files table — its state,
//! and how many files and bytes of the share set lie under it — with "all"
//! first. `[` and `]` step the selection, which filters the table to that
//! directory; the list itself is edited in Settings.

use std::path::{Path, PathBuf};

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use rmule_core::SharedDirectoryDiagnostics;

use super::SharedView;
use crate::row_selection::gutter;
use crate::state::UiState;
use crate::theme::Theme;
use crate::words::scan::{role_words, state_words, under_words};
use crate::wrap::{clamp_u16, wrap_text};

/// The listed directories, in list order.
fn listed(state: &UiState) -> &[SharedDirectoryDiagnostics] {
    &state.diagnostics.shared_directories
}

impl SharedView {
    /// The directory the files table is filtered to, if it is still listed.
    pub(super) fn directory_filter<'a>(&self, state: &'a UiState) -> Option<&'a Path> {
        let dir = self.dir_filter.as_deref()?;
        listed(state)
            .iter()
            .find(|entry| entry.dir == dir)
            .map(|entry| entry.dir.as_path())
    }

    /// Step the strip's selection by one, "all" first, wrapping at both ends.
    pub(super) fn step_directory(&mut self, state: &UiState, forward: bool) {
        let mut choices: Vec<Option<PathBuf>> = vec![None];
        choices.extend(listed(state).iter().map(|entry| Some(entry.dir.clone())));
        let current = self.directory_filter(state).map(Path::to_path_buf);
        let at = choices
            .iter()
            .position(|choice| *choice == current)
            .unwrap_or(0);
        let next = if forward {
            (at + 1) % choices.len()
        } else {
            (at + choices.len() - 1) % choices.len()
        };
        self.dir_filter = choices.swap_remove(next);
    }

    /// Draw the strip at the top of `area`, one entry a line, wrapped rather
    /// than cut; the rest of `area` is returned for the table. Nothing is
    /// drawn while no directory is listed.
    pub(super) fn draw_strip(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
    ) -> Rect {
        let entries = listed(state);
        if entries.is_empty() || area.height < 3 {
            return area;
        }
        let selected = self.directory_filter(state);
        let text_w = usize::from(area.width).saturating_sub(2).max(1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let total = crate::words::scan::all_words(state.shared.len());
        push_entry(&mut lines, &total, selected.is_none(), text_w, theme);
        for entry in entries {
            let mut text = entry.dir.display().to_string();
            if let Some(role) = role_words(entry.role) {
                text.push_str(&format!(" ({role})"));
            }
            text.push_str(&format!(
                " · {} · {}",
                state_words(&entry.state),
                under_words(state.shared_under(&entry.dir))
            ));
            push_entry(
                &mut lines,
                &text,
                selected == Some(entry.dir.as_path()),
                text_w,
                theme,
            );
        }
        let hint = crate::words::scan::STRIP_HINT;
        lines.push(Line::from(Span::styled(hint, theme.dim_text())));
        // The table keeps at least its header and one row.
        let height = clamp_u16(lines.len()).min(area.height.saturating_sub(2));
        frame.render_widget(
            Paragraph::new(lines),
            Rect::new(area.x, area.y, area.width, height),
        );
        Rect::new(
            area.x,
            area.y + height,
            area.width,
            area.height.saturating_sub(height),
        )
    }
}

/// One strip entry, marked when selected, wrapped under its own gutter.
fn push_entry(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    selected: bool,
    width: usize,
    theme: &Theme,
) {
    let style = if selected {
        Style::new().fg(theme.fg)
    } else {
        theme.dim_text()
    };
    for (index, part) in wrap_text(text, width).into_iter().enumerate() {
        let mut spans = vec![if index == 0 {
            gutter(selected, true, theme)
        } else {
            Span::raw("  ")
        }];
        spans.push(Span::styled(part, style));
        lines.push(Line::from(spans));
    }
}

#[cfg(test)]
mod tests;
