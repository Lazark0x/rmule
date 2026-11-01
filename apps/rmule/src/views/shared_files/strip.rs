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
use crate::row_selection::{gutter, viewport};
use crate::state::UiState;
use crate::table::cut_middle;
use crate::theme::Theme;
use crate::words::scan::{role_words, state_words, under_words};
use crate::wrap::clamp_u16;

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

    /// Draw the strip at the top of `area`, one entry a line, over its hint
    /// line, which carries the strip's count; the
    /// rest of `area` is returned for the table. Entries the strip has no
    /// room for scroll under the Viewport, which follows the selection.
    /// Nothing is drawn while no directory is listed.
    pub(super) fn draw_strip(
        &mut self,
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
        let mut texts = vec![(
            crate::words::scan::all_words(state.shared.len()),
            selected.is_none(),
        )];
        texts.extend(entries.iter().map(|entry| {
            let mut text = entry.dir.display().to_string();
            if let Some(role) = role_words(entry.role) {
                text.push_str(&format!(" ({role})"));
            }
            text.push_str(&format!(
                " · {} · {}",
                state_words(&entry.state),
                under_words(state.shared_under(&entry.dir))
            ));
            (text, selected == Some(entry.dir.as_path()))
        }));
        let cursor = texts.iter().position(|(_, on)| *on).unwrap_or(0);
        // The table keeps at least its header and one row; the hint line
        // takes one more.
        let room = area.height.saturating_sub(3);
        let bar = texts.len() > usize::from(room);
        let width = if bar {
            area.width.saturating_sub(viewport::BAR_W)
        } else {
            area.width
        };
        let text_w = usize::from(width).saturating_sub(2);
        let entries_h = clamp_u16(texts.len()).min(room);
        let first = self
            .strip_viewport
            .follow(cursor, texts.len(), entries_h, |_| 1);
        let lines: Vec<Line<'static>> = texts
            .iter()
            .skip(first)
            .take(usize::from(entries_h))
            .map(|(text, on)| entry_line(text, *on, text_w, theme))
            .collect();
        let (list, bar) = viewport::split(
            Rect {
                height: entries_h,
                ..area
            },
            bar,
        );
        frame.render_widget(Paragraph::new(lines), list);
        self.strip_viewport.draw_bar(frame, bar, theme);
        let hint_line = Rect::new(area.x, area.y + entries_h, area.width, 1);
        let rest = self.strip_viewport.draw_count(frame, hint_line, theme);
        let hint = crate::words::scan::STRIP_HINT;
        if Span::raw(hint).width() <= usize::from(rest.width) {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(hint, theme.dim_text()))),
                rest,
            );
        }
        let height = entries_h + 1;
        Rect::new(
            area.x,
            area.y + height,
            area.width,
            area.height.saturating_sub(height),
        )
    }
}

/// One strip entry on its line, marked when selected, its path cut in the
/// middle where the strip is too narrow for it.
fn entry_line(text: &str, selected: bool, width: usize, theme: &Theme) -> Line<'static> {
    let style = if selected {
        Style::new().fg(theme.fg)
    } else {
        theme.dim_text()
    };
    Line::from(vec![
        gutter(selected, true, theme),
        Span::styled(cut_middle(text, width), style),
    ])
}

#[cfg(test)]
mod tests;
