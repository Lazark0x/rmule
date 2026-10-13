//! The one form machine every editable surface in this crate runs on.
//!
//! An editable surface is a field list with one focus: `Tab`/`BackTab`
//! between fields, `Backspace`/`Char` into the focused one, `Enter` to commit
//! and `Esc` to leave, [`labeled_lines`] rendering with a caret on the focused
//! row and the last rejection under the fields. The Networks add-server modal,
//! the Searches options editor and the Settings tab all run on it. Only
//! *validation* stays with each view, being the one part that is genuinely
//! about what is being edited.
//!
//! # What this module decides, and what it leaves alone
//!
//! - **Raw text, parsed on commit.** A field holds exactly what was typed. A
//!   rejected commit leaves the typing on screen to be corrected — losing an
//!   operator's entry to a validation failure is the one thing every form here
//!   already refused to do, so it is the machine's rule now.
//! - **Selectors are a field kind, not a special case.** [`FieldKind::Choice`]
//!   routes `←`/`→` itself, so no view re-implements "this one field cycles".
//! - **Display rows belong in the list.** [`FieldKind::Display`] keeps a
//!   read-only fact (a minted identity, an environment-resolved path) aligned
//!   with the fields around it, and focus steps straight past it — a row you
//!   cannot edit must not be a row you can land on.
//! - **Commit and cancel are the caller's.** [`Form::handle_key`] reports
//!   [`FormKey::Commit`]/[`FormKey::Cancel`] rather than acting: what a commit
//!   means (a `CoreCommand`, a search, a config write) is exactly what does not
//!   generalise.

use std::ops::Range;

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::theme::Theme;
use crate::wrap::{labeled_lines, wrapped_lines};

/// Label column every form's fields align on — the unification of the two
/// widths the views had drifted to (Networks 10, Searches 11). Sized to the
/// widest label any of them carries (`Download dir`, `Nodes.dat URL`).
pub(crate) const LABEL_W: usize = 12;

/// A trailing block glyph marks the caret, so the insertion point is visible
/// in glyph-only golden snapshots.
pub(crate) const CURSOR: &str = "▮";

/// A selector wears its cycle arrows where a text field wears the caret:
/// there is no insertion point to mark on something you step.
const ARROWS: &str = "  ←→";

/// Columns the value column gives up for whichever trailing marker the focused
/// row wears. Reserved on *every* row, and whether or not the caret is drawn,
/// so entering an editor cannot re-wrap the value under the cursor.
const MARKER_W: usize = 4; // the wider of the two: `ARROWS`

/// The narrowest a form renders without overrunning its pane: the label gutter
/// (a space either side of [`LABEL_W`]), the marker reserve, and one column of
/// value. Below this the *labels* are what would have to be cut, and a
/// truncated label names nothing — so the floor is stated rather than silently
/// crossed. It is far under the 80-column terminal this UI supports.
pub(crate) const MIN_WIDTH: usize = LABEL_W + 2 + MARKER_W + 1;

/// What a field holds.
pub(crate) enum FieldKind {
    /// Free text, kept exactly as typed.
    Text {
        value: String,
        /// What an empty field shows instead, so the accepted syntax is never
        /// a guess. Dim, and never mistaken for a value.
        placeholder: String,
    },
    /// A closed set stepped with `←`/`→` (and `Space`). The value is the
    /// chosen index, so a selector needs no parsing at all.
    Choice {
        options: Vec<&'static str>,
        index: usize,
    },
    /// A fact the form shows but nobody edits. Skipped by focus.
    Display { value: String },
    /// An entry of a list the form shows: focus rests on it so its view can
    /// act on it (remove it, say), but nothing is typed into it.
    Item { value: String },
}

/// One row of a form.
pub(crate) struct Field {
    /// Heading opening a new group above this field; `None` keeps it in the
    /// group above.
    pub section: Option<&'static str>,
    pub label: &'static str,
    pub kind: FieldKind,
    /// A dim note after the value — a unit, or an honest "takes effect on
    /// restart". Never a value: notes are not typed into and must not read as
    /// something that was.
    pub note: String,
}

impl Field {
    pub fn text(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            section: None,
            label,
            kind: FieldKind::Text {
                value: value.into(),
                placeholder: String::new(),
            },
            note: String::new(),
        }
    }

    pub fn choice(label: &'static str, options: Vec<&'static str>, index: usize) -> Self {
        Self {
            section: None,
            label,
            kind: FieldKind::Choice { options, index },
            note: String::new(),
        }
    }

    pub fn display(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            section: None,
            label,
            kind: FieldKind::Display {
                value: value.into(),
            },
            note: String::new(),
        }
    }

    pub fn item(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            section: None,
            label,
            kind: FieldKind::Item {
                value: value.into(),
            },
            note: String::new(),
        }
    }

    #[must_use]
    pub fn in_section(mut self, section: &'static str) -> Self {
        self.section = Some(section);
        self
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    #[must_use]
    pub fn with_placeholder(mut self, hint: impl Into<String>) -> Self {
        if let FieldKind::Text { placeholder, .. } = &mut self.kind {
            *placeholder = hint.into();
        }
        self
    }

    /// Can focus rest here? Display rows cannot.
    pub fn focusable(&self) -> bool {
        !matches!(self.kind, FieldKind::Display { .. })
    }

    fn is_choice(&self) -> bool {
        matches!(self.kind, FieldKind::Choice { .. })
    }

    /// The rendered value and whether it is the placeholder rather than an
    /// entry (which reads dim).
    fn value(&self) -> (&str, bool) {
        match &self.kind {
            FieldKind::Text { value, placeholder } if value.is_empty() => (placeholder, true),
            FieldKind::Text { value, .. } => (value, false),
            FieldKind::Choice { options, index } => {
                (options.get(*index).copied().unwrap_or_default(), false)
            }
            FieldKind::Display { value } => (value, true),
            FieldKind::Item { value } => (value, false),
        }
    }
}

/// What one key did to the form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FormKey {
    /// The form took it (typed, moved focus, stepped a selector).
    Consumed,
    /// `Enter`: the caller validates the fields and decides what happens.
    Commit,
    /// `Esc`: the caller closes or cancels.
    Cancel,
    /// Not a form key — the caller may route it onward. Only ever returned for
    /// keys no form has a meaning for, so a modal caller can safely swallow
    /// them and a non-modal one can let them bubble.
    Ignored,
}

/// A field list with one focus, its last rejection, and the key routing both.
pub(crate) struct Form {
    pub fields: Vec<Field>,
    /// Index into `fields`; always a focusable one once the form has any.
    pub focus: usize,
    /// The last commit's rejection, shown under the fields until the next one.
    /// The typing stays: a validation failure must never cost an entry.
    pub error: Option<String>,
}

impl Form {
    pub fn new(fields: Vec<Field>) -> Self {
        let focus = fields.iter().position(Field::focusable).unwrap_or(0);
        Self {
            fields,
            focus,
            error: None,
        }
    }

    /// Start focused on `field` instead of the first focusable one — the
    /// add-server form opens on Address, the only field with no sane default.
    #[must_use]
    pub fn focused_on(mut self, field: usize) -> Self {
        if self.fields.get(field).is_some_and(Field::focusable) {
            self.focus = field;
        }
        self
    }

    /// The focused field's raw text (trimmed), or `""` for a selector.
    pub fn text(&self, index: usize) -> &str {
        match self.fields.get(index).map(|field| &field.kind) {
            Some(FieldKind::Text { value, .. }) => value.trim(),
            _ => "",
        }
    }

    /// The chosen index of a selector field, or `0`.
    pub fn choice(&self, index: usize) -> usize {
        match self.fields.get(index).map(|field| &field.kind) {
            Some(FieldKind::Choice { index, .. }) => *index,
            _ => 0,
        }
    }

    /// Focus the first focusable field (a `g` jump, an editor re-opening).
    pub fn focus_first(&mut self) {
        // Stepping forward off the end wraps onto it, and skips a leading
        // display row on the way — which is why this is not `focus = 0`.
        self.focus = self.fields.len().saturating_sub(1);
        self.step_focus(true);
    }

    /// Focus the last focusable field (a `G` jump).
    pub fn focus_last(&mut self) {
        self.focus = 0;
        self.step_focus(false);
    }

    /// Move focus to the next/previous focusable field, wrapping.
    pub fn step_focus(&mut self, forward: bool) {
        let len = self.fields.len();
        if len == 0 {
            return;
        }
        for step in 1..=len {
            let index = if forward {
                (self.focus + step) % len
            } else {
                (self.focus + len - step % len) % len
            };
            if self.fields[index].focusable() {
                self.focus = index;
                return;
            }
        }
    }

    /// Step the focused selector, wrapping. Reports whether there was one.
    pub fn step_choice(&mut self, forward: bool) -> bool {
        let Some(FieldKind::Choice { options, index }) =
            self.fields.get_mut(self.focus).map(|field| &mut field.kind)
        else {
            return false;
        };
        let len = options.len();
        if len == 0 {
            return false;
        }
        *index = if forward {
            (*index + 1) % len
        } else {
            (*index + len - 1) % len
        };
        true
    }

    /// The width at which no value has to wrap: the label gutter, the marker
    /// reserve, and the longest entry the form currently holds.
    ///
    /// A modal sizes itself to this (the greedy-width rule, the same one
    /// the help overlay follows) so a pasted URL reads on one line inside a box
    /// that had room to grow.
    pub fn natural_width(&self) -> usize {
        let widest = self
            .fields
            .iter()
            .map(|field| field.value().0.chars().count())
            .max()
            .unwrap_or(0);
        LABEL_W + 2 + MARKER_W + widest
    }

    /// Is the focused field a selector (nothing to type into)?
    pub fn focus_is_item(&self) -> bool {
        matches!(
            self.fields.get(self.focus).map(|field| &field.kind),
            Some(FieldKind::Item { .. })
        )
    }

    pub fn focus_is_choice(&self) -> bool {
        matches!(
            self.fields.get(self.focus).map(|field| &field.kind),
            Some(FieldKind::Choice { .. })
        )
    }

    /// Route one key. `Enter`/`Esc` are reported, never acted on.
    pub fn handle_key(&mut self, key: KeyEvent) -> FormKey {
        match key.code {
            KeyCode::Esc => FormKey::Cancel,
            KeyCode::Enter => FormKey::Commit,
            KeyCode::Tab | KeyCode::Down => {
                self.step_focus(true);
                FormKey::Consumed
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.step_focus(false);
                FormKey::Consumed
            }
            KeyCode::Left if self.focus_is_choice() => {
                self.step_choice(false);
                FormKey::Consumed
            }
            KeyCode::Right | KeyCode::Char(' ') if self.focus_is_choice() => {
                self.step_choice(true);
                FormKey::Consumed
            }
            KeyCode::Backspace => {
                match self.fields.get_mut(self.focus).map(|field| &mut field.kind) {
                    Some(FieldKind::Text { value, .. }) => {
                        value.pop();
                    }
                    // A selector's "clear": back to its first option, which is
                    // every selector's "no constraint" entry.
                    Some(FieldKind::Choice { index, .. }) => *index = 0,
                    _ => {}
                }
                FormKey::Consumed
            }
            KeyCode::Char(c) => {
                if let Some(FieldKind::Text { value, .. }) =
                    self.fields.get_mut(self.focus).map(|field| &mut field.kind)
                {
                    value.push(c);
                }
                FormKey::Consumed
            }
            _ => FormKey::Ignored,
        }
    }

    /// The form as a modal lays it out: its fields, `footer` under them (the
    /// key legend), and the lines a scrolling frame keeps on screen for the
    /// focus. The first field answers for everything above it and the last
    /// for everything under it, so the heading, the rejection and the legend
    /// are in view when the focus is at an end.
    pub fn render_modal(
        &self,
        width: usize,
        theme: &Theme,
        footer: Vec<Line<'static>>,
    ) -> (Vec<Line<'static>>, Range<usize>) {
        let mut rendered = self.render(width, theme, true);
        rendered.lines.push(Line::raw(""));
        rendered.lines.extend(footer);
        let mut focus = rendered.focus;
        let mut focusable = self
            .fields
            .iter()
            .enumerate()
            .filter(|(_, field)| field.focusable())
            .map(|(index, _)| index);
        if focusable.next() == Some(self.focus) {
            focus.start = 0;
        }
        if focusable.next_back().unwrap_or(self.focus) == self.focus {
            focus.end = rendered.lines.len();
        }
        (rendered.lines, focus)
    }

    /// Render the whole form to `width` columns.
    ///
    /// `caret` marks the focused field's insertion point; a browsing surface
    /// (the Settings tab, whose fields are only editable once entered) passes
    /// `false` and still shows which row the cursor is on.
    ///
    /// No line exceeds `width` at or above [`MIN_WIDTH`]; values, notes and
    /// the error all wrap rather than clip.
    pub fn render(&self, width: usize, theme: &Theme, caret: bool) -> Rendered {
        // The label span is `" {label:<LABEL_W$} "` — one column of padding on
        // each side of the column itself.
        let gutter = LABEL_W + 2;
        let value_w = width.saturating_sub(gutter + MARKER_W).max(1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut rows: Vec<Option<usize>> = Vec::new();
        let mut focus = 0..0;

        for (index, field) in self.fields.iter().enumerate() {
            if let Some(section) = field.section {
                if !lines.is_empty() {
                    lines.push(Line::raw(""));
                    rows.push(None);
                }
                lines.push(Line::from(Span::styled(
                    section.to_string(),
                    Style::new().fg(theme.highlight),
                )));
                rows.push(None);
            }
            let focused = index == self.focus;
            let label_style = if focused {
                Style::new().fg(theme.accent)
            } else {
                theme.dim_text()
            };
            let (value, dim) = field.value();
            let value_style = if dim {
                theme.dim_text()
            } else {
                Style::new().fg(theme.fg)
            };
            let start = lines.len();
            let mut field_lines = labeled_lines(
                Span::styled(format!(" {:<LABEL_W$} ", field.label), label_style),
                value,
                value_style,
                value_w,
            );
            if focused
                && caret
                && let Some(last) = field_lines.last_mut()
            {
                // A selector shows its cycle arrows instead: there is no
                // insertion point to mark.
                last.spans.push(if field.is_choice() {
                    Span::styled(ARROWS, Style::new().fg(theme.accent))
                } else {
                    Span::styled(CURSOR, Style::new().fg(theme.accent))
                });
            }
            // The note rides the value's last line when there is room for it,
            // and drops to a hanging line under the value column when there is
            // not — never clipped, and never mistaken for a value by
            // sitting in the label column.
            if !field.note.is_empty() {
                let note = format!("  {}", field.note);
                let used = field_lines.last().map_or(0, Line::width);
                if used + note.chars().count() <= width {
                    if let Some(last) = field_lines.last_mut() {
                        last.spans.push(Span::styled(note, theme.dim_text()));
                    }
                } else {
                    let hang = " ".repeat(gutter);
                    field_lines.extend(crate::wrap::wrap_text(&note, value_w).into_iter().map(
                        |part| {
                            Line::from(vec![
                                Span::raw(hang.clone()),
                                Span::styled(part, theme.dim_text()),
                            ])
                        },
                    ));
                }
            }
            rows.resize(start + field_lines.len(), Some(index));
            lines.extend(field_lines);
            if focused {
                focus = start..lines.len();
            }
        }

        let mut error_at = None;
        if let Some(error) = &self.error {
            error_at = Some(lines.len());
            lines.push(Line::raw(""));
            // Glyph-marked, not just red: no fact in this UI is carried by
            // colour alone (spec §5), and a rejection is the last one that
            // should be.
            lines.extend(wrapped_lines(
                &format!(" ✗ {error}"),
                width,
                Style::new().fg(theme.bad),
            ));
            rows.resize(lines.len(), None);
        }
        Rendered {
            lines,
            rows,
            focus,
            error_at,
        }
    }
}

/// A rendered form: its display lines, which field each line belongs to (a
/// heading, a separator or the error carries `None`), where the focused field
/// sits so a scrolling surface can keep it on screen, and where the error
/// block begins so a scrolling surface can pin it instead of letting a
/// rejection scroll out of sight.
pub(crate) struct Rendered {
    pub lines: Vec<Line<'static>>,
    pub rows: Vec<Option<usize>>,
    pub focus: Range<usize>,
    pub error_at: Option<usize>,
}

/// A port entry: `1`–`65535`. Shared by every form that takes one — the
/// add-server modal and the two Settings port fields — so the three cannot
/// disagree about what a port is.
pub(crate) fn validate_port(port: &str) -> Result<u16, String> {
    if port.is_empty() {
        return Err("port is required (1–65535)".to_string());
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("'{port}' is not a port number (1–65535)")),
        Ok(port) => Ok(port),
    }
}

/// An `http`/`https` URL, the only two schemes anything here fetches over.
pub(crate) fn validate_url(url: &str) -> Result<&str, String> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(url)
    } else {
        Err("URL must start with http:// or https://".to_string())
    }
}

#[cfg(test)]
mod tests;
