//! The one form machine every editable surface in this crate runs on.
//!
//! An editable surface is a field list with one focus: `Tab`/`BackTab`
//! between fields, the [`LineEdit`] keys into the focused one, `Enter` to
//! commit and `Esc` to leave, [`labeled_lines`] rendering every field and the
//! last rejection under them, with the caret's place on screen beside the
//! lines. The Networks add-server modal, the Searches options editor and the
//! Settings tab all run on it. Only *validation* stays with each view, being
//! the one part that is genuinely about what is being edited.
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
//! - **A one-field edit stays on its field.** [`Form::field_key`] is the
//!   focused field's own keys and leaves focus alone: the Settings tab commits
//!   one field at a time, so moving off it would drop what was typed.

use std::ops::Range;

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::line_edit::LineEdit;
use crate::theme::Theme;
use crate::words::Sentence;
use crate::words::app as words;
use crate::wrap::{clamp_u16, display_width, labeled_lines, wrapped_lines};

mod path;

pub(crate) use path::complete_directory;

/// Label column every form's fields align on — the unification of the two
/// widths the views had drifted to (Networks 10, Searches 11). Sized to the
/// widest label any of them carries (`Download dir`, `Nodes.dat URL`).
pub(crate) const LABEL_W: usize = 12;

/// A focused selector wears its cycle arrows: there is no insertion point to
/// mark on something you step.
const ARROWS: &str = "  ←→";

/// Columns the value column gives up for the selector's arrows and the caret
/// past the end of a text. Reserved on *every* row, so entering an editor
/// cannot re-wrap a value that fits.
const MARKER_W: usize = 4; // `ARROWS`

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
        edit: LineEdit,
        /// What an empty field shows instead, so the accepted syntax is never
        /// a guess. Dim, with the caret before it, never mistaken for a value.
        placeholder: String,
        /// A directory: `Tab` completes it from the disk.
        path: bool,
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
                edit: LineEdit::new(value),
                placeholder: String::new(),
                path: false,
            },
            note: String::new(),
        }
    }

    /// A text field that names a directory.
    pub fn directory(label: &'static str, value: impl Into<String>) -> Self {
        let mut field = Self::text(label, value);
        if let FieldKind::Text { path, .. } = &mut field.kind {
            *path = true;
        }
        field
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

    /// The rendered value and whether it is the placeholder rather than an
    /// entry (which reads dim).
    fn value(&self) -> (&str, bool) {
        match &self.kind {
            FieldKind::Text {
                edit, placeholder, ..
            } if edit.is_empty() => (placeholder, true),
            FieldKind::Text { edit, .. } => (edit.text(), false),
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
    pub error: Option<Sentence>,
    /// A word about the focused field that refuses nothing, shown where a
    /// rejection is until the next key.
    pub note: Option<Sentence>,
}

impl Form {
    pub fn new(fields: Vec<Field>) -> Self {
        let focus = fields.iter().position(Field::focusable).unwrap_or(0);
        Self {
            fields,
            focus,
            error: None,
            note: None,
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
            Some(FieldKind::Text { edit, .. }) => edit.text().trim(),
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
            .map(|field| display_width(field.value().0))
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

    /// Is the focused field a directory, so `Tab` completes it?
    pub fn focus_is_directory(&self) -> bool {
        matches!(
            self.fields.get(self.focus).map(|field| &field.kind),
            Some(FieldKind::Text { path: true, .. })
        )
    }

    pub fn focus_is_choice(&self) -> bool {
        matches!(
            self.fields.get(self.focus).map(|field| &field.kind),
            Some(FieldKind::Choice { .. })
        )
    }

    /// A paste into the focused text field, at its caret, on one line.
    /// Whether there was a field to take it.
    pub fn paste(&mut self, text: &str) -> bool {
        let Some(FieldKind::Text { edit, .. }) = self.focused_kind() else {
            return false;
        };
        edit.paste(text);
        true
    }

    /// Replace the focused text field with `text`, kept as it stands.
    pub fn set_focused_text(&mut self, text: &str) {
        if let Some(FieldKind::Text { edit, .. }) = self.focused_kind() {
            edit.set(text);
        }
    }

    fn focused_kind(&mut self) -> Option<&mut FieldKind> {
        self.fields.get_mut(self.focus).map(|field| &mut field.kind)
    }

    /// `Tab` on a directory field: as much of the path as the disk settles,
    /// and what is left to choose from under the field.
    fn complete_path(&mut self) {
        let Some(FieldKind::Text { edit, .. }) = self.focused_kind() else {
            return;
        };
        let completion = complete_directory(edit.text());
        if let Some(text) = completion.text {
            edit.set(&text);
        }
        self.note = completion.note;
    }

    /// Route one key: the focused field's, then the moves between fields.
    /// `Enter`/`Esc` are reported, never acted on.
    pub fn handle_key(&mut self, key: KeyEvent) -> FormKey {
        match (self.field_key(key), key.code) {
            (FormKey::Ignored, KeyCode::Tab | KeyCode::Down) => {
                self.step_focus(true);
                FormKey::Consumed
            }
            (FormKey::Ignored, KeyCode::BackTab | KeyCode::Up) => {
                self.step_focus(false);
                FormKey::Consumed
            }
            (outcome, _) => outcome,
        }
    }

    /// The focused field's own keys; focus stays where it is.
    pub fn field_key(&mut self, key: KeyEvent) -> FormKey {
        self.note = None;
        match key.code {
            KeyCode::Esc => return FormKey::Cancel,
            KeyCode::Enter => return FormKey::Commit,
            _ => {}
        }
        match self.focused_kind() {
            Some(FieldKind::Text { path: true, .. }) if key.code == KeyCode::Tab => {
                self.complete_path();
                FormKey::Consumed
            }
            Some(FieldKind::Text { edit, .. }) => {
                if edit.key(&key) {
                    FormKey::Consumed
                } else {
                    FormKey::Ignored
                }
            }
            Some(FieldKind::Choice { index, .. }) if key.code == KeyCode::Backspace => {
                // A selector's "clear": back to its first option, which is
                // every selector's "no constraint" entry.
                *index = 0;
                FormKey::Consumed
            }
            Some(FieldKind::Choice { .. }) => match key.code {
                KeyCode::Left => {
                    self.step_choice(false);
                    FormKey::Consumed
                }
                KeyCode::Right | KeyCode::Char(' ') => {
                    self.step_choice(true);
                    FormKey::Consumed
                }
                KeyCode::Char(_) => FormKey::Consumed,
                _ => FormKey::Ignored,
            },
            Some(FieldKind::Display { .. } | FieldKind::Item { .. }) | None => match key.code {
                KeyCode::Backspace | KeyCode::Char(_) => FormKey::Consumed,
                _ => FormKey::Ignored,
            },
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
    ) -> ModalLines {
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
        ModalLines {
            lines: rendered.lines,
            focus,
            caret: rendered.caret,
        }
    }

    /// Render the whole form to `width` columns.
    ///
    /// `caret` opens the focused field for typing: a text field scrolls
    /// sideways around its caret, and [`Rendered::caret`] says where that is.
    /// A browsing surface (the Settings tab, whose fields are only editable
    /// once entered) passes `false` and still shows which row the cursor is
    /// on.
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
        let mut caret_at = None;

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
            let label = Span::styled(format!(" {:<LABEL_W$} ", field.label), label_style);
            let mut field_lines = match &field.kind {
                FieldKind::Text { edit, .. } if focused && caret && !edit.is_empty() => {
                    let shown = edit.show(value_w + MARKER_W, value_style, theme.dim_text());
                    caret_at = Some((start, clamp_u16(gutter) + shown.caret));
                    let mut spans = vec![label];
                    spans.extend(shown.spans);
                    vec![Line::from(spans)]
                }
                _ => labeled_lines(label, value, value_style, value_w),
            };
            if focused && caret {
                match &field.kind {
                    FieldKind::Text { edit, .. } if edit.is_empty() => {
                        caret_at = Some((start, clamp_u16(gutter)));
                    }
                    FieldKind::Choice { .. } => {
                        if let Some(last) = field_lines.last_mut() {
                            last.spans
                                .push(Span::styled(ARROWS, Style::new().fg(theme.accent)));
                        }
                    }
                    _ => {}
                }
            }
            // The note rides the value's last line when there is room for it,
            // and drops to a hanging line under the value column when there is
            // not — never clipped, and never mistaken for a value by
            // sitting in the label column.
            if !field.note.is_empty() {
                let note = format!("  {}", field.note);
                let used = field_lines.last().map_or(0, Line::width);
                if used + display_width(&note) <= width {
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
        } else if let Some(note) = &self.note {
            error_at = Some(lines.len());
            lines.push(Line::raw(""));
            lines.extend(wrapped_lines(&format!(" {note}"), width, theme.dim_text()));
            rows.resize(lines.len(), None);
        }
        Rendered {
            lines,
            rows,
            focus,
            error_at,
            caret: caret_at,
        }
    }
}

/// A form as a modal lays it out, for [`crate::views::modal::Modal::draw_form`].
pub(crate) struct ModalLines {
    pub lines: Vec<Line<'static>>,
    /// The lines the frame keeps on screen for the focus.
    pub focus: Range<usize>,
    /// The caret's line and column, while a text field holds it.
    pub caret: Option<(usize, u16)>,
}

/// A rendered form: its display lines, which field each line belongs to (a
/// heading, a separator or the error carries `None`), where the focused field
/// sits so a scrolling surface can keep it on screen, where the error block
/// begins so a scrolling surface can pin it instead of letting a rejection
/// scroll out of sight, and the caret's line and column while a text field
/// holds it.
pub(crate) struct Rendered {
    pub lines: Vec<Line<'static>>,
    pub rows: Vec<Option<usize>>,
    pub focus: Range<usize>,
    pub error_at: Option<usize>,
    pub caret: Option<(usize, u16)>,
}

/// A port entry: `1`–`65535`. Shared by every form that takes one — the
/// add-server modal and the two Settings port fields — so the three cannot
/// disagree about what a port is.
pub(crate) fn validate_port(port: &str) -> Result<u16, Sentence> {
    if port.is_empty() {
        return Err(words::port_refusal(&words::PortRefusal::Required));
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(words::port_refusal(&words::PortRefusal::NotAPort(
            port.to_string(),
        ))),
        Ok(port) => Ok(port),
    }
}

/// An `http`/`https` URL, the only two schemes anything here fetches over.
pub(crate) fn validate_url(url: &str) -> Result<&str, Sentence> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(url)
    } else {
        Err(words::URL_SCHEME)
    }
}

#[cfg(test)]
mod tests;
