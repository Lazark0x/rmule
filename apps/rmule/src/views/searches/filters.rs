//! The search-options editor: file type, min/max size, availability
//! and extension.
//!
//! aMule's extended-search panel offers exactly these five constraints, and
//! every one is a term in the request's expression tree. A bound that cannot
//! be read, or a max below its min, is refused in the editor with a reason
//! rather than silently dropped.

use ratatui::crossterm::event::KeyEvent;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use rmule_primitives::{Ed2kFileClass, Ed2kText, KeywordQuery};

use super::SearchesView;
use super::ViewOutcome;
use crate::form::{Field, Form, FormKey};
use crate::state::UiState;
use crate::theme::Theme;
use crate::words::search::{FilterError, SizeFault, filter_error_words};
use crate::wrap::wrap_text;

/// The parsed form of [`Filters`] — what actually reaches the query.
struct Constraints {
    class: Option<Ed2kFileClass>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    min_sources: Option<u32>,
    extension: Option<String>,
}

/// The five typed constraints, held as the operator entered them.
///
/// A thin skin over the shared [`Form`] — text, not parsed values, for
/// the reason every form here keeps text: a half-typed `700 M` must survive a
/// redraw, and a rejection must leave the entry on screen to be corrected
/// rather than swallow it. The field order is aMule's dialog order
/// (`SearchDlg.cpp:455-494`).
pub(super) struct Filters {
    pub(super) form: Form,
}

impl Filters {
    /// The form's field indices, in render order.
    const TYPE: usize = 0;
    const MIN_SIZE: usize = 1;
    const MAX_SIZE: usize = 2;
    const MIN_SOURCES: usize = 3;
    const EXTENSION: usize = 4;

    fn text(&self, field: usize) -> &str {
        self.form.text(field)
    }

    /// The chosen file class, or `None` for aMule's "Any" — the first entry of
    /// its type dropdown (`muuli_wdr.cpp:227-235`), which clears
    /// `params.typeText` and so contributes no term.
    fn class(&self) -> Option<Ed2kFileClass> {
        match self.form.choice(Self::TYPE) {
            0 => None,
            index => Ed2kFileClass::ALL.get(index - 1).copied(),
        }
    }

    /// Parse and cross-check every field, or say why not.
    fn constraints(&self) -> Result<Constraints, FilterError> {
        let min_size = parse_size(self.text(Self::MIN_SIZE)).map_err(FilterError::MinSize)?;
        let max_size = parse_size(self.text(Self::MAX_SIZE)).map_err(FilterError::MaxSize)?;
        // aMule warns and silently drops the max (`SearchDlg.cpp:467-474`).
        // rmule refuses instead: a dropped bound is a search the operator did
        // not ask for, and the editor is right there to fix it in.
        if let (Some(min), Some(max)) = (min_size, max_size)
            && max < min
        {
            return Err(FilterError::MaxBelowMin);
        }
        let min_sources = match self.text(Self::MIN_SOURCES) {
            "" => None,
            text => match text.parse::<u32>() {
                Ok(0) => None,
                Ok(count) => Some(count),
                Err(_) => return Err(FilterError::MinSourcesNotWhole(text.to_string())),
            },
        };
        // A leading dot is how people write extensions; the wire wants the bare
        // form (`FT_FILEFORMAT` values are captured bare — `mp3`, not `.mp3`).
        let extension = match self.text(Self::EXTENSION).trim_start_matches('.') {
            "" => None,
            text => Some(text.to_string()),
        };
        Ok(Constraints {
            class: self.class(),
            min_size,
            max_size,
            min_sources,
            extension,
        })
    }

    /// Attach the parsed constraints to `query`.
    pub(super) fn apply(&self, mut query: KeywordQuery) -> Result<KeywordQuery, FilterError> {
        let parsed = self.constraints()?;
        if let Some(class) = parsed.class {
            query = query.with_file_type(class);
        }
        if let Some(size) = parsed.min_size {
            query = query.with_min_size(size);
        }
        if let Some(size) = parsed.max_size {
            query = query.with_max_size(size);
        }
        if let Some(count) = parsed.min_sources {
            query = query.with_min_availability(count);
        }
        if let Some(extension) = parsed.extension {
            query = query.with_extension(Ed2kText::from_utf8(&extension));
        }
        Ok(query)
    }

    /// The idle one-liner: only the constraints that are actually set, so an
    /// unfiltered search says so in one word instead of five empty slots.
    fn summary(&self) -> String {
        let set = |field: usize| {
            let text = self.text(field);
            (!text.is_empty()).then_some(text)
        };
        let parts: Vec<String> = [
            self.class()
                .map(|class| crate::words::search::file_class_words(class).to_string()),
            set(Self::MIN_SIZE).map(|text| format!("≥{text}")),
            set(Self::MAX_SIZE).map(|text| format!("≤{text}")),
            set(Self::MIN_SOURCES).map(|text| format!("≥{text} src")),
            set(Self::EXTENSION).map(|text| format!(".{}", text.trim_start_matches('.'))),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

impl Default for Filters {
    fn default() -> Self {
        // "Any" leads the class selector, exactly where aMule's dropdown puts
        // it, so index 0 is always "no constraint".
        let mut classes = vec!["Any"];
        classes.extend(
            Ed2kFileClass::ALL
                .iter()
                .map(|class| crate::words::search::file_class_words(*class)),
        );
        Self {
            form: Form::new(vec![
                Field::choice("Type", classes, 0),
                Field::text("Min size", "").with_placeholder("any (e.g. 700 MB)"),
                Field::text("Max size", "").with_placeholder("any (e.g. 700 MB)"),
                Field::text("Min sources", "").with_placeholder("any (e.g. 10)"),
                Field::text("Extension", "").with_placeholder("any (e.g. avi)"),
            ]),
        }
    }
}

/// A size bound as a person writes it: a number with an optional binary unit.
///
/// aMule splits this into a spin control and a Bytes/KB/MB/GB dropdown, and
/// multiplies (`GetTypeSize`, `OtherFunctions.cpp:237-250`: 1, 1024, 1048576,
/// 1073741824). One text field is the terminal's equivalent, on the same
/// multipliers. `TB` goes past aMule's dropdown — its comment says values over
/// GB "aren't handled since the amount of Bytes 1TB represents is over the
/// uint32 capacity" — but rmule's bound is a `u64` and the request's `0x08`
/// node carries it, so the unit that needs 64 bits is exactly the one worth
/// having.
///
/// Blank, or a plain zero, is "no bound": aMule reads its spin control's 0 the
/// same way (`if (params.minSize > 0)`).
fn parse_size(text: &str) -> Result<Option<u64>, SizeFault> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let split = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        "t" | "tb" => 1024_u64.pow(4),
        other => return Err(SizeFault::UnknownUnit(other.to_string())),
    };
    let value: f64 = number
        .parse()
        .map_err(|_| SizeFault::NotASize(text.to_string()))?;
    if value < 0.0 || !value.is_finite() {
        return Err(SizeFault::NotASize(text.to_string()));
    }
    // f64 has 53 bits of mantissa, so a decimal count of TB rounds rather than
    // overflows; the clamp keeps a pathological entry from wrapping.
    let bytes = (value * multiplier as f64).round();
    if bytes >= u64::MAX as f64 {
        return Err(SizeFault::TooLarge);
    }
    Ok((bytes > 0.0).then_some(bytes as u64))
}

impl SearchesView {
    /// One key inside the expanded filter editor. `Tab`/`↑`/`↓` move between
    /// fields, `←`/`→` (and space) cycle the type selector, `Enter` applies —
    /// and searches, the way `Enter` in aMule's extension field does
    /// (`wxTE_PROCESS_ENTER` on `IDC_EDITSEARCHEXTENSION`) — and `Esc` closes
    /// without discarding what was typed.
    pub(super) fn handle_filter_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        match self.filters.form.handle_key(key) {
            FormKey::Cancel => {
                self.filters_open = false;
                ViewOutcome::Redraw
            }
            // Validate before closing: an unparseable bound must not vanish
            // into a search that silently ignored it (the house rule — the
            // editor stays up with the typing intact).
            FormKey::Commit => match self.filters.constraints() {
                Ok(_) => {
                    self.filters.form.error = None;
                    self.filters_open = false;
                    if self.query.trim().is_empty() {
                        ViewOutcome::Redraw
                    } else {
                        self.commit_query(state)
                    }
                }
                Err(reason) => {
                    self.filters.form.error = Some(filter_error_words(&reason));
                    ViewOutcome::Redraw
                }
            },
            // The editor is modal in the query input's sense: printables are
            // text, so no binding letter leaks out of it.
            FormKey::Consumed | FormKey::Ignored => ViewOutcome::Redraw,
        }
    }

    /// The search-options row: one summary line when idle, the labelled editor
    /// when expanded (the Networks add-server form's shape, inline instead of
    /// modal — these fields belong *to* the query above them).
    pub(super) fn filter_lines(&self, width: usize, theme: &Theme) -> Vec<Line<'static>> {
        if !self.filters_open {
            let mut spans = vec![Span::styled("Filters: ", theme.dim_text())];
            let summary = self.filters.summary();
            let style = if summary == "none" {
                theme.dim_text()
            } else {
                Style::new().fg(theme.fg)
            };
            spans.push(Span::styled(summary, style));
            spans.push(Span::styled("   o edit", theme.dim_text()));
            let line = Line::from(spans);
            if line.width() <= width {
                return vec![line];
            }
            let flat: String = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect();
            return wrap_text(&flat, width)
                .into_iter()
                .map(|part| Line::from(Span::styled(part, theme.dim_text())))
                .collect();
        }
        self.filters.form.render(width, theme, true).lines
    }
}

#[cfg(test)]
mod tests;
