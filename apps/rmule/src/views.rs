//! View modules. Each view owns its view state (selection,
//! scroll, menu/modal machines), its key handling, and its rendering; the
//! app loop offers the active view each input first and dispatches drawing.
//!
//! Contract every view implements (uniform, so integration is mechanical):
//!
//! ```ignore
//! pub struct <Name>View { /* view state only — data lives in UiState */ }
//! impl <Name>View {
//!     pub fn handle_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome;
//!     pub fn draw(&mut self, frame: &mut Frame, area: Rect, state: &UiState,
//!                 theme: &Theme, now: Instant);
//! }
//! ```

mod modal;
pub mod networks;
pub(crate) mod off_screen;
pub(crate) mod related;
pub mod searches;
pub mod settings;
pub mod shared_files;
mod software;

pub(crate) use crate::words::software::label as software_label;
// A byte quantity has one spelling, the words' own, on every surface.
pub(crate) use crate::words::units::human_size;
pub mod statistics;
pub(crate) mod title;
pub mod transfers;

use std::time::Instant;

use ratatui::layout::{Position, Rect};
use ratatui::style::Style;

use crate::action::Action;
use crate::rates::format_rate;
use crate::state::UiState;
use crate::theme::Theme;

/// The one way anything in this crate asks core to connect to a server
/// (ADR-0080 amendment).
///
/// The login presents core's own Core Settings' credentials; a UI-only run
/// (no [`SessionConfig`](crate::state::SessionConfig), no core) cannot
/// connect. Shared by the Networks row menu and the Networks `c` key (selected
/// row) so the two cannot degrade differently.
pub(crate) fn connect_action(state: &UiState, server: rmule_primitives::ServerEndpoint) -> Action {
    match &state.session {
        Some(_) => Action::Command(rmule_core::CoreCommand::ConnectToServer { server }),
        None => Action::Flash(crate::words::app::CORE_NOT_ATTACHED),
    }
}

/// Whether `server` is the one the operator's intent stands on: connected
/// to it, or re-making its lost session. There `c` and the row menu
/// disconnect; everywhere else they connect.
pub(crate) fn is_ours(state: &UiState, server: &rmule_primitives::ServerEndpoint) -> bool {
    is_connected_to(state, server) || is_remaking(state, server)
}

/// The Networks tab's `c` key, the eD2k connect/disconnect toggle: on the
/// server the operator is connected to — or whose lost session core is
/// re-making — it disconnects, which ends the intent to stay connected; on
/// any other it connects there, which replaces that intent.
/// Whether core is re-making `server`'s lost session: the intent stands on it
/// but no connection does.
pub(crate) fn is_remaking(state: &UiState, server: &rmule_primitives::ServerEndpoint) -> bool {
    state
        .reconnect
        .as_ref()
        .is_some_and(|reconnect| &reconnect.server == server)
        && !is_connected_to(state, server)
}

fn is_connected_to(state: &UiState, server: &rmule_primitives::ServerEndpoint) -> bool {
    state.connected_server.as_ref() == Some(server)
        || state.diagnostics.connected_server.as_ref() == Some(server)
}

pub(crate) fn connect_toggle(state: &UiState, server: rmule_primitives::ServerEndpoint) -> Action {
    if is_ours(state, &server) {
        Action::Command(rmule_core::CoreCommand::DisconnectFromServer)
    } else {
        connect_action(state, server)
    }
}

/// Text + style of a **Speed** cell, shared by every table that renders one
/// (downloads, sources, upload peers) so the meters read alike.
///
/// A measured rate reads normal; anything the bridge has not metered yet — a
/// row on its first tick, a queued peer with no upload slot — is an honest
/// dash rather than a zero nobody observed (spec §1's "no dead UI"). A meter
/// that has decayed still reports its number: a rate that stopped is a falling
/// rate, not a missing one.
pub(crate) fn rate_cell(bps: f64, theme: &Theme) -> (String, Style) {
    if bps > 0.0 {
        (format_rate(bps), Style::new().fg(theme.fg))
    } else {
        ("—".to_string(), theme.dim_text())
    }
}

/// The local calendar day of `at`, as a confirm or a table names a moment
/// rmule noticed something.
pub(crate) fn day(at: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(at)
        .format("%Y-%m-%d")
        .to_string()
}

/// Relative age of an observation (spec §3.4): seconds under a minute, then
/// whole minutes. Injected time only — `Instant` is monotonic, never
/// wall-clock. One vocabulary for every surface that dates a fact (the
/// Networks log pane, the Statistics graph axis).
pub(crate) fn relative_age(at: Instant, now: Instant) -> String {
    let secs = now.saturating_duration_since(at).as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else {
        format!("{}m ago", secs / 60)
    }
}

/// Rows region of a bordered table with one header row drawn at `area`:
/// inside the frame, below the header — where a test clicks a row.
#[cfg(test)]
pub(crate) fn table_rows(area: Rect) -> Rect {
    Rect {
        x: area.x.saturating_add(1),
        y: area.y.saturating_add(2),
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(3),
    }
}

/// A table's rows as the last draw laid them out: the region they occupy and
/// each drawn row's height from the first one on screen. A click is mapped
/// back through the heights, because a wrapped row is several screen lines
/// (**Greedy width**) and a line count is not a row count.
#[derive(Clone, Debug, Default)]
pub(crate) struct DrawnRows {
    area: Rect,
    first: usize,
    heights: Vec<u16>,
}

impl DrawnRows {
    /// Rows drawn into `area`, the topmost being display row `first`, each
    /// `heights[i]` lines tall.
    pub(crate) fn new(area: Rect, first: usize, heights: Vec<u16>) -> Self {
        Self {
            area,
            first,
            heights,
        }
    }

    /// The display row a click at (`column`, `row`) lands on, if any.
    pub(crate) fn hit(&self, column: u16, row: u16) -> Option<usize> {
        if !self.area.contains(Position::new(column, row)) {
            return None;
        }
        let mut line = row - self.area.y;
        for (index, height) in self.heights.iter().enumerate() {
            if line < *height {
                return Some(self.first + index);
            }
            line -= height;
        }
        None
    }
}

#[cfg(test)]
impl DrawnRows {
    /// The screen line display row `index` starts on, if it was drawn.
    pub(crate) fn line_of(&self, index: usize) -> Option<u16> {
        let drawn = index.checked_sub(self.first)?;
        (drawn < self.heights.len())
            .then(|| self.area.y + self.heights[..drawn].iter().sum::<u16>())
    }
}

/// A server-reported population, five columns wide at most: exact under ten
/// thousand, then whole thousands, then whole millions — `—` when nothing
/// was reported. A rounded population is still the server's claim; a wrapped
/// cell would only be noise.
pub(crate) fn short_count(count: Option<u32>) -> String {
    match count {
        None => "—".to_string(),
        Some(n) if n < 10_000 => n.to_string(),
        Some(n) if n < 1_000_000 => format!("{}k", n / 1_000),
        Some(n) => format!("{}M", n / 1_000_000),
    }
}

/// Did the click land anywhere inside `area` (border included)? Used for
/// pane-focus clicks where no row math applies.
pub(crate) fn pane_hit(area: Rect, column: u16, row: u16) -> bool {
    area.contains(Position::new(column, row))
}

/// Say on a bordered pane's bottom border which of its table's columns gave
/// way at this width ([`crate::wrap::gave_way`]): a column the pane cannot
/// hold is a gap in what the operator sees, and a gap is said in words — by
/// name when the border holds them, else by count, never cut. `foot` is the
/// stretch of the border the Viewport's count left
/// ([`Viewport::draw`](crate::row_selection::viewport::Viewport::draw)), so
/// the note gives way before the count does. Drawn after the pane, over its
/// border; nothing when every column shows.
pub(crate) fn say_gave_way(frame: &mut ratatui::Frame, foot: Rect, hidden: &[&str], theme: &Theme) {
    if foot.width == 0 || foot.height == 0 {
        return;
    }
    let Some(note) = crate::wrap::gave_way_note(hidden, usize::from(foot.width)) else {
        return;
    };
    let line = Rect { height: 1, ..foot };
    frame.render_widget(
        ratatui::widgets::Paragraph::new(ratatui::text::Span::styled(note, theme.dim_text())),
        line,
    );
}

/// The stretch of a bordered pane's bottom border between its corners, where
/// its count and its notes go; nothing for a pane too small to have one.
pub(crate) fn bottom_border(pane: Rect) -> Rect {
    if pane.width <= 2 || pane.height == 0 {
        return Rect::default();
    }
    Rect::new(pane.x + 1, pane.bottom() - 1, pane.width - 2, 1)
}

/// Center a `width`×`height` rect inside `area`, clamped to fit — the one
/// overlay geometry every view's modals and the help overlay share.
pub(crate) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

/// What a view did with an input it was offered.
// One outcome per keypress on the stack; boxing the `Emit` payload would add
// indirection for no measurable gain (mirrors CoreCommand's reasoning).
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ViewOutcome {
    /// Not this view's key — bubble on to the global bindings.
    Ignored,
    /// View state changed; repaint.
    Redraw,
    /// Hand an action to the app loop (a core command, a flash, navigation).
    Emit(Action),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn relative_age_switches_from_seconds_to_minutes_at_sixty() {
        let base = Instant::now();
        let now = base + Duration::from_secs(10_000);
        assert_eq!(relative_age(now - Duration::from_secs(12), now), "12s ago");
        assert_eq!(relative_age(now - Duration::from_secs(59), now), "59s ago");
        assert_eq!(relative_age(now - Duration::from_secs(60), now), "1m ago");
        assert_eq!(relative_age(now - Duration::from_secs(180), now), "3m ago");
    }
}
