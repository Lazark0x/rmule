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
//!                 theme: &Theme, now: Instant) -> Option<Position>;
//!     pub(crate) fn text_open(&self) -> bool;
//! }
//! ```
//!
//! `draw` returns where the caret of an open text field is, and the app puts
//! the terminal's cursor there; `text_open` says a field holds the keyboard,
//! so the Key Gate passes it the chords a line editor binds.

pub(crate) mod menu;
pub(crate) mod modal;
pub mod networks;
pub(crate) mod off_screen;
pub(crate) mod panes;
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
pub(crate) mod too_small;
pub mod transfers;

use std::ops::Range;

use ratatui::layout::{Position, Rect};
use ratatui::style::Style;

use crate::action::Action;
use crate::state::{Ed2kConnection, UiState};
use crate::table::Cell;
use crate::theme::Theme;
use crate::words::absent;
use crate::words::units::{self, rate};

/// The canonical eD2k link for a file, through [`rmule_primitives::Ed2kLink`]'s
/// `Display`, so names with spaces or `|` come out escaped. `None` for a size
/// no link can name: a stored share past eD2k's limit.
pub(crate) fn ed2k_file_link(
    name: &rmule_primitives::Ed2kText,
    size: u64,
    file_hash: rmule_primitives::FileHash,
) -> Option<String> {
    let link = rmule_primitives::Ed2kFileLink::new(name.clone(), size, file_hash).ok()?;
    Some(rmule_primitives::Ed2kLink::File(link).to_string())
}

/// The one way anything in this crate asks core to connect to a server
/// (ADR-0080 amendment).
///
/// The login presents core's own Core Settings' credentials. Shared by the
/// Networks row menu and the Networks `c` key (selected row).
pub(crate) const fn connect_action(server: rmule_primitives::ServerEndpoint) -> Action {
    Action::Command(rmule_core::CoreCommand::ConnectToServer { server })
}

/// Whether `server` is the one the operator's intent stands on: connected
/// to it, or re-making its lost session. There `c` and the row menu
/// disconnect; everywhere else they connect.
pub(crate) fn is_ours(state: &UiState, server: &rmule_primitives::ServerEndpoint) -> bool {
    is_connected_to(state, server) || is_remaking(state, server) || is_dialling(state, server)
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

/// Whether a dial to `server` is out, which `c` stops.
pub(crate) fn is_dialling(state: &UiState, server: &rmule_primitives::ServerEndpoint) -> bool {
    matches!(&state.ed2k, Ed2kConnection::Connecting { server: dialled } if dialled == server)
}

/// Read off the edge, as the status bar is: the level trails it by a tick, so
/// the two would disagree in one frame.
fn is_connected_to(state: &UiState, server: &rmule_primitives::ServerEndpoint) -> bool {
    state.connected_server.as_ref() == Some(server)
}

/// How Kad's dot is coloured, on the status bar and the Networks panel alike:
/// green joined, amber on its way, and off dim when that is simply where it
/// stands, red when it ended on its own.
pub(crate) fn kad_dot(state: &UiState, theme: &Theme) -> ratatui::style::Color {
    match (state.diagnostics.kad_state, state.diagnostics.kad) {
        (rmule_core::diagnostics::KadState::Off, _) if state.kad_lost => theme.bad,
        (rmule_core::diagnostics::KadState::Off, _) => theme.dim,
        (_, Some(kad)) if kad.contact_responded => theme.good,
        _ => theme.warn,
    }
}

/// Where Kad stands in the one word set the status bar and the Networks panel
/// share, styled by whether it is running.
pub(crate) fn kad_word(state: &UiState, theme: &Theme) -> (&'static str, Style) {
    let contact = state
        .diagnostics
        .kad
        .is_some_and(|kad| kad.contact_responded);
    let kad_state = state.diagnostics.kad_state;
    let word = crate::words::kad::state_word(kad_state, contact);
    let style = if kad_state == rmule_core::diagnostics::KadState::Off {
        theme.dim_text()
    } else {
        Style::new().fg(theme.fg)
    };
    (word, style)
}

pub(crate) fn connect_toggle(state: &UiState, server: rmule_primitives::ServerEndpoint) -> Action {
    if is_ours(state, &server) {
        Action::Command(rmule_core::CoreCommand::DisconnectFromServer)
    } else {
        connect_action(server)
    }
}

/// Text + style of a **Speed** cell, shared by every table that renders one
/// (downloads, sources, upload peers) so the meters read alike.
///
/// The floor of a column of sizes: the widest it draws, in this language's
/// units.
pub(crate) fn size_floor() -> usize {
    crate::wrap::display_width(&human_size(units::WIDEST_SIZE))
}

/// A rate cell. A meter reads what it measured, a zero as a zero, dim; a row
/// no meter stands behind — a queued peer with no upload slot, a source no
/// slot holds — has none, and says so rather than a zero nobody observed.
pub(crate) fn rate_cell(bps: Option<f64>, theme: &Theme) -> Cell {
    match bps {
        Some(bps) if bps > 0.0 => Cell::new(rate(bps), Style::new().fg(theme.fg)),
        Some(bps) => Cell::new(rate(bps), theme.dim_text()),
        None => Cell::absent(absent::NOT_MEASURED, theme.dim_text()),
    }
}

/// The local calendar day of `at`, as a confirm or a table names a moment
/// rmule noticed something.
pub(crate) fn day(at: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(at)
        .format(crate::words::log::DAY_FORMAT)
        .to_string()
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

/// Did the click land anywhere inside `area` (border included)? Used for
/// pane-focus clicks where no row math applies.
pub(crate) fn pane_hit(area: Rect, column: u16, row: u16) -> bool {
    area.contains(Position::new(column, row))
}

/// Say on a bordered pane's bottom border which of its table's columns gave
/// way at this width ([`crate::table::gave_way`]): a column the pane cannot
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
    let Some(note) = crate::table::gave_way_note(hidden, usize::from(foot.width)) else {
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

/// Where a caret at line `at.0`, column `at.1` of laid-out lines falls when
/// `shown` of them are drawn into `area`: nowhere when it is scrolled off.
pub(crate) fn caret_in(
    area: Rect,
    shown: Range<usize>,
    at: Option<(usize, u16)>,
) -> Option<Position> {
    let (line, column) = at?;
    if !shown.contains(&line) || column >= area.width {
        return None;
    }
    let row = crate::wrap::clamp_u16(line - shown.start);
    (row < area.height).then(|| Position::new(area.x + column, area.y + row))
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
