//! The Settings view (spec §6 return): aMule's Preferences dialog as a
//! tab, over the one store that actually holds these facts.
//!
//! # Real knobs only
//!
//! Every editable row here is something a running rmule *reads*: the download
//! directory the next completed file lands in, the nickname and eD2k port the
//! next login advertises, the UDP port the client binds, the one obfuscation
//! policy core starts with (ADR-0046 — peer TCP, peer UDP and the Kad node's datagram crypt),
//! whether core maps those ports on the router (ADR-0086),
//! the two mirror URLs a list update and a Kad
//! cold start fetch from, the first-run `server.met` fetch (ADR-0065), the
//! `nodes.dat` opt-in (ADR-0067 amendment),
//! and the palette. Nothing here is a switch with no wire behind it.
//!
//! # Live and restart, said out loud
//!
//! Config is the front-end's (ADR-0069): core is *told* what it needs when a
//! session command is sent, and is never reconfigured behind one. So a knob is
//! live exactly when something re-reads it — the theme (every frame), the
//! download directory (the next `StartDownload`, and its scan), the `server.met` mirror (the
//! next Networks list update), the obfuscation policy (the next dial, accept,
//! datagram and Kad exchange) — and every other knob is honestly labelled
//! "takes effect on restart" rather than pretended at. Building live
//! re-configuration for a listen port would mean tearing down and re-logging a
//! session the operator did not ask to lose.
//!
//! # Identity is shown, never edited
//!
//! The User Hash and the Kad node ID are minted once from OS entropy and key
//! the credit and DHT position this client has earned (ADR-0041/0043). They are
//! `FieldKind::Display` rows: aligned with the settings around them, and
//! impossible to land focus on.
//!
//! # Two gestures, because the fields are two kinds
//!
//! A selector has nothing to type into, so `←`/`→` step it and it commits on
//! the spot. A text field needs an editing mode — `Enter` opens it, `Enter`
//! commits it, `Esc` restores what was stored — because a tab is not a modal
//! and `q` must stay `q` while nobody is typing.

use std::time::Instant;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph};

use crate::action::Action;
use crate::config::{
    ObfuscationChoice, PrefEdit, Preferences, ThemeChoice, validate_download_dir,
    validate_nickname, validate_temp_dir,
};
use crate::form::{self, Field, Form, FormKey, validate_port, validate_url};
use crate::row_selection::viewport::{self, Viewport};
use crate::state::UiState;
use crate::theme::Theme;
use crate::views::ViewOutcome;
use crate::words::Sentence;
use crate::words::app as words;
use crate::words::front_door;
use crate::wrap::clamp_u16;
use shared_dirs::Slot;

mod shared_dirs;

/// The rows, in render order. The enum *is* the field list: it indexes the
/// form, names the section breaks, and carries what a commit means, so a row
/// cannot exist in one of those three places and be missing from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Row {
    DownloadDir,
    TempDir,
    DataDir,
    Nickname,
    TcpPort,
    UdpPort,
    Obfuscation,
    PortMapping,
    ConnectAtStart,
    ServerMetUrl,
    AutoFetchServerMet,
    DeadServerRetries,
    WithholdShares,
    RememberPeers,
    PlayerCommand,
    NodesDatUrl,
    AutoFetchNodesDat,
    Theme,
    RunLogFull,
    UserHash,
    KadNodeId,
}

impl Row {
    const ALL: [Row; 21] = [
        Row::DownloadDir,
        Row::TempDir,
        Row::DataDir,
        Row::Nickname,
        Row::TcpPort,
        Row::UdpPort,
        Row::Obfuscation,
        Row::PortMapping,
        Row::ConnectAtStart,
        Row::ServerMetUrl,
        Row::AutoFetchServerMet,
        Row::DeadServerRetries,
        Row::WithholdShares,
        Row::RememberPeers,
        Row::PlayerCommand,
        Row::NodesDatUrl,
        Row::AutoFetchNodesDat,
        Row::Theme,
        Row::RunLogFull,
        Row::UserHash,
        Row::KadNodeId,
    ];

    /// The heading this row opens, if it is the first of a group.
    const fn section(self) -> Option<&'static str> {
        match self {
            Row::DownloadDir => Some("Paths"),
            Row::Nickname => Some("Network"),
            Row::DeadServerRetries => Some("Servers"),
            Row::RememberPeers => Some("Downloads"),
            // Not a Kad row any more: reask, NAT-T and Kad share this one
            // socket (ADR-0057), so it belongs beside the eD2k listen port.
            Row::NodesDatUrl => Some("Kad"),
            Row::Theme => Some("Appearance"),
            Row::RunLogFull => Some("Diagnostics"),
            Row::UserHash => Some("Identity — minted once, never edited"),
            _ => None,
        }
    }
}

/// The **Dead Server Limit** as an operator types it: a whole number from 1
/// to 10, aMule's own spin box's range (`muuli_wdr.cpp:1659`).
fn validate_dead_after(text: &str) -> Result<u32, Sentence> {
    text.trim()
        .parse::<u32>()
        .ok()
        .filter(|limit| (1..=10).contains(limit))
        .ok_or(words::DEAD_AFTER_REFUSED)
}

/// `Remember peers` as an operator types it: a whole number from 1 to 255
/// (ADR-0109, "Source Seeds").
fn validate_remember_peers(text: &str) -> Result<rmule_core::RememberPeers, Sentence> {
    text.trim()
        .parse::<std::num::NonZeroU8>()
        .map(rmule_core::RememberPeers::new)
        .map_err(|_| words::REMEMBER_PEERS_REFUSED)
}

/// The **Player Command** as an operator types it (ADR-0114): empty clears
/// it; any other text must split into a player's words.
fn player_command(text: &str) -> Result<Option<String>, Sentence> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    crate::player::split(text)
        .map(|_| Some(text.to_string()))
        .map_err(crate::words::player::field_refusal)
}

/// Where a restart-shaped row says so.
const ON_RESTART: &str = "(on restart)";

/// The on/off selector's two options, in index order.
const ON_OFF: [&str; 2] = ["off", "on"];

/// The connect-at-start row's note: which server a start would dial, or that
/// none has been connected to yet.
fn connect_at_start_note(last: Option<&rmule_primitives::ServerEndpoint>) -> String {
    match last {
        Some(server) => format!(
            "at start, to {}:{}  (on restart)",
            server.host(),
            server.port()
        ),
        None => "at start, to the last server — none yet  (on restart)".to_string(),
    }
}

/// What an unknown display-only fact reads.
const DASH: &str = "—";

/// The Settings view. Holds view state only (ADR-0069): the form's cursor and
/// typing, whether a text field is open for editing, and its Viewport.
/// Every *value* comes from [`UiState::preferences`].
pub struct SettingsView {
    form: Form,
    /// `true` while a text field is open: the form owns every key, so a
    /// binding letter is a character and not a command.
    editing: bool,
    /// What part of the form is on screen, in display lines, so a long form
    /// scrolls under a short pane.
    viewport: Viewport,
    /// Field index behind each rendered display line, from the last draw — the
    /// map a click needs once a row can wrap to more than one line.
    line_rows: Vec<Option<usize>>,
    /// The form's inner rect from the last draw, for click hit-testing.
    body: Rect,
    /// A download directory whose commit has shown the disclosure warning
    /// (ADR-0101) and waits for the second `Enter` that confirms it.
    warned_dir: Option<std::path::PathBuf>,
    /// What each form row stands for, in form order.
    slots: Vec<Slot>,
    /// A shared directory whose remove confirm is open.
    removing: Option<std::path::PathBuf>,
    /// The disclosure questions this view answered (`ScanConsent::asked`).
    answered: std::collections::BTreeSet<u64>,
    /// What part of the remove confirm or a disclosure question is on
    /// screen, in a frame too short for it.
    modal_viewport: std::cell::Cell<Viewport>,
}

impl Default for SettingsView {
    fn default() -> Self {
        let (form, slots) = build(&Preferences::default(), &UiState::default());
        Self {
            form,
            editing: false,
            viewport: Viewport::default(),
            line_rows: Vec::new(),
            body: Rect::default(),
            warned_dir: None,
            slots,
            removing: None,
            answered: std::collections::BTreeSet::new(),
            modal_viewport: std::cell::Cell::default(),
        }
    }
}

/// Build the whole form from a preference snapshot and the shared
/// directories, with what each row stands for.
fn build(prefs: &Preferences, state: &UiState) -> (Form, Vec<Slot>) {
    let path = |dir: &Option<std::path::PathBuf>| {
        dir.as_ref()
            .map(|dir| dir.display().to_string())
            .unwrap_or_default()
    };
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let theme_index = ThemeChoice::ALL
        .iter()
        .position(|choice| *choice == prefs.theme)
        .unwrap_or(0);

    let fields = Row::ALL.map(|row| {
        let field = match row {
            Row::DownloadDir => Field::text("Download dir", path(&prefs.download_dir))
                .with_placeholder("unset — downloads have nowhere to land"),
            // Unset, the row names the directory core reads by default.
            Row::TempDir => Field::text("Temp dir", path(&prefs.temp_dir)).with_placeholder(
                crate::words::app::temp_dir_default(
                    prefs
                        .data_dir
                        .as_ref()
                        .map(|dir| rmule_core::CoreSettings::default_temp_dir(&dir.path))
                        .as_deref(),
                ),
            ),
            Row::DataDir => match &prefs.data_dir {
                Some(dir) => Field::display("Data dir", dir.path.display().to_string())
                    .with_note(format!("({})", front_door::source_words(dir.source))),
                None => Field::display("Data dir", DASH.to_string())
                    .with_note(format!("({})", front_door::NO_DATA_DIR)),
            },
            Row::Nickname => Field::text("Nickname", prefs.nickname.clone()).with_note(ON_RESTART),
            Row::TcpPort => {
                Field::text("eD2k port", prefs.tcp_port.to_string()).with_note(ON_RESTART)
            }
            Row::ServerMetUrl => {
                Field::text("server.met", prefs.server_met_url.clone()).with_note("(Networks: U)")
            }
            Row::AutoFetchServerMet => Field::choice(
                "Fetch list",
                ON_OFF.to_vec(),
                usize::from(prefs.auto_fetch_server_met),
            )
            .with_note("server.met at start when the list is empty  (on restart)"),
            Row::UdpPort => {
                Field::text("UDP port", prefs.udp_port.to_string()).with_note(ON_RESTART)
            }
            Row::Obfuscation => Field::choice(
                "Obfuscation",
                ObfuscationChoice::ALL.map(ObfuscationChoice::name).to_vec(),
                ObfuscationChoice::ALL
                    .iter()
                    .position(|choice| *choice == prefs.obfuscation)
                    .unwrap_or(0),
            )
            .with_note("peer TCP/UDP + Kad + server UDP"),
            Row::PortMapping => Field::choice(
                "Port mapping",
                ON_OFF.to_vec(),
                usize::from(prefs.port_mapping),
            )
            .with_note("opens router ports: UPnP, PCP, NAT-PMP  (on restart)"),
            Row::ConnectAtStart => Field::choice(
                "Autoconnect",
                ON_OFF.to_vec(),
                usize::from(prefs.connect_at_start),
            )
            .with_note(connect_at_start_note(prefs.last_server.as_ref())),
            Row::DeadServerRetries => {
                Field::text("Dead after", prefs.dead_server_retries.to_string())
                    .with_note("failed tries in a row; a dead server stays listed")
            }
            Row::WithholdShares => Field::choice(
                "Hide shares",
                ON_OFF.to_vec(),
                usize::from(prefs.withhold_shares),
            )
            .with_note("from servers that answer related searches"),
            Row::RememberPeers => {
                Field::text("Remember peers", prefs.remember_peers.get().to_string())
                    .with_note(crate::words::download::REMEMBER_PEERS_NOTE)
            }
            Row::PlayerCommand => {
                Field::text("Player", prefs.player_command.clone().unwrap_or_default())
                    .with_placeholder(crate::words::player::UNSET)
            }
            Row::NodesDatUrl => {
                Field::text("nodes.dat", prefs.nodes_dat_url.clone()).with_note(ON_RESTART)
            }
            Row::AutoFetchNodesDat => Field::choice(
                "Fetch seeds",
                ON_OFF.to_vec(),
                usize::from(prefs.auto_fetch_nodes_dat),
            )
            .with_note("nodes.dat on first Kad start  (on restart)"),
            Row::Theme => Field::choice(
                "Theme",
                ThemeChoice::ALL.map(ThemeChoice::name).to_vec(),
                theme_index,
            )
            .with_note("auto = RMULE_THEME / COLORTERM"),
            Row::RunLogFull => Field::choice(
                "Full run log",
                ON_OFF.to_vec(),
                usize::from(prefs.run_log_full),
            )
            .with_note("adds peers, files and paths to rmule.log"),
            Row::UserHash => Field::display(
                "User hash",
                prefs
                    .user_hash
                    .map_or_else(|| DASH.to_string(), |hash| hex(hash.as_bytes())),
            ),
            Row::KadNodeId => Field::display(
                "Kad node ID",
                prefs
                    .kad_node_id
                    .map_or_else(|| DASH.to_string(), |id| hex(id.as_bytes().as_slice())),
            ),
        };
        match row.section() {
            Some(section) => field.in_section(section),
            None => field,
        }
    });
    // The shared directories follow the paths: the download directory is
    // their first entry.
    let mut rows: Vec<(Field, Slot)> = Vec::new();
    for (row, field) in Row::ALL.into_iter().zip(fields) {
        rows.push((field, Slot::Row(row)));
        if row == Row::DataDir {
            rows.extend(shared_dirs::fields(state));
        }
    }
    let (fields, slots) = rows.into_iter().unzip();
    (Form::new(fields), slots)
}

impl SettingsView {
    /// A view on the first row, nothing being edited.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the fields from the store's snapshot, keeping the cursor and
    /// the last rejection. Skipped while a field is open for editing: what has
    /// been typed there is not yet a stored value and must survive the redraw.
    fn sync(&mut self, state: &UiState) {
        if self.editing {
            return;
        }
        let (mut fresh, slots) = build(&state.preferences, state);
        fresh.focus = self.form.focus.min(fresh.fields.len().saturating_sub(1));
        fresh.error = self.form.error.take();
        self.form = fresh;
        self.slots = slots;
    }

    /// Validate the focused field into the edit it names, or the reason it is
    /// not one. Cross-field checks live here because this is the only place
    /// that can see the other fields.
    fn commit(&self, prefs: &Preferences) -> Result<Option<PrefEdit>, Sentence> {
        let index = self.form.focus;
        let text = self.form.text(index);
        let row = match self.slots.get(index) {
            Some(Slot::Row(row)) => Some(*row),
            _ => None,
        };
        let edit = match row.as_ref() {
            Some(Row::DownloadDir) => PrefEdit::DownloadDir(validate_download_dir(text)?),
            Some(Row::TempDir) => PrefEdit::TempDir(validate_temp_dir(text)?),
            Some(Row::Nickname) => PrefEdit::Nickname(validate_nickname(text)?),
            Some(Row::TcpPort) => {
                let port = validate_port(text)?;
                if port == prefs.udp_port {
                    return Err(words::port_clash(words::PortClash::TcpAgainstUdp));
                }
                PrefEdit::TcpPort(port)
            }
            Some(Row::UdpPort) => {
                let port = validate_port(text)?;
                if port == prefs.tcp_port {
                    return Err(words::port_clash(words::PortClash::UdpAgainstTcp));
                }
                PrefEdit::UdpPort(port)
            }
            Some(Row::ServerMetUrl) => PrefEdit::ServerMetUrl(validate_url(text)?.to_string()),
            Some(Row::DeadServerRetries) => PrefEdit::DeadServerRetries(validate_dead_after(text)?),
            Some(Row::RememberPeers) => PrefEdit::RememberPeers(validate_remember_peers(text)?),
            Some(Row::PlayerCommand) => PrefEdit::PlayerCommand(player_command(text)?),
            Some(Row::NodesDatUrl) => PrefEdit::NodesDatUrl(validate_url(text)?.to_string()),
            Some(Row::ConnectAtStart) => PrefEdit::ConnectAtStart(self.form.choice(index) == 1),
            Some(Row::PortMapping) => PrefEdit::PortMapping(self.form.choice(index) == 1),
            Some(Row::RunLogFull) => PrefEdit::RunLogFull(self.form.choice(index) == 1),
            Some(Row::WithholdShares) => PrefEdit::WithholdShares(self.form.choice(index) == 1),
            Some(Row::AutoFetchServerMet) => {
                PrefEdit::AutoFetchServerMet(self.form.choice(index) == 1)
            }
            Some(Row::AutoFetchNodesDat) => {
                PrefEdit::AutoFetchNodesDat(self.form.choice(index) == 1)
            }
            Some(Row::Obfuscation) => PrefEdit::Obfuscation(
                ObfuscationChoice::ALL
                    .get(self.form.choice(index))
                    .copied()
                    .unwrap_or_default(),
            ),
            Some(Row::Theme) => PrefEdit::Theme(
                ThemeChoice::ALL
                    .get(self.form.choice(index))
                    .copied()
                    .unwrap_or_default(),
            ),
            // A display row cannot hold focus, so this is unreachable in
            // practice; answering "nothing to commit" beats a panic.
            Some(Row::DataDir | Row::UserHash | Row::KadNodeId) | None => return Ok(None),
        };
        Ok(Some(edit))
    }

    /// Offer one key the globals did not claim. While a field is
    /// open every printable is text; otherwise the row cursor moves and
    /// unclaimed keys bubble out as [`ViewOutcome::Ignored`].
    pub fn handle_key(&mut self, key: KeyEvent, state: &UiState) -> ViewOutcome {
        self.sync(state);
        if let Some(consent) =
            crate::views::shared_files::scan::open_consent(state, &self.answered, true)
        {
            return crate::views::shared_files::scan::consent_key(
                key,
                consent,
                (&mut self.answered, &mut self.modal_viewport),
            );
        }
        if self.removing.is_some() {
            return self.remove_key(key);
        }

        // A selector commits where it is stepped: there is nothing to type, so
        // an editing mode for one would be ceremony with no purpose.
        if self.form.focus_is_choice()
            && matches!(key.code, KeyCode::Left | KeyCode::Right | KeyCode::Enter)
        {
            self.form.step_choice(key.code != KeyCode::Left);
            return self.emit(&state.preferences);
        }

        if self.editing {
            return match self.form.handle_key(key) {
                FormKey::Commit if self.focused_slot() == Some(&Slot::AddDir) => self.send_add(),
                FormKey::Commit => self.emit(&state.preferences),
                FormKey::Cancel => {
                    // Restore: the next sync rebuilds from what is stored.
                    self.editing = false;
                    self.warned_dir = None;
                    self.form.error = None;
                    self.sync(state);
                    ViewOutcome::Redraw
                }
                // A field open for editing is modal in the query input's sense:
                // every printable is text, so no binding letter leaks out.
                FormKey::Consumed | FormKey::Ignored => ViewOutcome::Redraw,
            };
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.form.step_focus(true);
                ViewOutcome::Redraw
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.form.step_focus(false);
                ViewOutcome::Redraw
            }
            KeyCode::Char('g') => {
                self.form.focus_first();
                ViewOutcome::Redraw
            }
            KeyCode::Char('G') => {
                self.form.focus_last();
                ViewOutcome::Redraw
            }
            // A listed directory is not typed into.
            KeyCode::Enter if self.form.focus_is_item() => ViewOutcome::Redraw,
            KeyCode::Enter => {
                self.editing = true;
                self.form.error = None;
                ViewOutcome::Redraw
            }
            KeyCode::Char('x') => self.ask_remove(),
            // Everything else (h/l/1–6/c/p/?/q) is a global binding.
            _ => ViewOutcome::Ignored,
        }
    }

    /// Validate the focused field and hand the app the edit — or keep the form
    /// up with the reason under it and the typing intact.
    fn emit(&mut self, prefs: &Preferences) -> ViewOutcome {
        match self.commit(prefs) {
            // Everything under a download directory is offered to the network
            // (ADR-0101): the first `Enter` has the app ask the share guards,
            // which warn through [`Self::warn_share`] when they pass; the
            // second commits.
            Ok(Some(PrefEdit::DownloadDir(dir))) if self.warned_dir.as_ref() != Some(&dir) => {
                ViewOutcome::Emit(Action::ConfirmDownloadDir(dir))
            }
            Ok(Some(edit)) => {
                self.warned_dir = None;
                self.editing = false;
                self.form.error = None;
                ViewOutcome::Emit(Action::Preference(edit))
            }
            Ok(None) => ViewOutcome::Redraw,
            Err(reason) => {
                self.form.error = Some(reason);
                ViewOutcome::Redraw
            }
        }
    }

    /// The share guards pass `dir`: say that everything under it will be
    /// offered, and let the next `Enter` commit it.
    pub fn warn_share(&mut self, dir: std::path::PathBuf) {
        self.form.error = Some(words::share_warning(&dir));
        self.warned_dir = Some(dir);
    }

    /// The download directory whose share warning waits for its confirm.
    #[cfg(test)]
    pub(crate) fn warned_dir(&self) -> Option<&std::path::Path> {
        self.warned_dir.as_deref()
    }

    /// A click selects the field it landed on. Editing stays keyboard-only,
    /// like every other form in this crate.
    pub fn handle_click(&mut self, column: u16, row: u16, _state: &UiState) -> ViewOutcome {
        if self.editing || !crate::views::pane_hit(self.body, column, row) {
            return ViewOutcome::Ignored;
        }
        let line = usize::from(row - self.body.y) + self.viewport.first();
        if let Some(Some(index)) = self.line_rows.get(line)
            && self.form.fields[*index].focusable()
        {
            self.form.focus = *index;
        }
        ViewOutcome::Redraw
    }

    /// Render one frame into `area` (spec §6 return). Re-reads the
    /// stored preferences first, except while a field is open — an edit in
    /// progress outranks the snapshot underneath it.
    pub fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        state: &UiState,
        theme: &Theme,
        _now: Instant,
    ) {
        self.sync(state);
        let hint = if self.editing {
            " Enter save  Esc cancel "
        } else if self.form.focus_is_item() {
            " j/k row  x stop sharing "
        } else {
            " j/k row  ←→ step  Enter edit "
        };
        let block = crate::views::title::titled(
            Block::bordered().border_style(Style::new().fg(if self.editing {
                theme.accent
            } else {
                theme.dim
            })),
            area.width,
            (" Settings ", Style::new().fg(theme.fg)),
            (hint, theme.dim_text()),
        );
        let inner = block.inner(area);
        frame.render_widget(block, area);
        self.body = inner;
        // Below the form's own floor the *labels* are what would have to be
        // cut, so the pane shows its frame and nothing else rather than a
        // garbled column (`form::MIN_WIDTH`; far under the 80 columns this UI
        // supports).
        if inner.height == 0 || usize::from(inner.width) < form::MIN_WIDTH {
            return;
        }

        // A rejection is pinned to the foot of the pane rather than left in
        // the scrolling flow: the form is taller than the pane it lives in, so
        // an inline error would routinely land below the fold — and a reason
        // the operator cannot see is the same as no reason at all.
        let render = |width: u16| {
            let mut rendered = self.form.render(usize::from(width), theme, self.editing);
            let error: Vec<Line<'static>> = match rendered.error_at {
                Some(at) => rendered.lines.split_off(at.saturating_add(1)),
                None => Vec::new(),
            };
            if rendered.error_at.is_some() {
                rendered.lines.pop(); // the blank line that separated it
            }
            (rendered, error)
        };
        let room = |error: &[Line<'static>]| {
            inner
                .height
                .saturating_sub(clamp_u16(error.len()).min(inner.height))
        };
        let (mut rendered, mut error) = render(inner.width);
        let bar = rendered.lines.len() > usize::from(room(&error))
            && usize::from(inner.width - viewport::BAR_W) >= form::MIN_WIDTH;
        if bar {
            (rendered, error) = render(inner.width - viewport::BAR_W);
        }
        self.line_rows = rendered.rows;
        let error_h = clamp_u16(error.len()).min(inner.height);
        let height = room(&error);

        // Keep the focused field on screen; a form taller than its pane
        // scrolls rather than hiding the row the cursor is on. The count
        // says which row it is, of the rows the cursor can rest on.
        let rows = self.form.fields.iter().filter(|field| field.focusable());
        let row = self.form.fields[..self.form.focus.min(self.form.fields.len())]
            .iter()
            .filter(|field| field.focusable())
            .count();
        let first = self.viewport.follow_span(
            rendered.focus,
            rendered.lines.len(),
            height,
            (row, rows.count()),
        );

        let visible: Vec<Line<'static>> = rendered
            .lines
            .into_iter()
            .skip(first)
            .take(usize::from(height))
            .collect();
        let [body, foot] =
            Layout::vertical([Constraint::Length(height), Constraint::Length(error_h)])
                .areas(inner);
        let (list, bar) = viewport::split(body, bar);
        frame.render_widget(Paragraph::new(visible), list);
        if error_h > 0 {
            frame.render_widget(Paragraph::new(error), foot);
        }
        self.viewport.draw(frame, area, bar, theme);
        if let Some(dir) = &self.removing {
            shared_dirs::draw_remove(frame, area, (dir, &self.modal_viewport), state, theme);
        }
        if let Some(consent) =
            crate::views::shared_files::scan::open_consent(state, &self.answered, true)
        {
            crate::views::shared_files::scan::draw_consent(
                frame,
                area,
                consent,
                theme,
                &self.modal_viewport,
            );
        }
    }
}

#[cfg(test)]
mod tests;
