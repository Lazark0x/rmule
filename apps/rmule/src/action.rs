//! The single `Action` mpsc bus (ADR-0069): one write path for both core
//! events and user input.

use rmule_core::CoreEvent;

use crate::bridge::BridgeSnapshot;
use crate::view::ViewId;

/// Everything that may mutate UI state — [`crate::state::UiState`] for the
/// core arms, [`crate::chrome::ChromeState`] for the chrome arms. Raw input
/// rides the bus too and is mapped against current chrome state at the apply
/// site ([`crate::input::map_key`]), so mapping sees help/focus context.
#[derive(Debug)]
pub enum Action {
    /// A lifecycle *edge* from the core's event stream; folds immediately.
    Core(CoreEvent),
    /// The 1 Hz data tick's *levels* + synthesized rates; latest wins, and
    /// the bridge drops a frame rather than queue behind a slow UI.
    Snapshot(BridgeSnapshot),
    /// The core's event stream ended: the core has stopped. Terminal — no
    /// further `Core` or `Snapshot` actions follow.
    CoreClosed,
    /// A raw terminal event from the input pump.
    Input(ratatui::crossterm::event::Event),
    /// Switch straight to a view (`1–4`, tab click).
    SwitchView(ViewId),
    /// Cycle views (`l` forward, `h` back); sign is the direction.
    CycleView(i8),
    /// `?` — open/close the help overlay.
    ToggleHelp,
    /// `Esc`/`q` while a modal is up.
    DismissOverlay,
    /// Scroll the help overlay by this many lines (negative: up); it scrolls
    /// when its bindings outgrow the frame.
    ScrollHelp(i16),
    /// Transient status-bar action feedback (spec §3.1 amber ✱, ~3 s), in
    /// the words modules' words.
    Flash(crate::words::Sentence),
    /// A durable fact the *app* learned rather than the core reported — the
    /// startup Kad seed outcome is the first. It lands in the Networks
    /// log pane and the status-bar info feed, exactly where a core event's
    /// would, because the app has no other honest place to say it: `rmule`
    /// installs no tracing subscriber (stdout is the alternate screen).
    /// Reserved for facts, not chatter — a [`Flash`](Self::Flash) is the right
    /// arm for anything that may safely scroll away.
    Note(crate::words::Sentence),
    /// A core command produced by a view (row menu, query commit); the app
    /// forwards it through the `CoreClient` once one is bound — until then
    /// it flashes the honest "core not attached".
    Command(rmule_core::CoreCommand),
    /// Several core commands one operator answer produced, forwarded in
    /// order exactly as if each had arrived as a [`Command`](Self::Command).
    Commands(Vec<rmule_core::CoreCommand>),
    /// Several actions one operator gesture produced, reduced in order as if
    /// each had arrived alone — a command and the note that goes with it.
    Actions(Vec<Action>),
    /// Copy text (an eD2k link) to the system clipboard via OSC 52
    /// (additive escape: terminals without it ignore the write).
    CopyLink(String),
    /// A validated Settings edit. The app writes it through to the
    /// config store — front-end-owned config, ADR-0069 — folds it into
    /// [`crate::state::UiState::preferences`], and applies the live half of it
    /// (the theme, the session's download directory).
    Preference(crate::config::PrefEdit),
    /// A download directory the Settings form would commit (ADR-0101): the
    /// app asks core's share guards first, and only a directory they pass
    /// gets the form's warning that everything under it is offered — a
    /// refused one is said at once, before anything is confirmed.
    ConfirmDownloadDir(std::path::PathBuf),
    /// The operator closed a held search (ADR-0073, Held Searches): its
    /// results leave memory with it. Core has already ended the search.
    ForgetSearch(rmule_core::SearchId),
    /// A row menu's *Search related* (ADR-0037, Related-Files Search): the
    /// Search tab opens a Held Search for the file and becomes current.
    SearchRelated(rmule_primitives::RelatedFilesQuery),
    /// `K` in Networks while Kad is off: the app asks its Kad join to
    /// start a node now, seeds and all, without a server connect.
    StartKad,
    /// `q` at the top level.
    Quit,
}
