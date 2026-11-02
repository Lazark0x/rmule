//! The Settings tab's configuration (ADR-0069): the door its edits go
//! through, the preference snapshot it renders, and the one edit vocabulary
//! that writes both.
//!
//! # Core's keys and the front end's
//!
//! Core owns every preference that changes what core does — the download
//! directory, the Temp Directory, the ports, obfuscation, port mapping, the server policy,
//! `Remember peers`, the mirrors — and an edit to one goes through **Core
//! Settings**: the handle validates it, persists it, takes up a live key in
//! the running core, and answers when it takes effect. The receipt reads that
//! answer; this side never decides it for a core key. The handle a running
//! core gave reaches it; one opened on the store alone, before attach or
//! without a core, answers that every key waits for the next start.
//!
//! The front end keeps its own keys in the same store and applies them itself:
//! the theme, the table sorts, the last server, the Player Command, the last
//! tab, and each [`AppFlag`].

use std::path::PathBuf;
use std::sync::Arc;

use rmule_core::{
    AppConfigStore, CoreError, CoreSettings, CoreSettingsHandle, DurableAppConfig, DurableStore,
    FlagTable, Flags, KadId, ObfuscationPolicy, Setting, SettingError, TakesEffect, flag_text,
};
use rmule_primitives::{ServerEndpoint, UserHash};

use crate::table_sort::{Direction, TableSorts};
use crate::theme::Theme;
use crate::view::ViewId;
use crate::words::Sentence;
use crate::words::app as words;

mod front_end_key;

pub use front_end_key::{AppFlag, FrontEndKey};

/// This front end's door to its preferences: the Core Settings handle for
/// core's keys and, through its raw surface, for this app's own
/// ([`FrontEndKey`]); the store itself only for the identity it displays.
/// Cloneable; every clone reaches the same store, and nothing locks around
/// it — every seam method is `&self` (ADR-0083).
#[derive(Clone)]
pub struct SharedConfig {
    settings: CoreSettingsHandle,
    store: Arc<DurableAppConfig>,
    /// Makes every commit fail as a store that refuses writes would.
    #[cfg(test)]
    refuse_commits: Arc<std::sync::atomic::AtomicBool>,
}

impl SharedConfig {
    /// The door through `settings` — a running core's, so its live keys are
    /// taken up at once — over `store`, the same open store.
    #[must_use]
    pub fn new(settings: CoreSettingsHandle, store: DurableAppConfig) -> Self {
        Self {
            settings,
            store: Arc::new(store),
            #[cfg(test)]
            refuse_commits: Arc::default(),
        }
    }

    /// The door over `store` alone, where no core runs: every core key waits
    /// for the next start.
    #[must_use]
    pub fn open(store: Arc<DurableStore>) -> Self {
        Self::new(
            CoreSettingsHandle::open(Arc::clone(&store)),
            DurableAppConfig::new(store),
        )
    }

    /// From now on every commit fails with the store's refusal.
    #[cfg(test)]
    pub(crate) fn refuse_commits(&self) {
        self.refuse_commits
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// What [`commit`](Self::commit) would refuse `edit` for, writing
    /// nothing: core's own check of one of its keys (ADR-0069). A front end's
    /// own key is never refused.
    ///
    /// # Errors
    /// The refusal core's `set` would answer, or the store's failure to read
    /// what core judges the value against.
    pub fn check(&self, edit: &PrefEdit) -> Result<(), SettingError> {
        if let PrefEdit::Core(setting) = edit {
            self.settings.check(setting)
        } else {
            Ok(())
        }
    }

    /// Persist one edit and answer when it takes effect, reporting the store's
    /// own refusal verbatim. A core key's answer is core's; a flag says its
    /// own; the rest of the app's keys apply at once.
    pub fn commit(&self, edit: &PrefEdit) -> Result<TakesEffect, SettingError> {
        #[cfg(test)]
        if self
            .refuse_commits
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(CoreError::Repository("the store refused the write".into()).into());
        }
        let set =
            |key: FrontEndKey, value: &str| self.settings.set_front_end_value(key.key(), value);
        match edit {
            PrefEdit::Core(setting) => return self.settings.set(setting.clone()),
            PrefEdit::Flag(flag, on) => {
                self.settings
                    .set_front_end_value(flag.key(), flag_text(*on))?;
                return Ok(flag.takes_effect());
            }
            PrefEdit::Theme(choice) => set(FrontEndKey::Theme, choice.name())?,
            PrefEdit::LastServer(server) => set(
                FrontEndKey::LastServer,
                &format!("{}:{}", server.host(), server.port()),
            )?,
            // Empty text is the stored unset: every launch reads the key.
            PrefEdit::PlayerCommand(command) => {
                set(FrontEndKey::PlayerCommand, command.as_deref().unwrap_or(""))?;
            }
            PrefEdit::LastTab(view) => set(FrontEndKey::LastTab, view.key())?,
            // Every table shares one value: re-read it so the write keeps the
            // other tables' entries as the store has them.
            PrefEdit::TableSort {
                table,
                column,
                direction,
            } => {
                let mut sorts = TableSorts::parse(
                    self.settings
                        .front_end_value(FrontEndKey::TableSorts.key())?
                        .as_deref(),
                );
                sorts.set(table, column, *direction);
                set(FrontEndKey::TableSorts, &sorts.text())?;
            }
        }
        Ok(TakesEffect::Now)
    }

    /// Read every preference the Settings tab shows.
    ///
    /// Read from the store rather than passed in, so a reload after an edit
    /// sees the edit, which a caller holding what it loaded at startup would
    /// not.
    pub fn load(&self, data_dir: Option<crate::args::DataDir>) -> Result<Preferences, CoreError> {
        let store = &*self.store;
        let identity = store.ensure_identity()?;
        let kad = store.ensure_kad_identity()?;
        let text = |key: FrontEndKey| self.settings.front_end_value(key.key());
        Ok(Preferences {
            core: self.settings.read()?,
            flags: Flags::read(|key| self.settings.front_end_value(key))?,
            data_dir,
            theme: ThemeChoice::parse(text(FrontEndKey::Theme)?.as_deref()),
            table_sorts: TableSorts::parse(text(FrontEndKey::TableSorts)?.as_deref()),
            last_server: text(FrontEndKey::LastServer)?
                .and_then(|value| ServerEndpoint::parse_host_port(&value).ok()),
            player_command: text(FrontEndKey::PlayerCommand)?.filter(|text| !text.is_empty()),
            last_tab: ViewId::parse(text(FrontEndKey::LastTab)?.as_deref()),
            user_hash: Some(identity.user_hash()),
            kad_node_id: Some(kad.id),
        })
    }
}

/// Which palette the app runs in, as a durable choice rather than an
/// environment reading.
///
/// [`Auto`](Self::Auto) *is* the environment reading — `RMULE_THEME`, then the
/// terminal's [`Capability`](crate::capability::Capability) — so a stored choice and the
/// escape hatch are one setting with six values instead of two mechanisms
/// arguing over which wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ThemeChoice {
    /// Defer to the environment and the terminal, read again at every start.
    #[default]
    Auto,
    /// The truecolor dark palette, whatever the terminal reports.
    Dark,
    /// The light palette, likewise unconditional.
    Light,
    /// The hand-tuned 256-color palette, for terminals that mangle RGB.
    Fallback256,
    /// The sixteen named colours, as the terminal's own settings paint them.
    Ansi16,
    /// No colour: the terminal's own, whatever it reports.
    Mono,
}

impl ThemeChoice {
    /// Every choice, in the order the Settings field cycles them.
    pub const ALL: [Self; 6] = [
        Self::Auto,
        Self::Dark,
        Self::Light,
        Self::Fallback256,
        Self::Ansi16,
        Self::Mono,
    ];

    /// The stored spelling, and what [`parse`](Self::parse) reads back.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dark => "dark",
            Self::Light => "light",
            Self::Fallback256 => "256",
            Self::Ansi16 => "16",
            Self::Mono => "mono",
        }
    }

    /// Read a stored name; anything unrecognised (or absent) is `Auto`.
    #[must_use]
    pub fn parse(name: Option<&str>) -> Self {
        Self::ALL
            .into_iter()
            .find(|choice| Some(choice.name()) == name)
            .unwrap_or(Self::Auto)
    }

    /// The palette this choice means, given what the environment resolved to.
    #[must_use]
    pub fn resolve(self, detected: Theme) -> Theme {
        match self {
            Self::Auto => detected,
            Self::Dark => Theme::default_dark(),
            Self::Light => Theme::light(),
            Self::Fallback256 => Theme::fallback_256(),
            Self::Ansi16 => Theme::ansi_for(detected.light),
            Self::Mono => Theme::mono(),
        }
    }
}

/// rmule's one protocol-obfuscation policy as an operator picks it — aMule's
/// Security preferences, where "support", "request" and "require" are three
/// checkboxes that only ever nest (`Preferences.h:870-877`), so four steps
/// say every combination they can hold.
///
/// One setting for every surface, because ADR-0046 keeps one policy across
/// stream and datagram: it becomes `CoreSettings::obfuscation`, which lights
/// the hello's crypt bits, makes peer TCP and peer UDP obfuscation-aware, arms
/// the Kad node's datagram crypt and verify keys, and arms the
/// server-UDP crypt-ping arm — a running core takes a change up at once,
/// every surface reading the policy as it decides. aMule gates Kad and
/// server-UDP obfuscation on the same
/// `IsClientCryptLayerSupported()` / `IsServerCryptLayerUDPEnabled()` pair
/// (`MuleUDPSocket.cpp:282-284`, `Preferences.h:883`).
///
/// [`Off`](Self::Off) is the default: the
/// library's, which ADR-0046 keeps off until each surface's capture has
/// ratified it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObfuscationChoice {
    /// No obfuscation anywhere; every datagram and dial is plaintext.
    #[default]
    Off,
    /// Accept obfuscation, never initiate it.
    Supported,
    /// Initiate obfuscation where the peer can take it.
    Requested,
    /// Obfuscated peer TCP only; datagrams read it as `Requested`.
    Required,
}

impl ObfuscationChoice {
    /// Every choice, in the order the Settings field cycles them.
    pub const ALL: [Self; 4] = [Self::Off, Self::Supported, Self::Requested, Self::Required];

    /// The choice that names `policy`.
    #[must_use]
    pub fn of(policy: Option<ObfuscationPolicy>) -> Self {
        Self::ALL
            .into_iter()
            .find(|choice| choice.policy() == policy)
            .unwrap_or(Self::Off)
    }

    /// The policy core runs under (`CoreSettings::obfuscation`).
    #[must_use]
    pub const fn policy(self) -> Option<ObfuscationPolicy> {
        match self {
            Self::Off => None,
            Self::Supported => Some(ObfuscationPolicy::Supported),
            Self::Requested => Some(ObfuscationPolicy::Requested),
            Self::Required => Some(ObfuscationPolicy::Required),
        }
    }
}

/// Everything the Settings tab shows: the editable preferences as the store
/// holds them, plus the display-only facts that identify this client.
///
/// Loaded once at startup and folded forward by every committed edit, so the
/// tab always shows what is *on disk* — which for a restart-shaped knob is
/// exactly the honest thing to show, since the running session is still using
/// the value it started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preferences {
    /// Every key core owns, as its one door reads them (ADR-0069).
    pub core: CoreSettings,
    /// Every [`AppFlag`].
    pub flags: Flags<AppFlag>,
    /// Where the databases live and which rule picked it — `--data-dir`,
    /// `RMULE_DATA`, `XDG_DATA_HOME`, `HOME` or `LOCALAPPDATA`, resolved at
    /// startup, so it cannot be stored in the store it locates.
    pub data_dir: Option<crate::args::DataDir>,
    /// Which palette to run.
    pub theme: ThemeChoice,
    /// Every table's **Table Sort**, kept across runs.
    pub table_sorts: TableSorts,
    /// The server the operator last connected to, if any.
    pub last_server: Option<ServerEndpoint>,
    /// The **Player Command** (ADR-0114): the text Preview splits into the
    /// player's words. `None` until the operator sets one, and then Preview
    /// opens the **Default App**.
    pub player_command: Option<String>,
    /// The tab the last run showed, which this run opens on.
    pub last_tab: ViewId,
    /// Minted once from OS entropy and never editable (ADR-0041/0043).
    /// `None` until the store is read.
    pub user_hash: Option<UserHash>,
    /// Minted with the user hash and just as permanent; `None` likewise
    /// until the store is read.
    pub kad_node_id: Option<KadId>,
}

/// What the app shows before — or without — a config store: core's defaults,
/// but for the two ports, which show the seed values a store would mint rather
/// than the `0` a library default holds, and honest absence for what only a
/// store can supply: where the databases live, and which User Hash and Kad ID
/// were minted, read as `None` and render as a dash.
impl Default for Preferences {
    fn default() -> Self {
        Self {
            core: CoreSettings {
                tcp_port: rmule_core::DEFAULT_TCP_PORT,
                udp_port: rmule_core::DEFAULT_UDP_PORT,
                ..CoreSettings::default()
            },
            flags: Flags::default(),
            data_dir: None,
            theme: ThemeChoice::Auto,
            table_sorts: TableSorts::default(),
            last_server: None,
            player_command: None,
            last_tab: ViewId::default(),
            user_hash: None,
            kad_node_id: None,
        }
    }
}

impl Preferences {
    /// Fold a committed edit into the snapshot.
    pub fn apply(&mut self, edit: &PrefEdit) {
        match edit {
            PrefEdit::Core(setting) => self.core.apply(setting),
            PrefEdit::Flag(flag, on) => self.flags.set(*flag, *on),
            PrefEdit::Theme(choice) => self.theme = *choice,
            PrefEdit::LastServer(server) => self.last_server = Some(server.clone()),
            PrefEdit::PlayerCommand(command) => self.player_command.clone_from(command),
            PrefEdit::LastTab(view) => self.last_tab = *view,
            PrefEdit::TableSort {
                table,
                column,
                direction,
            } => self.table_sorts.set(table, column, *direction),
        }
    }
}

/// One committed preference edit — what the Settings form produces and what
/// the app writes through to the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefEdit {
    /// A key core owns, changed through its settings handle, which validates
    /// it and says when it takes effect (ADR-0069).
    Core(Setting),
    /// An [`AppFlag`], on or off.
    Flag(AppFlag, bool),
    /// The next frame paints in it.
    Theme(ThemeChoice),
    /// The **Player Command**, its text already split once
    /// ([`crate::player::split`]); `None` clears it. The next launch reads it.
    PlayerCommand(Option<String>),
    /// The server the operator just connected to, written by the app on the
    /// `Connected` edge rather than by the Settings form.
    LastServer(ServerEndpoint),
    /// The tab now up, written by the app on each switch rather than by the
    /// Settings form.
    LastTab(ViewId),
    /// A table's sort, written by the table itself rather than the Settings
    /// form; the view already shows it.
    TableSort {
        /// The table's stored key (`SortedTable::TABLE`).
        table: &'static str,
        /// The column's stored key.
        column: &'static str,
        /// Its direction.
        direction: Direction,
    },
}

impl PrefEdit {
    /// The download directory `dir`, validated by [`validate_download_dir`].
    ///
    /// It is chosen in Settings, whose commit carried the warning that
    /// everything under it is offered (ADR-0101), so the answer rides the
    /// setting and the scan core starts asks nothing more.
    #[must_use]
    pub const fn download_dir(dir: PathBuf) -> Self {
        Self::Core(Setting::DownloadDir {
            dir,
            share_confirmed: true,
        })
    }
}

/// A download directory as an operator types it: absolute, and not something
/// that already exists as a non-directory.
///
/// The existence check is deliberately *not* "must exist": aMule creates its
/// incoming directory, and refusing a path the user is about to make would be
/// a lie about what rmule can do. A path that exists as a **file**, though, is
/// a typo the operator wants to hear about now rather than at the first
/// completed download.
pub fn validate_download_dir(path: &str) -> Result<PathBuf, Sentence> {
    if path.trim().is_empty() {
        return Err(words::DOWNLOAD_DIR_REQUIRED);
    }
    directory(path).map_err(|unfit| words::download_dir_unfit(&unfit))
}

/// A Temp Directory as an operator types it, by the same rule as
/// [`validate_download_dir`]: core judges where it lies at the set, and makes
/// it. Empty text is `None`, which clears the one set back to the default.
pub fn validate_temp_dir(path: &str) -> Result<Option<PathBuf>, Sentence> {
    if path.trim().is_empty() {
        return Ok(None);
    }
    directory(path)
        .map(Some)
        .map_err(|unfit| words::temp_dir_unfit(&unfit))
}

/// Why typed text does not name a directory a Paths row takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnfitDirectory {
    /// The path is relative.
    Relative,
    /// The path exists and is not a directory; the text as typed, trimmed.
    NotADirectory(String),
}

/// The text `path`, trimmed, as a directory: absolute once a leading `~` is
/// read, and not an existing non-directory.
fn directory(path: &str) -> Result<PathBuf, UnfitDirectory> {
    let trimmed = path.trim();
    let path = expand_home(trimmed);
    if !path.is_absolute() {
        return Err(UnfitDirectory::Relative);
    }
    if path.exists() && !path.is_dir() {
        return Err(UnfitDirectory::NotADirectory(trimmed.to_string()));
    }
    Ok(path)
}

/// The path `text` names, a leading `~` read as the operator's home.
pub(crate) fn expand_home(text: &str) -> PathBuf {
    under_home(text, rmule_core::home_dir(|name| std::env::var_os(name)))
}

/// `text` under `home` when it starts `~`, as it stands otherwise: also when
/// no home is known, or `~name` asks for somebody else's.
fn under_home(text: &str, home: Option<PathBuf>) -> PathBuf {
    match (text.strip_prefix('~'), home) {
        (Some(""), Some(home)) => home,
        (Some(rest), Some(home)) if rest.starts_with(std::path::is_separator) => {
            home.join(rest.trim_start_matches(std::path::is_separator))
        }
        _ => PathBuf::from(text),
    }
}

/// A nickname as it will travel on the wire: non-empty, and free of the
/// control characters an `Ed2kText` would carry into a hello packet.
pub fn validate_nickname(nickname: &str) -> Result<String, Sentence> {
    let trimmed = nickname.trim();
    if trimmed.is_empty() {
        return Err(words::nickname_refusal(words::NicknameRefusal::Required));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(words::nickname_refusal(
            words::NicknameRefusal::ControlCharacter,
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests;
