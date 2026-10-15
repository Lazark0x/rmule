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
//! The front end keeps six keys of its own — the theme, the table sorts, the
//! Run Log level, connect at start, the last server and the Player Command —
//! in the same store, and applies them itself.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmule_core::port_mapping::PortMappingMode;
use rmule_core::{
    AppConfigStore, CoreError, CoreSettingsHandle, DurableAppConfig, DurableStore, KadId,
    ObfuscationPolicy, Setting, SettingError, TakesEffect,
};
use rmule_primitives::{ServerEndpoint, UserHash};

use crate::table_sort::{Direction, TableSorts};
use crate::theme::Theme;
use crate::words::Sentence;
use crate::words::app as words;

mod front_end_key;

pub use front_end_key::FrontEndKey;

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
        match edit.keeper() {
            Keeper::Core(setting) => self.settings.check(&setting),
            Keeper::FrontEnd(_) => Ok(()),
        }
    }

    /// Persist one edit and answer when it takes effect, reporting the store's
    /// own refusal verbatim. A core key's answer is core's; a front-end key's
    /// is this app's own: the theme, the Run Log level, a sort, the last
    /// server and the Player Command apply at once, connect at start only at
    /// a start.
    pub fn commit(&self, edit: &PrefEdit) -> Result<TakesEffect, SettingError> {
        #[cfg(test)]
        if self
            .refuse_commits
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(CoreError::Repository("the store refused the write".into()).into());
        }
        let edit = match edit.keeper() {
            Keeper::Core(setting) => return self.settings.set(setting),
            Keeper::FrontEnd(edit) => edit,
        };
        let set =
            |key: FrontEndKey, value: &str| self.settings.set_front_end_value(key.key(), value);
        match edit {
            FrontEndEdit::Theme(choice) => set(FrontEndKey::Theme, choice.name())?,
            FrontEndEdit::ConnectAtStart(on) => {
                set(FrontEndKey::ConnectAtStart, &on.to_string())?;
                return Ok(TakesEffect::NextStart);
            }
            FrontEndEdit::RunLogFull(on) => set(
                FrontEndKey::RunLogFull,
                rmule_core::run_log::Level::from_full(on).preference(),
            )?,
            FrontEndEdit::LastServer(server) => set(
                FrontEndKey::LastServer,
                &format!("{}:{}", server.host(), server.port()),
            )?,
            // Empty text is the stored unset: every launch reads the key.
            FrontEndEdit::PlayerCommand(command) => {
                set(FrontEndKey::PlayerCommand, command.unwrap_or(""))?;
            }
            // Every table shares one value: re-read it so the write keeps the
            // other tables' entries as the store has them.
            FrontEndEdit::TableSort {
                table,
                column,
                direction,
            } => {
                let mut sorts = TableSorts::parse(
                    self.settings
                        .front_end_value(FrontEndKey::TableSorts.key())?
                        .as_deref(),
                );
                sorts.set(table, column, direction);
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
        let core = self.settings.read()?;
        let store = &*self.store;
        let identity = store.ensure_identity()?;
        let kad = store.ensure_kad_identity()?;
        let text = |key: FrontEndKey| self.settings.front_end_value(key.key());
        Ok(Preferences {
            download_dir: core.download_dir,
            temp_dir: core.temp_dir,
            data_dir,
            nickname: core.nickname,
            tcp_port: core.tcp_port,
            udp_port: core.udp_port,
            server_met_url: core.server_met_url,
            auto_fetch_server_met: core.auto_fetch_server_met,
            nodes_dat_url: core.nodes_dat_url,
            auto_fetch_nodes_dat: core.auto_fetch_nodes_dat,
            theme: ThemeChoice::parse(text(FrontEndKey::Theme)?.as_deref()),
            obfuscation: ObfuscationChoice::of(core.obfuscation),
            port_mapping: core.port_mapping == PortMappingMode::Auto,
            table_sorts: TableSorts::parse(text(FrontEndKey::TableSorts)?.as_deref()),
            // Off unless the operator turned it on (ADR-0095).
            connect_at_start: text(FrontEndKey::ConnectAtStart)?
                .is_some_and(|value| value == "true"),
            // Lean unless the operator turned the full level on.
            run_log_full: rmule_core::run_log::Level::from_preference(
                text(FrontEndKey::RunLogFull)?.as_deref(),
            ) == rmule_core::run_log::Level::Full,
            dead_server_retries: core.server_policy.dead_after,
            withhold_shares: core.server_policy.withhold_from_related_search,
            remember_peers: core.remember_peers,
            last_server: text(FrontEndKey::LastServer)?
                .and_then(|value| ServerEndpoint::parse_host_port(&value).ok()),
            player_command: text(FrontEndKey::PlayerCommand)?.filter(|text| !text.is_empty()),
            user_hash: Some(identity.user_hash()),
            kad_node_id: Some(kad.id),
        })
    }
}

/// Which palette the app runs in, as a durable choice rather than an
/// environment reading.
///
/// [`Auto`](Self::Auto) *is* the environment reading — `RMULE_THEME`, then the
/// `COLORTERM` truecolor convention (spec §5) — so a stored choice and the
/// escape hatch are one setting with four values instead of two mechanisms
/// arguing over which wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ThemeChoice {
    /// Defer to the environment, re-read at every start.
    #[default]
    Auto,
    /// The truecolor dark palette, whatever the terminal reports.
    Dark,
    /// The light palette, likewise unconditional.
    Light,
    /// The hand-tuned 256-color palette, for terminals that mangle RGB.
    Fallback256,
}

impl ThemeChoice {
    /// Every choice, in the order the Settings field cycles them.
    pub const ALL: [Self; 4] = [Self::Auto, Self::Dark, Self::Light, Self::Fallback256];

    /// The stored spelling, and what [`parse`](Self::parse) reads back.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dark => "dark",
            Self::Light => "light",
            Self::Fallback256 => "256",
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

    /// The choice's stable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Supported => "supported",
            Self::Requested => "requested",
            Self::Required => "required",
        }
    }

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
    /// Where downloads are written; `None` until something chooses one.
    pub download_dir: Option<PathBuf>,
    /// The **Temp Directory** new downloads keep their part files in
    /// (ADR-0115); `None` until the operator chooses one, and core then
    /// reads the default in the data directory.
    pub temp_dir: Option<PathBuf>,
    /// Where the databases live and which rule picked it — `--data-dir`,
    /// `RMULE_DATA`, `XDG_DATA_HOME`, `HOME` or `LOCALAPPDATA`, resolved at
    /// startup, so it cannot be stored in the store it locates.
    pub data_dir: Option<crate::args::DataDir>,
    /// The name carried in every session command, so a change reaches the
    /// wire only on the next start.
    pub nickname: String,
    /// The eD2k listen port advertised at login.
    pub tcp_port: u16,
    /// The port the Kad node binds.
    pub udp_port: u16,
    /// Where a server-list refresh fetches `server.met` from.
    pub server_met_url: String,
    /// Whether a start with an empty server list fetches `server.met` from
    /// [`server_met_url`](Self::server_met_url) once (ADR-0065). On by
    /// default; read at start.
    pub auto_fetch_server_met: bool,
    /// Where a Kad bootstrap fetch pulls `nodes.dat` from.
    pub nodes_dat_url: String,
    /// Whether a Kad start with no contacts may fetch that file itself
    /// (ADR-0067 amendment: opt-out, not silent).
    pub auto_fetch_nodes_dat: bool,
    /// Which palette to run.
    pub theme: ThemeChoice,
    /// The one obfuscation policy core runs under; a running core takes a
    /// change up at once.
    pub obfuscation: ObfuscationChoice,
    /// Whether core maps its ports on the router (ADR-0086). On by default;
    /// read at start.
    pub port_mapping: bool,
    /// Every table's **Table Sort**, kept across runs.
    pub table_sorts: TableSorts,
    /// Whether the app performs the operator's connect at start, to
    /// [`last_server`](Self::last_server) (ADR-0095). Off by default.
    pub connect_at_start: bool,
    /// Whether the Run Log is written at its full level. Off by default.
    pub run_log_full: bool,
    /// The server the operator last connected to, if any.
    pub last_server: Option<ServerEndpoint>,
    /// The **Player Command** (ADR-0114): the text Preview splits into the
    /// player's words. `None` until the operator sets one, and then Preview
    /// opens the **Default App**.
    pub player_command: Option<String>,
    /// The **Dead Server Limit** (ADR-0052): failed tries in a row after
    /// which a listed server is dead. Live — core takes it up at once.
    pub dead_server_retries: u32,
    /// The **Announce Policy** (ADR-0099): withhold the shares from servers
    /// that answer related searches. Off by default; live.
    pub withhold_shares: bool,
    /// `Remember peers` (ADR-0109): how many peers each running download keeps
    /// for a restart to dial first. Live — core's next write keeps that many.
    pub remember_peers: rmule_core::RememberPeers,
    /// Minted once from OS entropy and never editable (ADR-0041/0043).
    /// `None` on a UI-only run, where no store was opened.
    pub user_hash: Option<UserHash>,
    /// Minted with the user hash and just as permanent; `None` likewise
    /// means no store was opened.
    pub kad_node_id: Option<KadId>,
}

/// What the app shows before — or without — a config store: the library
/// defaults for every knob that has one independent of storage, and honest
/// absence for the three facts only a store can supply.
///
/// Nothing here is invented. The ports and nickname are `rmule_core`'s
/// published seed values, the URLs are `rmule_bootstrap`'s mirrors, and the
/// `nodes.dat` opt-in is the app's own ADR-0067 amendment. What a store would
/// have told us and did not — where the databases live, which User Hash and
/// Kad ID were minted, where downloads go — reads as `None` and renders as a
/// dash, so a UI-only run cannot be mistaken for a configured one.
impl Default for Preferences {
    fn default() -> Self {
        Self {
            download_dir: None,
            temp_dir: None,
            data_dir: None,
            nickname: rmule_core::DEFAULT_NICKNAME.to_string(),
            tcp_port: rmule_core::DEFAULT_TCP_PORT,
            udp_port: rmule_core::DEFAULT_UDP_PORT,
            server_met_url: rmule_bootstrap::DEFAULT_SERVER_MET_URL.to_string(),
            auto_fetch_server_met: true,
            nodes_dat_url: rmule_bootstrap::DEFAULT_NODES_DAT_URL.to_string(),
            auto_fetch_nodes_dat: true,
            theme: ThemeChoice::Auto,
            obfuscation: ObfuscationChoice::Off,
            port_mapping: true,
            table_sorts: TableSorts::default(),
            connect_at_start: false,
            run_log_full: false,
            last_server: None,
            player_command: None,
            dead_server_retries: rmule_core::DEFAULT_DEAD_AFTER,
            withhold_shares: false,
            remember_peers: rmule_core::RememberPeers::DEFAULT,
            user_hash: None,
            kad_node_id: None,
        }
    }
}

impl Preferences {
    /// The **Server Policy** these preferences hold, as core judges by it.
    #[must_use]
    pub fn server_policy(&self) -> rmule_core::ServerPolicy {
        rmule_core::ServerPolicy {
            dead_after: self.dead_server_retries,
            withhold_from_related_search: self.withhold_shares,
        }
    }

    /// Fold a committed edit into the snapshot.
    pub fn apply(&mut self, edit: &PrefEdit) {
        match edit {
            PrefEdit::DownloadDir(dir) => self.download_dir = Some(dir.clone()),
            PrefEdit::TempDir(dir) => self.temp_dir = dir.clone(),
            PrefEdit::Nickname(name) => self.nickname = name.clone(),
            PrefEdit::TcpPort(port) => self.tcp_port = *port,
            PrefEdit::UdpPort(port) => self.udp_port = *port,
            PrefEdit::ServerMetUrl(url) => self.server_met_url = url.clone(),
            PrefEdit::AutoFetchServerMet(on) => self.auto_fetch_server_met = *on,
            PrefEdit::NodesDatUrl(url) => self.nodes_dat_url = url.clone(),
            PrefEdit::AutoFetchNodesDat(on) => self.auto_fetch_nodes_dat = *on,
            PrefEdit::Theme(choice) => self.theme = *choice,
            PrefEdit::Obfuscation(choice) => self.obfuscation = *choice,
            PrefEdit::PortMapping(on) => self.port_mapping = *on,
            PrefEdit::ConnectAtStart(on) => self.connect_at_start = *on,
            PrefEdit::RunLogFull(on) => self.run_log_full = *on,
            PrefEdit::LastServer(server) => self.last_server = Some(server.clone()),
            PrefEdit::PlayerCommand(command) => self.player_command = command.clone(),
            PrefEdit::DeadServerRetries(limit) => self.dead_server_retries = *limit,
            PrefEdit::WithholdShares(on) => self.withhold_shares = *on,
            PrefEdit::RememberPeers(peers) => self.remember_peers = *peers,
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
    /// Validated by [`validate_download_dir`]; the next download reads it.
    DownloadDir(PathBuf),
    /// Validated by [`validate_temp_dir`]; a running core places the next
    /// download's part file there, and every download already placed keeps
    /// its own. `None`, the field left empty, clears the one set: the default
    /// in the data directory is in force again.
    TempDir(Option<PathBuf>),
    /// Takes effect at the next start — the running session already sent its
    /// identity.
    Nickname(String),
    /// Takes effect at the next start: the port is advertised at login.
    TcpPort(u16),
    /// Takes effect at the next start: the socket is already bound.
    UdpPort(u16),
    /// The next list refresh fetches from here.
    ServerMetUrl(String),
    /// Takes effect at the next start: the first-run fetch is decided once,
    /// at attach.
    AutoFetchServerMet(bool),
    /// Takes effect at the next start: bootstrap config is read once.
    NodesDatUrl(String),
    /// Takes effect at the next start, for the same reason.
    AutoFetchNodesDat(bool),
    /// The next frame paints in it.
    Theme(ThemeChoice),
    /// A running core takes it up at once: every surface reads the policy as
    /// it decides, and a connection already negotiated keeps its own.
    Obfuscation(ObfuscationChoice),
    /// Takes effect at the next start: core starts its port-mapping runtime,
    /// or does not, once, when it is built.
    PortMapping(bool),
    /// Whether the next start performs the operator's connect (ADR-0095).
    ConnectAtStart(bool),
    /// Whether the Run Log is written at its full level; the next line
    /// written is at the new level.
    RunLogFull(bool),
    /// The **Dead Server Limit**; core takes it up at once.
    DeadServerRetries(u32),
    /// The **Announce Policy**; core re-decides the live session at once.
    WithholdShares(bool),
    /// `Remember peers`; core's next seed write keeps that many.
    RememberPeers(rmule_core::RememberPeers),
    /// The **Player Command**, its text already split once
    /// ([`crate::player::split`]); `None` clears it. The next launch reads it.
    PlayerCommand(Option<String>),
    /// The server the operator just connected to, written by the app on the
    /// `Connected` edge rather than by the Settings form.
    LastServer(ServerEndpoint),
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

/// Who keeps one edit's key: core, as a Core Setting (ADR-0069), or the
/// front end itself.
pub enum Keeper<'a> {
    /// A key core owns, changed through its settings handle.
    Core(Setting),
    /// A key the front end keeps in its own namespace.
    FrontEnd(FrontEndEdit<'a>),
}

/// An edit of a key the front end keeps itself.
pub enum FrontEndEdit<'a> {
    /// See [`PrefEdit::Theme`].
    Theme(ThemeChoice),
    /// See [`PrefEdit::ConnectAtStart`].
    ConnectAtStart(bool),
    /// See [`PrefEdit::RunLogFull`].
    RunLogFull(bool),
    /// See [`PrefEdit::LastServer`].
    LastServer(&'a ServerEndpoint),
    /// See [`PrefEdit::PlayerCommand`].
    PlayerCommand(Option<&'a str>),
    /// See [`PrefEdit::TableSort`].
    TableSort {
        /// The table's stored key.
        table: &'static str,
        /// The column's stored key.
        column: &'static str,
        /// Its direction.
        direction: Direction,
    },
}

impl PrefEdit {
    /// Who keeps this edit's key, and the edit in that keeper's terms.
    ///
    /// A download directory is chosen in Settings, whose commit carried the
    /// warning that everything under it is offered (ADR-0101), so the answer
    /// rides the setting and the scan core starts asks nothing more.
    #[must_use]
    pub fn keeper(&self) -> Keeper<'_> {
        Keeper::Core(match self {
            Self::DownloadDir(dir) => Setting::DownloadDir {
                dir: dir.clone(),
                share_confirmed: true,
            },
            Self::TempDir(dir) => Setting::TempDir(dir.clone()),
            Self::Nickname(name) => Setting::Nickname(name.clone()),
            Self::TcpPort(port) => Setting::TcpPort(*port),
            Self::UdpPort(port) => Setting::UdpPort(*port),
            Self::ServerMetUrl(url) => Setting::ServerMetUrl(url.clone()),
            Self::AutoFetchServerMet(on) => Setting::AutoFetchServerMet(*on),
            Self::NodesDatUrl(url) => Setting::NodesDatUrl(url.clone()),
            Self::AutoFetchNodesDat(on) => Setting::AutoFetchNodesDat(*on),
            Self::Obfuscation(choice) => Setting::Obfuscation(choice.policy()),
            Self::PortMapping(on) => Setting::PortMapping(if *on {
                PortMappingMode::Auto
            } else {
                PortMappingMode::Off
            }),
            Self::DeadServerRetries(limit) => Setting::DeadServerRetries(*limit),
            Self::WithholdShares(on) => Setting::WithholdShares(*on),
            Self::RememberPeers(peers) => Setting::RememberPeers(*peers),
            Self::Theme(choice) => return Keeper::FrontEnd(FrontEndEdit::Theme(*choice)),
            Self::ConnectAtStart(on) => {
                return Keeper::FrontEnd(FrontEndEdit::ConnectAtStart(*on));
            }
            Self::RunLogFull(on) => return Keeper::FrontEnd(FrontEndEdit::RunLogFull(*on)),
            Self::LastServer(server) => return Keeper::FrontEnd(FrontEndEdit::LastServer(server)),
            Self::PlayerCommand(command) => {
                return Keeper::FrontEnd(FrontEndEdit::PlayerCommand(command.as_deref()));
            }
            Self::TableSort {
                table,
                column,
                direction,
            } => {
                return Keeper::FrontEnd(FrontEndEdit::TableSort {
                    table,
                    column,
                    direction: *direction,
                });
            }
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

/// The text `path`, trimmed, as a directory: absolute, and not an existing
/// non-directory.
fn directory(path: &str) -> Result<PathBuf, UnfitDirectory> {
    let trimmed = path.trim();
    let path = Path::new(trimmed);
    if !path.is_absolute() {
        return Err(UnfitDirectory::Relative);
    }
    if path.exists() && !path.is_dir() {
        return Err(UnfitDirectory::NotADirectory(trimmed.to_string()));
    }
    Ok(path.to_path_buf())
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
