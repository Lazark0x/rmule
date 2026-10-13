//! **Core Settings** (ADR-0069): the operator's preferences that change what
//! core does, and the one door every change to them goes through.
//!
//! [`CoreSettings`] is the value a core runs under: the builder reads it from
//! the store it is given, or a test injects one. [`CoreSettingsHandle`] is the
//! synchronous handle on the same keys: [`set`](CoreSettingsHandle::set)
//! validates a [`Setting`], persists it, and answers when it
//! [`TakesEffect`]. The handle hides where each value is kept — the nickname
//! and the two ports in the identity rows, every other key in the preferences
//! table — so no front end parses a stored spelling of its own. It refuses a
//! download directory the Shared Directory List's guards refuse (ADR-0101),
//! with the add's reason, and a Temp Directory that is not apart from every
//! shared directory (ADR-0115), so a refused directory is never stored.

mod stored;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmule_net::peer::ObfuscationPolicy;

use crate::app_config::{AppConfigStore, DEFAULT_NICKNAME, DEFAULT_PROTOCOL_VERSION, Preference};
use crate::directory_scan::guard_temp_dir;
use crate::port_mapping::PortMappingMode;
use crate::server_list::ServerPolicy;
use crate::service::SettingsDoor;
use crate::store::app_config::DurableAppConfig;
use crate::store::registry::DurableSharedFileRegistry;
use crate::{
    ClientCredentials, CoreError, DirectoryRefusal, DurableStore, RememberPeers, ShareGuards,
};

/// The operator's preferences a core runs under (ADR-0069, "Core Settings").
///
/// [`Core::builder`](crate::Core::builder) reads them from the store it is
/// given; a test or a tool injects its own with
/// [`CoreBuilder::settings`](crate::CoreBuilder::settings), so nothing reads
/// the store behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreSettings {
    /// Where finished downloads are written, and the Shared Directory List's
    /// entry 0 (ADR-0101); `None` until the operator chooses one.
    pub download_dir: Option<PathBuf>,
    /// The **Temp Directory** (ADR-0115): where a download started from now
    /// on keeps its part file. `None` until the operator chooses one, and
    /// then [`temp_directory`](Self::temp_directory) reads the default.
    pub temp_dir: Option<PathBuf>,
    /// The nickname the identity row advertises.
    pub nickname: String,
    /// The eD2k listen port: the listener binds it, and every login, hello
    /// and Kad dial presents it through [`credentials`](Self::credentials).
    /// `0` takes a port the OS assigns, and what is presented is the port
    /// bound — what a test wants; the store never holds one.
    pub tcp_port: u16,
    /// The UDP port rmule's one client-UDP socket binds (ADR-0057's socket
    /// unification): peer reask, the NAT-T frames and the Kad node all ride
    /// it. `0` takes an OS-assigned port — what a test wants; the store never
    /// holds one, so an operator's core always binds a port it can advertise.
    pub udp_port: u16,
    /// The one protocol-obfuscation policy (ADR-0042/0046), or `None` for no
    /// obfuscation at all. One value across the stream and datagram forms,
    /// interpreted per transport, so this single setting:
    ///
    /// - lights the peer hello's `MiscOptions2` crypt bits, honestly, because
    ///   it also
    /// - makes every accepted peer-TCP connection dual-path,
    /// - arms the peer-UDP per-datagram layer on the shared client-UDP socket:
    ///   dual-path receive always, send-encrypt under the ADR-0046 gate,
    /// - arms the Kad node's datagram crypt and UDP verify keys, keyed on
    ///   [`KadNodeIdentity::kad_udp_key`](crate::KadNodeIdentity::kad_udp_key)
    ///   — aMule gates Kad obfuscation on the same
    ///   `IsClientCryptLayerSupported()` — and
    /// - arms the server-UDP crypt-ping arm: aMule ties it to the same
    ///   preference (`Preferences.h:883`), and rmule keeps no separate bool.
    ///
    /// `Supported` accepts obfuscation without initiating it; `Requested` and
    /// `Required` also initiate. Off by default: rmule advertises no
    /// capability before a capture has proven it can answer it. A running
    /// core takes a change up at once ([`Setting::Obfuscation`]): every
    /// surface reads the policy as it decides.
    pub obfuscation: Option<ObfuscationPolicy>,
    /// Whether rmule maps its own ports on the router (ADR-0086). **Auto by
    /// default**, against aMule's off-by-default: a firewalled home node is
    /// the common deployment, and forfeiting High-ID for every operator who
    /// never opens a settings screen is the larger harm.
    pub port_mapping: PortMappingMode,
    /// `Remember peers` (ADR-0109, "Source Seeds"): how many peers each
    /// running download writes as its seeds.
    pub remember_peers: RememberPeers,
    /// The **Dead Server Limit** and the **Announce Policy** (ADR-0052,
    /// ADR-0099): what core does with a server by what reaching it has shown.
    pub server_policy: ServerPolicy,
    /// The `server.met` mirror the first-run fetch and the front end's list
    /// update default to.
    pub server_met_url: String,
    /// Whether a start with an empty server list fetches `server.met` from
    /// [`server_met_url`](Self::server_met_url) once (ADR-0065). On by default.
    pub auto_fetch_server_met: bool,
    /// The `nodes.dat` mirror a Kad seed acquisition fetches.
    pub nodes_dat_url: String,
    /// Whether a Kad start with no contacts may fetch `nodes.dat` itself
    /// (ADR-0067 amendment): on by default, and the operator's to turn off.
    pub auto_fetch_nodes_dat: bool,
}

impl Default for CoreSettings {
    /// Every key at the value a store with nothing set reads as, but for the
    /// two ports: `0`, an OS-assigned port, because a library default that
    /// named a fixed port would have every test core fight for it.
    fn default() -> Self {
        Self {
            download_dir: None,
            temp_dir: None,
            nickname: DEFAULT_NICKNAME.to_owned(),
            tcp_port: 0,
            udp_port: 0,
            obfuscation: None,
            port_mapping: PortMappingMode::Auto,
            remember_peers: RememberPeers::DEFAULT,
            server_policy: ServerPolicy::default(),
            server_met_url: rmule_bootstrap::DEFAULT_SERVER_MET_URL.to_owned(),
            auto_fetch_server_met: true,
            nodes_dat_url: rmule_bootstrap::DEFAULT_NODES_DAT_URL.to_owned(),
            auto_fetch_nodes_dat: true,
        }
    }
}

impl CoreSettings {
    /// What a login and a hello present beside the node's own hash: the
    /// [`nickname`](Self::nickname), the [`tcp_port`](Self::tcp_port) and the
    /// protocol version rmule speaks. The one place the presentation half of
    /// the identity rows becomes credentials: core presents them on every
    /// wire-touching path, so no command carries any.
    #[must_use]
    pub fn credentials(&self) -> ClientCredentials {
        ClientCredentials::new(
            rmule_primitives::Ed2kText::from_utf8(&self.nickname),
            self.tcp_port,
            DEFAULT_PROTOCOL_VERSION,
        )
    }

    /// Where a download started now keeps its part file (ADR-0115): the
    /// [`temp_dir`](Self::temp_dir) set, or else
    /// [`default_temp_dir`](Self::default_temp_dir) in `data_dir`, rmule's
    /// data directory. `None` with neither — a test's or a tool's core — and
    /// the part file then lies beside its final path.
    #[must_use]
    pub fn temp_directory(&self, data_dir: Option<&Path>) -> Option<PathBuf> {
        temp_directory(self.temp_dir.clone(), data_dir)
    }

    /// The Temp Directory of an operator who never chose one: `Temp` in the
    /// data directory `data_dir`.
    #[must_use]
    pub fn default_temp_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("Temp")
    }
}

/// The Temp Directory `set`, or the default in `data_dir`.
pub(crate) fn temp_directory(set: Option<PathBuf>, data_dir: Option<&Path>) -> Option<PathBuf> {
    set.or_else(|| data_dir.map(CoreSettings::default_temp_dir))
}

/// One change to a core-owned preference, as a front end asks for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Setting {
    /// The download directory. Absolute, valid UTF-8, not an existing file,
    /// and passing the Shared Directory List's guards (ADR-0101) where it is,
    /// or would be made: not the home, a filesystem root, or rmule's data
    /// directory, inside it or holding it, and neither the Temp Directory nor
    /// holding it.
    DownloadDir {
        /// The directory.
        dir: PathBuf,
        /// Whether the operator already confirmed that everything under `dir`
        /// is offered to the network — the front end's ADR-0101 confirm, given
        /// before the set. `true` records that yes, so the scan asks nothing
        /// more; `false` leaves the disclosure guard to ask at the scan's first
        /// share.
        share_confirmed: bool,
    },
    /// The **Temp Directory** (ADR-0115), made by the set when it is missing.
    /// Absolute, valid UTF-8, a directory, not the home or a filesystem root,
    /// and apart from every shared directory: not the download directory or
    /// another listed one, inside one or holding one. Inside rmule's data
    /// directory is allowed. Downloads already placed keep their paths.
    TempDir(PathBuf),
    /// The advertised nickname: not blank, and free of control characters.
    Nickname(String),
    /// The eD2k listen port; never `0`.
    TcpPort(u16),
    /// The one client-UDP port; never `0`.
    UdpPort(u16),
    /// The obfuscation policy, or `None` for none.
    Obfuscation(Option<ObfuscationPolicy>),
    /// Whether rmule maps its ports on the router.
    PortMapping(PortMappingMode),
    /// `Remember peers`.
    RememberPeers(RememberPeers),
    /// The **Dead Server Limit**; at least 1.
    DeadServerRetries(u32),
    /// The **Announce Policy**: withhold the shares from servers that grant
    /// related search.
    WithholdShares(bool),
    /// The `server.met` mirror; not blank.
    ServerMetUrl(String),
    /// The first-run `server.met` fetch.
    AutoFetchServerMet(bool),
    /// The `nodes.dat` mirror; not blank.
    NodesDatUrl(String),
    /// The Kad cold start's `nodes.dat` fetch.
    AutoFetchNodesDat(bool),
}

/// When a persisted [`Setting`] changes what core does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakesEffect {
    /// The running core takes it up before any command sent after this
    /// answer: the change and the commands share one queue.
    Now,
    /// The next core built on this store starts under it.
    NextStart,
}

/// Why [`CoreSettingsHandle::set`] refused a value outright. Nothing was
/// written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingRefusal {
    /// A port of `0`: the OS would choose one, and no peer could be told it.
    #[error("a port must be from 1 to 65535")]
    PortZero,
    /// A Dead Server Limit of `0` would mark a server dead before it failed.
    #[error("the dead server limit must be at least 1")]
    DeadServerRetriesZero,
    /// A relative download directory would move with the working directory.
    #[error("the download directory must be an absolute path")]
    DownloadDirNotAbsolute,
    /// The preferences column is text.
    #[error("the download directory is not valid UTF-8")]
    DownloadDirNotUtf8,
    /// The path exists and is not a directory.
    #[error("the download directory exists and is not a directory")]
    DownloadDirNotADirectory,
    /// Everything under the download directory is shared, and the guards an
    /// added directory must pass refuse it, for this reason (ADR-0101).
    #[error("the share guards refuse the download directory")]
    DownloadDirRefused(DirectoryRefusal),
    /// The Temp Directory is refused for this reason (ADR-0115), the set's
    /// own failure to make it among them.
    #[error("the temp directory is refused")]
    TempDirRefused(DirectoryRefusal),
    /// A blank nickname, or one holding control characters a hello would carry.
    #[error("the nickname must not be blank or hold control characters")]
    NicknameUnfit,
    /// A blank mirror URL.
    #[error("the mirror URL must not be blank")]
    UrlBlank,
    /// A front end named one of core's own keys on its raw surface, which
    /// would write a Core Setting without validating it or taking it up.
    #[error("that key is a core setting")]
    CoreKey,
}

/// Why a [`Setting`] was not saved.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingError {
    /// The value is not one the key takes.
    #[error(transparent)]
    Refused(#[from] SettingRefusal),
    /// The store refused the write.
    #[error(transparent)]
    Store(#[from] CoreError),
}

/// A persisted change a running core takes up at once — the live half of
/// [`TakesEffect::Now`], queued from a handle to the actor that owns the
/// state it changes, in order with the commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveSetting {
    /// The next seed write keeps this many peers.
    RememberPeers(RememberPeers),
    /// Every server is judged again, and the live session follows.
    ServerPolicy(ServerPolicy),
    /// The download directory's scan moves here, with the confirm's answer
    /// recorded first when one was given.
    DownloadDir {
        /// The directory.
        dir: PathBuf,
        /// Whether the front end's confirm already said yes.
        share_confirmed: bool,
    },
    /// The next download placed keeps its part file in this Temp Directory,
    /// and the guards judge every directory against it.
    TempDir(PathBuf),
    /// The one obfuscation policy every surface reads as it decides
    /// (ADR-0046): the next dial, accept, datagram and crypt-ping follow it,
    /// and the Kad node is re-armed.
    Obfuscation(Option<ObfuscationPolicy>),
}

/// The one door to **Core Settings** (ADR-0069): opened on the store alone
/// where no core runs, or taken from a running core with
/// [`Core::settings`](crate::Core::settings). Cloneable and `Sync`: every
/// clone reaches the same store, and every method is one store transaction —
/// a live key's hand-off to the running core never waits on it.
#[derive(Clone, Debug)]
pub struct CoreSettingsHandle {
    store: DurableAppConfig,
    registry: DurableSharedFileRegistry,
    /// The running core's inbox, shared with its commands; `None` on the
    /// store alone.
    live: Option<SettingsDoor>,
    /// What the download directory's guards refuse beyond the filesystem's
    /// own facts: the running core's own, or what the front end named.
    guards: ShareGuards,
}

impl CoreSettingsHandle {
    /// A handle on `store` alone: every [`set`](Self::set) persists and
    /// answers [`TakesEffect::NextStart`], since no core runs behind it. Its
    /// download directory guards know only the filesystem's own facts until
    /// [`share_guards`](Self::share_guards) names the rest.
    #[must_use]
    pub fn open(store: Arc<DurableStore>) -> Self {
        Self {
            registry: DurableSharedFileRegistry::new(Arc::clone(&store)),
            store: DurableAppConfig::new(store),
            live: None,
            guards: ShareGuards::default(),
        }
    }

    /// The operator's home and rmule's data directory, which a download
    /// directory set through this handle may not be (ADR-0101), and the data
    /// directory the default Temp Directory lies in (ADR-0115): the same
    /// [`ShareGuards`] a front end hands
    /// [`CoreBuilder::share_guards`](crate::CoreBuilder::share_guards), since
    /// core never reads the environment. A running core's handle has its
    /// builder's already.
    #[must_use]
    pub fn share_guards(mut self, guards: ShareGuards) -> Self {
        self.guards = guards;
        self
    }

    /// A handle on `store` whose live keys reach the core through `live`,
    /// guarding the download directory with the core's own `guards`.
    pub(crate) fn running(
        store: Arc<DurableStore>,
        live: SettingsDoor,
        guards: ShareGuards,
    ) -> Self {
        Self {
            live: Some(live),
            ..Self::open(store).share_guards(guards)
        }
    }

    /// Every core-owned preference as the store holds it, defaults filling
    /// what the operator never set. Mints the identity rows on a cold store,
    /// as every front end's first read does.
    ///
    /// # Errors
    /// The store's.
    pub fn read(&self) -> Result<CoreSettings, CoreError> {
        stored::read(&self.store)
    }

    /// The text a front end stored under its own `key`, or `None` when
    /// nothing has set it. Core never interprets it (ADR-0069); a key of
    /// core's own reads as unset here, since it is not the front end's.
    ///
    /// # Errors
    /// The store's.
    pub fn front_end_value(&self, key: &str) -> Result<Option<String>, CoreError> {
        if is_core_key(key) {
            return Ok(None);
        }
        self.store.value(key)
    }

    /// Persist `value` under a front end's own `key`, in the same table as
    /// core's keys and never interpreted by core.
    ///
    /// # Errors
    /// [`SettingRefusal::CoreKey`] when `key` is one of core's, with nothing
    /// written; [`SettingError::Store`] when the store refused the write.
    pub fn set_front_end_value(&self, key: &str, value: &str) -> Result<(), SettingError> {
        if is_core_key(key) {
            return Err(SettingRefusal::CoreKey.into());
        }
        Ok(self.store.set_value(key, value)?)
    }

    /// What [`set`](Self::set) would refuse `setting` for, writing nothing:
    /// the check a front end makes before it asks the operator to confirm
    /// what the value means — a download directory the guards refuse is
    /// refused before the disclosure it would need. A Temp Directory that
    /// cannot be made is found only by the set, which makes it.
    ///
    /// # Errors
    /// [`SettingError::Refused`] with the refusal `set` would answer;
    /// [`SettingError::Store`] when the store could not be read for what a
    /// directory is judged against.
    pub fn check(&self, setting: &Setting) -> Result<(), SettingError> {
        match setting {
            Setting::DownloadDir { dir, .. } => {
                let temp_dir = temp_directory(
                    self.store
                        .preference(Preference::TempDir)?
                        .map(PathBuf::from),
                    self.guards.data_dir.as_deref(),
                );
                stored::validate_download_dir(dir, &self.guards, temp_dir.as_deref())?;
            }
            Setting::TempDir(dir) => {
                let download_dir = self.store.download_dir()?;
                let shared = self.registry.shared_directories()?;
                guard_temp_dir(dir, &self.guards, download_dir.as_deref(), &shared)
                    .map_err(SettingRefusal::TempDirRefused)?;
            }
            other => stored::validate(other)?,
        }
        Ok(())
    }

    /// Validate `setting`, persist it, and answer when it takes effect.
    ///
    /// A handle taken from a running core queues a live key for it before
    /// answering [`TakesEffect::Now`]: `Remember peers`, the Dead Server
    /// Limit, the Announce Policy, the download directory, whose scan core
    /// starts itself, the Temp Directory, where the next download placed
    /// keeps its part file, and the obfuscation policy, which every surface
    /// reads as it decides (ADR-0046). The key shares the core's command queue, so a
    /// command sent after the answer is taken after the change. Every other
    /// key, every key set on the store alone, and a live key whose core has
    /// stopped answer [`TakesEffect::NextStart`].
    ///
    /// # Errors
    /// [`SettingError::Refused`] for a value the key cannot take, with nothing
    /// written — among them a download directory the share guards refuse,
    /// [`SettingRefusal::DownloadDirRefused`] with the add's reason, and a
    /// Temp Directory refused or not made,
    /// [`SettingRefusal::TempDirRefused`]; [`SettingError::Store`] when the
    /// store refused the read or the write.
    pub fn set(&self, setting: Setting) -> Result<TakesEffect, SettingError> {
        self.check(&setting)?;
        if let Setting::TempDir(dir) = &setting {
            std::fs::create_dir_all(dir).map_err(|error| {
                SettingRefusal::TempDirRefused(DirectoryRefusal::Unreachable(error.kind()))
            })?;
        }
        stored::persist(&self.store, &setting)?;
        if let Setting::DownloadDir {
            dir,
            share_confirmed: true,
        } = &setting
        {
            self.registry.record_directory_answer(dir, true)?;
        }
        let Some(live) = &self.live else {
            return Ok(TakesEffect::NextStart);
        };
        let change = match setting {
            Setting::RememberPeers(peers) => LiveSetting::RememberPeers(peers),
            Setting::DeadServerRetries(_) | Setting::WithholdShares(_) => {
                LiveSetting::ServerPolicy(stored::server_policy(&self.store)?)
            }
            Setting::DownloadDir {
                dir,
                share_confirmed,
            } => LiveSetting::DownloadDir {
                dir,
                share_confirmed,
            },
            Setting::TempDir(dir) => LiveSetting::TempDir(dir),
            Setting::Obfuscation(policy) => LiveSetting::Obfuscation(policy),
            _ => return Ok(TakesEffect::NextStart),
        };
        Ok(if live.send(change) {
            TakesEffect::Now
        } else {
            TakesEffect::NextStart
        })
    }
}

/// Whether `key` names one of core's own preferences.
fn is_core_key(key: &str) -> bool {
    crate::Preference::ALL
        .into_iter()
        .any(|preference| preference.key() == key)
}

#[cfg(test)]
mod tests;
