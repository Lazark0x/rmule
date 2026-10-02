//! Durable application-configuration state owned by the Core Orchestrator:
//! the persisted Client Identity, the managed server list, and the
//! download-directory preference. Every Application Front-End (the CLI now,
//! the terminal client) shares this one source of truth (ADR-0069).
//!
//! The managed server list is a seam of its own —
//! [`ServerListStore`], ADR-0080 — because the core
//! actor owns the list and needs nothing else here: handing it identity and
//! keypairs to reach a server row would be a wider capability than the job.
//! [`AppConfigStore`] is that seam plus the rest, so a front-end still opens
//! one store.
//!
//! This file holds the vocabulary — the seam, the [`Preference`] keys, the
//! [`KadIdentity`], and the entropy the generate-once minting draws on. The one
//! implementation behind it is the Durable Store's
//! [`DurableAppConfig`](crate::DurableAppConfig) — opened on a file in
//! production and on the engine's in-memory backend by a test, so there is no
//! twin (ADR-0083).

use std::path::{Path, PathBuf};

use rmule_kad::KadId;
use rmule_primitives::{ClientIdentity, Ed2kText, SecureIdentKey, UserHash};

use crate::CoreError;
use crate::server_list::ServerListStore;

/// Nickname seeded into a freshly generated Client Identity.
pub const DEFAULT_NICKNAME: &str = "rmule";
/// eD2k listening TCP port seeded into a freshly generated identity.
pub const DEFAULT_TCP_PORT: u16 = 4662;
/// eDonkey protocol version (`0x3C`) seeded into a freshly generated identity.
pub const DEFAULT_PROTOCOL_VERSION: u32 = 60;
/// UDP listen port seeded into a freshly generated identity: the one port
/// peer reask, the NAT-T frames and Kad share (ADR-0057's socket
/// unification), and the eMule/aMule default for exactly that socket.
pub const DEFAULT_UDP_PORT: u16 = 4672;

/// The durable Kad node identity (ADR-0043): a random 128-bit Kad ID —
/// independent of the **User Hash**, never derived from it — plus the stable
/// UDP listen port. Both survive restarts so the node keeps its place in the
/// DHT keyspace and stays reachable at the advertised port.
///
/// The port is **the client's one UDP port**, not a Kad-only one: since the
/// socket unification (ADR-0057) peer reask, the NAT-T frames and Kad share a
/// single bind, so there is one number to configure and one router mapping to
/// hold open. It rides with the Kad ID because that is the row it has always
/// been persisted in, and because the durable-identity pair is what a
/// front-end reads once at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KadIdentity {
    /// The node's 128-bit place in the Kad keyspace. Stable across restarts and
    /// across a port change.
    pub id: KadId,
    /// The one UDP port this client binds — what Kad advertises to contacts
    /// and what a peer's `CT_EMULE_UDPPORTS` reask half names.
    pub udp_port: u16,
}

/// A named front-end preference — the closed set of keys the durable
/// key/value `preferences` table holds (ADR-0069: config is the front-end's,
/// core is storage-agnostic).
///
/// The **key** is typed and the **value** is text, because text is what the
/// column is. Core stores preferences; it does not interpret them. Each key's
/// meaning — a path, a URL, a boolean, a theme name — is parsed where its one
/// consumer lives, so no second copy of that meaning can drift out of step
/// with the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preference {
    /// Directory finished downloads are written to.
    DownloadDir,
    /// The `server.met` mirror an operator-driven list update fetches
    /// (`rmule_bootstrap::DEFAULT_SERVER_MET_URL` when unset).
    ServerMetUrl,
    /// Whether a session start with an empty server list fetches
    /// `server.met` from [`ServerMetUrl`](Self::ServerMetUrl) once
    /// (`"true"`/`"false"`, on when unset — ADR-0065's first-run fetch,
    /// `rmule_bootstrap::BootstrapConfig::auto_fetch_server_met`).
    AutoFetchServerMet,
    /// The `nodes.dat` mirror a Kad seed acquisition fetches
    /// (`rmule_bootstrap::DEFAULT_NODES_DAT_URL` when unset).
    NodesDatUrl,
    /// Whether the front-end may fetch `nodes.dat` for a Kad cold start
    /// (`"true"`/`"false"`; ADR-0067 amendment — an opt-in the TUI takes and
    /// no library caller does).
    AutoFetchNodesDat,
    /// The terminal theme name a front-end starts in (`dark`/`light`/`256`,
    /// or unset for environment detection).
    Theme,
    /// The per-install secret mixed into the PCP Mapping Nonce (ADR-0086),
    /// as a decimal `u32`.
    PortMapSecret,
    /// Whether rmule maps its own ports on the router — PCP, NAT-PMP and
    /// UPnP-IGD raced (ADR-0086) — as `"true"`/`"false"`, on when unset. The
    /// front end hands it to `CoreConfig::port_mapping` as the mode, so it
    /// takes effect at the next start.
    PortMapping,
    /// The port-mapping method that last won a race (ADR-0086), so the next
    /// run opens with one short probe instead of a full three-protocol race.
    PortMapMethod,
    /// The per-install **Kad UDP Key** the node's verify keys derive from
    /// (aMule `/Obfuscation/CryptoKadUDPKey`), as a decimal `u32`.
    KadUdpKey,
    /// The one protocol-obfuscation policy a front-end hands
    /// `CoreConfig::peer_crypt` (ADR-0046; aMule's `/Obfuscation/` trio):
    /// `supported`/`requested`/`required`, or unset for none.
    Obfuscation,
    /// Every TUI table's **Table Sort** (ADR-0070), one entry
    /// per table in a single value, so a table that gains a sort adds an entry
    /// rather than a key. The front-end owns the format.
    TableSorts,
    /// Whether the front end performs the operator's connect at attach
    /// (`"true"`/`"false"`, off when unset — ADR-0093, "Connecting is the
    /// operator's act"; aMule's `Autoconnect`, which rmule keeps off by
    /// default).
    ConnectAtStart,
    /// The server the operator last connected to, as `host:port`: what a
    /// connect at start dials. Written by the front end on every `Connected`.
    LastServer,
    /// Whether the front end's Run Log is written at its full level
    /// (`"true"`/`"false"`, off when unset): lean holds reachability evidence
    /// only, full adds peer addresses, file names, paths and hashes.
    RunLogFull,
    /// The **Dead Server Limit** (ADR-0052): the failure tally at which a
    /// listed server is dead, a whole number of at least 1 (aMule's
    /// `/eMule/DeadServerRetry`, default 3). One of the two preferences core
    /// itself reads, at the actor's start ([`ServerPolicy`](crate::ServerPolicy)).
    DeadServerRetries,
    /// The **Announce Policy** (ADR-0099): whether the share set is withheld
    /// from servers that grant related search (`"true"`/`"false"`, off when
    /// unset). The other preference core reads at the actor's start.
    WithholdSharesFromRelatedSearch,
    /// `Remember peers` (ADR-0109, "Source Seeds"): how many peers each
    /// running download keeps for a restart to dial first, a whole number
    /// from 1 to 255 (default 10). The front end hands it to
    /// `CoreConfig::remember_peers` and changes it live.
    RememberPeers,
}

impl Preference {
    /// The `preferences.key` this entry is stored under. Stable: renaming one
    /// would orphan an installed value.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::DownloadDir => "download_dir",
            Self::ServerMetUrl => "server_met_url",
            Self::AutoFetchServerMet => "auto_fetch_server_met",
            Self::NodesDatUrl => "nodes_dat_url",
            Self::AutoFetchNodesDat => "auto_fetch_nodes_dat",
            Self::Theme => "theme",
            Self::PortMapSecret => "port_map_secret",
            Self::PortMapping => "port_mapping",
            Self::PortMapMethod => "port_map_method",
            Self::KadUdpKey => "kad_udp_key",
            Self::Obfuscation => "obfuscation",
            Self::TableSorts => "table_sorts",
            Self::ConnectAtStart => "connect_at_start",
            Self::LastServer => "last_server",
            Self::RunLogFull => "run_log_full",
            Self::DeadServerRetries => "dead_server_retries",
            Self::WithholdSharesFromRelatedSearch => "withhold_shares_related_search",
            Self::RememberPeers => "remember_peers",
        }
    }
}

/// Durable owner of the app's Client Identity, managed server list, and the
/// front-end [`Preference`] table. `ensure_identity` is generate-once:
/// the first call mints and persists a random identity; later calls return it.
///
/// The server list half is [`ServerListStore`], the narrower seam the core
/// actor is handed (ADR-0080).
///
/// # What is editable and what is minted once
///
/// The **identity material** — the User Hash, the Secure User Identification
/// keypair, the Kad ID — has no setter anywhere in this trait and never will:
/// it is generated from OS entropy on first use and keys the credit and
/// reputation this client has earned. What a front-end's preferences editor
/// may change is the *presentation* half of the same rows — the advertised
/// nickname and the two listen ports — which are aMule preferences that happen
/// to travel with identity on the wire.
pub trait AppConfigStore: ServerListStore {
    /// Generate-once the eD2k [`ClientIdentity`] — User Hash, nickname and the
    /// two listen ports. The first call mints and persists it from OS entropy;
    /// later calls return the same one, so the client's earned credit and
    /// reputation stay attached to it.
    fn ensure_identity(&self) -> Result<ClientIdentity, CoreError>;
    /// Generate-once the application's Secure User Identification keypair
    /// (ADR-0041), persisted **plaintext** alongside the Client Identity —
    /// matching eMule's unencrypted `cryptkey.dat`. The first call mints and
    /// persists it; later calls return the same keypair. Bound to the
    /// **User Hash** it proves: both are durable identity material.
    fn ensure_secure_ident_key(&self) -> Result<SecureIdentKey, CoreError>;
    /// Generate-once the durable [`KadIdentity`] (ADR-0043): the first call
    /// mints a random Kad ID with the default UDP port and persists both;
    /// later calls return the same identity, so a restarted node keeps its
    /// DHT position and listen port.
    fn ensure_kad_identity(&self) -> Result<KadIdentity, CoreError>;

    /// The stored value of `preference`, or `None` when nothing has set it —
    /// which is how a caller tells "unset, use my default" from "set to the
    /// same string my default happens to be".
    fn preference(&self, preference: Preference) -> Result<Option<String>, CoreError>;

    /// Persist `value` under `preference`, replacing any installed one.
    fn set_preference(&self, preference: Preference, value: &str) -> Result<(), CoreError>;

    /// Replace the advertised nickname. Mints the identity first when none
    /// exists, so the edit can never land on a row that is not there.
    fn set_nickname(&self, nickname: &Ed2kText) -> Result<(), CoreError>;

    /// Replace the advertised eD2k listen port (the one a server's login
    /// answer grades into a High/Low ID).
    fn set_tcp_port(&self, port: u16) -> Result<(), CoreError>;

    /// Replace the UDP listen port — the one socket reask, NAT-T and Kad
    /// share. The Kad **ID** is untouched: a node that moves ports keeps its
    /// place in the keyspace.
    fn set_udp_port(&self, port: u16) -> Result<(), CoreError>;

    /// Generate-once the per-install **port-mapping secret** (ADR-0086): the
    /// value mixed into the PCP Mapping Nonce.
    ///
    /// RFC 6887 §11.3 makes that nonce a capability — a request for a mapping
    /// we already hold, carrying a *different* nonce, earns `NOT_AUTHORIZED`
    /// against ourselves until the lease expires, and measured firmware answers
    /// with silence rather than the refusal the RFC requires. So the nonce must
    /// be the same after a restart, which is why it is derived from a persisted
    /// value rather than drawn. Persisting it also makes it a real capability:
    /// a LAN neighbour who can see the mapped port still cannot derive the
    /// nonce that deletes it.
    ///
    /// A store that cannot persist one answers `0`, which still derives a
    /// *stable* nonce — the property renewal and deletion need — and gives up
    /// only the unguessability.
    fn ensure_port_map_secret(&self) -> Result<u32, CoreError> {
        ensure_secret(self, Preference::PortMapSecret)
    }

    /// Generate-once the per-install **Kad UDP Key**: the seed
    /// every Kad UDP verify key rmule hands a counterparty derives from,
    /// carried to the node as [`KadEnableConfig::kad_udp_key`].
    ///
    /// Persisted where aMule persists it — a preference minted from
    /// `GetRandomUint32()` on first read (`/Obfuscation/CryptoKadUDPKey`,
    /// `Preferences.cpp:1541`) — because a counterparty checks the key we
    /// echo against the one it derived *for us*: a seed that changed across a
    /// restart turns every key the network learned for this node into a
    /// mismatch.
    ///
    /// [`KadEnableConfig::kad_udp_key`]: crate::KadEnableConfig::kad_udp_key
    fn ensure_kad_udp_key(&self) -> Result<u32, CoreError> {
        ensure_secret(self, Preference::KadUdpKey)
    }

    /// The configured download directory, if one has been set.
    fn download_dir(&self) -> Result<Option<PathBuf>, CoreError> {
        Ok(self.preference(Preference::DownloadDir)?.map(PathBuf::from))
    }

    /// Persist the download directory. Fails with
    /// [`CoreError::Repository`] on a path that is not valid UTF-8, since the
    /// preferences column is text.
    fn set_download_dir(&self, dir: &Path) -> Result<(), CoreError> {
        let value = dir
            .to_str()
            .ok_or_else(|| CoreError::Repository("download dir is not valid UTF-8".to_owned()))?;
        self.set_preference(Preference::DownloadDir, value)
    }
}

/// Random eMule-compatible User Hash from OS entropy (`getrandom`), with the
/// conventional client markers (`[5] = 14`, `[14] = 111`) eMule/aMule set so
/// peers recognise a real client. A secure RNG keeps the identity — which keys
/// upload credit and reputation on the network — unpredictable, matching how
/// real eMule/aMule mint it.
pub(crate) fn generate_user_hash() -> UserHash {
    let mut bytes = [0u8; UserHash::BYTE_LEN];
    getrandom::fill(&mut bytes).expect("OS entropy for user hash generation");
    bytes[5] = 14;
    bytes[14] = 111;
    UserHash::from_bytes(bytes)
}

/// Random 128-bit Kad ID from OS entropy, mirroring how eMule/aMule mint
/// theirs (`CUInt128(true)` — pure random, no client markers, no relation to
/// the User Hash).
pub(crate) fn generate_kad_identity() -> KadIdentity {
    let mut bytes = [0u8; KadId::BYTE_LEN];
    getrandom::fill(&mut bytes).expect("OS entropy for Kad ID generation");
    KadIdentity {
        id: KadId::from_bytes(bytes),
        udp_port: DEFAULT_UDP_PORT,
    }
}

/// Build the default Client Identity around a chosen User Hash.
pub(crate) fn default_identity(user_hash: UserHash) -> ClientIdentity {
    ClientIdentity::new(
        user_hash,
        Ed2kText::from_utf8(DEFAULT_NICKNAME),
        DEFAULT_TCP_PORT,
        DEFAULT_PROTOCOL_VERSION,
    )
}

/// Read the decimal `u32` stored under `preference`, or mint one from OS
/// entropy and persist it — the generate-once shape both per-install secrets
/// share.
fn ensure_secret<S: AppConfigStore + ?Sized>(
    store: &S,
    preference: Preference,
) -> Result<u32, CoreError> {
    if let Some(stored) = store.preference(preference)?
        && let Ok(secret) = stored.parse::<u32>()
    {
        return Ok(secret);
    }
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes).expect("OS entropy for a per-install secret");
    let secret = u32::from_le_bytes(bytes);
    store.set_preference(preference, &secret.to_string())?;
    Ok(secret)
}
