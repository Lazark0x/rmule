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

use std::path::PathBuf;

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

/// A core-owned preference — the closed set of keys core keeps in the
/// durable key/value `preferences` table.
///
/// Core owns the preferences that change what core does and reaches them
/// through **Core Settings** (ADR-0069), which parses each key's text into
/// its typed value in one place. A front end's own keys — the TUI's theme,
/// table sorts, Run Log level, connect at start and last server — share the
/// table under keys the front end names, through
/// [`CoreSettingsHandle::front_end_value`](crate::CoreSettingsHandle::front_end_value);
/// core never interprets them, and refuses one that names a key of its own.
///
/// The **key** is typed and the **value** is text, because text is what the
/// column is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preference {
    /// Directory finished downloads are written to.
    DownloadDir,
    /// The **Temp Directory** new downloads keep their part files in
    /// (ADR-0115): [`CoreSettings::temp_dir`](crate::CoreSettings::temp_dir).
    TempDir,
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
    /// The per-install secret mixed into the PCP Mapping Nonce (ADR-0086),
    /// as a decimal `u32`.
    PortMapSecret,
    /// Whether rmule maps its own ports on the router — PCP, NAT-PMP and
    /// UPnP-IGD raced (ADR-0086) — as `"true"`/`"false"`, on when unset:
    /// [`CoreSettings::port_mapping`](crate::CoreSettings::port_mapping).
    PortMapping,
    /// The port-mapping method that last won a race (ADR-0086), so the next
    /// run opens with one short probe instead of a full three-protocol race.
    PortMapMethod,
    /// The per-install **Kad UDP Key** the node's verify keys derive from
    /// (aMule `/Obfuscation/CryptoKadUDPKey`), as a decimal `u32`.
    KadUdpKey,
    /// The one protocol-obfuscation policy,
    /// [`CoreSettings::obfuscation`](crate::CoreSettings::obfuscation)
    /// (ADR-0046; aMule's `/Obfuscation/` trio):
    /// `supported`/`requested`/`required`, or `off` or unset for none.
    Obfuscation,
    /// The **Dead Server Limit** (ADR-0052): the failure tally at which a
    /// listed server is dead, a whole number of at least 1 (aMule's
    /// `/eMule/DeadServerRetry`, default 3): half of
    /// [`CoreSettings::server_policy`](crate::CoreSettings::server_policy).
    DeadServerRetries,
    /// The **Announce Policy** (ADR-0099): whether the share set is withheld
    /// from servers that grant related search (`"true"`/`"false"`, off when
    /// unset): the other half of
    /// [`CoreSettings::server_policy`](crate::CoreSettings::server_policy).
    WithholdSharesFromRelatedSearch,
    /// `Remember peers` (ADR-0109, "Source Seeds"): how many peers each
    /// running download keeps for a restart to dial first, a whole number
    /// from 1 to 255 (default 10):
    /// [`CoreSettings::remember_peers`](crate::CoreSettings::remember_peers).
    RememberPeers,
}

impl Preference {
    /// Every core-owned key, so the front end's raw surface can refuse them.
    pub const ALL: [Self; 14] = [
        Self::DownloadDir,
        Self::TempDir,
        Self::ServerMetUrl,
        Self::AutoFetchServerMet,
        Self::NodesDatUrl,
        Self::AutoFetchNodesDat,
        Self::PortMapSecret,
        Self::PortMapping,
        Self::PortMapMethod,
        Self::KadUdpKey,
        Self::Obfuscation,
        Self::DeadServerRetries,
        Self::WithholdSharesFromRelatedSearch,
        Self::RememberPeers,
    ];

    /// The `preferences.key` this entry is stored under. Stable: renaming one
    /// would orphan an installed value.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::DownloadDir => "download_dir",
            Self::TempDir => "temp_dir",
            Self::ServerMetUrl => "server_met_url",
            Self::AutoFetchServerMet => "auto_fetch_server_met",
            Self::NodesDatUrl => "nodes_dat_url",
            Self::AutoFetchNodesDat => "auto_fetch_nodes_dat",
            Self::PortMapSecret => "port_map_secret",
            Self::PortMapping => "port_mapping",
            Self::PortMapMethod => "port_map_method",
            Self::KadUdpKey => "kad_udp_key",
            Self::Obfuscation => "obfuscation",
            Self::DeadServerRetries => "dead_server_retries",
            Self::WithholdSharesFromRelatedSearch => "withhold_shares_related_search",
            Self::RememberPeers => "remember_peers",
        }
    }
}

/// Durable owner of the app's Client Identity, managed server list, and the
/// core-owned [`Preference`] keys. `ensure_identity` is generate-once:
/// the first call mints and persists a random identity; later calls return it.
///
/// The server list half is [`ServerListStore`], the narrower seam the core
/// actor is handed (ADR-0080).
///
/// # What is editable and what is minted once
///
/// The **identity material** — the User Hash, the Secure User Identification
/// keypair, the Kad ID — has no setter anywhere and never will: it is
/// generated from OS entropy on first use and keys the credit and reputation
/// this client has earned. What a front end's preferences editor may change
/// is the *presentation* half of the same rows — the advertised nickname and
/// the two listen ports — which are aMule preferences that happen to travel
/// with identity on the wire.
///
/// This seam writes none of them. Every change to a core-owned key goes
/// through [`CoreSettingsHandle::set`](crate::CoreSettingsHandle::set), which
/// validates it and hands a live key to a running core (ADR-0069); a raw
/// setter here would be a second door around both.
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
    fn ensure_port_map_secret(&self) -> Result<u32, CoreError>;

    /// Generate-once the per-install **Kad UDP Key**: the seed
    /// every Kad UDP verify key rmule hands a counterparty derives from,
    /// read by core at build and handed to the node as
    /// [`KadNodeIdentity::kad_udp_key`].
    ///
    /// Persisted where aMule persists it — a preference minted from
    /// `GetRandomUint32()` on first read (`/Obfuscation/CryptoKadUDPKey`,
    /// `Preferences.cpp:1541`) — because a counterparty checks the key we
    /// echo against the one it derived *for us*: a seed that changed across a
    /// restart turns every key the network learned for this node into a
    /// mismatch.
    ///
    /// [`KadNodeIdentity::kad_udp_key`]: crate::KadNodeIdentity::kad_udp_key
    fn ensure_kad_udp_key(&self) -> Result<u32, CoreError>;

    /// The configured download directory, if one has been set.
    fn download_dir(&self) -> Result<Option<PathBuf>, CoreError> {
        Ok(self.preference(Preference::DownloadDir)?.map(PathBuf::from))
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
