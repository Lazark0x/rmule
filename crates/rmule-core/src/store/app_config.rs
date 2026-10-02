//! The durable [`AppConfigStore`] on `rmule-store` (ADR-0083): the three
//! generate-once identity singletons, the front-end preference table, and —
//! beside it in `app_config/servers.rs` — the managed server list that makes
//! up the narrower [`ServerListStore`](crate::ServerListStore) half.
//!
//! Each identity is a record kind of its own under a single fixed key rather
//! than a shared row, so a shape change versions one identity without
//! touching the others, and the engine refuses a table written under an older
//! record version instead of misreading it. Preferences are text under text,
//! which is not a record kind at all, so they ride a plain typed table.
//!
//! Every method takes `&self`: the store is `Sync`, so the handle is shared
//! through an `Arc` with no lock of rmule's own.

mod servers;

pub(crate) use servers::{grow_from_v8, grow_from_v9, grow_from_v11};

use std::sync::Arc;

use rmule_kad::KadId;
use rmule_primitives::{ClientIdentity, Ed2kText, SecureIdentKey, UserHash};
use rmule_store::{Indexed, Readable, Record, Store, StoreError, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::app_config::{
    AppConfigStore, KadIdentity, Preference, default_identity, generate_kad_identity,
    generate_user_hash,
};

use super::Schema;

/// The key every identity singleton is stored under. The table holds at most
/// this one record, so the key is a constant rather than a mint.
const SINGLETON: u8 = 0;

/// The preference table: a [`Preference::key`] to the text a front-end set.
/// Not a record kind — the value is the column, and core never interprets it.
const PREFERENCES: TableDefinition<'static, &str, &str> =
    TableDefinition::new("app_config.preference");

/// The persisted eD2k [`ClientIdentity`]. `extra_tags` is not carried: it is a
/// login-time decoration of the identity, not durable identity material.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientIdentityRecord {
    user_hash: UserHash,
    nickname: Ed2kText,
    tcp_port: u16,
    protocol_version: u32,
}

impl Record for ClientIdentityRecord {
    const NAME: &'static str = "app_config.client_identity";
    const VERSION: u32 = 1;
}

impl From<&ClientIdentity> for ClientIdentityRecord {
    fn from(identity: &ClientIdentity) -> Self {
        Self {
            user_hash: identity.user_hash(),
            nickname: identity.nickname().clone(),
            tcp_port: identity.tcp_port(),
            protocol_version: identity.protocol_version(),
        }
    }
}

impl From<ClientIdentityRecord> for ClientIdentity {
    fn from(record: ClientIdentityRecord) -> Self {
        Self::new(
            record.user_hash,
            record.nickname,
            record.tcp_port,
            record.protocol_version,
        )
    }
}

/// The persisted [`KadIdentity`]. The ID is stored as its 16 wire bytes:
/// `KadId` is a thin wrapper over exactly those, so a serde derive on the
/// protocol crate would buy nothing the array does not already give.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct KadIdentityRecord {
    kad_id: [u8; KadId::BYTE_LEN],
    udp_port: u16,
}

impl Record for KadIdentityRecord {
    const NAME: &'static str = "app_config.kad_identity";
    const VERSION: u32 = 1;
}

impl From<KadIdentity> for KadIdentityRecord {
    fn from(identity: KadIdentity) -> Self {
        Self {
            kad_id: *identity.id.as_bytes(),
            udp_port: identity.udp_port,
        }
    }
}

impl From<KadIdentityRecord> for KadIdentity {
    fn from(record: KadIdentityRecord) -> Self {
        Self {
            id: KadId::from_bytes(record.kad_id),
            udp_port: record.udp_port,
        }
    }
}

/// The persisted Secure User Identification keypair, plaintext DER exactly as
/// eMule's `cryptkey.dat` holds it (ADR-0041). The key type is a parsed RSA
/// keypair, not a value: DER is its canonical durable form.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SecureIdentKeyRecord {
    private_key: Vec<u8>,
}

impl Record for SecureIdentKeyRecord {
    const NAME: &'static str = "app_config.secure_ident_key";
    const VERSION: u32 = 1;
}

static CLIENT_IDENTITY: Indexed<u8, ClientIdentityRecord> =
    Indexed::new(ClientIdentityRecord::NAME, &[]);
static KAD_IDENTITY: Indexed<u8, KadIdentityRecord> = Indexed::new(KadIdentityRecord::NAME, &[]);
static SECURE_IDENT_KEY: Indexed<u8, SecureIdentKeyRecord> =
    Indexed::new(SecureIdentKeyRecord::NAME, &[]);

/// The tables this seam owns, for the store's owner to merge with the other
/// seams' before `Store::open`.
#[must_use]
pub(crate) fn schema() -> Schema {
    Schema::new()
        .indexed(&CLIENT_IDENTITY)
        .indexed(&KAD_IDENTITY)
        .indexed(&SECURE_IDENT_KEY)
        .table(PREFERENCES)
        .merge(servers::schema())
}

/// The seam's tables as store versions 1 to 8 declared them, the server list
/// in its old shape with its endpoint index, for a test that builds an older
/// store.
#[cfg(test)]
pub(crate) fn schema_v1() -> Schema {
    Schema::new()
        .indexed(&CLIENT_IDENTITY)
        .indexed(&KAD_IDENTITY)
        .indexed(&SECURE_IDENT_KEY)
        .table(PREFERENCES)
        .merge(servers::schema_v1())
}

/// Add a static server named `name` at `endpoint`, failed twice, to the
/// list as a store of versions 1 to 8 kept it.
///
/// # Errors
/// The store's.
#[cfg(test)]
pub(crate) fn add_server_v1(
    txn: &rmule_store::WriteTransaction,
    endpoint: &rmule_primitives::ServerEndpoint,
    name: &str,
) -> Result<(), StoreError> {
    servers::add_v1(txn, endpoint, name)
}

/// The durable owner of the app's Client Identity, Secure User Identification
/// keypair, Kad identity, managed server list and front-end preferences, on
/// the one `rmule-store` database.
///
/// Cloneable-by-`Arc` and `Sync`: every method takes `&self` and does its own
/// transaction, so a front-end and the core actor share one handle.
#[derive(Clone, Debug)]
pub struct DurableAppConfig {
    store: Arc<Store>,
}

/// An identity the app mints once and then edits in place: the table it
/// lives in and the generator that fills it, declared together so no caller
/// can pair one with the other's mint.
struct Singleton<T: Record> {
    table: &'static Indexed<u8, T>,
    mint: fn() -> Result<T, CoreError>,
}

impl<T: Record> Singleton<T> {
    /// The stored record, minting it on first ask. The read, the re-check and
    /// the insert are one transaction, so two handles racing a cold start
    /// still mint once.
    fn ensure(&self, store: &Store) -> Result<T, CoreError> {
        let stored = store.read::<_, CoreError>(|txn| Ok(self.table.get(txn, &SINGLETON)?))?;
        if let Some(record) = stored {
            return Ok(record);
        }
        let minted = (self.mint)()?;
        store.write(|txn| {
            if let Some(installed) = self.table.get(txn, &SINGLETON)? {
                return Ok(installed);
            }
            self.table.insert(txn, &SINGLETON, &minted)?;
            Ok(minted)
        })
    }

    /// Apply `edit` to the record, minting it first if this is a cold start.
    fn edit(&self, store: &Store, edit: impl FnOnce(&mut T)) -> Result<(), CoreError> {
        let mut record = self.ensure(store)?;
        edit(&mut record);
        store.write::<_, CoreError>(|txn| {
            Ok(self.table.put(txn, &SINGLETON, &record).map(|_| ())?)
        })
    }
}

static IDENTITY: Singleton<ClientIdentityRecord> = Singleton {
    table: &CLIENT_IDENTITY,
    mint: || {
        Ok(ClientIdentityRecord::from(&default_identity(
            generate_user_hash(),
        )))
    },
};

static SECURE_IDENT: Singleton<SecureIdentKeyRecord> = Singleton {
    table: &SECURE_IDENT_KEY,
    mint: || {
        let key = SecureIdentKey::generate()
            .map_err(|e| CoreError::Repository(format!("secure-ident keygen: {e}")))?;
        Ok(SecureIdentKeyRecord {
            private_key: key.to_der(),
        })
    },
};

static KAD_IDENTITY_SINGLETON: Singleton<KadIdentityRecord> = Singleton {
    table: &KAD_IDENTITY,
    mint: || Ok(KadIdentityRecord::from(generate_kad_identity())),
};

impl DurableAppConfig {
    /// Wrap the shared store. Every table this seam reads was created by
    /// `Store::open` against this module's schema, so no read can miss one.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl AppConfigStore for DurableAppConfig {
    fn ensure_identity(&self) -> Result<ClientIdentity, CoreError> {
        IDENTITY.ensure(&self.store).map(ClientIdentity::from)
    }

    fn ensure_secure_ident_key(&self) -> Result<SecureIdentKey, CoreError> {
        let record = SECURE_IDENT.ensure(&self.store)?;
        SecureIdentKey::from_der(&record.private_key)
            .map_err(|e| CoreError::Repository(format!("stored secure-ident key: {e}")))
    }

    fn ensure_kad_identity(&self) -> Result<KadIdentity, CoreError> {
        KAD_IDENTITY_SINGLETON
            .ensure(&self.store)
            .map(KadIdentity::from)
    }

    fn preference(&self, preference: Preference) -> Result<Option<String>, CoreError> {
        self.store.read(|txn| {
            let table = txn.table(PREFERENCES)?;
            let found = table.get(preference.key()).map_err(StoreError::from)?;
            Ok(found.map(|value| value.value().to_owned()))
        })
    }

    fn set_preference(&self, preference: Preference, value: &str) -> Result<(), CoreError> {
        self.store.write::<_, CoreError>(|txn| {
            txn.open_table(PREFERENCES)
                .map_err(StoreError::from)?
                .insert(preference.key(), value)
                .map_err(StoreError::from)?;
            Ok(())
        })
    }

    fn set_nickname(&self, nickname: &Ed2kText) -> Result<(), CoreError> {
        IDENTITY.edit(&self.store, |record| {
            record.nickname = nickname.clone();
        })
    }

    fn set_tcp_port(&self, port: u16) -> Result<(), CoreError> {
        IDENTITY.edit(&self.store, |record| record.tcp_port = port)
    }

    fn set_udp_port(&self, port: u16) -> Result<(), CoreError> {
        KAD_IDENTITY_SINGLETON.edit(&self.store, |record| record.udp_port = port)
    }
}
