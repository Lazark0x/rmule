//! How a tool's Core gets its node identity (ADR-0048 "Identity ownership"):
//! the User Hash a tool names on its command line is fixed at
//! build time, never carried by a command, and the Secure User Identification
//! key that proves it comes from a store that outlives the run — the
//! TUI/CLI's `AppConfigStore::ensure_secure_ident_key`, keyed per hash.
//!
//! A counterparty that keeps its `clients.met` between runs (aMule's
//! `CClientCreditsList`, which binds a hash to the public key it first proved
//! with) would otherwise see a fixed `--user-hash` arrive under a new key every
//! run and refuse the proof as a hash/key mismatch.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rmule_core::{
    AppConfigStore, Core, CoreBuilder, CoreCommand, CoreConfig, CoreSettings, DurableAppConfig,
    DurableStore, ManagedServer, RuntimeKadFactory, RuntimePeerTransferService,
    RuntimeServeRuntimeService, RuntimeSourceLookupService, ServerListCommand, open_durable_store,
};
use rmule_primitives::{SecureIdentKey, ServerEndpoint, UserHash};

/// The default production builder over `store`, as the node whose hash is
/// `user_hash`, under the `settings` the tool's own operands state — a tool
/// never runs under preferences its store happens to hold. With an
/// `identity_dir`, the SUI key is the one stored in
/// `<identity_dir>/<HASH>` — created on first use, reused on every later run
/// with the same hash; without one, the key is `store`'s own (persistent for a
/// `--data-dir` store, fresh per run for an in-memory one).
pub(crate) fn core_builder(
    config: CoreConfig,
    settings: CoreSettings,
    store: Arc<DurableStore>,
    user_hash: UserHash,
    identity_dir: Option<&Path>,
) -> Result<
    CoreBuilder<
        RuntimeSourceLookupService,
        RuntimePeerTransferService,
        RuntimeServeRuntimeService,
        RuntimeKadFactory,
    >,
> {
    let builder = Core::builder(config, store)
        .settings(settings)
        .user_hash(user_hash);
    Ok(match identity_dir {
        Some(dir) => builder.secure_ident_key(stored_key(dir, user_hash)?),
        None => builder,
    })
}

/// The operator's connect a one-shot tool gives on its own command line: list
/// `server`, then connect to it. Nothing in core dials a server but this
/// command (ADR-0095, "Connecting is the operator's act"); it binds the
/// listener if none is up, waits for its mapping, then logs in, and every
/// download or search already waiting rides the session it makes. The login
/// presents the Core Settings' credentials the tool built its core under.
///
/// # Errors
/// Core refused a command (it has stopped).
pub(crate) async fn connect(core: &Core, server: &ServerEndpoint) -> Result<()> {
    core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
        server: ManagedServer::listed(server.clone()),
    }))
    .await
    .context("list the server")?;
    core.send(CoreCommand::ConnectToServer {
        server: server.clone(),
    })
    .await
    .context("connect to the server")
}

/// The SUI key kept for `user_hash` under `identity_dir`: one Durable Store
/// per hash, so a fixed hash always carries the same key and two hashes never
/// share one.
fn stored_key(identity_dir: &Path, user_hash: UserHash) -> Result<SecureIdentKey> {
    let dir = identity_dir.join(user_hash.to_hex_upper());
    let store = open_durable_store(&dir)
        .with_context(|| format!("open the identity store in {}", dir.display()))?;
    DurableAppConfig::new(store)
        .ensure_secure_ident_key()
        .with_context(|| format!("load the SUI key in {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two runs naming one hash over one identity dir prove
    /// with one key; another hash gets its own.
    #[test]
    fn a_fixed_user_hash_keeps_its_sui_key_across_runs() {
        let dir = tempfile::tempdir().unwrap();
        let hash = UserHash::from_bytes([0x42; UserHash::BYTE_LEN]);
        let first = stored_key(dir.path(), hash).unwrap();
        let second = stored_key(dir.path(), hash).unwrap();
        let other =
            stored_key(dir.path(), UserHash::from_bytes([0x43; UserHash::BYTE_LEN])).unwrap();
        assert_eq!(first.public_key_der(), second.public_key_der());
        assert_ne!(first.public_key_der(), other.public_key_der());
    }
}
