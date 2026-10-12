//! The **Kad-seed leg** of the Join Sequence (ADR-0067 §Join Sequence, step 3): resolve
//! what a starting Kad node has to go on, in aMule's recovery-route order —
//! the routing table the running node persisted first, an opt-in one-shot
//! acquisition second — and report which route served. A leg of its own
//! because a front-end that drives `EnableKad` itself (the `rmule` TUI, whose
//! durable store the core actor owns by then) has to resolve seeds the same
//! way without running the rest of the sequence.
//!
//! Never fatal: every route's failure lands in the returned
//! [`KadSeedOutcome`] and the Kad join proceeds regardless, because an
//! empty-table node is what arms the ed2k→Kad handoff.

use std::net::SocketAddrV4;

use rmule_bootstrap::{
    BootstrapConfig, Fetcher, NodesDatInstall, NodesDatPipelineError, decode_nodes_dat,
    fetch_nodes_dat, should_auto_fetch_nodes_dat,
};
use rmule_kad::BootstrapDialList;

use crate::adapters::KadEnableConfig;

/// Where the Kad join's seeds came from — the observable result of step 3, and
/// the honest degrade a front-end shows when there are none.
///
/// The Kad join **always fires** regardless of this outcome: a node with an
/// empty routing table is what arms the two recovery routes that need it
/// running (the ed2k→Kad peer handoff, ADR-0067, and any later seed
/// injection). Starting Kad only when seeds exist would silently disarm them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KadSeedOutcome {
    /// The Kad join is off: nothing was read, nothing was acquired.
    Skipped,
    /// The persisted routing table
    /// ([`KadEnableConfig::nodes_dat_path`]) supplied the seeds — the warm
    /// restart. `contacts` enter the routing table directly (they carry earned
    /// Kad IDs); `candidates` are v3 bootstrap-edition dial candidates.
    Persisted {
        /// Seeds that entered the routing table directly, carrying earned Kad IDs.
        contacts: usize,
        /// Bootstrap-edition dial candidates, which must earn an ID before they
        /// join the table.
        candidates: usize,
    },
    /// No usable seeds and no acquisition — aMule's own posture (its nodes.dat
    /// fetch is user-triggered, so a stranded node logs and waits). Kad starts
    /// anyway. `read_error` names why a *present* persisted file did not
    /// serve; `None` means there was simply nothing to read.
    Stranded {
        /// Why a *present* persisted file did not serve; `None` when there was
        /// simply nothing to read.
        read_error: Option<SeedReadFault>,
    },
    /// A one-shot acquisition installed these seeds (opt-in, default OFF —
    /// [`should_auto_fetch_nodes_dat`]).
    Acquired {
        /// Seeds that entered the routing table directly.
        contacts: usize,
        /// Bootstrap-edition dial candidates.
        candidates: usize,
    },
    /// The acquisition ran and failed. Kad starts stranded regardless: one-shot
    /// and wait, the same posture the server.met leg keeps.
    AcquireFailed(NodesDatPipelineError),
}

/// Why a present persisted routing table served no seeds, as a code a front
/// end words; what the OS or the decoder said is for the Run Log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedReadFault {
    /// The OS refused the read: its error kind, and its error number when it
    /// gave one.
    Io {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The file is a legacy version-0 nodes.dat, refused outright.
    TooOld,
    /// The file does not decode as a nodes.dat.
    Undecodable,
}

/// Resolve the Kad join's seeds into `kad_enable`, in aMule's recovery-route
/// order — the Join Sequence's **Kad-seed leg** (step 3), split out so a
/// front-end that drives `EnableKad` itself (the `rmule` TUI, whose durable
/// store is owned by the core actor by then) resolves seeds the same way.
///
/// 1. **The persisted routing table.** The Kad driver writes
///    [`nodes_dat_path`](KadEnableConfig::nodes_dat_path) as it runs;
///    this reads it back. Contacts carrying an earned Kad ID land in
///    [`KadEnableConfig::contacts`] (merged straight into the table, no dial);
///    a v3 bootstrap-edition file's closest-50 land in
///    [`bootstrap`](KadEnableConfig::bootstrap) as dial candidates. A missing
///    file is a normal first run, not an error.
/// 2. **A one-shot acquisition**, iff no route above produced a seed *and* the
///    caller opted in ([`should_auto_fetch_nodes_dat`], default OFF). One GET,
///    no retry.
///
/// Seeds already in `kad_enable` (operator-configured endpoints) count as
/// route 0: they suppress the acquisition, exactly as a persisted server list
/// suppresses the server.met fetch.
///
/// `own_id` is the node's Kad ID ([`Core::kad_id`](crate::Core::kad_id)): a
/// bootstrap-edition file's closest-50 are closest to it.
///
/// Never fails: every route's failure is reported in the returned
/// [`KadSeedOutcome`] and the Kad join proceeds regardless.
pub async fn acquire_kad_seeds<F>(
    kad_enable: &mut KadEnableConfig,
    own_id: rmule_kad::KadId,
    bootstrap: &BootstrapConfig,
    fetcher: &F,
) -> KadSeedOutcome
where
    F: Fetcher + Sync,
{
    let mut read_error = None;

    // 1. The persisted routing table.
    if let Some(path) = kad_enable.nodes_dat_path.clone() {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                // A fresh dial list per attempt: `load_v3_bootstrap_edition`
                // refuses to load onto one that already holds candidates.
                let mut dial_list = BootstrapDialList::new();
                match decode_nodes_dat(&bytes, own_id, &mut dial_list) {
                    Ok(install) => {
                        let (contacts, candidates) = install_seeds(kad_enable, install);
                        if contacts + candidates > 0 {
                            return KadSeedOutcome::Persisted {
                                contacts,
                                candidates,
                            };
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "the saved Kad contacts could not be decoded");
                        read_error = Some(match error {
                            NodesDatPipelineError::TooOld => SeedReadFault::TooOld,
                            _ => SeedReadFault::Undecodable,
                        });
                    }
                }
            }
            // No file is the ordinary first run; anything else is worth saying.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, "the saved Kad contacts could not be read");
                read_error = Some(SeedReadFault::Io {
                    kind: error.kind(),
                    os_code: error.raw_os_error(),
                });
            }
        }
    }

    // 2. The opt-in one-shot acquisition.
    let no_seeds = kad_enable.contacts.is_empty() && kad_enable.bootstrap.is_empty();
    if !should_auto_fetch_nodes_dat(true, no_seeds, bootstrap.auto_fetch_nodes_dat) {
        return KadSeedOutcome::Stranded { read_error };
    }
    let mut dial_list = BootstrapDialList::new();
    match fetch_nodes_dat(
        fetcher,
        &bootstrap.nodes_dat_url,
        bootstrap.max_nodes_dat_bytes,
        own_id,
        &mut dial_list,
    )
    .await
    {
        Ok(install) => {
            let (contacts, candidates) = install_seeds(kad_enable, install);
            KadSeedOutcome::Acquired {
                contacts,
                candidates,
            }
        }
        Err(error) => KadSeedOutcome::AcquireFailed(error),
    }
}

/// Fold one decoded [`NodesDatInstall`] plan into the Kad start config,
/// reporting `(contacts merged, dial candidates seeded)`.
///
/// The v3 candidates arrive as bare endpoints: their Kad IDs did their work in
/// the reader's closest-50 XOR selection, and the dial that follows learns the
/// ID from the bootstrap answer — the same shape an operator-configured seed
/// endpoint has.
fn install_seeds(kad_enable: &mut KadEnableConfig, install: NodesDatInstall) -> (usize, usize) {
    match install {
        NodesDatInstall::Contacts(contacts) => {
            let merged = contacts.len();
            kad_enable.contacts.extend(contacts);
            (merged, 0)
        }
        NodesDatInstall::BootstrapCandidates(candidates) => {
            let seeded = candidates.len();
            kad_enable
                .bootstrap
                .extend(candidates.into_iter().map(|node| {
                    let endpoint = node.endpoint();
                    SocketAddrV4::new(endpoint.ip(), endpoint.udp_port())
                }));
            (0, seeded)
        }
    }
}
