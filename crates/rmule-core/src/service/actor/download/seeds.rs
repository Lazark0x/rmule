//! The **Source Seeds** writer (ADR-0109): every running download's latest
//! ranking, cut to the operator's `Remember peers`, into the store — every
//! ten minutes and at **Quit**.

use std::time::SystemTime;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};

use super::super::CoreActor;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Write each running download's seeds, in one transaction. A run with
    /// no ranking yet writes nothing, so the set its last run left stands
    /// until it ages out.
    pub(in crate::service::actor) fn write_source_seeds(&self) {
        let keep = usize::from(self.remember_peers.get().get());
        let sets: Vec<_> = self
            .activities
            .downloads()
            .map(|(download_id, active)| {
                let ranking = active.seeds.borrow();
                (download_id, ranking[..ranking.len().min(keep)].to_vec())
            })
            .collect();
        let written = self
            .wiring
            .store
            .write_source_seed_sets(&sets, SystemTime::now());
        if let Err(error) = written {
            tracing::warn!(%error, "the downloads' seeds could not be written");
        }
    }
}
