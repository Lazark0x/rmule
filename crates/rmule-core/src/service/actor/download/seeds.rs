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
    /// Write each running download's seeds. A run with no ranking yet writes
    /// nothing, so the set its last run left stands until it ages out.
    pub(in crate::service::actor) fn write_source_seeds(&self) {
        let now = SystemTime::now();
        let keep = usize::from(self.remember_peers.get().get());
        for (download_id, active) in self.activities.downloads() {
            let ranking = active.seeds.borrow();
            let seeds = &ranking[..ranking.len().min(keep)];
            if let Err(error) = self
                .wiring
                .store
                .write_source_seeds(download_id, seeds, now)
            {
                tracing::warn!(
                    download_id = download_id.as_u64(),
                    %error,
                    "a download's seeds could not be written"
                );
            }
        }
    }
}
