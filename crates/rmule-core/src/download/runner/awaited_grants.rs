//! The run's **Awaited Grants** (ADR-0107): every source its Source Book holds
//! in the RemoteQueued stage, filed in the Peer Links under the names its
//! record knows — the endpoint it waits at and the User Hash its record
//! knows, the hello its standing kept among them — so a link that reads that
//! uploader's unasked grant hands it to this run (ADR-0057, "A grant by
//! dial-back is taken") wherever the peer came back from, and a grant on the
//! peer's **Queue Standing** calls this run's record to the holder's link.

use std::collections::HashMap;

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use crate::adapters::{AwaitedGrant, GrantSender, LinkName, LinkOffer, SharedPeerLinks};
use crate::download::state::DownloadState;

/// How many offers may wait for the run's loop; a link that finds the queue
/// full offers the grant to the next download awaiting one, or gives it back.
const GRANT_QUEUE: usize = 4;

/// The run's filed waits, held to its RemoteQueued stage, and the offers
/// links handed over.
pub(super) struct AwaitedGrants {
    links: SharedPeerLinks,
    grants: GrantSender,
    granted: mpsc::Receiver<LinkOffer>,
    filed: HashMap<PeerEndpoint, AwaitedGrant>,
}

impl AwaitedGrants {
    /// No wait filed yet in `links`.
    pub(super) fn new(links: SharedPeerLinks) -> Self {
        let (grants, granted) = mpsc::channel(GRANT_QUEUE);
        Self {
            links,
            grants,
            granted,
            filed: HashMap::new(),
        }
    }

    /// The next offer a link handed over, naming the endpoint its source
    /// waits at.
    pub(super) async fn next(&mut self) -> Option<LinkOffer> {
        self.granted.recv().await
    }

    /// File a wait for every source `state` holds in the RemoteQueued stage,
    /// marked as the standing holder's or a waiter's, and give up the rest:
    /// however a record left the stage — its grant, a call, a TCP full ask, a
    /// `0x92`, a merge, a purge — its wait goes with it.
    pub(super) fn hold(&mut self, state: &DownloadState) {
        let waiting: Vec<PeerEndpoint> = state.remote_queued().collect();
        self.filed.retain(|at, _| waiting.contains(at));
        for at in waiting {
            let holds = state.holds_standing(at);
            if let Some(filed) = self.filed.get_mut(&at) {
                filed.set_holds(holds);
                continue;
            }
            let mut names = vec![LinkName::Endpoint(at)];
            names.extend(state.peer_crypt(at).user_hash().map(LinkName::User));
            let filed = self
                .links
                .await_grant(at, names, holds, self.grants.clone());
            self.filed.insert(at, filed);
        }
    }
}

#[cfg(test)]
mod tests;
