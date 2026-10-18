//! The run's **Awaited Grants** (ADR-0107): every source its Source Book holds
//! in the RemoteQueued stage, filed in the Peer Links under the names its
//! record knows — the endpoint it waits at and the User Hash its hello named —
//! so a link that reads that uploader's unasked grant hands it to this run
//! (ADR-0057, "A grant by dial-back is taken").

use std::collections::HashMap;

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use crate::adapters::{AwaitedGrant, GrantSender, LinkName, SharedPeerLinks};
use crate::download::state::DownloadState;

/// How many grants may wait for the run's loop; a link that finds the queue
/// full offers the grant to the next download awaiting one, or gives it back.
const GRANT_QUEUE: usize = 4;

/// The run's filed waits, held to its RemoteQueued stage, and the grants
/// links handed over.
pub(super) struct AwaitedGrants {
    links: SharedPeerLinks,
    grants: GrantSender,
    granted: mpsc::Receiver<PeerEndpoint>,
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

    /// The next grant a link handed over: the endpoint its source waits at.
    pub(super) async fn next(&mut self) -> Option<PeerEndpoint> {
        self.granted.recv().await
    }

    /// File a wait for every source `state` holds in the RemoteQueued stage
    /// and give up the rest: however a record left the stage — its grant, a
    /// TCP full ask, a `0x92`, a merge, a purge — its wait goes with it.
    pub(super) fn hold(&mut self, state: &DownloadState) {
        let waiting: Vec<PeerEndpoint> = state.remote_queued().collect();
        self.filed.retain(|at, _| waiting.contains(at));
        for at in waiting {
            if self.filed.contains_key(&at) {
                continue;
            }
            let mut names = vec![LinkName::Endpoint(at)];
            names.extend(state.peer_crypt(at).user_hash().map(LinkName::User));
            let filed = self.links.await_grant(at, names, self.grants.clone());
            self.filed.insert(at, filed);
        }
    }
}
