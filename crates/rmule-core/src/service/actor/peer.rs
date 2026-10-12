//! The peer-reach command arms (ADR-0061): an operator's
//! `CoreCommand::ReachPeer` and a download's [`DownloadReach`] each end in one
//! call into **Peer Reach** ([`crate::peer_reach`]), which reads our position,
//! chooses the road, carries it out and reports it.

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::callback::DownloadReach;
use crate::service::PeerReach;

use super::CoreActor;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Reach one peer by the best route this session can offer.
    pub(super) async fn on_reach_peer(&mut self, peer: PeerReach) {
        self.peer_reach.reach(&peer, None).await;
    }

    /// A download's Low-ID candidate down the road its brain opened, held
    /// under its pending callback.
    pub(super) async fn on_download_reach(&mut self, reach: DownloadReach) {
        self.peer_reach
            .reach(&reach.peer, Some(reach.pending))
            .await;
    }
}
