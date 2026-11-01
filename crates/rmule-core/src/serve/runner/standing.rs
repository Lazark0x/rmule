//! What the serve loop reads for the brain before an input: what the node holds
//! of an address, the standings a ban reached, and every identified peer's
//! score modifier. All memory reads (ADR-0031).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use rmule_peer::PeerIdentity;
use rmule_primitives::PeerEndpoint;

use crate::credit::SharedCreditStore;
use crate::held_places::{RECIPROCITY_FACTOR, SharedHeldPlaces};
use crate::serve::state::{ServeAsker, ServeState};
use crate::upload_queue::ScoreModifiers;

/// What the node holds of `ip`, for the input that came from it.
pub(super) async fn asker_at(
    ip: IpAddr,
    bans: &crate::ban_store::SharedBanStore,
    roster: &crate::peer_roster::SharedPeerRoster,
) -> ServeAsker {
    let banned = bans.lock().await.is_banned(ip, Instant::now());
    let our_source = match ip.to_canonical() {
        IpAddr::V4(ip) => roster.is_source(ip),
        IpAddr::V6(_) => false,
    };
    ServeAsker { banned, our_source }
}

/// The standings whose address a ban reached since the last sweep, a source of
/// ours left out: a ban leaves the queue with them, heard from or not
/// (`UploadQueue.cpp:98`).
pub(super) async fn banned_standings(
    state: &ServeState,
    bans: &crate::ban_store::SharedBanStore,
    roster: &crate::peer_roster::SharedPeerRoster,
) -> Vec<PeerEndpoint> {
    let mut banned = Vec::new();
    for peer in state.standing_peers() {
        let asker = asker_at(peer.ip(), bans, roster).await;
        if asker.banned && !asker.our_source {
            banned.push(peer);
        }
    }
    banned
}

/// The live score modifiers: a peer's credit as its ledger row pays it at its
/// address (ADR-0041), times the **Reciprocity Factor** when its link's address
/// and its User Hash name one of the node's **Held Places** (ADR-0116). A client
/// that named nobody scores nothing (`UploadClient.cpp:83`). Each reading is a
/// few memory reads under node-wide locks (ADR-0031), taken for a peer when a
/// queue ranks it; building one costs a reference count.
pub(super) struct LiveModifiers<'a> {
    credit: &'a SharedCreditStore,
    held_places: &'a SharedHeldPlaces,
    identities: Arc<HashMap<PeerEndpoint, PeerIdentity>>,
}

impl ScoreModifiers for LiveModifiers<'_> {
    fn modifier(&self, peer: PeerEndpoint) -> f64 {
        let Some(identity) = self.identities.get(&peer) else {
            return 1.0;
        };
        let credit = self
            .credit
            .score_modifier(identity.user_hash(), peer.ip())
            .unwrap_or(1.0);
        let named = if identity
            .nickname()
            .is_some_and(|name| !name.as_bytes().is_empty())
        {
            1.0
        } else {
            0.0
        };
        let place = if self.held_places.holds(identity.user_hash(), peer.ip()) {
            RECIPROCITY_FACTOR
        } else {
            1.0
        };
        credit * place * named
    }
}

/// The modifiers as `identities` name their peers.
pub(super) fn current_modifiers<'a>(
    credit: &'a SharedCreditStore,
    held_places: &'a SharedHeldPlaces,
    identities: Arc<HashMap<PeerEndpoint, PeerIdentity>>,
) -> LiveModifiers<'a> {
    LiveModifiers {
        credit,
        held_places,
        identities,
    }
}
