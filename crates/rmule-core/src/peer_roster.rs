//! The core-owned **Peer Roster** (ADR-0059): the set
//! of IPs this session already has an eD2k relationship with — aMule's
//! `CClientList::FindClientByIP`, consulted by two ADR-0058 UDP self-check
//! rules that are otherwise Kad-only and would gladly test a stranger it is
//! already dealing with:
//!
//! - the **requester gate**: `CClientList::DoRequestFirewallCheckUDP` refuses
//!   to test a helper candidate whose IP the client list already knows
//!   (`ClientList.cpp:1204-1211`) — cancelled, not failed, freeing the slot
//!   for the next candidate;
//! - the **helper bias**: `CUpDownClient::ProcessFirewallCheckUDPRequest`
//!   biases its `0x62` when the requester has an active upload, download or
//!   chat with us (`BaseClient.cpp:4002-4003`), the sibling of the
//!   routing-zone bias `rmule-kad` already applies on its own.
//!
//! Two writers feed it: the upload queue's enactment (a granted or queued
//! slot is aMule's `GetUploadState() != US_NONE`), the
//! download runner (a worker's peer session connected — the hello completed
//! — is aMule's `GetDownloadState() != DS_NONE`), and the
//! download's Remote-Queued Pool (a source that queued us and hung up —
//! `DS_ONQUEUE`, still `!= DS_NONE`). A chat session is not fed in — rmule
//! has no chat.
//!
//! Kept per **endpoint** (ip + port) *and* per [`PeerRelation`], not per plain
//! reference count: a peer is admitted and released by the same
//! [`Ipv4Endpoint`] every time, so marking it known is idempotent within one
//! relation (a reask that re-admits an already-queued peer, or a fact stream
//! that redelivers `Connected`, costs no second reason to forget). The
//! relation tag is what keeps the two writers from cancelling each other:
//! ADR-0031 bridges a dialed download connection to the same peer's serve
//! half over the identical socket, so an upload and a download to one peer
//! can legitimately share one [`Ipv4Endpoint`] — ending one relation's hold on
//! that endpoint must not forget the other's. Two distinct endpoints that
//! happen to share an IP (two connections through the same NAT, or one
//! relation each) each hold their own membership too — the IP stays known
//! until the last relation on the last endpoint goes.
//! A Download relation is held per download: two downloads
//! fetching from one peer each keep it known until their own worker ends.
//! Every relation is added and removed by its owner's paired start/terminal
//! events — ADR-0059 "Roster relations" tables them.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use rmule_primitives::Ipv4Endpoint;

use crate::DownloadId;

/// Which relationship a mark or forget belongs to, and whose it is
/// (ADR-0059 "Roster relations"). Never read back — it only keys a write to
/// its own holder, so every holder retires only what it marked: an upload and
/// a download on the same [`Ipv4Endpoint`], or two downloads fetching from one
/// peer, each keep that endpoint known until their own terminal event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PeerRelation {
    /// A queued waiter or a granted upload slot — aMule's single upload state
    /// (`US_ONUPLOADQUEUE` → `US_UPLOADING`), so a promotion needs no write.
    Upload,
    /// One download's connected worker session, held per
    /// download so one download ending never un-knows another's live worker
    /// on the same endpoint.
    Download(DownloadId),
    /// One download's **Remote-Queued Pool** membership: the
    /// peer queued us and hung up, and its standing rides the reask heartbeat
    /// — aMule's `DS_ONQUEUE`, a client still known after its socket closed.
    /// Held per download, like [`Self::Download`].
    Queued(DownloadId),
}

/// One IP's live relations, each on the port it was marked with.
type HeldRelations = HashSet<(PeerRelation, u16)>;

/// The core-owned Peer Roster, shared between every enactment that opens or
/// closes a relationship with a peer and the two ADR-0058 rules that read it
/// (`Core::builder`'s single instance, the same create-once-clone-into-every-
/// adapter pattern as [`crate::ban_store::SharedBanStore`]).
#[derive(Clone, Default)]
pub(crate) struct SharedPeerRoster(Arc<Mutex<HashMap<Ipv4Addr, HeldRelations>>>);

impl SharedPeerRoster {
    /// Whether `ip` is one this session already has a relationship with,
    /// upload or download.
    #[must_use]
    pub(crate) fn knows(&self, ip: Ipv4Addr) -> bool {
        self.0
            .lock()
            .is_ok_and(|known| known.get(&ip).is_some_and(|held| !held.is_empty()))
    }

    /// Mark this session as having `relation` with `endpoint`. Idempotent
    /// within `relation`: marking the same endpoint twice for the same
    /// relation — a reask that re-admits an already-queued peer, say — is one
    /// reason to forget, not two.
    pub(crate) fn mark_known(&self, relation: PeerRelation, endpoint: Ipv4Endpoint) {
        if let Ok(mut known) = self.0.lock() {
            known
                .entry(endpoint.ip)
                .or_default()
                .insert((relation, endpoint.port));
        }
    }

    /// Retire `endpoint`'s `relation` reason. A no-op when it was never
    /// marked — a stray release never un-knows an IP some *other* endpoint,
    /// or the *other* relation on this same endpoint, still holds.
    pub(crate) fn forget(&self, relation: PeerRelation, endpoint: Ipv4Endpoint) {
        if let Ok(mut known) = self.0.lock()
            && let Some(held) = known.get_mut(&endpoint.ip)
        {
            held.remove(&(relation, endpoint.port));
            if held.is_empty() {
                known.remove(&endpoint.ip);
            }
        }
    }

    /// Retire `relation` on every endpoint it still holds: its owner ended
    /// whole rather than peer by peer. Every other relation stays.
    pub(crate) fn forget_every(&self, relation: PeerRelation) {
        if let Ok(mut known) = self.0.lock() {
            known.retain(|_, held| {
                held.retain(|(held_relation, _)| *held_relation != relation);
                !held.is_empty()
            });
        }
    }
}

/// One owner's hold on a [`PeerRelation`], ended on drop (ADR-0093 invariant 1):
/// whatever way the owning task leaves — a stop,
/// a death, a `?`, a panic or a quit's abort — every endpoint it marked
/// under `relation` is forgotten. The paired per-peer forgets still run on
/// the live road; this is the terminal none of them can miss.
///
/// Sound only for a relation one live task owns outright: `Upload` belongs
/// to the one serve activity, `Download(id)` to that download's runner.
pub(crate) struct RelationLease {
    roster: SharedPeerRoster,
    relation: PeerRelation,
}

impl RelationLease {
    /// Hold `relation` on `roster` until the lease drops.
    pub(crate) fn new(roster: SharedPeerRoster, relation: PeerRelation) -> Self {
        Self { roster, relation }
    }
}

impl Drop for RelationLease {
    fn drop(&mut self) {
        self.roster.forget_every(self.relation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(o: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, o)
    }

    fn ep(o: u8, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint::new(ip(o), port)
    }

    fn download(n: u64) -> DownloadId {
        DownloadId::from_u64(n)
    }

    #[test]
    fn an_unmarked_ip_is_unknown_and_a_marked_one_is_known_until_forgotten() {
        let roster = SharedPeerRoster::default();
        assert!(!roster.knows(ip(1)));

        roster.mark_known(PeerRelation::Upload, ep(1, 4662));
        assert!(roster.knows(ip(1)));
        assert!(!roster.knows(ip(2)), "marking one IP does not mark another");

        roster.forget(PeerRelation::Upload, ep(1, 4662));
        assert!(!roster.knows(ip(1)));
    }

    #[test]
    fn marking_the_same_endpoint_twice_needs_only_one_forget() {
        // A reask re-admitting an already-queued peer must not cost a second
        // reason to forget it.
        let roster = SharedPeerRoster::default();
        roster.mark_known(PeerRelation::Upload, ep(1, 4662));
        roster.mark_known(PeerRelation::Upload, ep(1, 4662));
        roster.forget(PeerRelation::Upload, ep(1, 4662));
        assert!(!roster.knows(ip(1)));
    }

    #[test]
    fn two_distinct_endpoints_sharing_an_ip_each_need_their_own_forget() {
        let roster = SharedPeerRoster::default();
        roster.mark_known(PeerRelation::Upload, ep(1, 4662));
        roster.mark_known(PeerRelation::Upload, ep(1, 4663));
        roster.forget(PeerRelation::Upload, ep(1, 4662));
        assert!(
            roster.knows(ip(1)),
            "the second endpoint still holds the IP known"
        );
        roster.forget(PeerRelation::Upload, ep(1, 4663));
        assert!(!roster.knows(ip(1)));
    }

    #[test]
    fn forgetting_an_unknown_endpoint_never_panics() {
        let roster = SharedPeerRoster::default();
        roster.forget(PeerRelation::Upload, ep(1, 4662));
        assert!(!roster.knows(ip(1)));
    }

    #[test]
    fn upload_and_download_sharing_one_endpoint_do_not_cancel_each_other() {
        // ADR-0031: a dialed download connection bridges the same peer's
        // serve half over the identical socket, so an upload and a download
        // to one peer can legitimately share one `Ipv4Endpoint`. Forgetting
        // one relation must not un-know the IP while the other still holds
        // it.
        let roster = SharedPeerRoster::default();
        roster.mark_known(PeerRelation::Upload, ep(1, 4662));
        roster.mark_known(PeerRelation::Download(download(1)), ep(1, 4662));

        roster.forget(PeerRelation::Upload, ep(1, 4662));
        assert!(
            roster.knows(ip(1)),
            "the download relation still holds this same endpoint"
        );

        roster.forget(PeerRelation::Download(download(1)), ep(1, 4662));
        assert!(!roster.knows(ip(1)), "the last relation just let go");
    }

    #[test]
    fn two_downloads_fetching_from_one_endpoint_each_hold_it_until_their_own_end() {
        // Two downloads dialing the same peer each hold its endpoint: the
        // first to end its worker must not un-know the IP the second's live
        // worker still holds.
        let roster = SharedPeerRoster::default();
        roster.mark_known(PeerRelation::Download(download(1)), ep(1, 4662));
        roster.mark_known(PeerRelation::Download(download(2)), ep(1, 4662));

        roster.forget(PeerRelation::Download(download(1)), ep(1, 4662));
        assert!(roster.knows(ip(1)), "the second download still holds it");

        roster.forget(PeerRelation::Download(download(2)), ep(1, 4662));
        assert!(!roster.knows(ip(1)), "no relation left, the peer leaves");
    }

    #[test]
    fn a_dropped_lease_ends_only_its_own_relation_everywhere() {
        let roster = SharedPeerRoster::default();
        roster.mark_known(PeerRelation::Upload, ep(1, 4662));
        roster.mark_known(PeerRelation::Upload, ep(2, 4662));
        roster.mark_known(PeerRelation::Download(download(1)), ep(2, 4662));
        roster.mark_known(PeerRelation::Queued(download(1)), ep(3, 4662));

        drop(RelationLease::new(roster.clone(), PeerRelation::Upload));

        assert!(!roster.knows(ip(1)), "its only relation was the lease's");
        assert!(roster.knows(ip(2)), "the download still holds this one");
        assert!(roster.knows(ip(3)), "another relation is untouched");
    }
}
