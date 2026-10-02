//! **Distrusted peers** of a download (ADR-0090 "Source ownership", invariant 4):
//! a peer proven to have served this file bad data is not
//! pooled again, nor kept once its hello names it.
//!
//! *Proven* is the rule's whole weight. A part that failed its hash blames a
//! peer only when the bytes are attributed to it: the AICH recovery pins the
//! corrupt blocks to their senders, and a part with a single contributor has
//! nobody else to blame. A retire-all across several contributors blames none
//! of them, and a hash-set dissent (`VerificationAuthorityMismatch`) served no
//! bytes at all — under a peer-supplied authority the dissenter may be the
//! honest one.
//!
//! The set is keyed by User Hash, not address, so the distrust follows the
//! peer to a new one — a `SpentEndpoints` entry, by contrast, is a fact about
//! an address. It lives for the download's life and is durable beside the
//! download's own record (the runner persists each
//! [`Decision::DistrustPeer`] and hands a resumed run the set back), because
//! the evidence is about this file's bytes: another download, or the upload
//! queue, is not this set's business — the core-wide, IP-keyed `BanStore`
//! (ADR-0064) punishes a peer across surfaces, and it expires.

use rmule_primitives::{PeerEndpoint, UserHash};

use crate::service::{DownloadEvent, PeerRetirementReason};

use super::{Decision, DownloadState};

impl DownloadState {
    /// Whether a source whose record names `user_hash` is distrusted. A record
    /// that names none is judged when its hello does ([`Self::on_hello_hash`]).
    pub(super) fn distrusts(&self, user_hash: Option<UserHash>) -> bool {
        user_hash.is_some_and(|hash| self.distrusted.contains(&hash))
    }

    /// `peer` is proven to have served this file bad data: distrust the User
    /// Hash its hello named, and have the runner persist it. A peer whose hello
    /// named none leaves nothing to key the distrust by.
    pub(super) fn distrust(&mut self, peer: PeerEndpoint, out: &mut Vec<Decision>) {
        let Some(&user_hash) = self.peer_user_hashes.get(&peer) else {
            return;
        };
        if self.distrusted.insert(user_hash) {
            tracing::info!(%peer, "a peer that served bad data is distrusted for this download");
            out.push(Decision::DistrustPeer { user_hash });
        }
    }

    /// `peer`'s hello named `user_hash`. A distrusted peer reached through a
    /// record that named no hash — a server answer, an address it moved to —
    /// is retired here, before any part is assigned to it.
    pub(super) fn on_hello_hash(
        &mut self,
        peer: PeerEndpoint,
        user_hash: UserHash,
        out: &mut Vec<Decision>,
    ) {
        self.peer_user_hashes.insert(peer, user_hash);
        if !self.distrusted.contains(&user_hash) {
            return;
        }
        out.push(Decision::Emit(DownloadEvent::PeerRetired {
            download_id: self.download_id,
            peer,
            reason: PeerRetirementReason::Distrusted,
        }));
        self.release(peer, PeerRetirementReason::Distrusted, out);
    }
}
