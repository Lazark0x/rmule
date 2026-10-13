//! The uploader side of the peer-UDP reask (ADR-0057): a `0x90` ping is read
//! and answered by the **Reask Responder**; serve state resolves the pinger
//! against its queue, refreshes the standing the answer says was heard, records
//! the part status the ping restated, and counts a silenced malformed ping.

use std::time::Instant;

use rmule_peer::peer_udp::responder::{
    self, KnownWaiter, Pinger, QueueRoom, ReaskReply, SharedFile, Silence, Standing,
};
use rmule_peer::{PartBitmap, PeerIdentity};
use rmule_primitives::{PeerEndpoint, ed2k_status_part_count};

use super::{ServeDecision, ServeState};
use crate::service::ServeEvent;
use crate::upload_queue::ReaskResolution;

impl ServeState {
    /// Answer one inbound `OP_REASKFILEPING` from `udp_src` (ADR-0057
    /// uploader side). The responder holds every reply rule; this resolves the
    /// pinger for it and enacts what its answer says of the queue.
    pub(crate) fn on_reask_ping(
        &mut self,
        now: Instant,
        udp_src: PeerEndpoint,
        datagram: &[u8],
    ) -> Vec<ServeDecision> {
        let Some(ping) = responder::read(datagram) else {
            return Vec::new();
        };
        // The queue attributes a reask by the whole address (ADR-0087), and the
        // front hands this call the family the datagram truly arrived in, so an
        // IPv6 waiter is matched on all 128 bits and answered on the socket its
        // ping came in on.
        let (peer, pinger) = match self.queue.resolve_reask(udp_src) {
            ReaskResolution::Known {
                peer,
                file_hash,
                rank,
                udp_version,
            } => {
                let identity = self.identities.get(&peer);
                (
                    Some(peer),
                    Pinger::Known(KnownWaiter {
                        waiting_for: file_hash,
                        rank,
                        udp_version,
                        extended_requests: identity
                            .map_or(0, PeerIdentity::extended_requests_version),
                        crypt_target: identity.map(PeerIdentity::udp_crypt_target),
                    }),
                )
            }
            ReaskResolution::AmbiguousIp => (None, Pinger::Ambiguous),
            ReaskResolution::Unknown => (None, Pinger::Unknown),
        };
        // Only a file in the share set is answered (aMule's `sharedfiles`,
        // `ClientUDPSocket.cpp:177`): a row with its count `0`, a Partial
        // Share with its Verified Range.
        let file_hash = ping.file_hash();
        let shared = self
            .asked(file_hash)
            .filter(|asked| asked.offered())
            .map(|asked| SharedFile {
                size: asked.file_size(),
                status: asked.status(),
            });
        let room = QueueRoom {
            waiting: self.queue.waiting_len(),
            max: self.queue.max_queue_len(),
        };
        let answer = responder::answer(&ping, &pinger, room, shared.as_ref());

        if let (Some(peer), Some(file_size)) = (peer, shared.map(|shared| shared.size)) {
            match answer.standing {
                Standing::Untouched => {}
                Standing::Heard => self.queue.refresh_reask(peer, now),
                Standing::Restated(status) => {
                    self.queue.refresh_reask(peer, now);
                    self.record_part_status(peer, file_hash, file_size, status);
                }
            }
        }
        match answer.reply {
            ReaskReply::Send {
                datagram,
                encrypt_for,
            } => vec![ServeDecision::SendClientUdp {
                to: udp_src,
                datagram,
                crypt_target: encrypt_for,
            }],
            ReaskReply::Silent(Silence::Malformed) => peer
                .map(|peer| ServeDecision::Emit(ServeEvent::ReaskPingMalformed { peer }))
                .into_iter()
                .collect(),
            ReaskReply::Silent(
                Silence::OtherFile | Silence::AmbiguousIp | Silence::UnknownWithRoom,
            ) => Vec::new(),
        }
    }
}

/// A bitmap with every part present, for a complete shared file, at the count
/// a status states for it, phantom part included.
pub(super) fn full_bitmap(file_size: u64) -> PartBitmap {
    PartBitmap::all_present(ed2k_status_part_count(file_size))
}
