//! The uploader side of the peer-UDP reask (ADR-0057): a `0x90` ping is read
//! and answered by the **Reask Responder**; serve state resolves the pinger
//! against its queue, refreshes the standing the answer says was heard, records
//! the part status the ping restated, and counts a silenced malformed ping.

use std::time::Instant;

use rmule_peer::peer_udp::responder::{
    self, KnownWaiter, Pinger, QueueRoom, ReaskReply, Silence, Standing,
};
use rmule_peer::{PartBitmap, PeerIdentity};
use rmule_primitives::{ED2K_PART_SIZE, PeerEndpoint};

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
        let file_hash = ping.file_hash();
        let file_size = self.shared.get(&file_hash).map(|entry| entry.file_size);
        let room = QueueRoom {
            waiting: self.queue.waiting_len(),
            max: self.queue.max_queue_len(),
        };
        let answer = responder::answer(&ping, &pinger, room, file_size);

        if let (Some(peer), Some(file_size)) = (peer, file_size) {
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

/// The ED2K part count a peer expects in an `OP_FILESTATUS` for a `file_size`-byte
/// file: `file_size / ED2K_PART_SIZE + 1` (aMule `CKnownFile::SetFileSize`,
/// `m_iED2KPartCount`, KnownFile.cpp). A file whose size is an exact multiple of
/// `ED2K_PART_SIZE` carries a trailing zero-length part, so this is one more than
/// the count of non-empty parts that a plain `ceil` (`rmule_primitives::part_count`)
/// yields. aMule's `CUpDownClient::ProcessFileStatus` (DownloadClient.cpp) throws
/// "wrong part number" and drops the source when the received count differs, so the
/// serve status must use this value. It matches the count
/// `PartHashSet::expected_hash_count` uses for a multi-part hash set, keeping
/// `OP_FILESTATUS` and `OP_HASHSETANSWER` mutually consistent.
pub(super) fn ed2k_status_part_count(file_size: u64) -> u32 {
    if file_size == 0 {
        return 0;
    }
    u32::try_from(file_size / ED2K_PART_SIZE + 1).unwrap_or(u32::MAX)
}

/// A bitmap with every part present, for a complete shared file. `PartBitmap`
/// has no all-present constructor; decode tolerates the all-ones byte and
/// zeroes the unused trailing bits, giving a canonical full bitmap.
pub(super) fn full_bitmap(file_size: u64) -> PartBitmap {
    let parts = ed2k_status_part_count(file_size);
    let bytes = vec![0xFF_u8; (parts as usize).div_ceil(8)];
    PartBitmap::decode(parts, &bytes).expect("all-ones bitmap of the exact length always decodes")
}
