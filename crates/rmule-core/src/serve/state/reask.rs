//! The uploader side of the peer-UDP reask (ADR-0057): a `0x90` ping matched
//! against the queue answers the pinger's live rank, carrying our part status
//! when its client is UDPv4 era — and refuses, drops, or reports not-found in
//! every other case.

use std::time::Instant;

use rmule_peer::{
    PartBitmap, PingStatus, ReaskAck, ReaskFilePing, file_not_found_datagram, queue_full_datagram,
};
use rmule_primitives::{ED2K_PART_SIZE, PeerEndpoint};

use super::{ServeDecision, ServeState};
use crate::service::ServeEvent;
use crate::upload_queue::ReaskResolution;

impl ServeState {
    /// The reask reply matrix (ADR-0057 uploader side): turn one inbound
    /// `OP_REASKFILEPING` from `udp_src` into its aMule-exact answer —
    /// `OP_REASKACK` with the current rank (+ our part status for a UDPv4
    /// waiter), `OP_FILENOTFOUND` when we do not share the hash, `OP_QUEUEFULL`
    /// for an unknown pinger while `waiting + 50 > queue-size`, or a deliberate
    /// **silent drop** (hash mismatch, unknown-with-room, same-IP-multiple-ports)
    /// that forces the peer to a TCP full ask which repairs the state mismatch.
    pub(crate) fn on_reask_ping(
        &mut self,
        now: Instant,
        udp_src: PeerEndpoint,
        datagram: &[u8],
    ) -> Vec<ServeDecision> {
        let Some(file_hash) = ReaskFilePing::file_hash_of(datagram) else {
            return Vec::new(); // malformed / not a ping → drop
        };
        // The queue attributes a reask by the whole address (ADR-0087), and the
        // front now hands this call the family the datagram truly arrived in,
        // so an IPv6 waiter is matched on all 128 bits and answered on the
        // socket its ping came in on. The `0x90`/`0x91` bodies are
        // byte-identical either way — neither packs an address.
        let resolution = self.queue.resolve_reask(udp_src);
        // aMule resolves the *sender* before the file (`ClientUDPSocket.cpp`),
        // which is what lets even the "file not found" answer be obfuscated for
        // a client we know — so the crypt target is read here, ahead of the
        // shared-file check, not per reply branch.
        let crypt_target = match resolution {
            ReaskResolution::Known { peer, .. } => self.crypt_targets.get(&peer).copied(),
            ReaskResolution::AmbiguousIp | ReaskResolution::Unknown => None,
        };
        // Not shared at all → OP_FILENOTFOUND, regardless of pinger.
        let Some(entry) = self.shared.get(&file_hash) else {
            return vec![ServeDecision::SendClientUdp {
                to: udp_src,
                datagram: file_not_found_datagram(),
                crypt_target,
            }];
        };
        let file_size = entry.file_size;
        match resolution {
            ReaskResolution::Known {
                peer,
                file_hash: waiting_for,
                rank,
                udp_version,
            } => {
                if waiting_for != file_hash {
                    // The waiter is queued for another file → silent drop.
                    return Vec::new();
                }
                // A matched reask refreshes the standing clock, then answers
                // the current rank (+ our part status for a UDPv4 waiter, since
                // a complete shared file has every part).
                self.queue.refresh_reask(peer, now);
                // A UDPv4 waiter's ping restates its own part status, read as
                // its name ask's is — aMule hands the ping to that reader
                // (stock 2.3.3 `4e8f2b3c` `ClientUDPSocket.cpp:202-203` →
                // `ProcessExtendedInfo`), so a long-queued peer's needed parts
                // stay current between TCP asks (ADR-0055 §Serving). An
                // older waiter's ping carries none and leaves the status alone.
                //
                // A ping cut short for the waiter's claim — the hash alone, a
                // status short of the file's part count, no complete-source
                // count from a claim above `1` — makes that reader throw after
                // it cleared or partly set the status, and the dispatcher's
                // catch only logs (`ClientUDPSocket.cpp:131-134`): no
                // `OP_REASKACK` goes out. Silence, counted (ADR-0055 §Serving).
                if udp_version > 3 {
                    let claim = self.extended_requests.get(&peer).copied().unwrap_or(0);
                    match ReaskFilePing::read_status(datagram, file_size, claim) {
                        PingStatus::Read(status) => {
                            self.record_part_status(peer, file_hash, file_size, status);
                        }
                        PingStatus::Malformed(status) => {
                            self.record_part_status(peer, file_hash, file_size, status);
                            return vec![ServeDecision::Emit(ServeEvent::ReaskPingMalformed {
                                peer,
                            })];
                        }
                    }
                }
                // A UDPv3 waiter's ping is read for its complete-source count
                // alone (`ClientUDPSocket.cpp:204-205`); the hash alone throws
                // there and is silenced the same way.
                if udp_version == 3 && !ReaskFilePing::carries_complete_count(datagram) {
                    return vec![ServeDecision::Emit(ServeEvent::ReaskPingMalformed { peer })];
                }
                // A UDPv4 waiter's ack carries our status in aMule's writer
                // shape: a file that is not a part file writes the count `0`
                // alone (stock 2.3.3 `4e8f2b3c` `ClientUDPSocket.cpp:214-219`),
                // as the TCP status answer does — every file rmule shares is
                // complete.
                let part_status = (udp_version > 3).then(PartBitmap::complete_source_sentinel);
                vec![ServeDecision::SendClientUdp {
                    to: udp_src,
                    datagram: ReaskAck { part_status, rank }.encode_udp(),
                    crypt_target,
                }]
            }
            // Multiple waiters share the pinger's IP on different UDP ports →
            // silent (the port-mapping ambiguity forces a TCP full ask).
            ReaskResolution::AmbiguousIp => Vec::new(),
            ReaskResolution::Unknown => {
                if self.queue.waiting_len() + 50 > self.queue.max_queue_len() {
                    vec![ServeDecision::SendClientUdp {
                        to: udp_src,
                        datagram: queue_full_datagram(),
                        // Always plaintext: this branch *is* the unknown pinger
                        // (aMule: "we cannot answer this one encrypted since we
                        // dont know this client").
                        crypt_target: None,
                    }]
                } else {
                    // Unknown pinger, room to spare → silent.
                    Vec::new()
                }
            }
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
