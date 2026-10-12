//! The run's queue standing (ADR-0057): a source's **Source Book** record
//! carries the standing its worker earned, waits in the RemoteQueued stage
//! with no worker, and the brain keeps it alive. The sweep runs inside
//! [`DownloadState::on_tick`]; pings are framed and replies read through
//! `rmule-peer`'s **Reask Requester**, because the source's UDP version is on
//! the record. The runner only sends and hands replies back.

use std::time::Instant;

use rmule_peer::PartBitmap;
use rmule_peer::peer_udp::requester::{self, HeardReply, IgnoredReply};
use rmule_primitives::PeerEndpoint;

use super::{Decision, DownloadState};
use crate::adapters::advertises_complete;
use crate::client_udp::ClientUdpSend;
use crate::download::source_book::{Answer, Reask, ReaskGates};
use crate::service::{DownloadEvent, IgnoredReaskReply};

impl DownloadState {
    /// The reask sweep at `now` (ADR-0057): each due `0x90` leaves as a
    /// [`Decision::SendReaskPing`], and each TCP full ask hands its record to
    /// its road, which the fill that follows opens.
    pub(super) fn reask_sweep(&mut self, now: Instant, out: &mut Vec<Decision>) {
        let gates = ReaskGates {
            socket: self.our_udp_enabled,
            reachable: self.callback_capability.reachable(),
        };
        let mut asked_by_tcp = false;
        for reask in self.sources.sweep(now, gates) {
            match reask {
                Reask::Ping {
                    peer,
                    contact,
                    crypt,
                } => {
                    let ping = requester::ping(
                        self.file_hash,
                        self.our_udp_version,
                        contact.version,
                        || self.our_part_status(),
                    );
                    out.push(Decision::SendReaskPing {
                        peer,
                        ping: ClientUdpSend::to_peer(contact.endpoint, ping, crypt),
                    });
                }
                Reask::FullAsk { peer } => {
                    asked_by_tcp = true;
                    out.push(Decision::Emit(DownloadEvent::SourceReaskedOverTcp {
                        download_id: self.download_id,
                        peer,
                    }));
                }
            }
        }
        if asked_by_tcp {
            self.fill(now, out);
        }
    }

    /// The ping to `peer` could not leave at `now`: another download's ping
    /// holds its endpoint (ADR-0107). Its window is looked at again shortly,
    /// and the TCP full ask keeps its time.
    pub(crate) fn on_ping_held(&mut self, now: Instant, peer: PeerEndpoint) {
        self.sources.ping_held(peer, now);
    }

    /// One reask reply datagram from the client-UDP endpoint `from` at `now`
    /// (`0x91`/`0x92`/`0x93`): read by the Reask Requester against the source
    /// standing at that endpoint, and enacted on its record. A reply that
    /// changes nothing is reported with its reason.
    pub(crate) fn on_reask_reply(
        &mut self,
        now: Instant,
        from: PeerEndpoint,
        datagram: &[u8],
    ) -> Vec<Decision> {
        let source = self.sources.reask_source(from);
        let heard = requester::read_reply(
            datagram,
            self.our_udp_version,
            source.map(|(_, version)| version),
        );
        let event = match (source, heard) {
            (_, HeardReply::Ignored(why)) => self.ignored(from, ignored_reason(why)),
            (None, _) => self.ignored(from, IgnoredReaskReply::NoPooledSource),
            (Some((peer, _)), HeardReply::Rank { rank, part_status }) => {
                // A UDPv4 ack's part status is read as a probe's (aMule
                // `ProcessFileStatus(true, …)`, stock 2.3.3
                // `ClientUDPSocket.cpp:258-263`): one counting other than
                // the file's parts throws there before the rank is read.
                let parts_needed = match part_status.as_ref().map(|s| self.lacks_any_of(s)) {
                    Some(None) => {
                        return vec![Decision::Emit(
                            self.ignored(from, IgnoredReaskReply::PartCountMismatch),
                        )];
                    }
                    Some(Some(needed)) => Some(needed),
                    None => None,
                };
                self.sources
                    .reask_answered(peer, Answer::Rank { rank, parts_needed }, now);
                // It is an advertisement like a probe's (ADR-0108).
                if let Some(status) = part_status {
                    self.sources
                        .advertised(peer, advertises_complete(&status), now);
                }
                DownloadEvent::SourceReaskAcked {
                    download_id: self.download_id,
                    peer,
                    rank,
                }
            }
            (Some((peer, _)), HeardReply::QueueFull) => {
                self.sources.reask_answered(peer, Answer::QueueFull, now);
                DownloadEvent::SourceReaskQueueFull {
                    download_id: self.download_id,
                    peer,
                }
            }
            (Some((peer, _)), HeardReply::FileNotFound) => {
                // It no longer has the file: aMule drops the source and with
                // it `m_bCompleteSource` (ADR-0108).
                self.sources.advertised(peer, false, now);
                self.sources.reask_dropped(peer);
                DownloadEvent::SourceReaskDropped {
                    download_id: self.download_id,
                    peer,
                }
            }
        };
        vec![Decision::Emit(event)]
    }

    /// Whether a source whose part status is `status` holds a part we lack —
    /// aMule's `bPartsNeeded` (stock 2.3.3 `DownloadClient.cpp:397-449`): a
    /// complete source's sentinel always does; a status is read against the
    /// file's `size / PARTSIZE + 1` parts, the phantom last part of an exact
    /// multiple never counting; `None` when it counts other parts, which
    /// aMule refuses whole.
    fn lacks_any_of(&self, status: &PartBitmap) -> Option<bool> {
        if status.part_count() == 0 {
            return Some(true);
        }
        if status.part_count() != self.our_part_status().part_count() {
            return None;
        }
        let real = rmule_primitives::part_count(self.file_size);
        Some(
            status
                .iter_present()
                .any(|part| part.value() < real && !self.scheduler.is_part_verified(part.value())),
        )
    }

    /// The event for a reply from `from` that changed nothing, for `reason`.
    const fn ignored(&self, from: PeerEndpoint, reason: IgnoredReaskReply) -> DownloadEvent {
        DownloadEvent::ReaskReplyIgnored {
            download_id: self.download_id,
            peer: from,
            reason,
        }
    }

    /// The endpoints the run's sources stand at with no worker: the
    /// **Remote-Queued Pool**.
    pub(crate) fn remote_queued(&self) -> impl Iterator<Item = PeerEndpoint> + '_ {
        self.sources.remote_queued()
    }

    /// Sources this run knows now — aMule's source count, republished beside
    /// the part map: every record the **Source Book** holds, once.
    pub(crate) fn known_sources(&self) -> u32 {
        self.sources.counts().known
    }
}

/// The download event's word for why the requester ignored a reply.
const fn ignored_reason(why: IgnoredReply) -> IgnoredReaskReply {
    match why {
        IgnoredReply::Runt => IgnoredReaskReply::Runt,
        IgnoredReply::UnexpectedOpcode => IgnoredReaskReply::UnexpectedOpcode,
        IgnoredReply::UnknownSource => IgnoredReaskReply::NoPooledSource,
        IgnoredReply::Misframed => IgnoredReaskReply::Misframed,
    }
}
