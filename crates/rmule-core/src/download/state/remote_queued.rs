//! The run's queue standing (ADR-0057): a source's **Source Book** record
//! carries the standing its worker earned, waits in the RemoteQueued stage
//! with no worker, and the brain keeps it alive. The sweep runs inside
//! [`DownloadState::on_tick`]; pings are framed and replies read through
//! `rmule-peer`'s **Reask Requester**, because the source's UDP version is on
//! the record. The runner only sends and hands replies back.

use std::time::Instant;

use rmule_peer::peer_udp::requester::{self, HeardReply, IgnoredReply};
use rmule_primitives::PeerEndpoint;

use super::{Decision, DownloadState};
use crate::adapters::advertises_complete;
use crate::client_udp::ClientUdpSend;
use crate::diagnostics::WorkerSlot;
use crate::download::source_book::{Answer, Reask, ReaskGates};
use crate::service::{DownloadEvent, IgnoredReaskReply};

impl DownloadState {
    /// The reask sweep at `now` (ADR-0057): each due `0x90`, and each `0x94`
    /// a firewalled source is reasked by through its buddy, leaves as a
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
                        answered_from: contact.endpoint,
                    });
                }
                Reask::ThroughBuddy {
                    peer,
                    contact,
                    buddy,
                } => {
                    let ping = requester::ping_via_buddy(
                        *buddy.buddy_id.as_bytes(),
                        self.file_hash,
                        self.our_udp_version,
                        contact.version,
                        || self.our_part_status(),
                    );
                    // Plain, as aMule sends it to a buddy whose key it does
                    // not hold (`DownloadClient.cpp:1318`).
                    out.push(Decision::SendReaskPing {
                        peer,
                        ping: ClientUdpSend::plaintext(PeerEndpoint::V4(buddy.buddy_udp), ping),
                        answered_from: contact.endpoint,
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

    /// The uploader at `peer` granted a slot on a link no worker of ours rides
    /// — it promoted the source from its queue by dialing us back, or on a
    /// link it held (ADR-0057, "A grant by dial-back is taken"): the record
    /// waiting there opens its worker at once, on a slot of its own when the
    /// cap is full. A granted slot is a transfer, not a dial (ADR-0030), and
    /// the worker rides the link the grant came on. Nothing waits at an
    /// endpoint with no record in the RemoteQueued stage.
    pub(crate) fn on_slot_offered(&mut self, now: Instant, peer: PeerEndpoint) -> Vec<Decision> {
        let mut out = Vec::new();
        if !self.sources.take_grant(peer) {
            return out;
        }
        let slot = match self.free_slots.pop_first() {
            Some(free) => WorkerSlot::from_usize(free),
            None => self.slot_past_the_cap(),
        };
        out.push(Decision::Emit(DownloadEvent::SlotOffered {
            download_id: self.download_id,
            peer,
        }));
        self.spawn_worker(now, peer, slot, &mut out);
        out
    }

    /// A slot number no worker, callback or free slot holds: the first past
    /// every one in use.
    fn slot_past_the_cap(&self) -> WorkerSlot {
        let highest = self
            .worker_slots
            .values()
            .chain(self.callback_slots.values())
            .map(|slot| slot.as_usize())
            .chain(self.free_slots.iter().copied())
            .max();
        WorkerSlot::from_usize(highest.map_or(0, |highest| highest + 1))
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
                // A UDPv4 ack's part status is read as a probe's, by the one
                // reader (aMule `ProcessFileStatus(true, …)`, stock 2.3.3
                // `ClientUDPSocket.cpp:258-263`): one counting other than
                // the file's parts throws there before the rank is read.
                let parts = match part_status
                    .as_ref()
                    .map(|status| status.advertised_parts(self.file_size))
                {
                    Some(None) => {
                        return vec![Decision::Emit(
                            self.ignored(from, IgnoredReaskReply::PartCountMismatch),
                        )];
                    }
                    Some(Some(parts)) => Some(parts),
                    None => None,
                };
                let parts_needed = parts
                    .as_ref()
                    .map(|parts| self.scheduler.lacks_any_of(parts));
                self.sources
                    .reask_answered(peer, Answer::Rank { rank, parts_needed }, now);
                // It is an advertisement like a probe's (ADR-0108), and its
                // parts replace the record's (ADR-0112).
                if let Some(status) = part_status {
                    self.sources
                        .advertised(peer, advertises_complete(&status), now);
                    self.sources.write_parts(peer, parts);
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
