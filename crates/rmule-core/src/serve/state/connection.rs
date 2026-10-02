//! One peer connection's events folded into the serve state: the hello that
//! identifies it, the slot ask that queues or grants, the part asks that turn
//! into reads, and the disconnect that promotes the next waiter. Served ranges
//! are tracked here so a re-ask never re-reads what the flow already sent.

use std::collections::HashMap;
use std::time::Instant;

use rmule_peer::{BundleCut, BundledAsk, FileSizedStatus, PartStatusTail};
use rmule_primitives::{
    Ed2kText, ExchangedSource, FileHash, Ipv6Endpoint, PeerEndpoint, PeerSource,
};

use crate::WaiterLeaveCause;
use crate::adapters::{ServeConnCommand, ServeConnEvent};
use crate::client_udp::PeerUdpCryptTarget;
use crate::service::ServeEvent;
use crate::upload_queue::{Admission, LowIdAbuseFacts, refuses_as_low_id_abuse};

use super::reask::full_bitmap;
use super::transfer::answer_aich_recovery;
use super::{ReadPurpose, ServeDecision, ServeState};

impl ServeState {
    /// Answer a standalone name ask (`OP_REQUESTFILENAME`) as aMule's
    /// uploader does (stock 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:428-470`),
    /// keeping the asker's status for the source-exchange answer (ADR-0055
    /// §Name-ask surface).
    fn answer_name_ask(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
        tail: &PartStatusTail,
    ) -> Vec<ServeDecision> {
        // A file we do not share is not answered and the connection stays up
        // (`:442-447` `break`s before any reply); the asker learns it from
        // its status ask or its bundle.
        let Some(entry) = self.shared.get(&file_hash) else {
            return Vec::new();
        };
        let command = ServeConnCommand::AnswerFileName {
            file_hash,
            file_name: Ed2kText::from_utf8(entry.name.as_str()),
        };
        let file_size = entry.file_size;
        let moved = self.follow_asked_file(peer, file_hash);
        let claims_status = self.extended_requests.get(&peer).is_some_and(|&v| v > 0);
        let part_status = if claims_status {
            // Read by the asked file (`UploadClient.cpp:408-446`, the reader a
            // UDPv4 reask shares): a count that is not the file's clears the
            // status and the ask is still answered.
            match tail.read(file_size) {
                FileSizedStatus::Read { status, .. } => Some(status),
                FileSizedStatus::Cleared => None,
                // The hash alone or a status cut short throws, and the packet
                // handler's catch disconnects (`ClientTCPSocket.cpp:2018-2047`):
                // no answer, the bits read standing.
                FileSizedStatus::Cut(partial) => {
                    self.record_part_status(peer, file_hash, file_size, partial);
                    return self.malformed_name_ask(peer);
                }
            }
        } else {
            // A `0` claimant's status is cleared before anything is read
            // (`UploadClient.cpp:400-406`), so its bytes cannot fail the ask.
            None
        };
        self.record_part_status(peer, file_hash, file_size, part_status);
        std::iter::once(ServeDecision::Send { peer, command })
            .chain(moved)
            .collect()
    }

    /// Move a waiter to the file it just asked about, and report the move so a
    /// consumer's row names the file the waiter now waits for.
    fn follow_asked_file(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Option<ServeDecision> {
        let rank = self.queue.follow_asked_file(peer, file_hash)?;
        Some(ServeDecision::Emit(ServeEvent::PeerQueued {
            peer,
            rank,
            file_hash,
            software: self.software.get(&peer).cloned(),
        }))
    }

    /// Answer a bundle (`OP_MULTIPACKET` / `OP_MULTIPACKET_EXT`) as aMule's
    /// uploader does (`ClientTCPSocket.cpp:1041-1192`): the file gates the
    /// bundle as a whole — one `OP_FILEREQANSNOFIL` for a file we do not
    /// share or a size that is not the file's (`:1061-1085`), whatever the
    /// bundle asked — and only then is each ask answered, in wire order. A
    /// bundle cut short inside a sub-ask throws in aMule's walk after the gate
    /// and the packet handler disconnects (`:2018-2047`): nothing is answered,
    /// the statuses read stand, the connection ends, counted as a malformed
    /// name ask.
    fn answer_bundle(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        file_size: Option<u64>,
        asks: Vec<BundledAsk>,
        cut: Option<BundleCut>,
    ) -> Vec<ServeDecision> {
        let entry = self
            .shared
            .get(&file_hash)
            .filter(|entry| file_size.is_none_or(|size| size == entry.file_size));
        let Some(entry) = entry else {
            let command = ServeConnCommand::AnswerFileNotFound { file_hash };
            return vec![ServeDecision::Send { peer, command }];
        };
        let (name, size) = (Ed2kText::from_utf8(entry.name.as_str()), entry.file_size);
        // The file is set before any sub is walked (`:1103`).
        let moved = self.follow_asked_file(peer, file_hash);
        if let Some(cut) = cut {
            let statuses = asks.into_iter().filter_map(|ask| match ask {
                BundledAsk::Name { part_status } => Some(part_status),
                _ => None,
            });
            let cut_status = match cut {
                BundleCut::NameStatus(partial) => Some(partial),
                BundleCut::Sources2 => None,
            };
            for part_status in statuses.chain(cut_status) {
                self.record_part_status(peer, file_hash, size, part_status);
            }
            return self.malformed_name_ask(peer);
        }
        let mut decisions: Vec<ServeDecision> = moved.into_iter().collect();
        for ask in asks {
            match ask {
                // Every name ask restates the asker's status; one the file
                // cannot read leaves it unknown.
                BundledAsk::Name { part_status } => {
                    self.record_part_status(peer, file_hash, size, part_status);
                    decisions.push(ServeDecision::Send {
                        peer,
                        command: ServeConnCommand::AnswerFileName {
                            file_hash,
                            file_name: name.clone(),
                        },
                    });
                }
                BundledAsk::SetReqId => decisions.extend(self.answer_file_status(peer, file_hash)),
                BundledAsk::AichRoot => decisions.extend(self.answer_aich_root(peer, file_hash)),
                BundledAsk::Sources(version) => {
                    decisions.extend(self.answer_source_exchange(now, peer, file_hash, version));
                }
            }
        }
        decisions
    }

    /// A name ask aMule's reader throws on: counted, and the connection ends.
    fn malformed_name_ask(&self, peer: PeerEndpoint) -> Vec<ServeDecision> {
        vec![
            ServeDecision::Emit(ServeEvent::NameAskMalformed { peer }),
            ServeDecision::Send {
                peer,
                command: ServeConnCommand::Disconnect,
            },
        ]
    }

    /// Answer a status ask (`OP_SETREQFILEID`): the file's bitmap, or
    /// `OP_FILEREQANSNOFIL` for a file we do not share
    /// (`ClientTCPSocket.cpp:503-533`).
    fn answer_file_status(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Vec<ServeDecision> {
        let (command, moved) = match self.shared.get(&file_hash) {
            Some(entry) => {
                let bitmap = full_bitmap(entry.file_size);
                let moved = self.follow_asked_file(peer, file_hash);
                (
                    ServeConnCommand::AnswerFileStatus { file_hash, bitmap },
                    moved,
                )
            }
            None => (ServeConnCommand::AnswerFileNotFound { file_hash }, None),
        };
        std::iter::once(ServeDecision::Send { peer, command })
            .chain(moved)
            .collect()
    }

    /// Answer an AICH master-hash ask from the file's tree, building it first
    /// when it is not cached (ADR-0038).
    fn answer_aich_root(&self, peer: PeerEndpoint, file_hash: FileHash) -> Vec<ServeDecision> {
        let Some(entry) = self.shared.get(&file_hash) else {
            return Vec::new(); // not shared
        };
        match self.aich_cache.get(&file_hash) {
            Some(tree) => vec![ServeDecision::Send {
                peer,
                command: ServeConnCommand::AnswerAichFileHash {
                    root: tree.master_root(),
                },
            }],
            None => vec![ServeDecision::ReadRange {
                peer,
                path: entry.path.clone(),
                offset: 0,
                len: entry.file_size,
                purpose: ReadPurpose::AichMasterRoot { file_hash },
            }],
        }
    }

    /// Turn one connection event into the decisions it warrants. `modifiers`
    /// carries the identified peers' current credit modifiers (read by the
    /// enactor from the shared ledger), used when a freed slot promotes a
    /// waiter.
    pub(crate) fn on_conn_event(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        event: ServeConnEvent,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        match event {
            ServeConnEvent::FileRequested { file_hash, status } => {
                self.answer_name_ask(peer, file_hash, &status)
            }
            ServeConnEvent::FileBundleRequested {
                file_hash,
                file_size,
                asks,
                cut,
            } => self.answer_bundle(now, peer, file_hash, file_size, asks, cut),
            ServeConnEvent::FileIdSet { file_hash } => self.answer_file_status(peer, file_hash),
            ServeConnEvent::HashSetRequested { file_hash } => {
                // Not shared (e.g. unshared mid-probe): answer "no such file"
                // rather than silently dropping the request (design §5).
                let command = match self.shared.get(&file_hash) {
                    Some(entry) => ServeConnCommand::AnswerHashSet {
                        file_hash,
                        part_hashes: entry.part_hashes.clone(),
                    },
                    None => ServeConnCommand::AnswerFileNotFound { file_hash },
                };
                vec![ServeDecision::Send { peer, command }]
            }
            ServeConnEvent::SlotRequested { file_hash } => {
                if !self.shared.contains_key(&file_hash) {
                    // We do not share it: nothing is sent, as aMule queues and
                    // answers only a file it finds (stock 2.3.3 `4e8f2b3c`
                    // `ClientTCPSocket.cpp:607-617`). `OP_OUTOFPARTREQS` ends
                    // an upload session; this asker never had one.
                    return Vec::new();
                }
                // The **Low-ID abuse guard** (ADR-0031 amendment),
                // ahead of admission because it is not a queue decision: a
                // firewalled node's callback capacity is what is scarce, not
                // its wait list. Refused in silence, like both queue caps —
                // eMule `srchybrid/UploadQueue.cpp:535-545` and aMule
                // `src/UploadQueue.cpp:403-409` `return` before framing a
                // packet.
                let facts = LowIdAbuseFacts {
                    we_are_low_id: self.ours.low_id,
                    downloading_from_us: self.queue.is_granted(peer),
                    // rmule keeps no friend list; the input is named so that
                    // adding one later fills a hole instead of finding one.
                    is_friend: false,
                    on_our_server: self.ours.server.is_some()
                        && self.peer_servers.get(&peer).copied().flatten() == self.ours.server,
                    waiting: self.queue.waiting_len(),
                };
                if refuses_as_low_id_abuse(&facts) {
                    return vec![ServeDecision::Emit(ServeEvent::UploadLowIdAbuseRefused {
                        peer,
                    })];
                }
                // aMule counts the request before it decides, once the peer
                // is past the per-address cap — and not for a waiter asking
                // again, which returns earlier (`UploadQueue.cpp:401-431`).
                let waiting_already = self.queue.contains(peer) && !self.queue.is_granted(peer);
                let admission = self.queue.admit(peer, file_hash, now);
                let counted = !waiting_already && admission != Admission::RefusedAddressCap;
                let mut decisions = match admission {
                    Admission::Granted => vec![
                        ServeDecision::Send {
                            peer,
                            command: ServeConnCommand::GrantSlot { file_hash },
                        },
                        ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                            peer,
                            file_hash,
                            software: self.software.get(&peer).cloned(),
                        }),
                    ],
                    Admission::Queued { rank } => {
                        // Stamp the waiter's advertised UDP contact so its
                        // reask heartbeat matches by IP + port (ADR-0057); an
                        // absent (0) port keeps it TCP-reask-only.
                        if let Some(&(udp_port, udp_version)) = self.udp_contacts.get(&peer) {
                            self.queue.set_udp_contact(
                                peer,
                                (udp_port != 0).then_some(udp_port),
                                udp_version,
                            );
                        }
                        vec![
                            ServeDecision::Send {
                                peer,
                                command: ServeConnCommand::SetQueueRank { rank },
                            },
                            ServeDecision::Emit(ServeEvent::PeerQueued {
                                peer,
                                rank,
                                file_hash,
                                software: self.software.get(&peer).cloned(),
                            }),
                        ]
                    }
                    // Nothing is sent, and that is the references' answer: both
                    // aMule (`src/UploadQueue.cpp:534-537`) and eMule
                    // (`srchybrid/UploadQueue.cpp:639-656`) `return` at the
                    // wait-list cap before any packet is framed.
                    // `OP_OUTOFPARTREQS` would say something else entirely —
                    // it ends an upload session — and `OP_QUEUEFULL 0x93` is
                    // the UDP reask reply, not this. The requester falls back
                    // to its own reask timer; the event is the only trace.
                    Admission::Refused => {
                        vec![ServeDecision::Emit(ServeEvent::UploadQueueFull { peer })]
                    }
                    // Nothing is sent: the reference frames no packet for a
                    // per-address refusal (ADR-0088), so the ask goes
                    // unanswered and the requester falls back to its own reask
                    // timer. Only the diagnostic fact leaves.
                    Admission::RefusedAddressCap => {
                        vec![ServeDecision::Emit(ServeEvent::UploadAddressCapReached {
                            peer,
                        })]
                    }
                };
                if counted {
                    decisions.insert(0, ServeDecision::CountUploadRequest { file_hash });
                }
                decisions
            }
            ServeConnEvent::PartsRequested { file_hash, ranges } => {
                let Some(entry) = self.shared.get(&file_hash) else {
                    return Vec::new();
                };
                let path = entry.path.clone();
                let mut decisions = Vec::new();
                // `PartRanges::as_array()` yields the fixed `[(u64,u64); 3]`;
                // the `(0,0)` padding slots are skipped by the `e > s` filter.
                for &(start, end) in ranges.as_array().iter().filter(|(s, e)| e > s) {
                    let served = self.served_ranges.entry((peer, file_hash)).or_default();
                    for (send_start, send_end) in subtract_served_ranges(start, end, served) {
                        // Recorded at decision time, not on the read result: a
                        // repeat request must not double-send a range whose
                        // read is still in flight, and a failed read closes
                        // the flow (its `Disconnected` wipes the peer's
                        // ranges), so nothing is stranded.
                        record_served_range(served, send_start, send_end);
                        decisions.push(ServeDecision::ReadRange {
                            peer,
                            path: path.clone(),
                            offset: send_start,
                            len: send_end - send_start,
                            purpose: ReadPurpose::Block {
                                file_hash,
                                start: send_start,
                                end: send_end,
                            },
                        });
                    }
                }
                decisions
            }
            ServeConnEvent::AichRequested {
                file_hash,
                part,
                root: _,
            } => {
                let Some(entry) = self.shared.get(&file_hash) else {
                    return Vec::new(); // not shared; let the requester fall back
                };
                // A cache hit answers pure; the first request round-trips one
                // whole-file read to build the tree (ADR-0038). We answer with
                // our own root + recovery data; the requester verifies it
                // against the root it trusts.
                match self.aich_cache.get(&file_hash) {
                    Some(tree) => answer_aich_recovery(peer, file_hash, part, tree),
                    None => vec![ServeDecision::ReadRange {
                        peer,
                        path: entry.path.clone(),
                        offset: 0,
                        len: entry.file_size,
                        purpose: ReadPurpose::AichRecovery { file_hash, part },
                    }],
                }
            }
            ServeConnEvent::AichFileHashRequested { file_hash } => {
                // Same lazily-built tree cache as the recovery path; we answer
                // our master root so the peer can count it toward its
                // trusted-set vote (ADR-0038).
                self.answer_aich_root(peer, file_hash)
            }
            ServeConnEvent::SourcesRequested { file_hash, version } => {
                self.answer_source_exchange(now, peer, file_hash, version)
            }
            ServeConnEvent::Identified {
                user_hash,
                client_id,
                connected_server,
                tcp_port,
                udp_port,
                udp_version,
                extended_requests_version,
                crypt,
                ipv6,
                software,
            } => {
                self.identified.insert(peer, user_hash);
                self.software.insert(peer, software);
                // The "on our server" half of the Low-ID abuse guard:
                // what the peer *claims*, kept verbatim — a claim that cannot
                // be proven (`0.0.0.0:0` → `None`) never matches ours.
                self.peer_servers.insert(peer, connected_server);
                self.udp_contacts.insert(peer, (udp_port, udp_version));
                self.extended_requests
                    .insert(peer, extended_requests_version);
                // The peer's peer-UDP crypt target (ADR-0046): its hash keys
                // an obfuscated reask reply, its advertised stance says whether
                // it accepts one at all.
                self.crypt_targets
                    .insert(peer, PeerUdpCryptTarget::new(user_hash, crypt));
                // The peer's own source coordinate for source-exchange serving
                // (ADR-0055 §Serving): its advertised (client id, listen port),
                // with the user hash a v>=2 answer entry carries, and the
                // usable IPv6 its hello named as the source's IPv6 half —
                // emule-qt writes `CT_MOD_IP_V6` for any source with one,
                // High ID included (`KnownFile.cpp:937`), and only an ExtSX
                // record can carry it (ADR-0087). A Low-ID client with an
                // IPv6 is a source over that IPv6 alone, the client emule-qt's
                // writer keeps (`KnownFile.cpp:846-854`); any other Low-ID
                // client is stored too but filtered out at answer time.
                let classic = PeerSource::new(client_id, tcp_port);
                let ipv6 = ipv6.map(|address| Ipv6Endpoint::new(address, tcp_port));
                let source = match ipv6 {
                    Some(endpoint) if !classic.is_high_id() => PeerSource::Ipv6(endpoint),
                    _ => classic,
                };
                self.sx_sources.insert(
                    peer,
                    ExchangedSource::new(source, Some(user_hash), None).with_ipv6_half(ipv6),
                );
                Vec::new()
            }
            ServeConnEvent::ReaskContactRevised {
                udp_port,
                udp_version,
            } => {
                if self.identified.contains_key(&peer) {
                    self.udp_contacts.insert(peer, (udp_port, udp_version));
                    // A waiter already on the list is stamped now; one that
                    // queues later is stamped from the map, as the hello's is.
                    self.queue.set_udp_contact(
                        peer,
                        (udp_port != 0).then_some(udp_port),
                        udp_version,
                    );
                }
                Vec::new()
            }
            ServeConnEvent::SoftwareRevised { software } => {
                // Only a peer the serve side already holds a hello for: the
                // map is keyed by live identified connections.
                if self.identified.contains_key(&peer) {
                    self.software.insert(peer, software);
                }
                Vec::new()
            }
            ServeConnEvent::IdentityVerified {
                user_hash,
                public_key,
            } => {
                // Every proof is forwarded — including a thief's under a
                // different key — because only the ledger knows the stored
                // key; its compare-and-set arbitrates at enactment (ADR-0041).
                vec![ServeDecision::BindIdentity {
                    user_hash,
                    public_key,
                }]
            }
            // `OP_CANCELTRANSFER` (ADR-0056): the same release/promote batch
            // `Disconnected` runs, minus teardown. The canceller's served
            // ranges are wiped (dropping any pending unsent block a stray
            // late `on_read_result` would otherwise frame — the session
            // already cleared `served_slot`, so the enactor's `SendBlock`
            // is harmless either way), the slot is released and the highest
            // waiter promoted in the same batch, but the connection is left
            // registered (the runner only retires it on `Disconnected` /
            // `Readopted`) and — unlike a disconnected *waiter* — the
            // canceller keeps no queue standing: a later re-ask is a fresh
            // `admit()` at the tail.
            ServeConnEvent::TransferCancelled { file_hash: _ } => {
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                let was_granted = self.queue.is_granted(peer);
                let was_waiting = !was_granted && self.queue.contains(peer);
                let promotion = self.queue.release(peer, now, modifiers);
                let mut decisions = self.promotion_decisions(promotion);
                if was_granted {
                    decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
                } else if was_waiting {
                    // A waiter's cancel drops its place too — the Waiter
                    // relation's own terminal, or its roster mark would
                    // outlive the wait (ADR-0059 "Roster relations").
                    decisions.push(ServeDecision::Emit(ServeEvent::WaiterLeft {
                        peer,
                        cause: WaiterLeaveCause::Cancelled,
                    }));
                }
                decisions
            }
            ServeConnEvent::Disconnected => {
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                // A waiting peer keeps its queue position across disconnect —
                // disconnected standing (ADR-0057); only a granted peer frees
                // a slot. The transfer flow is wiped either way.
                let disconnect = self.queue.on_disconnect(peer, now, modifiers);
                // A waiter that retains standing keeps its identity + UDP
                // contact for reask matching; a released or fully-gone peer
                // sheds them.
                if !self.queue.contains(peer) {
                    self.identified.remove(&peer);
                    self.software.remove(&peer);
                    self.udp_contacts.remove(&peer);
                    self.extended_requests.remove(&peer);
                    self.sx_sources.remove(&peer);
                    self.sx_part_status
                        .retain(|(held_by, _), _| *held_by != peer);
                    self.crypt_targets.remove(&peer);
                    self.peer_servers.remove(&peer);
                }
                // The source-exchange throttle is per connection: a disconnect
                // ends it, so the peer's next ask (over a fresh connection) is
                // free again.
                self.sx_throttle.forget(peer);
                let mut decisions = self.promotion_decisions(disconnect.promotion);
                if disconnect.slot_released {
                    decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
                }
                decisions
            }
            ServeConnEvent::Readopted => {
                // The accept-router handed this inbound peer to a download as
                // an adopted worker (ADR-0039). It never requested an upload
                // slot, so there is nothing in the queue to release and no
                // slot-released event to emit — just drop the serve-side
                // bookkeeping (the task removes its connection).
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                self.identified.remove(&peer);
                self.software.remove(&peer);
                self.extended_requests.remove(&peer);
                self.sx_sources.remove(&peer);
                self.sx_part_status
                    .retain(|(held_by, _), _| *held_by != peer);
                self.crypt_targets.remove(&peer);
                self.peer_servers.remove(&peer);
                self.sx_throttle.forget(peer);
                Vec::new()
            }
        }
    }
}

pub(super) fn subtract_served_ranges(
    start: u64,
    end: u64,
    served: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    let mut missing = vec![(start, end)];
    for &(served_start, served_end) in served {
        let mut next = Vec::new();
        for (missing_start, missing_end) in missing {
            if served_end <= missing_start || served_start >= missing_end {
                next.push((missing_start, missing_end));
                continue;
            }
            if missing_start < served_start {
                next.push((missing_start, served_start.min(missing_end)));
            }
            if served_end < missing_end {
                next.push((served_end.max(missing_start), missing_end));
            }
        }
        missing = next;
        if missing.is_empty() {
            break;
        }
    }
    missing
}

pub(super) fn record_served_range(served: &mut Vec<(u64, u64)>, start: u64, end: u64) {
    served.push((start, end));
    served.sort_unstable_by_key(|(range_start, _)| *range_start);

    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(served.len());
    for (range_start, range_end) in served.drain(..) {
        if let Some((_, last_end)) = merged.last_mut()
            && range_start <= *last_end
        {
            *last_end = (*last_end).max(range_end);
            continue;
        }
        merged.push((range_start, range_end));
    }
    *served = merged;
}
