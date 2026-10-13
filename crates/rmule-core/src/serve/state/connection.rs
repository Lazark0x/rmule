//! One peer connection's events folded into the serve state: the hello that
//! identifies it, the slot ask that queues or grants, the part asks that turn
//! into reads, and the disconnect that promotes the next waiter. Served ranges
//! are tracked here so a re-ask never re-reads what the flow already sent.

use std::collections::HashMap;
use std::time::Instant;

use rmule_peer::{
    BundleCut, BundledAsk, ConnectionEvent, FileSizedStatus, IdentityChange, PartStatusTail,
    ServerCommand, ServerEvent,
};
use rmule_primitives::{FileHash, PeerEndpoint};

use crate::WaiterLeaveCause;
use crate::adapters::ServeInput;
use crate::service::ServeEvent;
use crate::upload_queue::{Admission, LowIdAbuseFacts, refuses_as_low_id_abuse};

use super::transfer::answer_aich_recovery;
use super::{ReadPurpose, ServeDecision, ServeState};

impl ServeState {
    /// Answer a standalone name ask (`OP_REQUESTFILENAME`) as aMule's
    /// uploader does (stock 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:428-470`),
    /// keeping the asker's status for the source-exchange answer (ADR-0055
    /// §Name-ask surface). A Served Download is named from the download's
    /// start; only an offered file moves the asker, and a running download
    /// keeps the asker as a candidate source before its status is read, as
    /// aMule adds it before the read that may throw (`:449-458`).
    fn answer_name_ask(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
        tail: &PartStatusTail,
    ) -> Vec<ServeDecision> {
        // A file we do not share is not answered and the connection stays up
        // (`:442-447` `break`s before any reply); the asker learns it from
        // its status ask or its bundle.
        let Some(asked) = self.asked(file_hash) else {
            return Vec::new();
        };
        let command = ServerCommand::AnswerFileName {
            file_hash,
            file_name: asked.name(),
        };
        let (file_size, offered) = (asked.file_size(), asked.offered());
        let kept = self.keep_asker(peer, file_hash);
        let moved = offered
            .then(|| self.follow_asked_file(peer, file_hash))
            .flatten();
        let claims_status = self
            .identities
            .get(&peer)
            .is_some_and(|identity| identity.extended_requests_version() > 0);
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
                    return kept
                        .into_iter()
                        .chain(self.malformed_name_ask(peer))
                        .collect();
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
            .chain(kept)
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
            software: self.software_of(peer),
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
    /// name ask. A running Served Download keeps the asker as a candidate
    /// source past the gate, before any sub is walked (`:1092-1096`).
    fn answer_bundle(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        file_hash: FileHash,
        file_size: Option<u64>,
        asks: Vec<BundledAsk>,
        cut: Option<BundleCut>,
    ) -> Vec<ServeDecision> {
        let asked = self
            .asked(file_hash)
            .filter(|asked| file_size.is_none_or(|size| size == asked.file_size()));
        let Some(asked) = asked else {
            let command = ServerCommand::AnswerFileNotFound { file_hash };
            return vec![ServeDecision::Send { peer, command }];
        };
        let (name, size, offered) = (asked.name(), asked.file_size(), asked.offered());
        let kept = self.keep_asker(peer, file_hash);
        // The file is set before any sub is walked (`:1103`).
        let moved = offered
            .then(|| self.follow_asked_file(peer, file_hash))
            .flatten();
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
            return kept
                .into_iter()
                .chain(self.malformed_name_ask(peer))
                .collect();
        }
        let mut decisions: Vec<ServeDecision> = moved.into_iter().chain(kept).collect();
        for ask in asks {
            match ask {
                // Every name ask restates the asker's status; one the file
                // cannot read leaves it unknown.
                BundledAsk::Name { part_status } => {
                    self.record_part_status(peer, file_hash, size, part_status);
                    decisions.push(ServeDecision::Send {
                        peer,
                        command: ServerCommand::AnswerFileName {
                            file_hash,
                            file_name: name.clone(),
                        },
                    });
                }
                BundledAsk::SetReqId => decisions.extend(self.answer_file_status(peer, file_hash)),
                BundledAsk::AichRoot => decisions.extend(self.answer_aich_root(peer, file_hash)),
                BundledAsk::Sources => {
                    decisions.extend(self.answer_source_exchange(now, peer, file_hash));
                }
            }
        }
        decisions
    }

    /// A name ask aMule's reader throws on: counted, and the connection ends.
    fn malformed_name_ask(&self, peer: PeerEndpoint) -> Vec<ServeDecision> {
        vec![
            ServeDecision::Emit(ServeEvent::NameAskMalformed { peer }),
            ServeDecision::Disconnect { peer },
        ]
    }

    /// Answer a status ask (`OP_SETREQFILEID`): the parts we hold of the
    /// file — every one of a row's, a Served Download's Verified Range, all
    /// zero before its first part — or `OP_FILEREQANSNOFIL` for a file we do
    /// not share (`ClientTCPSocket.cpp:503-533`). Only an offered file moves
    /// the asker.
    fn answer_file_status(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Vec<ServeDecision> {
        let (command, moved) = match self.asked(file_hash) {
            Some(asked) => {
                let (bitmap, offered) = (asked.status(), asked.offered());
                let moved = offered
                    .then(|| self.follow_asked_file(peer, file_hash))
                    .flatten();
                (ServerCommand::AnswerFileStatus { file_hash, bitmap }, moved)
            }
            None => (ServerCommand::AnswerFileNotFound { file_hash }, None),
        };
        std::iter::once(ServeDecision::Send { peer, command })
            .chain(moved)
            .collect()
    }

    /// Answer an AICH master-hash ask from the file's tree, building it first
    /// when it is not cached (ADR-0038). A Served Download answers nothing:
    /// its tree is whole only once the file is (ADR-0113).
    fn answer_aich_root(&self, peer: PeerEndpoint, file_hash: FileHash) -> Vec<ServeDecision> {
        let Some(entry) = self.asked(file_hash).and_then(|asked| asked.row()) else {
            return Vec::new(); // not shared whole
        };
        match self.aich_cache.get(&file_hash) {
            Some(tree) => vec![ServeDecision::Send {
                peer,
                command: ServerCommand::AnswerAichFileHash {
                    root: tree.master_root(),
                },
            }],
            None => vec![ServeDecision::ReadRange {
                peer,
                path: entry.path.clone(),
                offset: 0,
                len: entry.file_size,
                purpose: ReadPurpose::AichMasterRoot { file_hash },
                check: None,
            }],
        }
    }

    /// Turn one connection's input into the decisions it warrants.
    /// `modifiers` carries the identified peers' current credit modifiers
    /// (read by the enactor from the shared ledger), used when a freed slot
    /// promotes a waiter.
    pub(crate) fn on_conn_event(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        input: ServeInput,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        match input {
            ServeInput::Server(request) => self.on_server_request(now, peer, request, modifiers),
            ServeInput::Connection(fact) => self.on_connection_fact(now, peer, fact, modifiers),
            ServeInput::Readopted => {
                // The accept-router handed this inbound peer to a download as
                // an adopted worker (ADR-0039). It never requested an upload
                // slot, so there is nothing in the queue to release and no
                // slot-released event to emit — just drop the serve-side
                // bookkeeping (the task removes its connection).
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                self.forget(peer);
                self.sx_throttle.forget(peer);
                Vec::new()
            }
        }
    }

    /// Answer one Server Capability request.
    fn on_server_request(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        request: ServerEvent,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        match request {
            ServerEvent::FileRequested { file_hash, status } => {
                self.answer_name_ask(peer, file_hash, &status)
            }
            ServerEvent::FileBundleRequested {
                file_hash,
                file_size,
                asks,
                cut,
            } => self.answer_bundle(now, peer, file_hash, file_size, asks, cut),
            ServerEvent::FileIdSet { file_hash } => self.answer_file_status(peer, file_hash),
            ServerEvent::HashSetRequested { file_hash } => {
                // Not shared (e.g. unshared mid-probe), or a download whose
                // set is not yet whole: answer "no such file" rather than
                // silently dropping the request (design §5;
                // `UploadClient.cpp:676-698`).
                let part_hashes = self.asked(file_hash).and_then(|asked| asked.hash_set());
                let command = match part_hashes {
                    Some(part_hashes) => ServerCommand::AnswerHashSet {
                        file_hash,
                        part_hashes,
                    },
                    None => ServerCommand::AnswerFileNotFound { file_hash },
                };
                vec![ServeDecision::Send { peer, command }]
            }
            ServerEvent::SlotRequested { file_hash } => {
                if !self.asked(file_hash).is_some_and(|asked| asked.offered()) {
                    // We do not offer it — unshared, or a download with no
                    // verified part yet: nothing is sent, as aMule queues and
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
                    on_our_server: self.ours.server.is_some_and(|ours| {
                        self.identities
                            .get(&peer)
                            .is_some_and(|identity| identity.is_on_server(ours))
                    }),
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
                            command: ServerCommand::GrantSlot { file_hash },
                        },
                        ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                            peer,
                            file_hash,
                            software: self.software_of(peer),
                        }),
                    ],
                    Admission::Queued { rank } => {
                        // Stamp the waiter's advertised UDP contact so its
                        // reask heartbeat matches by IP + port (ADR-0057); an
                        // absent one keeps it TCP-reask-only.
                        self.stamp_udp_contact(peer);
                        vec![
                            ServeDecision::Send {
                                peer,
                                command: ServerCommand::SetQueueRank { rank },
                            },
                            ServeDecision::Emit(ServeEvent::PeerQueued {
                                peer,
                                rank,
                                file_hash,
                                software: self.software_of(peer),
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
            ServerEvent::PartsRequested { file_hash, ranges } => {
                self.on_parts_requested(now, peer, file_hash, &ranges, modifiers)
            }
            ServerEvent::AichRequested {
                file_hash,
                part,
                root: _,
            } => {
                // Not shared whole — a Served Download included, whose tree
                // is whole only once the file is: let the requester fall back.
                let Some(entry) = self.asked(file_hash).and_then(|asked| asked.row()) else {
                    return Vec::new();
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
                        check: None,
                    }],
                }
            }
            ServerEvent::AichFileHashRequested { file_hash } => {
                // Same lazily-built tree cache as the recovery path; we answer
                // our master root so the peer can count it toward its
                // trusted-set vote (ADR-0038).
                self.answer_aich_root(peer, file_hash)
            }
            ServerEvent::SourcesRequested { file_hash } => {
                self.answer_source_exchange(now, peer, file_hash)
            }
            // The session's report of what the framed answer carried; the
            // brain's own list may hold sources the wire form omits.
            ServerEvent::SourcesAnswered { file_hash, count } => {
                vec![ServeDecision::Emit(ServeEvent::SourcesServed {
                    peer,
                    file_hash,
                    count,
                })]
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
            ServerEvent::TransferCancelled { file_hash: _ } => {
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
            // A part ask without a granted slot frames nothing: the session
            // reported it and kept the link, and core has no answer for it.
            ServerEvent::PartsWithoutSlot { .. } => Vec::new(),
        }
    }

    /// Fold one fact about the link into the serve-side bookkeeping.
    fn on_connection_fact(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        fact: ConnectionEvent,
        modifiers: &HashMap<PeerEndpoint, f64>,
    ) -> Vec<ServeDecision> {
        match fact {
            ConnectionEvent::Identified { identity } => {
                self.identities.insert(peer, identity);
                Vec::new()
            }
            // Only a peer the serve side already holds a hello for: the map is
            // keyed by live identified connections. A waiter already on the
            // list takes a revised reask contact now; one that queues later
            // is stamped from the identity, as the hello's is.
            ConnectionEvent::IdentityRevised { identity, what } => {
                if let Some(held) = self.identities.get_mut(&peer) {
                    *held = identity;
                    if what == IdentityChange::ReaskContact {
                        self.stamp_udp_contact(peer);
                    }
                }
                Vec::new()
            }
            ConnectionEvent::IdentityVerified {
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
            ConnectionEvent::Disconnected { .. } => {
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                // A waiting peer keeps its queue position across disconnect —
                // disconnected standing (ADR-0057); only a granted peer frees
                // a slot. The transfer flow is wiped either way.
                let disconnect = self.queue.on_disconnect(peer, now, modifiers);
                // A waiter that retains standing keeps its identity for reask
                // matching; a released or fully-gone peer sheds it.
                if !self.queue.contains(peer) {
                    self.forget(peer);
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
            // Facts the serve side keeps nothing of.
            ConnectionEvent::HelloSent
            | ConnectionEvent::HelloRefused { .. }
            | ConnectionEvent::SecureIdentFailed { .. } => Vec::new(),
        }
    }

    /// Stamp the client-UDP reask contact `peer`'s identity names on its
    /// wait-list entry (ADR-0057), so an inbound `OP_REASKFILEPING` matches by
    /// IP + UDP port; a peer that named none stays TCP-reask-only.
    fn stamp_udp_contact(&mut self, peer: PeerEndpoint) {
        if let Some(identity) = self.identities.get(&peer) {
            let (udp_port, udp_version) = identity.client_udp_reask().unwrap_or_default();
            self.queue
                .set_udp_contact(peer, (udp_port != 0).then_some(udp_port), udp_version);
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
