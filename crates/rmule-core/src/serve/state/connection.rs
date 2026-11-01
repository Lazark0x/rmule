//! One peer connection's events folded into the serve state: the hello that
//! identifies it, the slot ask that queues or grants, the part asks that turn
//! into reads, and the disconnect that promotes the next waiter. Served ranges
//! are tracked here so a re-ask never re-reads what the flow already sent.

use std::sync::Arc;
use std::time::Instant;

use rmule_peer::{
    BundleCut, BundledAsk, ConnectionEvent, FileSizedStatus, IdentityChange, PartStatusTail,
    ServerCommand, ServerEvent,
};
use rmule_primitives::{FileHash, PeerEndpoint};

use crate::WaiterLeaveCause;
use crate::adapters::ServeInput;
use crate::service::{GrantRoad, ServeEvent};
use crate::upload_queue::ScoreModifiers;
use crate::upload_queue::{Admission, LowIdAbuseFacts, WaiterContact, refuses_as_low_id_abuse};

use super::{ServeDecision, ServeState};

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
        let Some(found) = self.lookup_for(peer, file_hash) else {
            return Vec::new();
        };
        let command = ServerCommand::AnswerFileName {
            file_hash,
            file_name: found.name(),
        };
        let file_size = found.file_size();
        let kept = self.keep_asker(peer, file_hash);
        let moved = self.follow_asked_file(peer, file_hash);
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
    /// consumer's row names the file the waiter now waits for. Only an
    /// offered file moves one: a download not yet offered can grant no slot
    /// (ADR-0113).
    fn follow_asked_file(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Option<ServeDecision> {
        if !self.in_share_set(file_hash) {
            return None;
        }
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
        let found = self
            .lookup_for(peer, file_hash)
            .filter(|found| file_size.is_none_or(|size| size == found.file_size()));
        let Some(found) = found else {
            let command = ServerCommand::AnswerFileNotFound { file_hash };
            return vec![ServeDecision::Send { peer, command }];
        };
        let (name, size) = (found.name(), found.file_size());
        let kept = self.keep_asker(peer, file_hash);
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
                BundledAsk::Sources { form } => {
                    decisions.extend(self.answer_source_exchange(now, peer, file_hash, form));
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
        let (command, moved) = match self.lookup_for(peer, file_hash) {
            Some(found) => {
                let bitmap = found.status();
                let moved = self.follow_asked_file(peer, file_hash);
                (ServerCommand::AnswerFileStatus { file_hash, bitmap }, moved)
            }
            None => (ServerCommand::AnswerFileNotFound { file_hash }, None),
        };
        std::iter::once(ServeDecision::Send { peer, command })
            .chain(moved)
            .collect()
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
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        self.link_moved(now, peer);
        if self.asker.banned && !self.spares(peer) && is_ask(&input) {
            return self.on_banned(now, peer, modifiers);
        }
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
                self.aich.forget_link(peer);
                self.forget(peer);
                self.sx_throttle.forget(peer);
                Vec::new()
            }
            ServeInput::IdentityBound { user_hash } => {
                self.on_identity_bound(now, peer, user_hash);
                Vec::new()
            }
            ServeInput::KeyMismatch { user_hash } => self.on_key_mismatch(peer, user_hash),
            // A slot holder's silence is the slot sweep's, which lends what the
            // kernel still holds; anyone else's link closes, and a waiter's
            // place rides its reask (ADR-0057), as stock leaves it queued
            // when its socket times out (`ClientTCPSocket.cpp:201-229`).
            ServeInput::LinkSilent if self.queue.is_granted(peer) => Vec::new(),
            ServeInput::LinkSilent => vec![ServeDecision::Disconnect { peer }],
            ServeInput::CrossedHelloHeld => {
                vec![ServeDecision::Emit(ServeEvent::CrossedHelloHeld { peer })]
            }
            ServeInput::CrossedDialKept => {
                vec![ServeDecision::Emit(ServeEvent::CrossedDialKept { peer })]
            }
            ServeInput::CrossedDialRefused => {
                vec![ServeDecision::Emit(ServeEvent::CrossedDialRefused { peer })]
            }
        }
    }

    /// Answer one Server Capability request.
    fn on_server_request(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        request: ServerEvent,
        modifiers: &dyn ScoreModifiers,
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
                let part_hashes = self
                    .lookup_for(peer, file_hash)
                    .and_then(|found| found.hash_set());
                let command = match part_hashes {
                    Some(part_hashes) => ServerCommand::AnswerHashSet {
                        file_hash,
                        part_hashes,
                    },
                    None => ServerCommand::AnswerFileNotFound { file_hash },
                };
                vec![ServeDecision::Send { peer, command }]
            }
            // Scored like any ask, and nothing else comes of it.
            ServerEvent::MalformedSlotAsk => {
                if self.ask_bans(now, peer) {
                    return self.ban_asker(now, peer, modifiers);
                }
                Vec::new()
            }
            ServerEvent::SlotRequested { file_hash } => {
                if self.ask_bans(now, peer) {
                    return self.ban_asker(now, peer, modifiers);
                }
                if !self
                    .lookup_for(peer, file_hash)
                    .is_some_and(|found| found.offered())
                {
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
                    our_source: self.spares(peer),
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
                // Two clients under one User Hash (ADR-0107): the ones not
                // identified leave the wait list, and an asker not identified
                // is answered nothing (`UploadQueue.cpp:432-458`).
                let (cleared, refused) = self.settle_hash_clash(now, peer, modifiers);
                if refused {
                    return cleared;
                }
                // aMule counts the request before it decides, once the peer
                // is past the per-address cap — and not for a waiter asking
                // again, which returns earlier (`UploadQueue.cpp:401-431`).
                let waiting_already = self.queue.contains(peer) && !self.queue.is_granted(peer);
                // A Low-ID waiter marked for its next connection is granted
                // at this ask (`UploadQueue.cpp:410-425`).
                let road = if self.queue.marked_for_next_connection(peer) {
                    GrantRoad::NextConnection
                } else {
                    GrantRoad::Linked
                };
                // An ask from the client holding the slot for this file is
                // answered as any is (`UploadQueue.cpp:486-493`), and is no
                // new grant (ADR-0057).
                let slot_held = self.queue.live_slot_file(peer) == Some(file_hash);
                let admission = self.queue.admit(peer, file_hash, now);
                let counted = !waiting_already && admission != Admission::RefusedAddressCap;
                let mut decisions =
                    self.admission_decisions(peer, file_hash, road, slot_held, admission);
                if counted {
                    decisions.insert(0, ServeDecision::CountUploadRequest { file_hash });
                }
                cleared.into_iter().chain(decisions).collect()
            }
            ServerEvent::PartsRequested { file_hash, ranges } => {
                self.on_parts_requested(now, peer, file_hash, &ranges, modifiers)
            }
            ServerEvent::AichRequested {
                file_hash,
                part,
                root,
            } => {
                if self.ask_bans(now, peer) {
                    return self.ban_asker(now, peer, modifiers);
                }
                self.answer_aich_recovery(peer, file_hash, part, root)
            }
            ServerEvent::AichFileHashRequested { file_hash } => {
                self.answer_aich_root(peer, file_hash)
            }
            ServerEvent::SourcesRequested { file_hash, form } => {
                self.answer_source_exchange(now, peer, file_hash, form)
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
                let promotion = self.leave_queue(peer, now, modifiers);
                let mut decisions = self.promotion_decisions(promotion);
                if was_granted {
                    decisions.push(ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer }));
                } else if was_waiting {
                    // A waiter's cancel drops its place too — the Waiter
                    // relation's own terminal, or its roster mark would
                    // outlive the wait (ADR-0059).
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
            ServerEvent::BlockLeft {
                file_hash,
                start,
                end,
            } => {
                let mut decisions = self.on_block_left(now, peer, file_hash, end - start);
                decisions.extend(self.end_over_session(now, modifiers));
                decisions
            }
        }
    }

    /// What `admission` of `peer`'s ask for `file_hash` says back. `slot_held`
    /// is an ask from the holder of that file's slot, which is no new grant.
    pub(super) fn admission_decisions(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
        road: GrantRoad,
        slot_held: bool,
        admission: Admission,
    ) -> Vec<ServeDecision> {
        match admission {
            Admission::Granted => {
                let grant = ServeDecision::Send {
                    peer,
                    command: ServerCommand::GrantSlot { file_hash },
                };
                if slot_held {
                    vec![grant]
                } else {
                    vec![
                        grant,
                        ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                            peer,
                            file_hash,
                            software: self.software_of(peer),
                            road,
                        }),
                    ]
                }
            }
            Admission::Queued { rank } => {
                // Stamp the waiter's advertised UDP contact so its
                // reask heartbeat matches by IP + port (ADR-0057); an
                // absent one keeps it TCP-reask-only.
                self.stamp_contact(peer);
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
        }
    }

    /// Fold one fact about the link into the serve-side bookkeeping.
    pub(super) fn on_connection_fact(
        &mut self,
        now: Instant,
        peer: PeerEndpoint,
        fact: ConnectionEvent,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        match fact {
            ConnectionEvent::Identified { identity } => {
                let changed =
                    self.hashes
                        .changed(now, peer.ip(), identity.tcp_port(), identity.user_hash());
                if self.refuses_hash_thief(peer, &identity) || changed && !self.spares(peer) {
                    return vec![
                        ServeDecision::Ban { peer },
                        ServeDecision::Disconnect { peer },
                    ];
                }
                Arc::make_mut(&mut self.identities).insert(peer, identity.clone());
                let relink = self.relink_waiter(now, peer, &identity);
                let Some(mut moved) = relink else {
                    return Vec::new();
                };
                self.stamp_contact(peer);
                // A link coming up is what makes a waiter reachable: a slot
                // nobody could be reached for goes to it now (ADR-0057).
                let filled = self.queue.fill_free_slot(now, modifiers);
                moved.extend(self.promotion_decisions(filled));
                moved
            }
            // Only a peer the serve side already holds a hello for: the map is
            // keyed by live identified connections. A waiter already on the
            // list takes a revised reask contact now; one that queues later
            // is stamped from the identity, as the hello's is.
            ConnectionEvent::IdentityRevised { identity, what } => {
                // A hash changed on a live link bans (`BaseClient.cpp:690-695`).
                let hash_moved = self
                    .identities
                    .get(&peer)
                    .is_some_and(|held| held.user_hash() != identity.user_hash());
                if let Some(held) = Arc::make_mut(&mut self.identities).get_mut(&peer) {
                    *held = identity;
                    if what == IdentityChange::ReaskContact {
                        self.stamp_contact(peer);
                    }
                }
                if hash_moved && !self.spares(peer) {
                    return self.ban_asker(now, peer, modifiers);
                }
                Vec::new()
            }
            ConnectionEvent::Disconnected { .. } => {
                self.aich.forget_link(peer);
                self.dialed.remove(&peer);
                if let Some(moved) = self.on_link_ended(now, peer, modifiers) {
                    return moved;
                }
                self.last_ask.remove(&peer);
                self.served_ranges
                    .retain(|(range_peer, _), _| *range_peer != peer);
                // A waiting peer keeps its queue position across disconnect —
                // disconnected standing (ADR-0057); only a granted peer frees
                // a slot. The transfer flow is wiped either way.
                self.track_holder(now, peer);
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
            // Facts the serve side keeps nothing of. A verification is the
            // link's to bind, which says so as `IdentityBound` (ADR-0041).
            ConnectionEvent::HelloSent
            | ConnectionEvent::IdentityVerified { .. }
            | ConnectionEvent::HelloRefused { .. }
            | ConnectionEvent::SecureIdentFailed { .. }
            | ConnectionEvent::ClientIdOffered { .. } => Vec::new(),
        }
    }

    /// Stamp how `peer`'s identity says it is reached on its wait-list entry
    /// (ADR-0057): its client-UDP reask contact, so an inbound
    /// `OP_REASKFILEPING` matches by IP + UDP port — a peer that named none
    /// stays TCP-reask-only — and whether a dial reaches it once it hangs up,
    /// a High ID or an IPv6 as the link it came on reads it.
    pub(super) fn stamp_contact(&mut self, peer: PeerEndpoint) {
        if let Some(identity) = self.identities.get(&peer) {
            let (udp_port, udp_version) = identity.client_udp_reask().unwrap_or_default();
            let dialable = identity
                .source_coordinate(peer)
                .peer_source()
                .and_then(rmule_primitives::PeerSource::as_peer_endpoint)
                .is_some();
            self.queue.set_contact(
                peer,
                WaiterContact {
                    udp_port: (udp_port != 0).then_some(udp_port),
                    udp_version,
                    dialable,
                },
            );
        }
    }
}

/// Whether `input` is a request stock answers only a client not banned
/// (`ClientTCPSocket.cpp:485`, `:547`, `:660`, `:924`, `:982`, `:1012`, `:1167`,
/// `:1336`, `:1463`, `:1769`): not the session's reports, nor a cancel that only
/// gives a place back.
const fn is_ask(input: &ServeInput) -> bool {
    match input {
        ServeInput::Server(request) => !matches!(
            request,
            ServerEvent::BlockLeft { .. }
                | ServerEvent::SourcesAnswered { .. }
                | ServerEvent::TransferCancelled { .. }
                | ServerEvent::PartsWithoutSlot { .. }
        ),
        _ => false,
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
