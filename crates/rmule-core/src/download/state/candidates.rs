//! Where a download's next worker comes from: the Low-ID callback leg
//! (ADR-0039) that reaches a firewalled source through its server, and the
//! discovered sources — server-UDP global (ADR-0051) and Kad (ADR-0043) —
//! that backfill the candidate pool while the download runs.

use std::time::Instant;

use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::PeerEndpoint;

use crate::DownloadFailure;
use crate::adapters::CallbackKey;
use crate::callback::CallbackSilence;
use crate::diagnostics::WorkerSlot;
use crate::download::source_book::{Adopted, Deadline};
use crate::service::DownloadEvent;
use crate::service::PeerReachRoute;

use super::{Decision, DownloadState, LowIdCandidate, LowIdRoad};

/// What a called-back peer's connection became (ADR-0039): the answer
/// [`DownloadState::on_callback_connected`] gives the runner, which holds the
/// connection's worker.
#[derive(Debug)]
pub(crate) struct CallbackLanding {
    /// The slot the connection works in as the callback's worker. `None` when
    /// it is surplus: a live worker already holds its endpoint, so the
    /// callback's record joined that worker's and its slot freed — the
    /// connection must not replace the live worker's channel — or the
    /// callback was no longer pending.
    pub(crate) worker_slot: Option<WorkerSlot>,
    /// What the landing decided.
    pub(crate) decisions: Vec<Decision>,
}

impl DownloadState {
    /// Resolve the key an adopted connection was handed over under to the
    /// pending callback it satisfies (ADR-0039 / ADR-0051). A per-server
    /// *global* callback keyed by the reported server is preferred over the
    /// *connected-server* form (keyed `None`), because the wire cannot say which
    /// relayed the peer — it reports the server it is logged into either way.
    /// The runner reads this in its accept-router arm, then drives
    /// [`Self::on_callback_connected`] with the key.
    pub(crate) fn match_inbound_callback(&self, reported: CallbackKey) -> Option<CallbackKey> {
        if self.callback_slots.contains_key(&reported) {
            return Some(reported);
        }
        let connected = CallbackKey {
            server: None,
            low_id: reported.low_id,
        };
        self.callback_slots
            .contains_key(&connected)
            .then_some(connected)
    }

    /// Whether any callback road holds a slot: it keeps a run with no worker
    /// alive (ADR-0039).
    pub(crate) fn has_pending_callbacks(&self) -> bool {
        !self.callback_slots.is_empty()
    }

    /// One of `key`'s road deadlines came due at `now` (ADR-0039, ADR-0091).
    pub(super) fn expire(
        &mut self,
        now: Instant,
        key: CallbackKey,
        deadline: Deadline,
    ) -> Vec<Decision> {
        match deadline {
            Deadline::SilenceFallback => self.on_callback_silence(now, key),
            Deadline::SlotRelease => self.on_callback_timeout(now, key),
            Deadline::TraversalBound => self.on_traversal_bound(now, key),
        }
    }

    /// End `key`'s road without a connection — a lapsed callback
    /// ([`Self::on_callback_timeout`]) or a retired punch: its registration is
    /// released, its slot goes to the next candidate, and the download fails
    /// `NoUsableSources` if nothing remains (ADR-0039 / ADR-0051). The ended
    /// candidate's record is offered rung 0 first
    /// ([`SourceBook::end_callback`](crate::download::source_book::SourceBook::end_callback)),
    /// so the refill dials a half a sighting named while the road was pending.
    fn release_callback_slot(&mut self, now: Instant, key: CallbackKey) -> Vec<Decision> {
        let mut out = vec![Decision::EndCallback { key }];
        if let Some(slot) = self.callback_slots.remove(&key) {
            self.free_slots.insert(slot.as_usize());
        }
        let _ = self.sources.end_callback(key, self.dial);
        self.fill(now, &mut out);
        if self.out_of_sources() {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
        out
    }
    /// Adopt a called-back Low-ID peer that has dialed in and identified (ADR-0039 /
    /// ADR-0051), matched by [`Self::match_inbound_callback`] to `key` — connected-server
    /// (`server: None`) or per-server global (`Some`), one path now. Its
    /// record keeps its candidate and key beside the worker. **Bind without
    /// assign**: register the peer on the slot its callback held, still
    /// short of its handshake, and do *not* assign a part. The peer dialed in and emits
    /// its own `Connected` event, which drives the normal assignment path
    /// ([`Self::on_worker_event`] → `Connected` → `assign`) exactly like a dialed
    /// worker — so the runner forwards that `Connected` rather than dropping it
    /// (this is what let the worker-pool `Connected`-drop filter go).
    /// The road's deadlines end with it, and its registration is released. An
    /// unknown/duplicate key is ignored.
    ///
    /// The landing names the slot the connection works in, so the runner
    /// registers its worker only when there is one: a connection landing on an
    /// endpoint a live worker already holds is surplus, and that worker keeps
    /// its channel.
    pub(crate) fn on_callback_connected(
        &mut self,
        now: Instant,
        key: CallbackKey,
        peer: PeerEndpoint,
    ) -> CallbackLanding {
        let Some(slot) = self.callback_slots.remove(&key) else {
            return CallbackLanding {
                worker_slot: None,
                decisions: Vec::new(),
            };
        };
        if self.sources.adopt(key, peer) == Some(Adopted::Worker) {
            self.worker_slots.insert(peer, slot);
            return CallbackLanding {
                worker_slot: Some(slot),
                decisions: vec![
                    Decision::EndCallback { key },
                    Decision::Emit(DownloadEvent::PeerSelected {
                        download_id: self.download_id,
                        peer,
                    }),
                ],
            };
        }
        // The peer's endpoint was already worked: the callback's record joined
        // that worker's, and its slot frees.
        let mut decisions = vec![Decision::EndCallback { key }];
        self.free_slots.insert(slot.as_usize());
        self.fill(now, &mut decisions);
        CallbackLanding {
            worker_slot: None,
            decisions,
        }
    }
    /// A requested callback lapsed without the peer dialing in (ADR-0039 /
    /// ADR-0051): `key`'s slot-release deadline came due. Release its
    /// registration and the held slot to refill from the next candidate; fail
    /// `NoUsableSources` if nothing remains. An unknown key (already adopted)
    /// is ignored. `OP_CALLBACK_FAIL` carries no
    /// id, so it cannot be attributed here — the deadline is the only release path.
    ///
    /// One exception keeps the slot: a buddy callback whose `0x52` went to a
    /// known buddy endpoint under the primary (aMule, captured) spelling of
    /// its `TAG_BUDDYHASH`, and whose other spelling names a different ID,
    /// gets one more `0x52` under that spelling and the same wait again
    /// ([`Self::fallback_spelling_callback`]).
    fn on_callback_timeout(&mut self, now: Instant, key: CallbackKey) -> Vec<Decision> {
        if let Some(retry) = self.fallback_spelling_callback(now, key) {
            return retry;
        }
        let Some(pending) = self.sources.road_mut(key) else {
            return Vec::new();
        };
        if pending.traversal_begun && pending.traversal_retired.is_none() {
            // The slot waits on the attempt: a traversal still
            // running keeps it until its Tunnel, its retirement or its bound.
            pending.slot_lapsed = true;
            return Vec::new();
        }
        self.release_callback_slot(now, key)
    }
    /// The buddy callback's second spelling (ADR-0061): aMule
    /// writes `TAG_BUDDYHASH` big-endian (captured), eMule 0.70b and eMuleAI
    /// word-ordered (source-derived), and the row cannot say which family
    /// wrote it. The primary went first; only its silence through the whole
    /// wait earns this one extra `0x52`, never both at once — an rmule buddy
    /// would relay both, and an aMule one would hand its firewalled node a
    /// callback it drops.
    ///
    /// Only for a buddy with a known endpoint: one datagram to the same buddy.
    /// A buddy named by ID alone was reached by a Callback Walk toward the
    /// primary, and the other spelling lives elsewhere in the keyspace — a
    /// second walk, not a second datagram.
    fn fallback_spelling_callback(
        &mut self,
        now: Instant,
        key: CallbackKey,
    ) -> Option<Vec<Decision>> {
        let mut candidate = self.sources.callback_candidate(key)?;
        let callback_timeout = self.callback_timeout;
        let pending = self.sources.road_mut(key)?;
        if pending.road != LowIdRoad::BuddyCallback || pending.fallback_spelling_sent {
            return None;
        }
        let buddy = candidate.buddy?;
        buddy.buddy_udp?;
        let fallback = buddy.fallback_buddy_id()?;
        pending.fallback_spelling_sent = true;
        pending.arm(Deadline::SlotRelease, now + callback_timeout);
        candidate.buddy = Some(crate::callback::BuddyContact {
            buddy_id: fallback,
            ..buddy
        });
        Some(vec![Decision::RequestFallbackBuddyCallback {
            candidate,
            want_sources: self.sources.wants_sources_for(key, now),
        }])
    }
    /// `key`'s callback has been silent for [`CALLBACK_SILENCE_FALLBACK`]
    /// (ADR-0091): the 12 s deadline the brain armed beside the 30 s one has
    /// fired. While the callback is still pending, hand its candidate's facts
    /// to the one ADR-0061 selector as a [`Decision::FallToNatTraversal`] — the
    /// callback assumed we are reachable, and twelve seconds of nothing is the
    /// evidence that, for this target, we are not.
    ///
    /// **Nothing is retracted.** The slot stays held and its 30 s deadline
    /// stays armed: a punch is an *additional* attempt, the callback may still
    /// land, and whichever connection arrives first takes the slot — an
    /// adoption through [`Self::on_callback_connected`], or the punched Tunnel
    /// this decision begins. A key that is no longer pending (already adopted,
    /// already lapsed) returns nothing, which is what a callback that landed at
    /// eleven seconds gets.
    ///
    /// The *whether* was decided at arming: only a candidate whose facts admit
    /// a coordinator got a 12 s deadline, so this answers with what it holds
    /// rather than judging the rung a second time.
    fn on_callback_silence(&mut self, now: Instant, key: CallbackKey) -> Vec<Decision> {
        let Some(candidate) = self.sources.callback_candidate(key) else {
            return Vec::new();
        };
        let Some(pending) = self.sources.road_mut(key) else {
            return Vec::new();
        };
        if pending.road == LowIdRoad::Punch {
            // The callback this deadline was armed for is over (its Callback Walk failed)
            // and the candidate already fell: there is
            // no invitation left whose silence could be measured.
            return Vec::new();
        }
        if pending.traversal_retired.is_some() {
            // Every coordinator that could introduce us to this candidate has
            // already been asked and none did (ADR-0091). A second
            // fallback would re-run a decision whose answer is on record.
            return Vec::new();
        }
        // The selector reads `taken` only to refuse falling back from
        // something that was never a callback. On the server road both forms
        // are a server relaying an invitation — the connected server (`0x1C`,
        // ADR-0039) or the source's own (`OP_GLOBCALLBACKREQUEST`, ADR-0051);
        // on the buddy road it is the `0x52` the buddy relays; on
        // the direct-UDP road it is the `0x95` the candidate itself answers.
        let taken = match pending.road {
            LowIdRoad::DirectUdp => candidate
                .kad_udp
                .map(|target_kad_udp| PeerReachRoute::DirectUdp { target_kad_udp }),
            LowIdRoad::BuddyCallback => candidate.buddy.map(|buddy| match buddy.buddy_udp {
                Some(buddy_udp) => PeerReachRoute::Buddy {
                    buddy_id: buddy.buddy_id,
                    emitted_to: Some(buddy_udp),
                },
                None => PeerReachRoute::CallbackWalk {
                    buddy_id: buddy.buddy_id,
                },
            }),
            LowIdRoad::Callback | LowIdRoad::Punch => None,
        }
        .unwrap_or(PeerReachRoute::Server { low_id: key.low_id });
        pending.traversal_begun = true;
        vec![self.fall_to_nat_traversal(
            now,
            candidate,
            CallbackSilence::After {
                taken,
                elapsed: CALLBACK_SILENCE_FALLBACK,
            },
        )]
    }
    /// The **Traversal Attempt** toward `key`'s candidate retired (ADR-0091),
    /// or was never opened at all because no coordinator could be
    /// asked. Either way the source is *temporarily unreachable by
    /// traversal*, with `reason` on record.
    ///
    /// **What it costs is what the candidate's road was.**
    ///
    /// On the callback road the punch ran *beside* a relayed invitation —
    /// ADR-0091's "two deadlines, one key" — so the slot it holds and the 30 s
    /// that governs it stay exactly where they were: the server may still relay
    /// the callback, and forfeiting the slot because the other road closed
    /// would cost the download a source it may still get. What ends is the
    /// claim: nothing will ever dial a Tunnel toward this target for this
    /// callback now, and a claim left standing holds the one entry that
    /// target's hash has in a table another download may want.
    ///
    /// On the buddy-callback and direct-UDP roads nothing is retracted at
    /// all: both claim the same **Dial-Back Claim** entry (keyed by the candidate's User Hash),
    /// and it is the one
    /// entry the dial-back is adopted through.
    ///
    /// On the punch road there is no other road. No callback was requested —
    /// none could be — so waiting out the slot-release deadline would buy the
    /// download nothing but thirty seconds, and the candidate lapses here
    /// instead: its slot is released to the next candidate, and a download with
    /// none left fails `NoUsableSources` at once, which is what it did before
    /// the rung was reachable at all.
    ///
    /// Idempotent, and quiet for a callback that has already been adopted or
    /// lapsed — a retirement can arrive after either.
    pub(crate) fn on_traversal_retired(
        &mut self,
        now: Instant,
        key: CallbackKey,
        reason: crate::diagnostics::NattRetirement,
    ) -> Vec<Decision> {
        if reason.ends_buddy_callback() {
            return self.on_buddy_callback_retired(now, key, reason);
        }
        let Some(pending) = self.sources.road_mut(key) else {
            return Vec::new();
        };
        if pending.traversal_retired.is_some() {
            return Vec::new();
        }
        pending.traversal_retired = Some(reason);
        if pending.slot_lapsed {
            // The callback's own deadline already came and went while the
            // slot waited on this attempt: its end is the lapse.
            return self.lapse_callback(now, key);
        }
        match pending.road {
            LowIdRoad::Callback => return vec![Decision::RetractTunnelClaim { key }],
            // The punch was claimed under the same User Hash entry the
            // dial-back will be adopted through, so retracting it would close
            // the road that is still open (the direct-UDP road claims the
            // same way).
            LowIdRoad::BuddyCallback | LowIdRoad::DirectUdp => return Vec::new(),
            LowIdRoad::Punch => {}
        }
        // The road's end takes its registration and its deadlines, the claim
        // included — the same end an adoption or a lapse gets, because this
        // *is* the candidate's lapse.
        self.release_callback_slot(now, key)
    }
    /// `key`'s **traversal bound** came due: the attempt it was
    /// armed for can no longer be running, reported or not. A slot still
    /// waiting on it lapses now; a callback whose traversal already ended, or
    /// that was adopted or lapsed, is someone else's clock and is left alone.
    fn on_traversal_bound(&mut self, now: Instant, key: CallbackKey) -> Vec<Decision> {
        match self.sources.road(key) {
            Some(pending) if pending.traversal_retired.is_none() => self.lapse_callback(now, key),
            _ => Vec::new(),
        }
    }
    /// End `key`'s callback as a lapse: both roads' registrations and
    /// deadlines go, and the slot is released to the next candidate.
    fn lapse_callback(&mut self, now: Instant, key: CallbackKey) -> Vec<Decision> {
        if self.sources.road(key).is_none() {
            return Vec::new();
        }
        self.release_callback_slot(now, key)
    }
    /// `key`'s **buddy-callback road** is over before any dial-back could
    /// answer it: its Callback Walk met nobody near the buddy ID,
    /// or could not start. aMule's own `FINDSOURCE` source just waits out its
    /// reask in `DS_WAITCALLBACKKAD` (`PartFile.cpp:1826`); rmule instead
    /// hands the candidate to its next road now, as the punch road's own end
    /// does, because a slot held for an invitation that never left buys the
    /// download nothing.
    ///
    /// The candidate's road becomes the punch. When a punch is already running
    /// (the 12 s fallback fired first) it simply is the road now; when none
    /// was begun and the facts admit a coordinator, it falls now, with no
    /// callback silence to measure; otherwise — no coordinator, or a punch
    /// that already retired — nothing is left, and the slot goes to the next
    /// candidate.
    fn on_buddy_callback_retired(
        &mut self,
        now: Instant,
        key: CallbackKey,
        reason: crate::diagnostics::NattRetirement,
    ) -> Vec<Decision> {
        let Some(candidate) = self.sources.callback_candidate(key) else {
            return Vec::new();
        };
        let Some(pending) = self.sources.road_mut(key) else {
            return Vec::new();
        };
        // A direct-UDP `0x95` that never left ends its road the same way
        // The invitation is over before anything could answer.
        if !matches!(
            pending.road,
            LowIdRoad::BuddyCallback | LowIdRoad::DirectUdp
        ) {
            return Vec::new();
        }
        tracing::debug!(?key, ?reason, "the buddy-callback road retired");
        pending.road = LowIdRoad::Punch;
        if pending.traversal_retired.is_none() {
            if pending.traversal_begun {
                return Vec::new();
            }
            if candidate
                .natt_facts(self.callback_capability.server())
                .admits_coordinator()
            {
                pending.traversal_begun = true;
                return vec![self.fall_to_nat_traversal(
                    now,
                    candidate,
                    CallbackSilence::NoCallbackPossible,
                )];
            }
        }
        self.release_callback_slot(now, key)
    }

    /// The punch at `now`, and the bound the slot waiting on it keeps, set on
    /// the candidate's record (ADR-0091 "Attempt lifecycle"): the attempt runs
    /// its whole budget from its Begin — eMuleAI's
    /// `NAT_TRAVERSAL_RENDEZVOUS_TIMEOUT` (`Opcodes.h:176`) — and ends at the
    /// first settle or tick past it, so one dial's bound and one redial
    /// interval of slack cover the latest its end can be reported.
    pub(super) fn fall_to_nat_traversal(
        &mut self,
        now: Instant,
        candidate: LowIdCandidate,
        silence: CallbackSilence,
    ) -> Decision {
        let key = candidate.key();
        if let Some(pending) = self.sources.road_mut(key) {
            pending.arm(Deadline::TraversalBound, now + TRAVERSAL_SLOT_BOUND);
        }
        Decision::FallToNatTraversal {
            candidate,
            silence,
            want_sources: self.sources.wants_sources_for(key, now),
        }
    }
}

/// How long a slot may wait on the **Traversal Attempt** it fell to: the
/// attempt's budget plus a redial interval, the latest the front reports its
/// end.
pub(crate) const TRAVERSAL_SLOT_BOUND: std::time::Duration =
    rmule_peer::natt::RENDEZVOUS_TIMEOUT.saturating_add(std::time::Duration::from_secs(5));
