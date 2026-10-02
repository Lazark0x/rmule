//! Where a download's next worker comes from: the Low-ID callback leg
//! (ADR-0039) that reaches a firewalled source through its server, and the
//! discovered sources — server-UDP global (ADR-0051) and Kad (ADR-0043) —
//! that backfill the candidate pool while the download runs.

use rmule_peer::natt::CALLBACK_SILENCE_FALLBACK;
use rmule_primitives::{ExchangedSource, Ipv4Endpoint, PeerCrypt, PeerEndpoint, PeerSource};

use crate::DownloadFailure;
use crate::adapters::CallbackKey;
use crate::callback::{CallbackRoute, CallbackSilence};
use crate::diagnostics::WorkerSlot;
use crate::dialable::{DialOrder, resolve_kad_family};
use crate::service::DownloadEvent;

use super::{Decision, DownloadState, LowIdCandidate, LowIdRoad, PendingCallback, Worker};

impl DownloadState {
    /// Resolve an inbound called-back peer's reported `(connected_server, low_id)`
    /// (packed as `reported`) to the pending callback it satisfies, returning that
    /// callback's [`CallbackKey`] and the diagnostics slot it holds (ADR-0039 / ADR-0051).
    /// A per-server *global* callback keyed by the reported server is preferred over
    /// the *connected-server* form (keyed `None`), because the wire cannot say which
    /// relayed the peer — it reports the server it is logged into either way. The
    /// runner reads this in its accept-router arm to register the adopted worker's
    /// command channel, then drives [`Self::on_callback_connected`] with the key.
    pub(crate) fn match_inbound_callback(
        &self,
        reported: CallbackKey,
    ) -> Option<(CallbackKey, WorkerSlot)> {
        if let Some(pending) = self.pending_callbacks.get(&reported) {
            return Some((reported, pending.slot));
        }
        let connected = CallbackKey {
            server: None,
            low_id: reported.low_id,
        };
        self.pending_callbacks
            .get(&connected)
            .map(|pending| (connected, pending.slot))
    }
    /// Release the slot a road that ended without a connection held — a lapsed
    /// callback ([`Self::on_callback_timeout`]) or a retired punch — refill
    /// from the next candidate, and fail `NoUsableSources` if nothing remains
    /// (ADR-0039 / ADR-0051). The ended candidate is offered rung 0 first
    /// ([`Self::on_low_id_road_ended`]), so the refill dials a half a sighting
    /// named while the road was pending.
    fn release_callback_slot(&mut self, pending: PendingCallback) -> Vec<Decision> {
        let mut out = Vec::new();
        self.free_slots.insert(pending.slot.as_usize());
        self.on_low_id_road_ended(pending.candidate);
        self.fill(&mut out);
        if self.workers.is_empty()
            && self.pending_callbacks.is_empty()
            && self.no_usable_candidate()
            && !self.scheduler.is_complete()
        {
            out.push(Decision::Fail(DownloadFailure::NoUsableSources));
        }
        out
    }
    /// Adopt a called-back Low-ID peer that has dialed in and identified (ADR-0039 /
    /// ADR-0051), matched by [`Self::match_inbound_callback`] to `key` — connected-server
    /// (`server: None`) or per-server global (`Some`), one path now. **Bind without
    /// assign**: register the peer on the slot its callback held, but leave it
    /// `connected: false` and do *not* assign a part. The peer dialed in and emits
    /// its own `Connected` event, which drives the normal assignment path
    /// ([`Self::on_worker_event`] → `Connected` → `assign`) exactly like a dialed
    /// worker — so the runner forwards that `Connected` rather than dropping it
    /// (this is what let the worker-pool `Connected`-drop filter go).
    /// Cancel the now-satisfied callback deadline. An unknown/duplicate key is ignored.
    pub(crate) fn on_callback_connected(
        &mut self,
        key: CallbackKey,
        peer: PeerEndpoint,
    ) -> Vec<Decision> {
        let Some(pending) = self.pending_callbacks.remove(&key) else {
            return Vec::new();
        };
        self.workers.insert(
            peer,
            Worker {
                slot: pending.slot,
                connected: false,
            },
        );
        vec![
            Decision::CancelCallbackTimeout { key },
            Decision::Emit(DownloadEvent::PeerSelected {
                download_id: self.download_id,
                peer,
            }),
        ]
    }
    /// A requested callback lapsed without the peer dialing in (ADR-0039 / ADR-0051): the
    /// runner's heap fired for `key`. Retract its routing index (its deadline was
    /// already fired — a `CancelCallbackTimeout`) and release the held slot to
    /// refill from the next candidate; fail `NoUsableSources` if nothing remains.
    /// An unknown key (already adopted) is ignored. `OP_CALLBACK_FAIL` carries no
    /// id, so it cannot be attributed here — the deadline is the only release path.
    ///
    /// One exception keeps the slot: a buddy callback whose `0x52` went to a
    /// known buddy endpoint under the primary (aMule, captured) spelling of
    /// its `TAG_BUDDYHASH`, and whose other spelling names a different ID,
    /// gets one more `0x52` under that spelling and the same wait again
    /// ([`Self::fallback_spelling_callback`]).
    pub(crate) fn on_callback_timeout(&mut self, key: CallbackKey) -> Vec<Decision> {
        if let Some(retry) = self.fallback_spelling_callback(key) {
            return retry;
        }
        if let Some(pending) = self.pending_callbacks.get_mut(&key)
            && pending.traversal_begun
            && pending.traversal_retired.is_none()
        {
            // The slot waits on the attempt: a traversal still
            // running keeps it until its Tunnel, its retirement or its bound.
            pending.slot_lapsed = true;
            return Vec::new();
        }
        let Some(pending) = self.pending_callbacks.remove(&key) else {
            return Vec::new();
        };
        let mut out = vec![Decision::CancelCallbackTimeout { key }];
        out.extend(self.release_callback_slot(pending));
        out
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
    fn fallback_spelling_callback(&mut self, key: CallbackKey) -> Option<Vec<Decision>> {
        let pending = self.pending_callbacks.get_mut(&key)?;
        if pending.road != LowIdRoad::BuddyCallback || pending.fallback_spelling_sent {
            return None;
        }
        let buddy = pending.candidate.buddy?;
        buddy.buddy_udp?;
        let fallback = buddy.fallback_buddy_id()?;
        pending.fallback_spelling_sent = true;
        let mut candidate = pending.candidate;
        candidate.buddy = Some(crate::callback::BuddyContact {
            buddy_id: fallback,
            ..buddy
        });
        Some(vec![
            Decision::RequestFallbackBuddyCallback { candidate },
            Decision::ArmCallbackTimeout {
                key,
                after: self.callback_timeout,
            },
        ])
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
    pub(crate) fn on_callback_silence(&mut self, key: CallbackKey) -> Vec<Decision> {
        let Some(pending) = self.pending_callbacks.get_mut(&key) else {
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
            LowIdRoad::DirectUdp => pending
                .candidate
                .kad_udp
                .map(|target_kad_udp| CallbackRoute::DirectUdp { target_kad_udp }),
            LowIdRoad::BuddyCallback => pending.candidate.buddy.map(|buddy| CallbackRoute::Buddy {
                buddy_id: buddy.buddy_id,
                buddy_udp: buddy.buddy_udp,
            }),
            LowIdRoad::Callback | LowIdRoad::Punch => None,
        }
        .unwrap_or(CallbackRoute::Server { low_id: key.low_id });
        pending.traversal_begun = true;
        fall_to_nat_traversal(
            pending.candidate,
            CallbackSilence::After {
                taken,
                elapsed: CALLBACK_SILENCE_FALLBACK,
            },
        )
        .to_vec()
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
        key: CallbackKey,
        reason: crate::diagnostics::NattRetirement,
    ) -> Vec<Decision> {
        if reason.ends_buddy_callback() {
            return self.on_buddy_callback_retired(key, reason);
        }
        let Some(pending) = self.pending_callbacks.get_mut(&key) else {
            return Vec::new();
        };
        if pending.traversal_retired.is_some() {
            return Vec::new();
        }
        pending.traversal_retired = Some(reason);
        if pending.slot_lapsed {
            // The callback's own deadline already came and went while the
            // slot waited on this attempt: its end is the lapse.
            return self.lapse_callback(key);
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
        let pending = *pending;
        self.pending_callbacks.remove(&key);
        // One cancel ends both registrations and both deadlines, the claim
        // included — the same end an adoption or a lapse gets, because this
        // *is* the candidate's lapse.
        let mut out = vec![Decision::CancelCallbackTimeout { key }];
        out.extend(self.release_callback_slot(pending));
        out
    }
    /// `key`'s **traversal bound** came due: the attempt it was
    /// armed for can no longer be running, reported or not. A slot still
    /// waiting on it lapses now; a callback whose traversal already ended, or
    /// that was adopted or lapsed, is someone else's clock and is left alone.
    pub(crate) fn on_traversal_bound(&mut self, key: CallbackKey) -> Vec<Decision> {
        match self.pending_callbacks.get(&key) {
            Some(pending) if pending.traversal_retired.is_none() => self.lapse_callback(key),
            _ => Vec::new(),
        }
    }
    /// End `key`'s callback as a lapse: both roads' registrations and
    /// deadlines go, and the slot is released to the next candidate.
    fn lapse_callback(&mut self, key: CallbackKey) -> Vec<Decision> {
        let Some(pending) = self.pending_callbacks.remove(&key) else {
            return Vec::new();
        };
        let mut out = vec![Decision::CancelCallbackTimeout { key }];
        out.extend(self.release_callback_slot(pending));
        out
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
        key: CallbackKey,
        reason: crate::diagnostics::NattRetirement,
    ) -> Vec<Decision> {
        let Some(pending) = self.pending_callbacks.get_mut(&key) else {
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
            if pending.candidate.natt_facts().admits_coordinator() {
                pending.traversal_begun = true;
                return fall_to_nat_traversal(
                    pending.candidate,
                    CallbackSilence::NoCallbackPossible,
                )
                .to_vec();
            }
        }
        let pending = *pending;
        self.pending_callbacks.remove(&key);
        let mut out = vec![Decision::CancelCallbackTimeout { key }];
        out.extend(self.release_callback_slot(pending));
        out
    }
    /// Fold sources discovered over server-UDP (ADR-0051 **global sources**) from
    /// `source_server` into the candidate pool. High-ID sources are dialable now and
    /// pooled directly. A Low-ID global source is callbackable only via its own
    /// `source_server`, never the connected one (ADR-0051, ADR-0039 per-server) — so when
    /// rmule is callback-capable it is held, tagged with that server, to drive a
    /// [`Decision::RequestGlobalCallback`]; when not, it is dropped, honestly. Then
    /// free slots fill.
    pub(crate) fn on_global_sources(
        &mut self,
        source_server: Ipv4Endpoint,
        sources: Vec<PeerSource>,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        for source in sources {
            if let Some(first) = source.as_peer_endpoint() {
                // Through the one High-ID pooling seam, so a `0x9E` sighting
                // keeps the spent and owner rules an exchanged or Kad one
                // does (ADR-0090 "Source ownership").
                self.pool_high_id(
                    DialOrder {
                        first,
                        fallback: None,
                    },
                    None,
                );
            } else if let Some(candidate) =
                // Low-ID global source: hold it, tagged with the server that
                // answered (low ids are unique only per server), for whichever
                // road the admission rule leaves open — a per-server callback,
                // or a punch its own facts admit a coordinator for. A `0x9E`
                // answer carries no crypt material, so the record it yields is
                // honestly bare of everything but id and port, which is the one
                // shape neither road can reach; `fill` is where that is judged,
                // once, rather than here and there.
                LowIdCandidate::from_source(
                    ExchangedSource::plain(source),
                    Some(source_server),
                )
            {
                self.admit_low_id(candidate);
            }
        }
        self.fill(&mut out);
        out
    }
    /// Pool a Low-ID candidate, merging it into an existing record for the same
    /// source rather than queueing it twice (ADR-0039 / ADR-0051).
    ///
    /// The record's own `source_server` picks the pool, so the two stay what
    /// their docs say they are: the connected-server queue holds only
    /// connected-server records. A candidate already on a road — its callback
    /// or punch pending, or its IPv6 half being dialed (rung 0) — is not
    /// re-pooled, since a second slot for the same peer would buy nothing; the
    /// sighting folds into the record that road holds instead, so a fact it
    /// names (a new IPv6 half above all) is still there when the road ends
    /// without a connection ([`Self::on_low_id_road_ended`]). A
    /// candidate naming a distrusted User Hash is not pooled at all.
    pub(super) fn admit_low_id(&mut self, mut candidate: LowIdCandidate) {
        if self.distrusts(candidate.user_hash) {
            return;
        }
        // A sighting that names the buddy by ID alone takes the endpoint the
        // source's own hello named earlier this run: the row is
        // silent about where the buddy is, the hello was not. A row that
        // names an endpoint is the newer statement and keeps its own.
        if let (Some(hash), Some(buddy)) = (candidate.user_hash, candidate.buddy)
            && buddy.buddy_udp.is_none()
            && let Some(buddy_udp) = self.hello_buddies.get(&hash)
        {
            candidate.learn_hello_buddy(*buddy_udp);
        }
        if let Some(pending) = self.pending_callbacks.get_mut(&candidate.key()) {
            pending.candidate.merge(candidate);
            return;
        }
        if self.merge_into_direct_ipv6(candidate) {
            return;
        }
        let pool = if candidate.source_server.is_none() {
            &mut self.low_id_pool
        } else {
            &mut self.low_id_global_pool
        };
        match pool.iter_mut().find(|held| held.key() == candidate.key()) {
            Some(held) => held.merge(candidate),
            None => pool.push_back(candidate),
        }
    }
    /// A worker's peer named its **serving buddy** in its hello (ADR-0061).
    /// Remembered under the peer's User Hash — the one name
    /// that survives its address changing under a NAT, and the key the buddy
    /// road cannot run without — for every later sighting of the source
    /// ([`Self::admit_low_id`]), and folded at once into every record this
    /// run already holds for it, since the hello is the newest statement of
    /// where the buddy is. A peer that has not identified has no hash to key
    /// it by and is ignored.
    pub(crate) fn on_hello_buddy(&mut self, peer: PeerEndpoint, buddy_udp: Ipv4Endpoint) {
        let Some(hash) = self.peer_user_hashes.get(&peer).copied() else {
            return;
        };
        self.hello_buddies.insert(hash, buddy_udp);
        self.low_id_pool
            .iter_mut()
            .chain(self.low_id_global_pool.iter_mut())
            .chain(
                self.pending_callbacks
                    .values_mut()
                    .map(|p| &mut p.candidate),
            )
            .chain(self.direct_ipv6_dials.values_mut())
            .filter(|held| held.user_hash == Some(hash))
            .for_each(|held| held.learn_hello_buddy(buddy_udp));
    }
    /// Kad-discovered sources (ADR-0043, widened to carry a row's rung-1
    /// facts). Every row
    /// arriving here passed the sealed **Kad Source Row Projection**, which
    /// tells the two shapes apart:
    ///
    /// - a **dialable** row (direct High-ID, already settled on the family
    ///   the Dial Chooser picked, or `ip6`-rescued) joins the candidate pool,
    ///   as it always has;
    /// - a **buddy-reachable** row (source type 3/5) becomes a
    ///   [`LowIdCandidate`] carrying the buddy, the User Hash and the crypt
    ///   bits its `TAG_ENCRYPTION` stated — the only channel that can give a
    ///   download a buddy. It takes no *server* callback: there is no server
    ///   in a Kad row to relay one ([`LowIdCandidate::from_kad`]); its buddy
    ///   relays one instead, or coordinates the punch;
    /// - a **direct-UDP-callable** row (source type 6) becomes a buddyless
    ///   [`LowIdCandidate`] whose own Kad UDP endpoint takes the `0x95`.
    ///
    /// Either callback candidate carries the row's `ip6` as its IPv6 half,
    /// which rung 0 of the route tree dials when we hold one (ADR-0087).
    ///
    /// Anything else — a refusal, or a buddy row whose contact was unusable —
    /// is dropped, because nothing names a way to reach it. Then free slots
    /// fill.
    pub(crate) fn on_kad_sources(
        &mut self,
        sources: Vec<crate::kad_sources::KadSource>,
    ) -> Vec<Decision> {
        let mut out = Vec::new();
        for source in sources {
            // A High-ID row with `ip6` is dialed first in the family the Dial
            // Chooser picks, its other half kept (ADR-0087).
            if let Some(order) = resolve_kad_family(&source, self.dial) {
                // The row's `TAG_ENCRYPTION` byte and hash, at
                // both halves.
                let crypt = PeerCrypt::from_record(source.connect_options, source.user_hash);
                for half in order.halves() {
                    self.note_peer_crypt(half, crypt);
                }
                self.pool_high_id(order, source.user_hash);
            } else if let Some(candidate) = LowIdCandidate::from_kad_row(&source) {
                self.admit_low_id(candidate);
            }
        }
        self.fill(&mut out);
        out
    }

    /// Whether this run already knows `source` (ADR-0089's amendment): a
    /// High-ID endpoint pooled, worked, remote-queued or spent; a Low-ID
    /// candidate pooled or awaiting its callback. A second link naming it
    /// adds nothing, so it is not counted as a new source.
    pub(crate) fn knows_source(&self, source: ExchangedSource) -> bool {
        if let Some(peer) = source.as_peer_endpoint() {
            return self.holds(peer) || self.spent.contains(&peer);
        }
        LowIdCandidate::from_connected_server(source).is_some_and(|candidate| {
            let key = candidate.into_inner().key();
            self.pending_callbacks.contains_key(&key)
                || self.low_id_pool.iter().any(|held| held.key() == key)
        })
    }

    /// Fold the sources a server session answered while the run was already
    /// running (ADR-0097, "A download's sources are independent"): the
    /// operator connected after the run started on Kad, or a session was
    /// re-made. They are the connected server's, exactly as the run's first
    /// answer would have been — High-ID rows pooled with the crypt side they
    /// stated, Low-ID rows held for a callback through that server. Then free
    /// slots fill.
    pub(crate) fn on_server_sources(&mut self, sources: Vec<ExchangedSource>) -> Vec<Decision> {
        let mut out = Vec::new();
        for source in sources {
            if let Some(first) = source.as_peer_endpoint() {
                let crypt = source.peer_crypt();
                self.note_peer_crypt(first, crypt);
                self.pool_high_id(
                    DialOrder {
                        first,
                        fallback: None,
                    },
                    crypt.user_hash(),
                );
            } else if let Some(candidate) = LowIdCandidate::from_connected_server(source) {
                self.admit_low_id(candidate.into_inner());
            }
        }
        self.fill(&mut out);
        out
    }
}

/// The punch, and the bound the slot waiting on it keeps (ADR-0091 "Attempt lifecycle"):
/// the attempt runs its whole budget from its Begin —
/// eMuleAI's `NAT_TRAVERSAL_RENDEZVOUS_TIMEOUT` (`Opcodes.h:176`) — and ends at
/// the first settle or tick past it, so one dial's bound and one redial
/// interval of slack cover the latest its end can be reported.
pub(super) fn fall_to_nat_traversal(
    candidate: LowIdCandidate,
    silence: CallbackSilence,
) -> [Decision; 2] {
    [
        Decision::FallToNatTraversal { candidate, silence },
        Decision::ArmTraversalBound {
            key: candidate.key(),
            after: TRAVERSAL_SLOT_BOUND,
        },
    ]
}

/// How long a slot may wait on the **Traversal Attempt** it fell to: the
/// attempt's budget plus a redial interval, the latest the front reports its
/// end.
pub(crate) const TRAVERSAL_SLOT_BOUND: std::time::Duration =
    rmule_peer::natt::RENDEZVOUS_TIMEOUT.saturating_add(std::time::Duration::from_secs(5));
