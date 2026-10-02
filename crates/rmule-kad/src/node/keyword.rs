//! The Kad Keyword leg (ADR-0062): serving inbound `0x43`/`0x33` from the
//! keyword store, fanning this node's own keyword publishes in ≤ 50-file
//! batches behind the publish gate, and folding `0x3B` results into the one
//! search stream with the residual-token filter a v1 requester applies
//! client-side.

use super::{KadEvent, KadNode, KadNodeDiagnostic, KeywordPublishRound, KeywordSearch};
use crate::keyword::KadKeywordSearchRequest;
use crate::keyword_publisher::{KeywordPublishBatch, MAX_CONCURRENT_STORE_KEY_WALKS};
use crate::keyword_store::{
    KEYWORD_PUBLISH_BATCH_CAP, KadKeywordResult, KeywordFileOutcome, KeywordPublishOutcome,
    KeywordResultRow, decode_publish_key_req, decode_search_key_req, decode_search_key_res,
    encode_publish_key_req, encode_search_key_res,
};
use crate::lookup_walk::{KadLookupWalk, KadPublishEnd, KadSearchEnd, KadWalkPurpose};
use crate::messages::Kad2Message;
use crate::source_result::search_res_target;
use crate::{KadEnvelope, KadId, KadInstant, KadNodeEndpoint, decode_source_result};

impl KadNode {
    /// The keyword store's sweep wake, but only while it holds entries. Its
    /// timer is armed from construction (aMule's `m_lastClean`), so an empty
    /// index would otherwise surface a perpetual 30-min re-arm and keep the node
    /// forever un-idle — nothing to expire, no reason to wake.
    pub(super) fn keyword_sweep_next_wake(&self) -> Option<KadInstant> {
        if self.keyword_store.is_empty() {
            None
        } else {
            self.keyword_store.next_wake()
        }
    }

    /// Route a `KADEMLIA2_SEARCH_RES`. The order is load-bearing: the
    /// endpoint gate comes first, so an unsolicited sender's payload is never
    /// even decoded; the sealed projection (`decode_source_result`) runs only
    /// for a solicited endpoint answering the target it was asked.
    pub(super) fn on_search_res(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
    ) {
        if !self.walks.iter().any(|walk| walk.is_search_endpoint(from)) {
            self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedSearchRes { from });
            return;
        }
        let embedded_target = match search_res_target(envelope) {
            Ok(target) => target,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::MalformedSearchRes { from, error });
                return;
            }
        };
        let Some(walk) = self
            .walks
            .iter_mut()
            .find(|walk| walk.is_search_endpoint(from) && walk.target() == embedded_target)
        else {
            self.emit_diagnostic(KadNodeDiagnostic::SearchResTargetMismatch { from });
            return;
        };
        let (target, purpose) = (walk.target(), walk.purpose());

        // A keyword search rides the same `0x3B` as a source search; the owning
        // walk's purpose picks the decoder (ADR-0062). Both consume rows against
        // the shared 300-result budget; a keyword walk additionally
        // residual-filters and dedups into the one search stream.
        if let KadWalkPurpose::SearchKeyword { .. } = purpose {
            let rows = match decode_search_key_res(envelope) {
                Ok(rows) => rows,
                Err(_) => {
                    self.emit_diagnostic(KadNodeDiagnostic::MalformedKeywordRes { from });
                    return;
                }
            };
            let (accepted, actions) = walk.accept_search_results(rows.len());
            let mut rows = rows;
            rows.truncate(accepted);
            let results = self.merge_keyword_results(target, rows);
            if !results.is_empty() {
                self.emit_event(KadEvent::KeywordsFound {
                    keyword: target,
                    results,
                });
            }
            self.apply_walk_actions(now, purpose, actions);
            return;
        }

        let candidates = match decode_source_result(envelope) {
            Ok(candidates) => candidates,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::MalformedSearchRes { from, error });
                return;
            }
        };
        let (accepted, actions) = walk.accept_search_results(candidates.len());
        if accepted > 0 {
            let mut candidates = candidates;
            candidates.truncate(accepted);
            self.emit_event(KadEvent::SourcesFound { target, candidates });
        }
        self.apply_walk_actions(now, purpose, actions);
    }

    /// Residual-filter (v1 client-side multi-word) and dedup (by file ID, into
    /// the one search stream, ADR-0062) a keyword search's accepted rows,
    /// recording the surfaced file IDs. Returns the newly-surfaced typed
    /// projections; a search already completed (no node-side state) yields none.
    fn merge_keyword_results(
        &mut self,
        target: KadId,
        rows: Vec<KeywordResultRow>,
    ) -> Vec<KadKeywordResult> {
        let Some(search) = self
            .keyword_searches
            .iter_mut()
            .find(|s| s.target == target)
        else {
            return Vec::new();
        };
        let mut merged = Vec::new();
        for row in rows {
            if search.surfaced.contains(&row.file_id) {
                continue;
            }
            let result = row.project();
            if !residual_match(&result, &search.residual_tokens) {
                continue;
            }
            search.surfaced.push(row.file_id);
            merged.push(result);
        }
        merged
    }

    /// The **Kad Storer**'s keyword publish intake (ADR-0062): decode the batch
    /// and index it through the store (which gates UDP-firewalled refusal and
    /// the tolerance check internally), then ack the keyword with the shared
    /// `0x4B` load. A refused batch is wire-silent, like aMule's early return.
    pub(super) fn on_publish_key_req(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
    ) {
        let (keyword, files) = match decode_publish_key_req(envelope) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::UndecodableKeywordReq { from, error });
                return;
            }
        };
        match self.keyword_store.publish_batch(
            now,
            self.config.id,
            self.reachability.udp_firewalled,
            from.ip(),
            keyword,
            files,
        ) {
            KeywordPublishOutcome::Dropped => {
                self.emit_diagnostic(KadNodeDiagnostic::KeywordPublishRefused { from });
            }
            KeywordPublishOutcome::Processed { ack_load, files } => {
                let indexed = files
                    .iter()
                    .filter(|outcome| matches!(outcome, KeywordFileOutcome::Stored { .. }))
                    .count();
                let stored = self.keyword_store.len();
                self.emit_event(KadEvent::KeywordPublishServed {
                    from,
                    keyword,
                    indexed,
                    stored,
                });
                self.send(
                    from,
                    &Kad2Message::PublishRes {
                        file: keyword,
                        load: ack_load,
                        options: 0,
                    },
                );
            }
        }
    }

    /// The **Kad Storer**'s keyword search answer (ADR-0062): decode the request
    /// (`decode_search_key_req` already rejected any unknown operator), look up
    /// the tree-matching, trusted-first rows, and re-encode them into `0x3B`
    /// datagrams. Zero rows answer nothing on the wire (aMule posture); the
    /// served event is emitted either way.
    pub(super) fn on_search_key_req(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
    ) {
        let (keyword, start_position, tree) = match decode_search_key_req(envelope) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::UndecodableKeywordReq { from, error });
                return;
            }
        };
        // `decode_search_key_req` validated the operators, so the store's
        // independent re-validation cannot fail here; a surprise degrades to a
        // zero-row (wire-silent) answer rather than a panic.
        let rows = self
            .keyword_store
            .lookup(now, keyword, start_position, tree.as_ref())
            .unwrap_or_default();
        for envelope in encode_search_key_res(self.config.id, keyword, &rows) {
            self.send_envelope(from, &envelope);
        }
        self.emit_event(KadEvent::KeywordSearchServed {
            from,
            keyword,
            rows: rows.len(),
        });
    }

    /// Start a keyword search walk (the **Kad Requester** role, ADR-0062): the
    /// target is the query's lead keyword ID; the residual tokens and dedup set
    /// live node-side. A query with no ≥ 3-byte token is diagnosed. A target
    /// already walked is resolved by ADR-0062's walk ownership, so every command
    /// naming a target is answered by one `KeywordSearchComplete` for it: a
    /// keyword search walk is joined, a keyword publish walk is preempted, any
    /// other walk answers the command at once with `TargetHeld`.
    pub(super) fn start_keyword_search(
        &mut self,
        now: KadInstant,
        request: &KadKeywordSearchRequest,
    ) {
        let Some(target) = request.target() else {
            self.emit_diagnostic(KadNodeDiagnostic::UnsearchableKeywordQuery);
            return;
        };
        let holder = self
            .walks
            .iter()
            .find(|walk| walk.target() == target)
            .map(KadLookupWalk::purpose);
        match holder {
            None => {}
            Some(KadWalkPurpose::SearchKeyword { .. }) => {
                self.join_keyword_search(target, request);
                return;
            }
            Some(KadWalkPurpose::PublishKeyword { .. }) => {
                self.preempt_keyword_publish(now, target);
            }
            Some(_) => {
                self.emit_event(KadEvent::KeywordSearchComplete {
                    keyword: target,
                    result_rows: 0,
                    ended_by: KadSearchEnd::TargetHeld,
                });
                return;
            }
        }
        self.keyword_searches.push(KeywordSearch {
            target,
            residual_tokens: request.residual_tokens(),
            surfaced: Vec::new(),
        });
        self.start_walk(now, KadWalkPurpose::SearchKeyword { target });
    }

    /// Join a search command to the keyword search already walking `target`: its
    /// residual screen narrows to the tokens both requests share, so it keeps
    /// every row either would keep.
    fn join_keyword_search(&mut self, target: KadId, request: &KadKeywordSearchRequest) {
        let residual = request.residual_tokens();
        if let Some(search) = self
            .keyword_searches
            .iter_mut()
            .find(|search| search.target == target)
        {
            search
                .residual_tokens
                .retain(|token| residual.contains(token));
        }
        self.emit_diagnostic(KadNodeDiagnostic::DuplicateKeywordSearch { target });
    }

    /// End the keyword publish walk holding `keyword` without a completion and
    /// give its round back to the scheduler, due now: it records no load, and
    /// its files are announced by the round that follows the search.
    fn preempt_keyword_publish(&mut self, now: KadInstant, keyword: KadId) {
        self.walks.retain(|walk| walk.target() != keyword);
        let taken = self
            .keyword_publishes
            .iter()
            .position(|round| round.keyword == keyword)
            .map_or(0, |position| {
                self.keyword_publishes.remove(position).files.len()
            });
        self.keyword_publisher.requeue(now, keyword, taken);
        self.emit_diagnostic(KadNodeDiagnostic::KeywordPublishPreempted { keyword });
    }

    /// Every target a walk holds — what the keyword publisher must not start
    /// a round on (ADR-0062, walk ownership).
    fn held_targets(&self) -> Vec<KadId> {
        self.walks.iter().map(KadLookupWalk::target).collect()
    }

    /// Start due keyword publish walks, honoring the publish gate, the
    /// concurrent-walk cap, and the scheduler's 2 s spacing (which yields at most
    /// one start per call). Called on registration and every `tick`.
    pub(super) fn drive_keyword_publishes(&mut self, now: KadInstant) {
        while self.keyword_publish_gate_open()
            && self.active_keyword_publish_walks() < MAX_CONCURRENT_STORE_KEY_WALKS
        {
            let held = self.held_targets();
            let Some(batch) = self.keyword_publisher.poll_due(now, &held) else {
                break;
            };
            self.start_keyword_publish_walk(now, batch);
        }
    }

    /// Launch one keyword publish walk, recording its batch and load tally
    /// node-side. The scheduler hands out only keywords no walk holds.
    fn start_keyword_publish_walk(&mut self, now: KadInstant, batch: KeywordPublishBatch) {
        let keyword = batch.keyword;
        self.keyword_publishes.push(KeywordPublishRound {
            keyword,
            files: batch.files,
            loads: Vec::new(),
        });
        self.start_walk(now, KadWalkPurpose::PublishKeyword { target: keyword });
    }

    /// Fan a keyword publish round's files to one storer as
    /// `KADEMLIA2_PUBLISH_KEY_REQ` packets, chunked at the emit-side 50-file cap
    /// (aMule stores ≤ 50 per packet; a 150-file round is up to three packets).
    pub(super) fn send_keyword_publish(&mut self, to: KadNodeEndpoint, keyword: KadId) {
        let Some(files) = self
            .keyword_publishes
            .iter()
            .find(|round| round.keyword == keyword)
            .map(|round| round.files.clone())
        else {
            return;
        };
        for chunk in files.chunks(KEYWORD_PUBLISH_BATCH_CAP) {
            self.send_envelope(to, &encode_publish_key_req(keyword, chunk));
        }
    }

    /// Fold a completed keyword publish walk's collected loads into the
    /// re-publish embargo, drop its node-side round state, and emit the
    /// completion.
    pub(super) fn complete_keyword_publish(
        &mut self,
        now: KadInstant,
        keyword: KadId,
        acked_stores: usize,
        ended_by: KadPublishEnd,
    ) {
        if let Some(position) = self
            .keyword_publishes
            .iter()
            .position(|round| round.keyword == keyword)
        {
            let round = self.keyword_publishes.remove(position);
            self.keyword_publisher
                .record_completion(now, keyword, &round.loads);
        }
        self.emit_event(KadEvent::KeywordPublishComplete {
            keyword,
            acked_stores,
            ended_by,
        });
    }

    /// The **Kad Publisher** gate (ADR-0062): a live contact to seed from ∧
    /// (TCP-open ∨ buddy connected). A firewalled node without a connected buddy simply does not
    /// publish; the reachability inputs are injected ([`KadReachability`](crate::KadReachability)).
    fn keyword_publish_gate_open(&self) -> bool {
        self.has_live_contact()
            && (!self.reachability.tcp_firewalled || self.reachability.buddy_connected)
    }

    /// The number of keyword publish walks currently in flight (the
    /// concurrent-walk cap's consumer).
    fn active_keyword_publish_walks(&self) -> usize {
        self.walks
            .iter()
            .filter(|walk| matches!(walk.purpose(), KadWalkPurpose::PublishKeyword { .. }))
            .count()
    }

    /// The publisher's contribution to [`next_wake`](Self::next_wake): the
    /// scheduler's next due instant, but only while the gate is open and a walk
    /// slot is free. A closed gate or full slots re-drive on the state change
    /// that clears them (a join, a `set_reachability`, or a walk completing), so
    /// surfacing a due-now wake here instead would livelock.
    pub(super) fn keyword_publish_next_wake(&self) -> Option<KadInstant> {
        if !self.keyword_publish_gate_open()
            || self.active_keyword_publish_walks() >= MAX_CONCURRENT_STORE_KEY_WALKS
        {
            return None;
        }
        self.keyword_publisher.next_wake(&self.held_targets())
    }
}

/// Whether a keyword result's filename contains every residual query token —
/// the v1 requester's client-side multi-word filter (ADR-0062). A row with no
/// filename tag cannot be verified, so it does not match; a single-token query
/// passes trivially (the keyword index already implies its lone token).
fn residual_match(result: &KadKeywordResult, tokens: &[String]) -> bool {
    let Some(filename) = &result.filename else {
        return false;
    };
    let lower = filename.to_lowercase();
    tokens.iter().all(|token| lower.contains(token.as_str()))
}
