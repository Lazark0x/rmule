//! The Kad pump's keyword-search subscribers: one walk per
//! lead keyword, and every search on that keyword subscribed to it with its own
//! query. A `KeywordsFound` batch reaches each subscriber screened by that
//! subscriber's query — the storer applied nothing but the keyword — and the
//! walk's end, told to every subscriber, closes its Kad leg; the walk putting
//! off a keyword publish round is told as it happens. A search that joins a running
//! walk is replayed what the walk found so far, screened the same way, so
//! joining costs it nothing a walk of its own would have found (ADR-0034).

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use rmule_ed2k::SearchResultSkipReason;
use rmule_kad::KadId;
use rmule_primitives::{KeywordQuery, SearchResult};

use crate::KadKeywordSink as KeywordSink;
use crate::search::{KadKeywordEnd, KadWalkFact};

/// The word a query's walk targets, as aMule picks it: the first token of three
/// or more bytes, or — for a query of several words — its longest word
/// ([`rmule_kad::keyword::lead_keyword`]); `None` when it has no such token.
/// The node is asked for this word alone, so its residual screen keeps every
/// row carrying it and each subscriber screens by its whole query.
pub(super) fn lead_keyword(query: &KeywordQuery) -> Option<String> {
    let words: Vec<String> = query
        .terms()
        .iter()
        .map(rmule_primitives::Ed2kText::to_display_string)
        .collect();
    rmule_kad::keyword::lead_keyword(&query.phrase().to_display_string(), &words)
}

/// The live keyword walks, keyed by the walked keyword ID — the only
/// correlation `KeywordsFound` / `KeywordSearchComplete` carry.
#[derive(Default)]
pub(super) struct KeywordSubscribers {
    walks: HashMap<KadId, KeywordWalk>,
}

struct KeywordWalk {
    /// Every row the walk has found, for a search that joins it later. The node
    /// already dedupes a walk's rows by file ID.
    found: Vec<SearchResult>,
    /// Why each row the walk could not keep was dropped, for a search that
    /// joins it later.
    skipped: Vec<SearchResultSkipReason>,
    subscribers: Vec<Subscriber>,
}

struct Subscriber {
    query: KeywordQuery,
    sink: KeywordSink,
}

impl Subscriber {
    /// Tell this subscriber why each row in `skipped` was dropped: a dropped
    /// row has no result to screen, and it answered the keyword this search
    /// walks. Never lost while the search listens.
    fn tell_skipped(&self, skipped: &[SearchResultSkipReason]) {
        for &reason in skipped {
            self.sink.tell(KadWalkFact::RowSkipped(reason));
        }
    }

    /// Hand over the rows of `rows` this subscriber's query proves. `false`
    /// once its search has ended. Lossy on a full sink by design: an awaited
    /// send would freeze the shared pump — source discovery, publishes, the
    /// handoff — behind one search's backlog.
    fn offer(&self, rows: &[SearchResult]) -> bool {
        let mine: Vec<SearchResult> = rows
            .iter()
            .filter(|row| self.query.matches(row))
            .cloned()
            .collect();
        if mine.is_empty() {
            return !self.sink.is_closed();
        }
        self.sink.offer(mine)
    }
}

impl KeywordSubscribers {
    /// Subscribe `sink`, screened by `query`, to the walk toward `target`.
    /// `true` when no walk toward `target` is live and the caller must start
    /// one; a joiner is replayed the walk's rows so far. A query that derives
    /// no target is never walked: its sink is told so and dropped here.
    pub(super) fn subscribe(
        &mut self,
        target: Option<KadId>,
        query: KeywordQuery,
        sink: KeywordSink,
    ) -> bool {
        let Some(target) = target else {
            sink.tell(KadWalkFact::Ended(KadKeywordEnd::NoKeyword));
            return false;
        };
        let subscriber = Subscriber { query, sink };
        match self.walks.entry(target) {
            Entry::Occupied(mut walk) => {
                let walk = walk.get_mut();
                subscriber.tell_skipped(&walk.skipped);
                if subscriber.offer(&walk.found) {
                    walk.subscribers.push(subscriber);
                }
                false
            }
            Entry::Vacant(slot) => {
                slot.insert(KeywordWalk {
                    found: Vec::new(),
                    skipped: Vec::new(),
                    subscribers: vec![subscriber],
                });
                true
            }
        }
    }

    /// Hand `batch` to every search listening to the walk toward `keyword`,
    /// each screened by its own query, and tell each why every row in
    /// `skipped` was dropped; a keyword nobody walks drops both. A subscriber
    /// whose search ended is forgotten; the walk stays known until it ends.
    pub(super) fn deliver(
        &mut self,
        keyword: KadId,
        batch: Vec<SearchResult>,
        skipped: Vec<SearchResultSkipReason>,
    ) {
        let Some(walk) = self.walks.get_mut(&keyword) else {
            return;
        };
        walk.subscribers.retain(|subscriber| {
            subscriber.tell_skipped(&skipped);
            subscriber.offer(&batch)
        });
        walk.found.extend(batch);
        walk.skipped.extend(skipped);
    }

    /// The walk toward `keyword` ended as `end` says: tell each search, then
    /// drop its sink, which is what tells it its Kad leg has nothing more to
    /// say.
    pub(super) fn complete(&mut self, keyword: KadId, end: KadKeywordEnd) {
        let Some(walk) = self.walks.remove(&keyword) else {
            return;
        };
        for subscriber in &walk.subscribers {
            subscriber.sink.tell(KadWalkFact::Ended(end));
        }
    }

    /// The walk toward `keyword` took it from a keyword publish round, which
    /// now waits for the walk: tell each search riding it.
    pub(super) fn publish_deferred(&self, keyword: KadId) {
        if let Some(walk) = self.walks.get(&keyword) {
            for subscriber in &walk.subscribers {
                subscriber.sink.tell(KadWalkFact::PublishDeferred);
            }
        }
    }
}

/// The pump that owns the walks ended: Kad stopped under every walk still
/// running, and each search riding one is told so before its sink drops.
impl Drop for KeywordSubscribers {
    fn drop(&mut self) {
        for walk in self.walks.values() {
            for subscriber in &walk.subscribers {
                subscriber
                    .sink
                    .tell(KadWalkFact::Ended(KadKeywordEnd::Stopped));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_primitives::{Ed2kText, FileHash};

    use super::*;
    use crate::search::{KadKeywordLeg, KadLegNews, kad_keyword_leg};
    use crate::service::{LegNotSent, SearchLegState};

    fn row(hash: u8, name: &str) -> SearchResult {
        SearchResult::new(
            FileHash::from_bytes([hash; FileHash::BYTE_LEN]),
            1_024,
            vec![Ed2kText::from_utf8(name)],
            Vec::new(),
        )
        .expect("a valid result")
    }

    fn query(phrase: &str) -> KeywordQuery {
        KeywordQuery::new(Ed2kText::from_utf8(phrase)).expect("valid phrase")
    }

    fn keyword(byte: u8) -> KadId {
        KadId::from_bytes([byte; 16])
    }

    /// The next news on `leg`, which must be rows: their names.
    async fn names(leg: &mut KadKeywordLeg) -> Vec<String> {
        match leg.next().await {
            KadLegNews::Rows(rows) => rows
                .iter()
                .map(|row| row.primary_name().to_display_string())
                .collect(),
            other => panic!("rows expected, got {other:?}"),
        }
    }

    /// The next news on `leg`, which must be its end: where it stands.
    async fn ended(leg: &mut KadKeywordLeg) -> SearchLegState {
        match leg.next().await {
            KadLegNews::Ended(state) => state,
            other => panic!("the end expected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_batch_reaches_only_its_keywords_searches_and_the_walks_end_closes_the_leg() {
        let mut subscribers = KeywordSubscribers::default();
        let (a_tx, mut a_rx) = kad_keyword_leg();
        let (b_tx, mut b_rx) = kad_keyword_leg();
        assert!(subscribers.subscribe(Some(keyword(0xA)), query("song"), a_tx));
        assert!(subscribers.subscribe(Some(keyword(0xB)), query("song"), b_tx));

        subscribers.deliver(keyword(0xA), vec![row(1, "song.mp3")], Vec::new());
        assert_eq!(names(&mut a_rx).await, ["song.mp3"]);
        assert!(
            b_rx.try_rows().is_none(),
            "another walk's rows stay its own"
        );

        subscribers.complete(keyword(0xA), KadKeywordEnd::Answered);
        assert_eq!(
            ended(&mut a_rx).await,
            SearchLegState::Settled,
            "the walk's end settles A's Kad leg"
        );
    }

    /// A walk that asked nobody, or never started, ends every search riding
    /// it as not sent, and says why.
    #[tokio::test]
    async fn a_walk_that_asked_nobody_ends_its_searches_legs_as_not_sent_and_why() {
        let mut subscribers = KeywordSubscribers::default();
        let (held_tx, mut held) = kad_keyword_leg();
        let (lonely_tx, mut lonely) = kad_keyword_leg();
        subscribers.subscribe(Some(keyword(0xA)), query("song"), held_tx);
        subscribers.subscribe(Some(keyword(0xB)), query("song"), lonely_tx);

        subscribers.complete(keyword(0xA), KadKeywordEnd::TargetHeld);
        subscribers.complete(keyword(0xB), KadKeywordEnd::NoContacts);
        assert_eq!(
            ended(&mut held).await,
            SearchLegState::NotSent(LegNotSent::KadKeywordHeld)
        );
        assert_eq!(
            ended(&mut lonely).await,
            SearchLegState::NotSent(LegNotSent::NoKadContact)
        );
    }

    /// Kad stopping never reads as a walk done: a walk the node never took
    /// ends its leg as not sent, and a walk Kad stopped under ends its legs
    /// as stopped, the rows they heard standing.
    #[tokio::test]
    async fn a_walk_kad_never_took_or_stopped_under_says_so() {
        let mut subscribers = KeywordSubscribers::default();
        let (untaken_tx, mut untaken) = kad_keyword_leg();
        let (cut_tx, mut cut) = kad_keyword_leg();
        subscribers.subscribe(Some(keyword(0xA)), query("song"), untaken_tx);
        subscribers.subscribe(Some(keyword(0xB)), query("song"), cut_tx);
        subscribers.deliver(keyword(0xB), vec![row(1, "song.mp3")], Vec::new());

        subscribers.complete(keyword(0xA), KadKeywordEnd::NotTaken);
        drop(subscribers);
        assert_eq!(
            ended(&mut untaken).await,
            SearchLegState::NotSent(LegNotSent::KadStopped)
        );
        assert_eq!(names(&mut cut).await, ["song.mp3"]);
        assert_eq!(ended(&mut cut).await, SearchLegState::WalkStopped);
    }

    /// A walk that took its keyword from a publish round tells each search
    /// riding it, ahead of the rows and the end that follow.
    #[tokio::test]
    async fn a_walk_that_put_off_a_publish_round_tells_its_searches() {
        let mut subscribers = KeywordSubscribers::default();
        let (tx, mut leg) = kad_keyword_leg();
        subscribers.subscribe(Some(keyword(0xA)), query("song"), tx);

        subscribers.publish_deferred(keyword(0xA));
        subscribers.deliver(keyword(0xA), vec![row(1, "song.mp3")], Vec::new());
        subscribers.complete(keyword(0xA), KadKeywordEnd::Answered);
        assert!(matches!(leg.next().await, KadLegNews::PublishDeferred));
        assert_eq!(names(&mut leg).await, ["song.mp3"]);
        assert_eq!(ended(&mut leg).await, SearchLegState::Settled);
    }

    /// Every search on a lead keyword shares the one walk, each
    /// hearing only the rows its own query proves — a different query on the
    /// same keyword included.
    #[tokio::test]
    async fn searches_on_one_lead_keyword_share_the_walk_each_screened_by_its_own_query() {
        let mut subscribers = KeywordSubscribers::default();
        let (iso_tx, mut iso_rx) = kad_keyword_leg();
        let (desktop_tx, mut desktop_rx) = kad_keyword_leg();
        assert!(subscribers.subscribe(Some(keyword(0xA)), query("ubuntu iso"), iso_tx));
        assert!(!subscribers.subscribe(Some(keyword(0xA)), query("ubuntu desktop"), desktop_tx));

        subscribers.deliver(
            keyword(0xA),
            vec![row(1, "ubuntu-server.iso"), row(2, "ubuntu-desktop.iso")],
            Vec::new(),
        );
        assert_eq!(
            names(&mut iso_rx).await,
            ["ubuntu-server.iso", "ubuntu-desktop.iso"]
        );
        assert_eq!(names(&mut desktop_rx).await, ["ubuntu-desktop.iso"]);

        // A row neither proves reaches neither, and closes nothing.
        subscribers.deliver(keyword(0xA), vec![row(3, "ubuntu.txt")], Vec::new());
        assert!(iso_rx.try_rows().is_none());
        assert!(desktop_rx.try_rows().is_none());
    }

    /// A search joining a running walk is replayed what the walk found so
    /// far, screened by its own query, then hears the rest.
    #[tokio::test]
    async fn a_search_joining_a_running_walk_is_replayed_its_rows() {
        let mut subscribers = KeywordSubscribers::default();
        let (first_tx, _first_rx) = kad_keyword_leg();
        assert!(subscribers.subscribe(Some(keyword(0xA)), query("ubuntu"), first_tx));
        subscribers.deliver(
            keyword(0xA),
            vec![row(1, "ubuntu-desktop.iso"), row(2, "ubuntu-server.iso")],
            Vec::new(),
        );

        let (joiner_tx, mut joiner_rx) = kad_keyword_leg();
        assert!(
            !subscribers.subscribe(Some(keyword(0xA)), query("ubuntu desktop"), joiner_tx),
            "the walk is running: no second walk"
        );
        assert_eq!(names(&mut joiner_rx).await, ["ubuntu-desktop.iso"]);

        subscribers.deliver(
            keyword(0xA),
            vec![row(3, "Ubuntu Desktop 24.iso")],
            Vec::new(),
        );
        assert_eq!(names(&mut joiner_rx).await, ["Ubuntu Desktop 24.iso"]);
        subscribers.complete(keyword(0xA), KadKeywordEnd::Answered);
        assert_eq!(ended(&mut joiner_rx).await, SearchLegState::Settled);
    }

    /// A row the walk dropped reaches every search on the walk by its reason,
    /// a later joiner included: it answered the keyword they share, and has
    /// no result to screen.
    #[tokio::test]
    async fn a_dropped_row_reaches_every_search_on_the_walk_by_its_reason() {
        let mut subscribers = KeywordSubscribers::default();
        let (tx, mut leg) = kad_keyword_leg();
        subscribers.subscribe(Some(keyword(0xA)), query("film"), tx);
        subscribers.deliver(
            keyword(0xA),
            Vec::new(),
            vec![SearchResultSkipReason::FileSizeAboveLimit],
        );
        assert!(matches!(
            leg.next().await,
            KadLegNews::RowSkipped(SearchResultSkipReason::FileSizeAboveLimit)
        ));

        let (joiner_tx, mut joiner) = kad_keyword_leg();
        subscribers.subscribe(Some(keyword(0xA)), query("film noir"), joiner_tx);
        assert!(matches!(
            joiner.next().await,
            KadLegNews::RowSkipped(SearchResultSkipReason::FileSizeAboveLimit)
        ));
    }

    /// A storer answers the keyword, not the constraints (the v1 requester
    /// sends no restrictive tree), so a row that fails the operator's bound
    /// never reaches the search — and an all-rejected batch sends
    /// nothing, so it cannot hold the quiet window open.
    #[tokio::test]
    async fn a_constraint_screens_the_walks_rows() {
        let mut subscribers = KeywordSubscribers::default();
        let (tx, mut rx) = kad_keyword_leg();
        subscribers.subscribe(Some(keyword(0xA)), query("song").with_min_size(8192), tx);
        subscribers.deliver(keyword(0xA), vec![row(1, "song.mp3")], Vec::new());
        assert!(rx.try_rows().is_none());
    }

    #[tokio::test]
    async fn an_unsearchable_query_ends_its_leg_at_once_as_not_sent() {
        let mut subscribers = KeywordSubscribers::default();
        let (tx, mut rx) = kad_keyword_leg();
        assert!(!subscribers.subscribe(None, query("a"), tx));
        assert_eq!(
            ended(&mut rx).await,
            SearchLegState::NotSent(LegNotSent::NoKadKeyword)
        );
    }

    #[test]
    fn the_lead_keyword_is_the_first_word_of_three_bytes() {
        assert_eq!(
            lead_keyword(&query("an ubuntu iso")).as_deref(),
            Some("ubuntu")
        );
        assert_eq!(lead_keyword(&query("a b")), None);
    }
}
