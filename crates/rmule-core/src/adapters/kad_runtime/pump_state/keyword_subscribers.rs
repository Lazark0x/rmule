//! The **Kad Pump State**'s keyword-search subscribers: one walk per lead
//! keyword, and every search on that keyword subscribed to it with its own
//! query. A `KeywordsFound` batch reaches each subscriber screened by that
//! subscriber's query — the storer applied nothing but the keyword — and the
//! walk's end, told to every subscriber, closes its Kad leg; the walk putting
//! off a keyword publish round is told as it happens. A search that joins a
//! running walk is replayed what the walk found so far, screened the same way,
//! so joining costs it nothing a walk of its own would have found (ADR-0034).
//!
//! Each subscriber is heard through its [`SearchSink`], which the brain holds
//! as an address and never writes to: every delivery leaves as a
//! [`KadPumpEffect::Search`] the driver carries out.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use rmule_ed2k::SearchResultSkipReason;
use rmule_kad::KadId;
use rmule_primitives::{KeywordQuery, SearchResult};

use super::{KadPumpEffect, SearchNews};
use crate::KadKeywordSink;
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

/// Where one search hears its Kad leg: the search's own sink, shared between
/// the brain's subscriber and the effects addressed to it. Two are equal when
/// they are the same search's. The leg ends once the brain lets go of it and
/// the last effect naming it is carried out.
#[derive(Clone)]
pub(crate) struct SearchSink(Arc<KadKeywordSink>);

impl SearchSink {
    pub(super) fn new(sink: KadKeywordSink) -> Self {
        Self(Arc::new(sink))
    }

    /// Hand the search `rows` if it has room; dropped if not.
    pub(crate) fn offer(&self, rows: Vec<SearchResult>) {
        self.0.offer(rows);
    }

    /// Tell the search `fact`; never lost while the search listens.
    pub(crate) fn tell(&self, fact: KadWalkFact) {
        self.0.tell(fact);
    }
}

impl PartialEq for SearchSink {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for SearchSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SearchSink")
    }
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
    sink: SearchSink,
}

impl Subscriber {
    fn tell(&self, fact: KadWalkFact, out: &mut Vec<KadPumpEffect>) {
        out.push(KadPumpEffect::Search {
            sink: self.sink.clone(),
            news: SearchNews::Fact(fact),
        });
    }

    /// Tell this subscriber why each row in `skipped` was dropped: a dropped
    /// row has no result to screen, and it answered the keyword this search
    /// walks.
    fn tell_skipped(&self, skipped: &[SearchResultSkipReason], out: &mut Vec<KadPumpEffect>) {
        for &reason in skipped {
            self.tell(KadWalkFact::RowSkipped(reason), out);
        }
    }

    /// Hand over the rows of `rows` this subscriber's query proves, if any.
    fn offer(&self, rows: &[SearchResult], out: &mut Vec<KadPumpEffect>) {
        let mine: Vec<SearchResult> = rows
            .iter()
            .filter(|row| self.query.matches(row))
            .cloned()
            .collect();
        if !mine.is_empty() {
            out.push(KadPumpEffect::Search {
                sink: self.sink.clone(),
                news: SearchNews::Rows(mine),
            });
        }
    }
}

impl KeywordSubscribers {
    /// Subscribe `sink`, screened by `query`, to the walk toward `target`.
    /// `true` when no walk toward `target` is live and the node must be asked
    /// for one; a joiner is replayed the walk's rows so far. A query that
    /// derives no target is never walked: its search is told so and let go.
    pub(super) fn subscribe(
        &mut self,
        target: Option<KadId>,
        query: KeywordQuery,
        sink: SearchSink,
        out: &mut Vec<KadPumpEffect>,
    ) -> bool {
        let subscriber = Subscriber { query, sink };
        let Some(target) = target else {
            subscriber.tell(KadWalkFact::Ended(KadKeywordEnd::NoKeyword), out);
            return false;
        };
        match self.walks.entry(target) {
            Entry::Occupied(mut walk) => {
                let walk = walk.get_mut();
                subscriber.tell_skipped(&walk.skipped, out);
                subscriber.offer(&walk.found, out);
                walk.subscribers.push(subscriber);
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
    /// `skipped` was dropped; a keyword nobody walks drops both.
    pub(super) fn deliver(
        &mut self,
        keyword: KadId,
        batch: Vec<SearchResult>,
        skipped: Vec<SearchResultSkipReason>,
        out: &mut Vec<KadPumpEffect>,
    ) {
        let Some(walk) = self.walks.get_mut(&keyword) else {
            return;
        };
        for subscriber in &walk.subscribers {
            subscriber.tell_skipped(&skipped, out);
            subscriber.offer(&batch, out);
        }
        walk.found.extend(batch);
        walk.skipped.extend(skipped);
    }

    /// The walk toward `keyword` ended as `end` says: tell each search, then
    /// let go of its sink, which is what tells it its Kad leg has nothing
    /// more to say.
    pub(super) fn complete(
        &mut self,
        keyword: KadId,
        end: KadKeywordEnd,
        out: &mut Vec<KadPumpEffect>,
    ) {
        let Some(walk) = self.walks.remove(&keyword) else {
            return;
        };
        for subscriber in &walk.subscribers {
            subscriber.tell(KadWalkFact::Ended(end), out);
        }
    }

    /// The walk toward `keyword` took it from a keyword publish round, which
    /// now waits for the walk: tell each search riding it.
    pub(super) fn publish_deferred(&self, keyword: KadId, out: &mut Vec<KadPumpEffect>) {
        if let Some(walk) = self.walks.get(&keyword) {
            for subscriber in &walk.subscribers {
                subscriber.tell(KadWalkFact::PublishDeferred, out);
            }
        }
    }

    /// Kad stopped under every walk still running: each search riding one is
    /// told so, and let go.
    pub(super) fn stopped(&mut self, out: &mut Vec<KadPumpEffect>) {
        for (_, walk) in self.walks.drain() {
            for subscriber in &walk.subscribers {
                subscriber.tell(KadWalkFact::Ended(KadKeywordEnd::Stopped), out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_primitives::Ed2kText;

    use super::lead_keyword;

    fn query(phrase: &str) -> rmule_primitives::KeywordQuery {
        rmule_primitives::KeywordQuery::new(Ed2kText::from_utf8(phrase)).expect("valid phrase")
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
