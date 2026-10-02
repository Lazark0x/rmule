//! **Search Attribution** (ADR-0034): the live searches, and
//! the one rule that hands them the rows of answers that name no search.
//!
//! An `OP_SEARCHRESULT` and a `0x99` carry no search id, so a row reaches a
//! search because of what it contains: it belongs to every live search whose
//! query it satisfies and to no other. The session names an answer's *owner*
//! when the answer's place on the link is known; the owner keeps each row the
//! row does not plainly contradict (the server matched it, on fields the row
//! may not echo), and every other live search must see the row prove its query.
//! A row that reaches nobody is dropped and counted, never shown.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use rmule_primitives::{Ipv4Endpoint, SearchQuery, SearchResult};
use tokio::sync::{mpsc, watch};

use super::ServerMoreResults;
use crate::diagnostics::DiagnosticsState;
use crate::service::SearchId;

/// The searches that are live now — registered at start, gone at their
/// terminal event — with the query each is attributed by. One per core; the
/// session loop and the `0x99` forwarder deliver through clones.
///
/// It also carries the session's **pager** (ADR-0036): the
/// search whose server holds more rows for it, which the session names and a
/// search waiting to ask for them watches.
#[derive(Clone)]
pub(crate) struct LiveSearches {
    searches: Arc<Mutex<HashMap<SearchId, Live>>>,
    diagnostics: DiagnosticsState,
    more: Arc<watch::Sender<Option<ServerMoreResults>>>,
}

impl Default for LiveSearches {
    fn default() -> Self {
        Self::new(DiagnosticsState::default())
    }
}

struct Live {
    query: SearchQuery,
    /// Unbounded: the producers are the shared session loop and the UDP
    /// forwarder, which must never wait on one search, and a dropped batch
    /// would be a lost row.
    rows: mpsc::UnboundedSender<Share>,
}

/// One answer's rows for one search, and the server-UDP address a `0x99`
/// came from; `None` for a TCP answer.
struct Share {
    rows: Vec<SearchResult>,
    from: Option<Ipv4Endpoint>,
}

/// One search's share of every attributed answer. Dropping it ends the
/// search's liveness: rows that would have been its are counted instead.
pub(crate) struct AttributedRows {
    rows: mpsc::UnboundedReceiver<Share>,
    live: Registration,
    /// The server-UDP addresses whose answers brought this search a row
    /// (ADR-0034's amendment).
    answered_by: HashSet<Ipv4Endpoint>,
}

/// One batch attributed to a search.
pub(crate) struct AttributedBatch {
    /// The rows.
    pub(crate) rows: Vec<SearchResult>,
    /// Whether a server's `0x99` brought them that had not answered this
    /// search before.
    pub(crate) new_answerer: bool,
}

struct Registration {
    searches: Arc<Mutex<HashMap<SearchId, Live>>>,
    search_id: SearchId,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.searches
            .lock()
            .expect("live searches")
            .remove(&self.search_id);
    }
}

impl AttributedRows {
    /// The next batch attributed to this search. Never `None` while it is
    /// live: the registry holds the sender until it lapses or is dropped.
    pub(crate) async fn recv(&mut self) -> Option<AttributedBatch> {
        let share = self.rows.recv().await?;
        let new_answerer = share
            .from
            .is_some_and(|server| self.answered_by.insert(server));
        Some(AttributedBatch {
            rows: share.rows,
            new_answerer,
        })
    }

    /// How many servers' `0x99` answers have brought this search a row.
    pub(crate) fn answered(&self) -> u32 {
        u32::try_from(self.answered_by.len()).unwrap_or(u32::MAX)
    }

    /// Stop being live, as a search does at completion: rows that would have
    /// been its are counted instead, until [`Self::renew`].
    pub(crate) fn lapse(&mut self) {
        self.live
            .searches
            .lock()
            .expect("live searches")
            .remove(&self.live.search_id);
    }

    /// Live again under `query` — a completed search asking its server for
    /// more (ADR-0036). Renew before the request is sent, or
    /// its own answer could find the search absent.
    pub(crate) fn renew(&mut self, query: SearchQuery) {
        let (tx, rows) = mpsc::unbounded_channel();
        self.live
            .searches
            .lock()
            .expect("live searches")
            .insert(self.live.search_id, Live { query, rows: tx });
        self.rows = rows;
    }
}

#[cfg(test)]
impl AttributedRows {
    /// Every row delivered so far, batches flattened, without waiting.
    pub(crate) fn drain(&mut self) -> Vec<SearchResult> {
        let mut rows = Vec::new();
        while let Ok(share) = self.rows.try_recv() {
            rows.extend(share.rows);
        }
        rows
    }
}

impl LiveSearches {
    /// A registry counting its unattributed rows into `diagnostics`.
    pub(crate) fn new(diagnostics: DiagnosticsState) -> Self {
        Self {
            searches: Arc::default(),
            diagnostics,
            more: Arc::new(watch::channel(None).0),
        }
    }

    /// The session names the search its server holds more rows for, or none.
    pub(crate) fn publish_more(&self, more: Option<ServerMoreResults>) {
        self.more.send_replace(more);
        self.diagnostics.set_search_more_results(more);
    }

    /// The search the server holds more rows for now, as it changes.
    pub(crate) fn watch_more(&self) -> watch::Receiver<Option<ServerMoreResults>> {
        self.more.subscribe()
    }

    /// Make `search_id` live under `query`. Register before the search's first
    /// request is sent, or its own answer could find it absent.
    pub(crate) fn register(&self, search_id: SearchId, query: SearchQuery) -> AttributedRows {
        let (tx, rows) = mpsc::unbounded_channel();
        self.searches
            .lock()
            .expect("live searches")
            .insert(search_id, Live { query, rows: tx });
        AttributedRows {
            rows,
            live: Registration {
                searches: Arc::clone(&self.searches),
                search_id,
            },
            answered_by: HashSet::new(),
        }
    }

    /// Hand each row of `batch` to every live search it belongs to. `owner` is
    /// the search whose request this answer is, when that is known; a
    /// **Related-Files Search** can only ever be reached that way.
    pub(crate) fn deliver(&self, batch: Vec<SearchResult>, owner: Option<SearchId>) {
        self.hand_out(batch, owner, None);
    }

    /// Hand each row of a server's `0x99` answer to every live search it
    /// proves, naming the server-UDP address it came from so each search can
    /// count the servers that answered it.
    pub(crate) fn deliver_udp_answer(&self, batch: Vec<SearchResult>, from: Ipv4Endpoint) {
        self.hand_out(batch, None, Some(from));
    }

    fn hand_out(
        &self,
        batch: Vec<SearchResult>,
        owner: Option<SearchId>,
        from: Option<Ipv4Endpoint>,
    ) {
        let mut unattributed = 0u64;
        {
            let searches = self.searches.lock().expect("live searches");
            let mut shares: HashMap<SearchId, Vec<SearchResult>> = HashMap::new();
            for row in batch {
                let mut reached = false;
                for (search_id, live) in searches.iter() {
                    let belongs = if owner == Some(*search_id) {
                        owner_keeps(&live.query, &row)
                    } else {
                        proves(&live.query, &row)
                    };
                    if belongs {
                        shares.entry(*search_id).or_default().push(row.clone());
                        reached = true;
                    }
                }
                if !reached {
                    unattributed += 1;
                }
            }
            for (search_id, rows) in shares {
                // A search ending right now has dropped its receiver; its rows
                // are as lost as if it had ended a moment sooner.
                let _ = searches[&search_id].rows.send(Share { rows, from });
            }
        }
        if unattributed > 0 {
            tracing::debug!(rows = unattributed, "search rows reached no live search");
            self.diagnostics
                .count_search_rows_unattributed(unattributed);
        }
    }
}

/// The owner keeps a row unless a field the row carries contradicts it.
fn owner_keeps(query: &SearchQuery, row: &SearchResult) -> bool {
    match query {
        SearchQuery::Keywords(query) => !query.contradicts(row),
        SearchQuery::RelatedFiles(_) => true,
    }
}

/// Any other live search must see the row prove its query; a related search's
/// results share no words with its query, so content never reaches one.
fn proves(query: &SearchQuery, row: &SearchResult) -> bool {
    match query {
        SearchQuery::Keywords(query) => query.matches(row),
        SearchQuery::RelatedFiles(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use rmule_primitives::{Ed2kText, FileHash, KeywordQuery};

    use super::*;

    fn row(name: &str) -> SearchResult {
        SearchResult::new(
            FileHash::from_bytes([0xAA; FileHash::BYTE_LEN]),
            1024,
            vec![Ed2kText::from_utf8(name)],
            Vec::new(),
        )
        .unwrap()
    }

    fn query(phrase: &str) -> SearchQuery {
        KeywordQuery::new(Ed2kText::from_utf8(phrase))
            .unwrap()
            .into()
    }

    /// Holding a row is no licence to be updated by an answer that is not the
    /// search's own: the row must prove the query, held or not.
    #[test]
    fn a_non_owner_gets_only_rows_that_prove_its_query_held_or_not() {
        let live = LiveSearches::default();
        let (first_id, second_id) = (SearchId::from_u64(1), SearchId::from_u64(2));
        let mut first = live.register(first_id, query("first"));
        let mut second = live.register(second_id, query("linux"));

        live.deliver(vec![row("linux.iso")], Some(first_id));
        assert_eq!(
            first.drain().len(),
            1,
            "its own answer: the server's verdict"
        );
        assert_eq!(second.drain().len(), 1, "proves the second query");

        live.deliver(vec![row("linux.iso"), row("other.bin")], Some(second_id));
        assert!(
            first.drain().is_empty(),
            "held, but proves nothing of its query"
        );
        assert_eq!(second.drain().len(), 2);
    }
}
