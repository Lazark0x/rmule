//! A search's Kad leg, both halves: the [`KadKeywordSink`] the Kad pump holds
//! for the walk on the search's lead keyword, and the [`KadKeywordLeg`] the
//! search task reads (ADR-0062 requester, ADR-0034 §5). Rows travel lossy, so
//! a slow search never stalls the pump; what the walk did — whether it asked
//! anybody, whether it put off the Kad Publisher's round on its keyword, and
//! why each row it could not keep was dropped — travels on a lane of its own
//! that loses nothing, and is told before the sink is dropped.

use rmule_ed2k::SearchResultSkipReason;
use rmule_primitives::SearchResult;
use tokio::sync::mpsc;

use crate::service::{LegNotSent, SearchLegState};

/// How many row batches wait for a search before the pump drops the next.
const ROW_BACKLOG: usize = 8;

/// Where the Kad walk on a search's lead keyword tells that search what it
/// found and how it ended. Dropping it ends the leg.
pub struct KadKeywordSink {
    rows: mpsc::Sender<Vec<SearchResult>>,
    facts: mpsc::UnboundedSender<KadWalkFact>,
}

/// How a Kad keyword walk ended, for each search riding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KadKeywordEnd {
    /// The walk asked storers and its window or row budget closed it.
    Answered,
    /// No contact answered the walk, so no storer was asked.
    NoContacts,
    /// Another kind of walk held the keyword's target, so no walk started.
    TargetHeld,
    /// The query has no word a walk can target.
    NoKeyword,
    /// Kad stopped before the node took the walk, so no walk started.
    NotTaken,
    /// Kad stopped under the running walk, before its window or row budget
    /// closed it.
    Stopped,
}

/// A fact about the walk, beside its rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KadWalkFact {
    /// The walk took its keyword from a keyword publish round, which runs
    /// once the walk ends.
    PublishDeferred,
    /// A row the walk found could not be kept, for this reason; it has no
    /// result to screen, so every search on the walk hears it.
    RowSkipped(SearchResultSkipReason),
    /// The walk ended so.
    Ended(KadKeywordEnd),
}

/// What the search task hears next from its Kad leg.
#[derive(Debug)]
pub(crate) enum KadLegNews {
    /// Rows, already screened by the search's own query.
    Rows(Vec<SearchResult>),
    /// The walk put off the keyword's publish round.
    PublishDeferred,
    /// A row the walk found could not be kept, for this reason.
    RowSkipped(SearchResultSkipReason),
    /// The leg has nothing more to say; it reads so.
    Ended(SearchLegState),
}

/// The search task's half of its Kad leg.
pub(crate) struct KadKeywordLeg {
    rows: mpsc::Receiver<Vec<SearchResult>>,
    facts: mpsc::UnboundedReceiver<KadWalkFact>,
    end: Option<KadKeywordEnd>,
    rows_closed: bool,
}

/// A fresh Kad leg: the sink for the pump, the leg for the search.
pub(crate) fn kad_keyword_leg() -> (KadKeywordSink, KadKeywordLeg) {
    let (rows_tx, rows) = mpsc::channel(ROW_BACKLOG);
    let (facts_tx, facts) = mpsc::unbounded_channel();
    (
        KadKeywordSink {
            rows: rows_tx,
            facts: facts_tx,
        },
        KadKeywordLeg {
            rows,
            facts,
            end: None,
            rows_closed: false,
        },
    )
}

impl KadKeywordSink {
    /// Hand the search `rows`, waiting for room. `Err` once its search has
    /// ended.
    ///
    /// # Errors
    ///
    /// The search no longer listens; the rows come back.
    pub async fn send(
        &self,
        rows: Vec<SearchResult>,
    ) -> Result<(), mpsc::error::SendError<Vec<SearchResult>>> {
        self.rows.send(rows).await
    }

    /// Hand the search `rows` if it has room, dropping them if not; `false`
    /// once its search has ended.
    pub(crate) fn offer(&self, rows: Vec<SearchResult>) -> bool {
        !matches!(
            self.rows.try_send(rows),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    }

    /// Tell the search `fact`; never lost while the search listens.
    pub(crate) fn tell(&self, fact: KadWalkFact) {
        let _ = self.facts.send(fact);
    }
}

impl KadKeywordLeg {
    /// A leg with nothing to say, read as settled at once.
    pub(crate) fn settled() -> Self {
        kad_keyword_leg().1
    }

    /// The leg's next news. A fact told before the rows closed is heard
    /// before the end. Cancel-safe: nothing received is lost when the call
    /// is dropped.
    pub(crate) async fn next(&mut self) -> KadLegNews {
        loop {
            if self.rows_closed {
                match self.facts.try_recv() {
                    Ok(fact) => match self.take(fact) {
                        Some(news) => return news,
                        None => continue,
                    },
                    Err(_) => return KadLegNews::Ended(self.state()),
                }
            }
            tokio::select! {
                biased;
                Some(fact) = self.facts.recv() => {
                    if let Some(news) = self.take(fact) {
                        return news;
                    }
                }
                rows = self.rows.recv() => match rows {
                    Some(rows) => return KadLegNews::Rows(rows),
                    None => self.rows_closed = true,
                },
            }
        }
    }

    /// The rows waiting now, if any.
    #[cfg(test)]
    pub(crate) fn try_rows(&mut self) -> Option<Vec<SearchResult>> {
        self.rows.try_recv().ok()
    }

    fn take(&mut self, fact: KadWalkFact) -> Option<KadLegNews> {
        match fact {
            KadWalkFact::PublishDeferred => Some(KadLegNews::PublishDeferred),
            KadWalkFact::RowSkipped(reason) => Some(KadLegNews::RowSkipped(reason)),
            KadWalkFact::Ended(end) => {
                self.end = Some(end);
                None
            }
        }
    }

    /// Where the ended leg stands: settled, cut short, or never sent and why.
    /// A leg closed without an end told has said all its channel will: the
    /// Kad pump tells every other end before it drops a sink.
    const fn state(&self) -> SearchLegState {
        match self.end {
            None | Some(KadKeywordEnd::Answered) => SearchLegState::Settled,
            Some(KadKeywordEnd::Stopped) => SearchLegState::WalkStopped,
            Some(KadKeywordEnd::NotTaken) => SearchLegState::NotSent(LegNotSent::KadStopped),
            Some(KadKeywordEnd::NoContacts) => SearchLegState::NotSent(LegNotSent::NoKadContact),
            Some(KadKeywordEnd::TargetHeld) => SearchLegState::NotSent(LegNotSent::KadKeywordHeld),
            Some(KadKeywordEnd::NoKeyword) => SearchLegState::NotSent(LegNotSent::NoKadKeyword),
        }
    }
}

impl From<rmule_kad::KadSearchEnd> for KadKeywordEnd {
    fn from(end: rmule_kad::KadSearchEnd) -> Self {
        match end {
            rmule_kad::KadSearchEnd::WindowElapsed | rmule_kad::KadSearchEnd::ResultBudget => {
                Self::Answered
            }
            rmule_kad::KadSearchEnd::NoSearchableContacts => Self::NoContacts,
            rmule_kad::KadSearchEnd::TargetHeld => Self::TargetHeld,
        }
    }
}
