//! The **Search Activity**'s event vocabulary: what a search found, how it
//! ended, and why one ended without completing.

use rmule_ed2k::SearchResultSkipReason;
use rmule_primitives::SearchResult;

use super::super::SearchId;

/// Why a search activity ended without completing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SearchFailure {
    /// The session carrying the search ended before its results did. The
    /// results already accepted stay in the set; no more will arrive.
    ServerDisconnected,
    /// A **Related-Files Search** reached a session whose server had just
    /// withdrawn `SRV_TCPFLG_RELATEDSEARCH` (a mid-session `OP_IDCHANGE`):
    /// nothing was sent. The usual refusal comes before the search starts, as
    /// [`SearchEvent::SearchRefused`].
    RelatedSearchNotOffered,
    /// A **Related-Files Search**'s answer arrived while an earlier request's
    /// answer on the same link was still owed (its wait ran out unanswered),
    /// so the answer in this search's place may be that late one instead. A
    /// related answer shares no words with its query, so nothing can show
    /// which: none of it is shown here (ADR-0034, Search Attribution). Asking
    /// again is the remedy.
    RelatedAnswerUnattributable,
}

/// Where one leg of a keyword search stands (ADR-0034, "The legs are
/// independent", "A server leg's states"). A leg that waits holds no other
/// leg back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SearchLegState {
    /// Waits for a server session while the operator's **Server Intent**
    /// stands: their connect is in flight or a reconnect is pending. Ended by
    /// the session (the leg is sent), by the intent ending (the leg reads
    /// [`SearchLegState::NotSent`], or [`SearchLegState::Unanswered`] if it
    /// had gone out before), or by a cancel; never by a timer.
    WaitingForSession,
    /// Waits for Kad to run. Ended by Kad starting (the leg is sent), or by
    /// every other leg settling first: the leg then reads
    /// [`SearchLegState::NotRun`] and the search completes without it.
    WaitingForKad,
    /// Sent, and still due to say something.
    Sent,
    /// Has said all it will: the answer in its place (empty included), its
    /// last datagram, its walk's end — or the wait or lifetime that bounds it.
    Settled,
    /// Never ran and never will for this search: Kad was not running while
    /// the other legs ran, or no server-UDP socket is bound for the sweep.
    NotRun,
    /// Sent, and Kad stopped under its walk before the walk ended: the leg
    /// is over, and every row it brought stands.
    WalkStopped,
    /// Sent, and its session ended before it answered, with no intent to
    /// stay connected that would send it again (ADR-0034): the leg is
    /// over, not failed — the other legs and every row received stand.
    Unanswered,
    /// Never sent and never will be for this search, for the reason given.
    /// Settled: it holds no completion, and a session or walk that comes
    /// later does not send it.
    NotSent(LegNotSent),
}

/// Why a leg of a search was never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LegNotSent {
    /// No server session, and no **Server Intent** to bring one: the server
    /// leg and the sweep beside it.
    NoServer,
    /// No Kad contact answered the walk toward the keyword, so no storer
    /// was asked: the Kad leg.
    NoKadContact,
    /// Another kind of Kad walk held the keyword's target, so no walk
    /// started (ADR-0062, walk ownership): the Kad leg.
    KadKeywordHeld,
    /// The query has no word of three bytes or more for a Kad walk to
    /// target: the Kad leg.
    NoKadKeyword,
    /// Kad stopped before its node took the walk: the Kad leg.
    KadStopped,
}

impl SearchLegState {
    /// Whether the leg still holds the search's completion open.
    #[must_use]
    pub const fn holds_completion(self) -> bool {
        matches!(self, Self::WaitingForSession | Self::Sent)
    }
}

/// The three legs of a keyword search, as they stand (ADR-0034). A
/// **Related-Files Search** has only its server leg; the other two read
/// [`SearchLegState::NotRun`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SearchLegs {
    /// The connected server's TCP answer.
    pub server: SearchLegState,
    /// The **Global Search Sweep**: datagrams to the listed servers. It
    /// needs a session as aMule's global search does (`SearchList.cpp:596`),
    /// so it waits and is sent with the server leg.
    pub sweep: SearchLegState,
    /// The Kad keyword walk.
    pub kad: SearchLegState,
    /// How many servers the sweep asked and how many answered this search
    /// (ADR-0034's amendment).
    pub sweep_servers: SweepTally,
}

/// The **Global Search Sweep**'s count for one search (ADR-0034). Both read
/// zero until they are known.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SweepTally {
    /// Servers the sweep sent its datagram to, set once it has sent its
    /// last: every managed server but the connected one, which the TCP leg
    /// asked.
    pub asked: u32,
    /// Servers whose `0x99` answer brought this search at least one row,
    /// counted as they arrive — the sweep's settling does not stop it. An
    /// answer carries no search id, so a server another search's sweep asked
    /// counts too when its rows prove this search's query.
    pub answered: u32,
}

/// The search activity's event vocabulary, wrapped by [`CoreEvent::Search`](super::CoreEvent::Search).
/// Every variant carries the `search_id` its `StartSearch` named, so
/// concurrent searches never cross and no outcome is paired by order.
#[derive(Clone, Debug)]
pub enum SearchEvent {
    /// The query went out and the activity exists. The id here is the one every
    /// later event and the cancel command use.
    SearchStarted {
        /// The id core minted for this search.
        search_id: SearchId,
    },
    /// The search's **whole merged result set so far**, re-sent on every batch
    /// that changed it — not the delta. Rows from the TCP answer, the global
    /// UDP sweep and the Kad keyword walk are deduped by `(hash, size)` before
    /// they get here, so a front-end replaces its list with this one rather
    /// than appending to it.
    SearchResultsReceived {
        /// The search whose set this is.
        search_id: SearchId,
        /// The whole merged set, not the new rows.
        results: Vec<SearchResult>,
    },
    /// A row in an answered batch was not admitted to the set. Reported rather
    /// than swallowed so a truncated-looking result list has a reason.
    SearchResultSkipped {
        /// The search that dropped the row.
        search_id: SearchId,
        /// What made the row unusable.
        reason: SearchResultSkipReason,
    },
    /// The quiet timeout expired with no further batch, so the activity closed
    /// normally. Terminal — unless its server holds more rows and the
    /// operator asks for them, which [`SearchEvent::SearchMoreRequested`]
    /// announces; it then completes again.
    SearchCompleted {
        /// The search that closed.
        search_id: SearchId,
        /// The size of the merged set at close — the final row count.
        total_results: usize,
    },
    /// A `CancelSearch` was honoured. Terminal; late batches are dropped.
    SearchCancelled {
        /// The search that was cancelled.
        search_id: SearchId,
    },
    /// Core refused to start a **Related-Files Search**: nothing was sent and
    /// no running search was touched. Terminal, and the search's only event —
    /// no `SearchStarted` precedes it. The reason is the one
    /// [`DiagnosticsSnapshot::related_search_refusal`](crate::diagnostics::DiagnosticsSnapshot::related_search_refusal)
    /// reports, so a menu that dims the action and the refusal agree.
    SearchRefused {
        /// The search the caller asked for.
        search_id: SearchId,
        /// Why it cannot be asked now.
        reason: crate::RelatedSearchRefusal,
    },
    /// The server leg is held back by the session's search spacing (ADR-0035):
    /// another search went to this server less than a second
    /// ago, and this one goes on the link in `send_in`. Followed by
    /// [`SearchEvent::SearchSentToServer`] once it is sent.
    SearchWaitingForTurn {
        /// The search that waits.
        search_id: SearchId,
        /// How long until its request goes on the link.
        send_in: std::time::Duration,
    },
    /// Neither a server session nor Kad exists, so the search waits for one
    /// (ADR-0095, "Connecting is the operator's act"; ADR-0034): it
    /// starts the moment the operator's connect brings a session up or Kad
    /// starts — [`SearchEvent::SearchStarted`] then follows — and a cancel
    /// reaches it while it waits. No search dials a server.
    SearchWaitingForConnection {
        /// The search that waits.
        search_id: SearchId,
    },
    /// A leg of the search moved: its whole leg picture, re-sent on every
    /// change. The first follows [`SearchEvent::SearchStarted`].
    SearchLegsChanged {
        /// The search whose legs these are.
        search_id: SearchId,
        /// Where each leg stands now.
        legs: SearchLegs,
    },
    /// The search's Kad walk took its keyword from the **Kad Publisher**'s
    /// round publishing the operator's shared files under that keyword; the
    /// round runs once the walk ends (ADR-0062, walk ownership).
    SearchDeferredKadPublish {
        /// The search whose walk it is.
        search_id: SearchId,
    },
    /// A search that waited its turn went on the link.
    SearchSentToServer {
        /// The search that was sent.
        search_id: SearchId,
    },
    /// The next page of the search's server answer was asked for
    /// ([`SearchCommand::MoreResults`](crate::SearchCommand::MoreResults)): the
    /// search runs again with its set kept, the page's rows join it, and it
    /// completes again once the page has arrived and the quiet window passed.
    SearchMoreRequested {
        /// The search asking for more.
        search_id: SearchId,
    },
    /// A request for more was not sent: the server holds no more rows rmule
    /// may ask for this search — another search went out since its answer,
    /// the search has ended, or it has asked
    /// [`MORE_RESULTS_ASKS`](crate::MORE_RESULTS_ASKS) times. The search's set
    /// and status are as they were.
    SearchMoreRefused {
        /// The search whose request was not sent.
        search_id: SearchId,
    },
    /// The search ended without completing. Terminal.
    SearchFailed {
        /// The search that failed.
        search_id: SearchId,
        /// What ended it.
        reason: SearchFailure,
    },
}
