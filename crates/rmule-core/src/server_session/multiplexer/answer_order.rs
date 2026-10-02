//! The session's **answer order**: every search request goes on the link in
//! the order it is asked, at least [`SEARCH_SPACING`] after the one before, and
//! each answer is attributed through **Search Attribution** (ADR-0034) with its place on the link
//! naming its owner.
//!
//! The spacing is Lugdunum's (ADR-0035): it reads a link's searches by its
//! clock's whole second. A search in the same second as its link's previous
//! one is answered empty; one in the same or the next second is a strike, and
//! the address's fourth strike closes the link, after which every later search
//! from that address goes unanswered. A search two seconds after its link's
//! previous one always lands at least two whole seconds later, so it is
//! neither. aMule never has two searches out, so no server is owed faster; the
//! spacing applies to every server, since which family a server is cannot be
//! known before it answers.
//!
//! An eD2k server's `OP_SEARCHRESULT` carries no search id, but a server
//! answers one link's requests in order, one answer each (ed2k-server runs a
//! frame to completion before reading the next and answers even an unparseable
//! request; aMule and eMule end their search on each answer) — so each answer
//! is the oldest unanswered request's. That place is trusted only while no
//! answer is **owed**: a request whose answer wait ran out may still be
//! answered and would shift every later place, so until an answer arrives with
//! nothing outstanding to pay it back, or [`OWED_LAPSE`] passes and the server
//! is taken to have dropped it, answers have no owner and their rows go only
//! where they prove a query (ADR-0034, "Owed answers lapse").
//!
//! The session keeps its own copy of the server's related-search grant, moved
//! by each `OP_IDCHANGE`: a **Related-Files Search** goes on the link only under
//! a grant held at that moment. A withdrawal refuses each related request still
//! waiting its turn, by its own search; one already on the link keeps its place
//! and its answer (ADR-0034, Search Attribution).
//!
//! A server's answer may say it holds more rows; the next page is asked for
//! with `OP_QUERY_MORE_RESULT`, which names no search — the server pages the
//! link's **last** search request. So the session names the **pager**: the
//! search whose own answer said more while its request was still the newest on
//! the link. Any later search request ends it (the server replaces what it
//! kept), and a request for more is a request like any other — owned by the
//! search that asked, spaced from the last like any request, its answer known by its
//! place (ADR-0034).

use std::collections::VecDeque;
use std::time::Duration;

use rmule_ed2k::Ed2kCommand;
use rmule_primitives::{SearchQuery, SearchResult};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{SearchStream, ServerSearchEvent};
use crate::search::{LiveSearches, MORE_RESULTS_ASKS, ServerMoreResults};
use crate::service::SearchId;

/// The least time between two search requests on one link: two whole
/// seconds of the server's clock, so no request is answered empty or counted
/// as a strike (ADR-0035).
pub(super) const SEARCH_SPACING: Duration = Duration::from_millis(2000);

/// How long after its answer wait ran out an owed answer is still awaited: a
/// server silent that long has dropped the request.
pub(super) const OWED_LAPSE: Duration = Duration::from_secs(60);

/// What a search asks the server: its query, or the next page of its answer.
pub(super) enum Ask {
    /// The search's own request (`OP_SEARCHREQUEST`).
    Search(SearchQuery),
    /// The next page (`OP_QUERY_MORE_RESULT`), for the pager alone.
    More,
}

/// The requests on the link, oldest first, the ones waiting their turn, and
/// the answers owed.
pub(super) struct AnswerOrder {
    sent: VecDeque<Sent>,
    /// Asked, not yet on the link: each waits until [`SEARCH_SPACING`] has
    /// passed since the last send.
    waiting: VecDeque<Waiting>,
    /// When the last request went on the link.
    last_sent: Option<Instant>,
    /// The **Owed Set**: when each request whose answer wait ran out
    /// unanswered was given up on, oldest first, less the answers that arrived
    /// with nothing outstanding since and the entries past [`OWED_LAPSE`].
    owed: VecDeque<Instant>,
    /// Every search asks through the one core registry; the last one handed
    /// over serves answers that arrive with nothing outstanding.
    live: Option<LiveSearches>,
    /// Whether the server grants a related search now, as the login and each
    /// `OP_IDCHANGE` since said.
    related_granted: bool,
    /// The number the next request put on the link takes.
    next_seq: u64,
    /// The search whose server holds more rows for it, and how many pages it
    /// has asked for.
    pager: Option<Pager>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Pager {
    search_id: SearchId,
    asked: u8,
}

struct Sent {
    search_id: SearchId,
    related: bool,
    /// Its place in the order requests went on the link.
    seq: u64,
    /// The pages its search had asked for when this request went out.
    asked: u8,
    /// The pager this request ended by going out, named again if it turns
    /// out never to have reached the server.
    displaced: Option<Pager>,
    /// The search's server leg: dropped to settle it.
    tx: mpsc::Sender<ServerSearchEvent>,
    deadline: Instant,
}

struct Waiting {
    search_id: SearchId,
    ask: Ask,
    tx: mpsc::Sender<ServerSearchEvent>,
    answer_wait: Duration,
}

impl AnswerOrder {
    /// An empty order on a link whose login granted the related search, or
    /// did not.
    pub(super) fn new(related_granted: bool) -> Self {
        Self {
            sent: VecDeque::new(),
            waiting: VecDeque::new(),
            last_sent: None,
            owed: VecDeque::new(),
            live: None,
            related_granted,
            next_seq: 0,
            pager: None,
        }
    }

    /// Take a search's request and hand back its leg, which closes after the
    /// answer in its place or once `answer_wait` has passed since its send.
    /// The command comes back when it may go on the link now; otherwise it
    /// waits for [`Self::release`].
    pub(super) fn ask(
        &mut self,
        search_id: SearchId,
        ask: Ask,
        answer_wait: Duration,
        live: LiveSearches,
        now: Instant,
    ) -> (SearchStream, Option<Ed2kCommand>) {
        let (tx, event_rx) = mpsc::channel(4);
        self.live = Some(live);
        let stream = SearchStream { event_rx };
        // A fresh channel: a refusal cannot find it full.
        let refusal = match &ask {
            Ask::Search(SearchQuery::RelatedFiles(_)) if !self.related_granted => {
                Some(ServerSearchEvent::RelatedSearchNotOffered)
            }
            Ask::More if !self.may_ask_more(search_id) => Some(ServerSearchEvent::MoreNotOffered),
            Ask::Search(_) | Ask::More => None,
        };
        if let Some(refusal) = refusal {
            let _ = tx.try_send(refusal);
            return (stream, None);
        }
        let waiting = Waiting {
            search_id,
            ask,
            tx,
            answer_wait,
        };
        let spaced_from = self.spaced_from();
        if self.waiting.is_empty() && spaced_from.is_none_or(|due| due <= now) {
            (stream, Some(self.put_on_link(waiting, now)))
        } else {
            // Its turn: after the last send, one spacing per request ahead.
            let ahead = u32::try_from(self.waiting.len()).unwrap_or(u32::MAX);
            let due = spaced_from.unwrap_or(now) + SEARCH_SPACING * ahead;
            // A fresh channel: the event cannot find it full.
            let _ = waiting.tx.try_send(ServerSearchEvent::WaitingForTurn {
                send_in: due.saturating_duration_since(now),
            });
            self.waiting.push_back(waiting);
            (stream, None)
        }
    }

    /// When the next waiting request may go on the link, if one waits.
    pub(super) fn next_send(&self) -> Option<Instant> {
        if self.waiting.is_empty() {
            return None;
        }
        self.spaced_from()
    }

    /// `search_id` is the pager, has pages left to ask for, and has no request
    /// for more already waiting.
    fn may_ask_more(&self, search_id: SearchId) -> bool {
        self.pager
            .is_some_and(|pager| pager.search_id == search_id && pager.asked < MORE_RESULTS_ASKS)
            && !self
                .waiting
                .iter()
                .any(|waiting| waiting.search_id == search_id && matches!(waiting.ask, Ask::More))
    }

    /// The earliest a request may follow the last one sent.
    fn spaced_from(&self) -> Option<Instant> {
        self.last_sent.map(|last| last + SEARCH_SPACING)
    }

    /// The waiting request whose turn has come, now counted as on the link.
    /// One whose search has ended meanwhile is dropped unsent, and so is a
    /// request for more whose search stopped being the pager while it waited —
    /// a search request went out ahead of it, and the server has let the
    /// pages go.
    pub(super) fn release(&mut self, now: Instant) -> Option<Ed2kCommand> {
        loop {
            let waiting = self.waiting.pop_front()?;
            if waiting.tx.is_closed() {
                continue;
            }
            if matches!(waiting.ask, Ask::More)
                && self
                    .pager
                    .is_none_or(|pager| pager.search_id != waiting.search_id)
            {
                let _ = waiting.tx.try_send(ServerSearchEvent::MoreNotOffered);
                continue;
            }
            let _ = waiting.tx.try_send(ServerSearchEvent::SentToServer);
            return Some(self.put_on_link(waiting, now));
        }
    }

    fn put_on_link(&mut self, waiting: Waiting, now: Instant) -> Ed2kCommand {
        self.last_sent = Some(now);
        let seq = self.next_seq;
        self.next_seq += 1;
        // Whatever goes out, the server's kept pages are no longer anyone's
        // to ask for until an answer says so again: a search request replaces
        // them, a request for more takes the next.
        let asked = match (&waiting.ask, self.pager) {
            (Ask::More, Some(pager)) => pager.asked.saturating_add(1),
            _ => 0,
        };
        let displaced = self.pager;
        self.set_pager(None);
        let (related, command) = match waiting.ask {
            Ask::Search(query) => (
                matches!(query, SearchQuery::RelatedFiles(_)),
                Ed2kCommand::Search { query },
            ),
            Ask::More => (false, Ed2kCommand::QueryMoreResults),
        };
        self.sent.push_back(Sent {
            search_id: waiting.search_id,
            related,
            seq,
            asked,
            displaced,
            tx: waiting.tx,
            deadline: now + waiting.answer_wait,
        });
        command
    }

    /// Name the pager, and say so to the front ends through the registry.
    fn set_pager(&mut self, pager: Option<Pager>) {
        if self.pager == pager {
            return;
        }
        self.pager = pager;
        if let Some(live) = &self.live {
            live.publish_more(pager.map(|pager| ServerMoreResults {
                search_id: pager.search_id,
                asks_left: MORE_RESULTS_ASKS.saturating_sub(pager.asked),
            }));
        }
    }

    /// A request taken back off the link because the send failed.
    pub(super) fn unsent(&mut self) {
        if let Some(sent) = self.sent.pop_back() {
            self.give_back(&sent);
        }
    }

    /// A request that never reached the server gives back its place: when it
    /// was the newest on the link, the one before it is the newest again and
    /// the pager its going out ended is the pager again, so the server's kept
    /// pages stay askable. An older one leaves a gap no answer can fill.
    fn give_back(&mut self, sent: &Sent) {
        if sent.seq + 1 == self.next_seq {
            self.next_seq = sent.seq;
            self.set_pager(sent.displaced);
        }
    }

    /// The server answered with `rows` (possibly none) and the reason each
    /// row it `skipped` did not stand, told to the owner one by one, saying
    /// whether it holds more. The more is the owner's only while its request
    /// is still the newest on the link and its search still listens; otherwise the
    /// server has already let those rows go, or nobody could ask for them.
    /// Should the request that followed the owner's turn out never to have
    /// reached the server, the owner's request is the newest again, so that
    /// request names the owner as the pager to give back.
    pub(super) async fn answered(
        &mut self,
        rows: Vec<SearchResult>,
        skipped: &[rmule_ed2k::SearchResultSkipReason],
        more_available: bool,
        now: Instant,
    ) {
        let (owner, unrecognised) = self.take_place(now);
        if let Some(owner) = &owner {
            for &reason in skipped {
                let _ = owner.tx.send(ServerSearchEvent::Skipped { reason }).await;
            }
        }
        let kept = owner
            .as_ref()
            .filter(|owner| more_available && !owner.tx.is_closed())
            .map(|owner| {
                (
                    owner.seq,
                    Pager {
                        search_id: owner.search_id,
                        asked: owner.asked,
                    },
                )
            });
        let pager = match kept {
            Some((seq, pager)) if seq + 1 == self.next_seq => Some(pager),
            Some((seq, pager)) => {
                if let Some(next) = self.sent.iter_mut().find(|sent| sent.seq == seq + 1) {
                    next.displaced = Some(pager);
                }
                None
            }
            None => None,
        };
        self.set_pager(pager);
        if let Some(live) = &self.live {
            live.deliver(rows, owner.as_ref().map(|sent| sent.search_id));
        }
        if let Some(sent) = unrecognised {
            let _ = sent
                .tx
                .send(ServerSearchEvent::RelatedAnswerUnattributable)
                .await;
        }
    }

    /// The server answered with a packet that did not decode: it still takes
    /// its place, and its owner hears why it shows nothing.
    pub(super) async fn skipped(
        &mut self,
        reason: rmule_ed2k::SearchResultSkipReason,
        now: Instant,
    ) {
        self.set_pager(None);
        match self.take_place(now) {
            (Some(owner), _) => {
                let _ = owner.tx.send(ServerSearchEvent::Skipped { reason }).await;
            }
            (None, Some(related)) => {
                let _ = related
                    .tx
                    .send(ServerSearchEvent::RelatedAnswerUnattributable)
                    .await;
            }
            (None, None) => {}
        }
    }

    /// An `OP_IDCHANGE` restated the grants. A withdrawal refuses every
    /// related request still waiting its turn, each by its own search: none
    /// reached the wire. Requests already on the link keep their places — the
    /// server took them under the grant and answers them.
    pub(super) async fn regranted(&mut self, related_granted: bool) {
        self.related_granted = related_granted;
        if related_granted {
            return;
        }
        let (refused, kept): (VecDeque<Waiting>, VecDeque<Waiting>) =
            std::mem::take(&mut self.waiting)
                .into_iter()
                .partition(|waiting| {
                    matches!(waiting.ask, Ask::Search(SearchQuery::RelatedFiles(_)))
                });
        self.waiting = kept;
        for waiting in refused {
            let _ = waiting
                .tx
                .send(ServerSearchEvent::RelatedSearchNotOffered)
                .await;
        }
    }

    /// The eD2k session refused a related request this session put on the
    /// link under a grant it had not yet heard withdrawn. It holds no place.
    /// It is the **newest** related request on the link: the eD2k session
    /// takes commands in order, and it withdrew the grant (reporting the
    /// `OP_IDCHANGE` first) before refusing, so every related request after
    /// the first it refused was refused too, and none after them was sent —
    /// this session sends none once it has heard the withdrawal. The refusals
    /// are indistinguishable, so taking the newest first refuses exactly the
    /// requests that never left.
    pub(super) async fn related_refused(&mut self) {
        if let Some(index) = self.sent.iter().rposition(|sent| sent.related) {
            let sent = self.sent.remove(index).expect("index in range");
            self.give_back(&sent);
            let _ = sent
                .tx
                .send(ServerSearchEvent::RelatedSearchNotOffered)
                .await;
        }
    }

    /// Take the answer's place. Returns its owner — `None` when an answer is
    /// owed and the place cannot be trusted — and, in that case, a related
    /// search whose place it was, which can then be told nothing true. Owed
    /// answers past [`OWED_LAPSE`] are given up first.
    fn take_place(&mut self, now: Instant) -> (Option<Sent>, Option<Sent>) {
        self.owed.retain(|given_up| *given_up + OWED_LAPSE > now);
        let Some(head) = self.sent.pop_front() else {
            self.owed.pop_front();
            return (None, None);
        };
        if self.owed.is_empty() {
            (Some(head), None)
        } else if head.related {
            (None, Some(head))
        } else {
            // A keyword search's leg settles all the same; its rows still
            // reach it wherever they prove its query.
            (None, None)
        }
    }

    /// When the earliest answer wait runs out, if a request is out.
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.sent.iter().map(|sent| sent.deadline).min()
    }

    /// Settle every request whose answer wait has run out; each is an answer
    /// that may still come.
    pub(super) fn expire(&mut self, now: Instant) {
        let owed = &mut self.owed;
        self.sent.retain(|sent| {
            let waiting = sent.deadline > now;
            if !waiting {
                owed.push_back(sent.deadline);
            }
            waiting
        });
    }

    /// The session ended: every request still out or waiting hears so.
    pub(super) async fn disconnect_all(&mut self) {
        self.set_pager(None);
        for sent in self.sent.drain(..) {
            let _ = sent.tx.send(ServerSearchEvent::Disconnected).await;
        }
        for waiting in self.waiting.drain(..) {
            let _ = waiting.tx.send(ServerSearchEvent::Disconnected).await;
        }
    }
}
