//! The α-concurrent lookup walk shared by the **Kad Requester** and **Kad
//! Publisher** roles (ADR-0043).
//!
//! A walk iteratively queries the contacts XOR-closest to its target
//! (`KADEMLIA2_REQ`), learns closer candidates from their answers, and — once
//! no unqueried candidate can improve the result — converges into its
//! [`KadWalkPurpose`]'s terminal action against the closest responded nodes:
//! a source search (`KADEMLIA2_SEARCH_SOURCE_REQ`) that consumes result rows,
//! or a source publish (`KADEMLIA2_PUBLISH_SOURCE_REQ`) that consumes store
//! acks. One walk implementation, two terminal phases — the termination
//! budgets below apply identically to both.
//!
//! The walk is pure bookkeeping with explicit time: [`KadNode`] feeds it
//! responses and tick instants and translates the returned
//! [`KadWalkAction`]s into datagrams and events. It holds no sockets, no
//! clock, and no RNG.
//!
//! ## Every walk terminates
//!
//! Three hard budgets guarantee termination regardless of peer behavior:
//!
//! 1. **No closer contacts** (the natural end): a candidate is queried only
//!    while fewer than [`KadNode::SEARCH_FANOUT`] contacts have responded or
//!    it is strictly closer to the target than the current fan's farthest
//!    member. When nothing launchable remains and nothing is in flight, the
//!    walk converges.
//! 2. **Query budget**: at most [`KadNode::LOOKUP_QUERY_BUDGET`] queries are
//!    ever sent, so a steering adversary feeding endless closer candidates
//!    ("come query this one next") runs the walk out of queries, not forever.
//! 3. **Silence budget**: every in-flight query carries a
//!    [`KadNode::LOOKUP_QUERY_TIMEOUT`] deadline, so total or partial silence
//!    drains the in-flight set instead of wedging it; a walk that ends with
//!    zero responded contacts completes with
//!    [`KadSearchEnd::NoSearchableContacts`] /
//!    [`KadPublishEnd::NoPublishableContacts`].
//!
//! The search phase is bounded by [`KadNode::SOURCE_SEARCH_WINDOW`] and cut
//! short by [`KadNode::SOURCE_RESULT_BUDGET`] consumed rows; the publish
//! phase by [`KadNode::PUBLISH_ACK_WINDOW`] and cut short by every fanned
//! recipient acking.

use crate::node::KadNode;
use crate::{
    KadContact, KadId, KadInstant, KadNodeEndpoint, KadPublishRequest, KadSourceLookupRequest,
};

/// Why a search ended. Every search command ends in exactly one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadSearchEnd {
    /// The walk found no live contact to search: nobody responded (or the
    /// routing table was empty to begin with), so no `0x34` was ever sent.
    NoSearchableContacts,
    /// The answer window after the `0x34` fan-out elapsed.
    WindowElapsed,
    /// The consumed-row budget was reached before the window closed.
    ResultBudget,
    /// Another kind of walk held the target, so no search walk started and no
    /// datagram was sent (ADR-0062, walk ownership).
    TargetHeld,
}

/// Why a source publish ended. Every started publish ends in exactly one of
/// these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadPublishEnd {
    /// The walk found no live contact to publish to, so no `0x44` was sent.
    NoPublishableContacts,
    /// Every fanned recipient acked the publish before the window closed.
    AllStoresAcked,
    /// The ack window after the `0x44` fan-out elapsed.
    WindowElapsed,
}

/// What a walk is for: the terminal action its convergence fans out.
///
/// Two families that share the terminal machinery — a **search-like** walk
/// (`SearchSources`/`SearchKeyword`) fans a request and consumes result rows;
/// a **publish-like** walk (`PublishSource`/`PublishKeyword`) fans an
/// announcement and consumes store acks. The keyword variants carry only the
/// target so the purpose stays `Copy`: the residual query (search) and the file
/// batch (publish) live node-side, keyed by that target.
#[derive(Clone, Copy, Debug)]
pub(crate) enum KadWalkPurpose {
    /// Ask the closest nodes for sources (`0x34`).
    SearchSources(KadSourceLookupRequest),
    /// Announce this node as a source to the closest nodes (`0x44`).
    PublishSource(KadPublishRequest),
    /// Search a keyword's index at the closest nodes (`0x33`).
    SearchKeyword { target: KadId },
    /// Announce a keyword's files to the closest nodes (`0x43`).
    PublishKeyword { target: KadId },
    /// The forced **self-lookup** (`FindNode(own Kad ID)`, ADR-0067): walk
    /// toward the node's own ID to warm its own-ID neighborhood — the join
    /// proper. It has no terminal fan-out; convergence just ends the walk (the
    /// warming is the lookup traffic itself, not a search or publish).
    SelfLookup { target: KadId },
    /// The **FINDBUDDY walk** (ADR-0061 firewalled-node recruitment, aMule
    /// `Search.cpp#L784`): walk toward `~ourKadID` and ask the closest
    /// responded contact to be our buddy (`0x51`). Its terminal action is a
    /// single datagram with no answer window of its own — the `0x5A` is
    /// tracked by the node's recruit guard, not by this walk — so convergence
    /// emits the request and ends.
    FindBuddy { target: KadId },
    /// The **Callback Walk** (aMule's `FINDSOURCE`, `BaseClient.cpp:2160-2170`):
    /// a firewalled source's row named its buddy
    /// by ID alone, so walk toward that ID and send the `0x52` to every
    /// responded contact within `SEARCHTOLERANCE` of it — the buddy was
    /// recruited by a walk toward the same ID, so it is one of them. Like
    /// FINDBUDDY, its terminal action has no answer window: the answer is the
    /// firewalled client's TCP dial-back, which only the core can see.
    CallbackWalk {
        buddy_id: KadId,
        file_hash: rmule_primitives::FileHash,
        tcp_port: u16,
    },
    /// The UDP tester's **helper lookup** (ADR-0058, aMule `NODEFWCHECKUDP`):
    /// query toward a random target for the addresses of nodes we have never
    /// sent a datagram to. Its answer rows go to the tester as candidates and
    /// are never walked (`Search.cpp:489-492` only counts the answer), so the
    /// walk queries its seeds and ends with no terminal fan-out.
    UdpFirewallHelpers { target: KadId },
}

impl KadWalkPurpose {
    pub(crate) fn kad_target(self) -> KadId {
        match self {
            Self::SearchSources(request) => request.kad_target(),
            Self::PublishSource(request) => request.kad_target(),
            Self::SearchKeyword { target }
            | Self::PublishKeyword { target }
            | Self::SelfLookup { target }
            | Self::FindBuddy { target }
            | Self::UdpFirewallHelpers { target } => target,
            Self::CallbackWalk { buddy_id, .. } => buddy_id,
        }
    }

    /// Whether this walk consumes result rows (`0x3B`) rather than store acks —
    /// the search family. Its complement is the publish family.
    pub(crate) const fn is_search(self) -> bool {
        matches!(self, Self::SearchSources(_) | Self::SearchKeyword { .. })
    }
}

/// How a completed walk ended, per purpose.
#[derive(Clone, Copy, Debug)]
pub(crate) enum KadWalkOutcome {
    Search {
        result_rows: usize,
        ended_by: KadSearchEnd,
    },
    Publish {
        acked_stores: usize,
        ended_by: KadPublishEnd,
    },
    /// A self-lookup converged — no terminal fan-out, so nothing to report but
    /// the end of the walk (the own-ID neighborhood was warmed by the walk's
    /// own `KADEMLIA2_REQ` traffic).
    SelfLookup,
    /// A FINDBUDDY walk converged. `asked` is whether any contact responded
    /// close enough to be sent the `0x51`: a walk that found nobody is the one
    /// outcome the recruiting node must hear about, because waiting out the
    /// 20-minute FindBuddy tick for a walk that never left would leave it
    /// buddyless for no reason.
    FindBuddy { asked: bool },
    /// A Callback Walk converged, having sent the `0x52` to `asked`
    /// contacts — zero when nobody responded within tolerance.
    CallbackWalk { asked: usize },
    /// A helper lookup ran out of seeds to query; its rows already went to
    /// the tester as they arrived.
    UdpFirewallHelpers,
}

/// One instruction from the walk to its owning node.
#[derive(Clone, Copy, Debug)]
pub(crate) enum KadWalkAction {
    /// Send a `KADEMLIA2_REQ` for the walk target to this contact.
    SendLookup { contact: KadContact },
    /// Send a `KADEMLIA2_SEARCH_SOURCE_REQ` to this contact.
    SendSearch { contact: KadContact },
    /// Send a `KADEMLIA2_PUBLISH_SOURCE_REQ` to this contact.
    SendPublish { contact: KadContact },
    /// Ask this contact to be our buddy (`0x51 KADEMLIA_FINDBUDDY_REQ`).
    SendFindBuddy { contact: KadContact },
    /// Send the Callback Walk's `0x52 KADEMLIA_CALLBACK_REQ` to this contact.
    SendCallback { contact: KadContact },
    /// The walk is over; emit the completion event and drop the walk.
    Complete { outcome: KadWalkOutcome },
}

/// An outstanding `KADEMLIA2_REQ`: `endpoint` must answer before `deadline`.
#[derive(Clone, Copy, Debug)]
struct InFlightQuery {
    id: KadId,
    endpoint: KadNodeEndpoint,
    deadline: KadInstant,
}

/// The terminal phase after walk convergence: the fanned-out `0x34` or
/// `0x44` recipients and the bounded wait for their answers.
#[derive(Clone, Debug)]
struct TerminalPhase {
    /// The fan recipients — the only endpoints whose answers are solicited.
    endpoints: Vec<KadNodeEndpoint>,
    deadline: KadInstant,
    /// Search: result rows consumed (capped by the result budget).
    rows_consumed: usize,
    /// Publish: endpoints whose ack was consumed (each counted once).
    acked: Vec<KadNodeEndpoint>,
}

/// State for one in-flight walk (see the module docs).
///
/// The walk keeps its own flat candidate shortlist rather than borrowing the
/// node's k-bucket routing table: a lookup ranks every learned candidate
/// against one fixed target, while the routing table buckets by the node's
/// own ID. Candidates learned from `0x29` answers are walk-local hearsay —
/// they are queried (which is their validation) but never offered to the
/// routing table, so a steering adversary cannot poison node state through a
/// lookup.
#[derive(Clone, Debug)]
pub(crate) struct KadLookupWalk {
    purpose: KadWalkPurpose,
    target: KadId,
    own_id: KadId,
    candidates: Vec<KadContact>,
    queried: Vec<KadId>,
    in_flight: Vec<InFlightQuery>,
    responded: Vec<KadContact>,
    queries_sent: usize,
    terminal: Option<TerminalPhase>,
    complete: bool,
}

impl KadLookupWalk {
    /// Start a walk from the given seed contacts (the node's closest
    /// responded contacts). Returns the initial α queries — or immediate
    /// completion when there is nothing to query.
    pub(crate) fn start(
        now: KadInstant,
        purpose: KadWalkPurpose,
        own_id: KadId,
        seeds: Vec<KadContact>,
    ) -> (Self, Vec<KadWalkAction>) {
        let mut walk = Self {
            purpose,
            target: purpose.kad_target(),
            own_id,
            candidates: Vec::new(),
            queried: Vec::new(),
            in_flight: Vec::new(),
            responded: Vec::new(),
            queries_sent: 0,
            terminal: None,
            complete: false,
        };
        for seed in seeds {
            walk.add_candidate(seed);
        }
        let mut actions = Vec::new();
        walk.advance(now, &mut actions);
        (walk, actions)
    }

    pub(crate) const fn target(&self) -> KadId {
        self.target
    }

    pub(crate) const fn purpose(&self) -> KadWalkPurpose {
        self.purpose
    }

    pub(crate) const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether `from` was fanned this walk's search request (`0x34`/`0x33`) —
    /// the only endpoints whose `KADEMLIA2_SEARCH_RES` is solicited.
    pub(crate) fn is_search_endpoint(&self, from: KadNodeEndpoint) -> bool {
        self.purpose.is_search() && self.is_terminal_endpoint(from)
    }

    /// Whether `from` was fanned this walk's announcement (`0x44`/`0x43`) — the
    /// only endpoints whose `KADEMLIA2_PUBLISH_RES` is solicited.
    pub(crate) fn is_publish_endpoint(&self, from: KadNodeEndpoint) -> bool {
        !self.purpose.is_search() && self.is_terminal_endpoint(from)
    }

    fn is_terminal_endpoint(&self, from: KadNodeEndpoint) -> bool {
        self.terminal
            .as_ref()
            .is_some_and(|terminal| terminal.endpoints.contains(&from))
    }

    /// The earliest instant [`tick`](Self::tick) has work to do.
    pub(crate) fn next_wake(&self) -> Option<KadInstant> {
        if self.complete {
            return None;
        }
        if let Some(terminal) = &self.terminal {
            return Some(terminal.deadline);
        }
        self.in_flight.iter().map(|query| query.deadline).min()
    }

    /// Consume a `KADEMLIA2_RES` (already target-matched by the node), or
    /// return `None` when `from` has no query in flight — late, duplicate,
    /// and never-queried endpoints all stay unsolicited hearsay.
    pub(crate) fn on_lookup_res(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        contacts: &[KadContact],
    ) -> Option<Vec<KadWalkAction>> {
        let position = self
            .in_flight
            .iter()
            .position(|query| query.endpoint == from)?;
        let query = self.in_flight.remove(position);

        // The responder is recorded under the identity *we queried*, not one
        // the payload claims: answering from the queried endpoint is what
        // validates it as a terminal-fan recipient.
        if let Some(contact) = self
            .candidates
            .iter()
            .find(|contact| contact.id() == query.id)
            .copied()
        {
            self.responded.push(contact);
        }
        // A helper lookup's rows are the tester's, not the walk's: querying
        // them would spend the one freshness they have.
        if !matches!(self.purpose, KadWalkPurpose::UdpFirewallHelpers { .. }) {
            for contact in contacts {
                self.add_candidate(*contact);
            }
        }

        let mut actions = Vec::new();
        self.advance(now, &mut actions);
        Some(actions)
    }

    /// Consume `offered` decoded result rows from a solicited search answer.
    /// Returns how many rows fit the remaining result budget, plus the
    /// completion action when the budget is reached.
    pub(crate) fn accept_search_results(&mut self, offered: usize) -> (usize, Vec<KadWalkAction>) {
        let Some(terminal) = &mut self.terminal else {
            return (0, Vec::new());
        };
        let accepted = offered.min(KadNode::SOURCE_RESULT_BUDGET - terminal.rows_consumed);
        terminal.rows_consumed += accepted;

        let mut actions = Vec::new();
        if terminal.rows_consumed >= KadNode::SOURCE_RESULT_BUDGET {
            self.complete = true;
            actions.push(KadWalkAction::Complete {
                outcome: KadWalkOutcome::Search {
                    result_rows: KadNode::SOURCE_RESULT_BUDGET,
                    ended_by: KadSearchEnd::ResultBudget,
                },
            });
        }
        (accepted, actions)
    }

    /// Consume a solicited publish ack from `from`. Each fanned endpoint is
    /// counted once — a duplicate ack is absorbed (`false`) without effect.
    /// When every fanned recipient has acked, the walk completes early.
    pub(crate) fn accept_publish_ack(
        &mut self,
        from: KadNodeEndpoint,
    ) -> (bool, Vec<KadWalkAction>) {
        let Some(terminal) = &mut self.terminal else {
            return (false, Vec::new());
        };
        if terminal.acked.contains(&from) {
            return (false, Vec::new());
        }
        terminal.acked.push(from);

        let mut actions = Vec::new();
        if terminal.acked.len() == terminal.endpoints.len() {
            let acked_stores = terminal.acked.len();
            self.complete = true;
            actions.push(KadWalkAction::Complete {
                outcome: KadWalkOutcome::Publish {
                    acked_stores,
                    ended_by: KadPublishEnd::AllStoresAcked,
                },
            });
        }
        (true, actions)
    }

    /// Expire due query deadlines and the terminal window.
    pub(crate) fn tick(&mut self, now: KadInstant) -> Vec<KadWalkAction> {
        let mut actions = Vec::new();
        if self.complete {
            return actions;
        }
        if let Some(terminal) = &self.terminal {
            if terminal.deadline <= now {
                self.complete = true;
                actions.push(KadWalkAction::Complete {
                    outcome: if self.purpose.is_search() {
                        KadWalkOutcome::Search {
                            result_rows: terminal.rows_consumed,
                            ended_by: KadSearchEnd::WindowElapsed,
                        }
                    } else {
                        KadWalkOutcome::Publish {
                            acked_stores: terminal.acked.len(),
                            ended_by: KadPublishEnd::WindowElapsed,
                        }
                    },
                });
            }
            return actions;
        }
        let before = self.in_flight.len();
        self.in_flight.retain(|query| query.deadline > now);
        if self.in_flight.len() != before {
            self.advance(now, &mut actions);
        }
        actions
    }

    /// A candidate the walk has not seen yet; the own ID is never queried.
    fn add_candidate(&mut self, contact: KadContact) {
        if contact.id() == self.own_id {
            return;
        }
        if self
            .candidates
            .iter()
            .any(|known| known.id() == contact.id())
        {
            return;
        }
        self.candidates.push(contact);
    }

    /// Launch queries up to α and the query budget; converge when nothing is
    /// launchable and nothing is in flight.
    fn advance(&mut self, now: KadInstant, actions: &mut Vec<KadWalkAction>) {
        while self.in_flight.len() < KadNode::LOOKUP_ALPHA
            && self.queries_sent < KadNode::LOOKUP_QUERY_BUDGET
        {
            let Some(contact) = self.next_launchable() else {
                break;
            };
            self.queried.push(contact.id());
            self.in_flight.push(InFlightQuery {
                id: contact.id(),
                endpoint: contact.endpoint(),
                deadline: now + KadNode::LOOKUP_QUERY_TIMEOUT,
            });
            self.queries_sent += 1;
            actions.push(KadWalkAction::SendLookup { contact });
        }
        if self.in_flight.is_empty() {
            self.converge(now, actions);
        }
    }

    /// The closest unqueried candidate, if querying it could still improve
    /// the terminal fan (budget 1 of the module docs).
    fn next_launchable(&self) -> Option<KadContact> {
        let candidate = self
            .candidates
            .iter()
            .filter(|contact| !self.queried.contains(&contact.id()))
            .min_by_key(|contact| contact.id().distance(&self.target))
            .copied()?;
        let fan = self.terminal_fan();
        if fan.len() < KadNode::SEARCH_FANOUT {
            return Some(candidate);
        }
        let fan_worst = fan[fan.len() - 1].id().distance(&self.target);
        (candidate.id().distance(&self.target) < fan_worst).then_some(candidate)
    }

    /// The responded contacts closest to the target, capped at the fan-out.
    fn terminal_fan(&self) -> Vec<KadContact> {
        let mut fan = self.responded.clone();
        // Distinct IDs have distinct XOR distances: deterministic order.
        fan.sort_by_key(|contact| contact.id().distance(&self.target));
        fan.truncate(KadNode::SEARCH_FANOUT);
        fan
    }

    /// The Callback Walk's recipients: every responded contact aMule's
    /// `StorePacket` would act on — inside `SEARCHTOLERANCE` of the target, or
    /// on a LAN address (`Search.cpp:624-628`) — closest first, capped at
    /// [`KadNode::CALLBACK_WALK_ASK_BUDGET`].
    fn callback_recipients(&self) -> Vec<KadContact> {
        let mut near: Vec<KadContact> = self
            .responded
            .iter()
            .filter(|contact| {
                crate::net::distance_top_word(contact.id(), self.target)
                    <= crate::net::PUBLISH_TOLERANCE
                    || crate::net::is_lan_ip(contact.endpoint().ip())
            })
            .copied()
            .collect();
        near.sort_by_key(|contact| contact.id().distance(&self.target));
        near.truncate(KadNode::CALLBACK_WALK_ASK_BUDGET);
        near
    }

    /// The walk is over: fan the purpose's terminal action to the closest
    /// responded contacts, or complete with nothing reachable.
    fn converge(&mut self, now: KadInstant, actions: &mut Vec<KadWalkAction>) {
        // A self-lookup has no terminal action — it warmed the neighborhood by
        // walking, and simply ends. No `0x34`/`0x44` fan-out, empty table or not.
        if let KadWalkPurpose::SelfLookup { .. } = self.purpose {
            self.complete = true;
            actions.push(KadWalkAction::Complete {
                outcome: KadWalkOutcome::SelfLookup,
            });
            return;
        }
        if let KadWalkPurpose::UdpFirewallHelpers { .. } = self.purpose {
            self.complete = true;
            actions.push(KadWalkAction::Complete {
                outcome: KadWalkOutcome::UdpFirewallHelpers,
            });
            return;
        }
        // The FINDBUDDY walk asks **one** contact — the closest that answered
        // (aMule's `m_possible.begin()`) — and ends. It opens no terminal
        // phase: the answer it waits for is a `0x5A` on the buddy codec, which
        // the node's own recruit window tracks, not a `KADEMLIA2_*_RES` this
        // walk could attribute. The contact must pass `StorePacket`'s gate,
        // the Callback Walk's own (`Search.cpp:624-628`): a buddy recruited
        // outside `SEARCHTOLERANCE` could never be reached by an ID-only
        // callback, which asks only contacts inside it.
        if let KadWalkPurpose::FindBuddy { .. } = self.purpose {
            let closest = self.callback_recipients().into_iter().next();
            self.complete = true;
            if let Some(contact) = closest {
                actions.push(KadWalkAction::SendFindBuddy { contact });
            }
            actions.push(KadWalkAction::Complete {
                outcome: KadWalkOutcome::FindBuddy {
                    asked: closest.is_some(),
                },
            });
            return;
        }
        if let KadWalkPurpose::CallbackWalk { .. } = self.purpose {
            let near = self.callback_recipients();
            self.complete = true;
            let asked = near.len();
            actions.extend(
                near.into_iter()
                    .map(|contact| KadWalkAction::SendCallback { contact }),
            );
            actions.push(KadWalkAction::Complete {
                outcome: KadWalkOutcome::CallbackWalk { asked },
            });
            return;
        }
        let fan = self.terminal_fan();
        if fan.is_empty() {
            self.complete = true;
            actions.push(KadWalkAction::Complete {
                outcome: if self.purpose.is_search() {
                    KadWalkOutcome::Search {
                        result_rows: 0,
                        ended_by: KadSearchEnd::NoSearchableContacts,
                    }
                } else {
                    KadWalkOutcome::Publish {
                        acked_stores: 0,
                        ended_by: KadPublishEnd::NoPublishableContacts,
                    }
                },
            });
            return;
        }
        let (window, action): (_, fn(KadContact) -> KadWalkAction) = if self.purpose.is_search() {
            (KadNode::SOURCE_SEARCH_WINDOW, |contact| {
                KadWalkAction::SendSearch { contact }
            })
        } else {
            (KadNode::PUBLISH_ACK_WINDOW, |contact| {
                KadWalkAction::SendPublish { contact }
            })
        };
        self.terminal = Some(TerminalPhase {
            endpoints: fan.iter().map(|contact| contact.endpoint()).collect(),
            deadline: now + window,
            rows_consumed: 0,
            acked: Vec::new(),
        });
        for contact in fan {
            actions.push(action(contact));
        }
    }
}
