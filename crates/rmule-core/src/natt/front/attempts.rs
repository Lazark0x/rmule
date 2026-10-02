//! The **Traversal Attempt** (ADR-0091): one target's punch, from
//! the coordinator the route tree picked to the Tunnel or the retirement it
//! ends in.
//!
//! An attempt outlives a coordinator, which is the whole reason it exists.
//! ADR-0091 orders the two — the server first, the buddy on its refusal or its
//! silence — but a coordinator's outcome surfaces nowhere near the facts
//! needed to pick the next one: the server's `0x62` and its fifteen seconds of
//! nothing reach the **server session**, which knows a `ClientId` and no more,
//! while [`next_natt_coordinator`] needs the candidate's [`NattFacts`] and our
//! own position. The attempt is where the two meet, and it lives on the NAT-T
//! front's requester side because that is the one task that already owns a
//! target's ledger, its schedule and its dials.
//!
//! # What the attempt keeps, and what it deliberately does not
//!
//! It keeps which coordinator is in play, the candidate's facts, our position
//! **as the route tree measured it**, and what a buddy rendezvous re-emits on
//! a retry. It does not keep the claimant: the **Pending Tunnel Claim** table
//! is keyed by the same target hash and is the one owner of that fact, and a
//! second copy here would go stale the moment a later download displaced the
//! claim.
//!
//! The position is a snapshot on purpose. The alternative — re-reading it when
//! an introduction settles — means the front asking the core actor for the
//! server session lock and the Kad flag from inside the loop that feeds the
//! demux, which is exactly the await the front may not make. A coordinator
//! chosen from a stale position is still enacted against live seams, and they
//! refuse if the surface has gone.

use std::collections::HashMap;
use std::time::Instant;

use rmule_ed2k::HolepunchFailReason;
use rmule_net::natt::NattDatagramSink;
use rmule_peer::BUDDY_ID_LEN;
use rmule_peer::natt::{RENDEZVOUS_TIMEOUT, RetireReason};
use rmule_primitives::{ClientId, Ipv4Endpoint, UserHash};

use crate::callback::{NattCoordinator, NattFacts, SelfReach, next_natt_coordinator};
use crate::natt::RendezvousOffer;
use crate::natt::server_punch::IntroductionFailure;

use super::NattFront;
use super::identity::os_punch_jitter;

/// Which **Rendezvous coordinator** is carrying one attempt right now.
///
/// The enactable half of [`NattCoordinator`]: a buddy whose endpoint is
/// unknown is a Kad walk, which is the Kad surface's emit and not this front's,
/// so it cannot be a coordinator *in play* here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptCoordinator {
    /// Our connected server was asked to introduce us (`0x60` naming
    /// `low_id`). The request left through the session, not through this
    /// front — the front owns what happens to it afterwards.
    Server {
        /// The Low-ID the `0x60` named, and the id a `0x62` names back.
        low_id: ClientId,
    },
    /// The target's Kad serving buddy is relaying our rendezvous.
    Buddy {
        /// The buddy's Kad ID — the rendezvous' routing key, and the only
        /// source a hint is believed from.
        buddy_id: [u8; BUDDY_ID_LEN],
        /// Where the rendezvous goes.
        buddy_udp: Ipv4Endpoint,
    },
}

/// Why a **Traversal Attempt** ended with no Tunnel.
///
/// Wider than [`RetireReason`] because a target can now run out of
/// *coordinators* as well as out of budget, and the two read differently: a
/// schedule that exhausted five rendezvous says the punch was tried and did
/// not work, while a server refusal with no buddy behind it says the punch was
/// never possible and names the server's own word for why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptRetirement {
    /// The **Rendezvous Schedule** spent the target's budget (ADR-0091's five
    /// attempts, or its 120 s), or a transport over the punched path failed
    /// for the last time.
    Schedule(RetireReason),
    /// Our server refused the introduction (`OP_LOWID_HOLEPUNCH_FAIL`) and no
    /// buddy could be asked. The server's own reason rides along: it is the
    /// only thing anyone ever *says* about a failed punch. Whether the reason
    /// is permanent is the reason's own property
    /// ([`HolepunchFailReason::is_permanent`]) and not a second fact —
    /// fallback runs server → buddy and never back, so a retryable refusal
    /// with no buddy behind it is just as final here.
    ServerRefused(HolepunchFailReason),
    /// Our server never answered the introduction and no buddy could be asked.
    /// A server that does not speak the punch ignores the opcode entirely, so
    /// silence is the only signal there is.
    ServerSilent,
    /// No coordinator could be asked at all, so no attempt was ever opened
    /// The candidate's facts admitted one — that is what got it
    /// admitted — but our own position did not: no live server punch to relay
    /// an introduction, and no buddy to fall to. Distinct from
    /// [`Self::ServerSilent`], which is a `0x60` that went out and drew
    /// nothing; here nothing went out.
    NoCoordinator,
    /// The **Callback Walk** toward the target's buddy ID met no contact near
    /// enough to be the buddy, so no `0x52` left. Not a Traversal
    /// Attempt's end: it retires the buddy-callback road a punch may ride
    /// beside, and it rides the same channel because the download brain is
    /// the one owner of what either costs the candidate.
    BuddyNotFound,
    /// A Callback Walk toward the same buddy ID was already running, so this
    /// one never started (aMule's `CSearchManager::StartSearch` refusal,
    /// `SearchManager.cpp:153-160`; `TryToConnect` declines the source,
    /// `BaseClient.cpp:2166-2171`). The buddy-callback road is over, as for
    /// [`Self::BuddyNotFound`].
    CallbackWalkBusy,
    /// The **punch** coordinator was named by ID alone — no `TAG_SERVERIP`/
    /// `TAG_SERVERPORT` to send `OP_REASKCALLBACKUDP` (`0x94`) to — and the
    /// dialect has no walk that carries it there (2026-09-23).
    /// eMuleAI's own unknown-buddy-IP fallback (`BaseClient.cpp:3282-3323`,
    /// `a2f05dc`) never resolves an endpoint for `OP_RENDEZVOUS`: it first
    /// asks the target directly (`RequestServingBuddyInfo`) and, failing
    /// that, starts the *same* aMule-shape `FINDSOURCE`/`0x52` lookup this
    /// crate already built as the Callback Walk (`0x52`) — which
    /// answers the buddy-callback road, not the punch, and which the
    /// dialect's own author calls a should-not-happen path ("I don't think
    /// we should ever have a serving buddy without its IP (any more)...
    /// bad luck, as lookups aren't supposed to happen anyway",
    /// `BaseClient.cpp:3308-3315`). A punch toward an ID-only buddy has no
    /// road at all, so it ends at once rather than holding a slot for a walk
    /// that would never carry it.
    CoordinatorEndpointUnknown,
    /// The **buddy-callback road** (the `0x52` emit or the Callback Walk)
    /// was asked with no Kad node running (2026-09-23).
    /// aMule removes such a source at once rather than waiting: its LowID
    /// branch checks `Kademlia::CKademlia::IsConnected()` before either the
    /// known-endpoint `0x52` or the `FINDSOURCE` walk and, finding it false,
    /// calls `RemoveSource` on the spot (`BaseClient.cpp:2123-2130`, "Kad
    /// Firewalled source but not connected to Kad"). The check gates both
    /// sub-cases at once, exactly as it does here. The direct-UDP `0x95`
    /// road is untouched: aMule's own branch for it
    /// (`BaseClient.cpp:2043-2050`) carries no such check.
    KadNotRunning,
    /// The route tree chose a punch this session could not open:
    /// the target's or our own User Hash is unknown, so no attempt could be
    /// keyed, or the NAT-T Front refused the `Begin`. A `0x60` that already
    /// left is then owned by nobody, and no retirement would ever follow it.
    NotEnactable,
    /// The candidate's invitation never left: the buddy's `0x52`
    /// had no buddy or no listener port to name, or the direct `0x95` had no
    /// bound client-UDP send half, listener, user hash or Kad UDP endpoint.
    /// Ends the invitation road as [`Self::KadNotRunning`] does.
    CallbackNotSent,
}

impl AttemptRetirement {
    /// Whether this ends the candidate's **buddy-callback road** (or, for
    /// [`Self::CallbackNotSent`], its direct-UDP road) rather than a punch.
    pub(crate) const fn ends_buddy_callback(self) -> bool {
        matches!(
            self,
            Self::BuddyNotFound
                | Self::CallbackWalkBusy
                | Self::KadNotRunning
                | Self::CallbackNotSent
        )
    }
}

/// What a settled introduction means for the attempt that asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FallThrough {
    /// Arm the rendezvous toward this buddy — ADR-0091's second coordinator.
    Buddy {
        buddy_id: [u8; BUDDY_ID_LEN],
        buddy_udp: Ipv4Endpoint,
    },
    /// No coordinator is left: the target is *temporarily unreachable*.
    Retire(AttemptRetirement),
}

/// One target's traversal, from the first coordinator to the last.
#[derive(Clone, Copy, Debug)]
pub(super) struct TraversalAttempt {
    /// The coordinator in play. It changes exactly once — server → buddy.
    pub(super) coordinator: AttemptCoordinator,
    /// The candidate's own half of rung 1's condition, as the channel that
    /// named it stated it.
    facts: NattFacts,
    /// Our position as the route tree measured it (see the module docs).
    ours: SelfReach,
    /// What a rendezvous toward the buddy re-emits on a retry. Carried from
    /// the first coordinator so a fall-through needs nothing from the caller —
    /// the caller is a `0x62` on the server session, which has no offer to
    /// make.
    pub(super) offer: RendezvousOffer,
    /// When this attempt began, for the log line that closes it.
    began_at: Instant,
}

impl TraversalAttempt {
    /// Who introduces us next, now that the coordinator in play has settled
    /// without a transport. Pure: the one place ADR-0091's fallback ordering
    /// is read at run time.
    ///
    /// A buddy the selector names but whose endpoint is unknown retires the
    /// attempt rather than arming anything: finding it is a FINDSOURCE walk
    /// toward the buddy ID, which is the Kad surface's emit and not this
    /// front's, so the attempt would sit on a rendezvous nobody sent.
    pub(super) fn on_coordinator_failed(&self, failure: IntroductionFailure) -> FallThrough {
        let retire = || {
            FallThrough::Retire(match failure {
                IntroductionFailure::Refused { reason, .. } => {
                    AttemptRetirement::ServerRefused(reason)
                }
                IntroductionFailure::Silence => AttemptRetirement::ServerSilent,
            })
        };
        let failed = match self.coordinator {
            AttemptCoordinator::Server { low_id } => NattCoordinator::Server { low_id },
            AttemptCoordinator::Buddy {
                buddy_id,
                buddy_udp,
            } => NattCoordinator::Buddy {
                buddy_id: rmule_kad::KadId::from_bytes(buddy_id),
                buddy_udp: Some(buddy_udp),
            },
        };
        match next_natt_coordinator(&self.facts, &self.ours, &failed) {
            Some(NattCoordinator::Buddy {
                buddy_id,
                buddy_udp: Some(buddy_udp),
            }) => FallThrough::Buddy {
                buddy_id: *buddy_id.as_bytes(),
                buddy_udp,
            },
            Some(NattCoordinator::Buddy { .. } | NattCoordinator::Server { .. }) | None => retire(),
        }
    }
}

/// Every **Traversal Attempt** this front owns, keyed the way a hint, a `0x61`
/// and the claim table all key a target: by its **User Hash**.
///
/// The second index is what lets a coordinator's outcome find its attempt at
/// all. A `0x62` and an overdue `0x60` name a **`ClientId`** — the only name
/// the server namespace has for a Low-ID peer — and nothing on the wire joins
/// it to a user hash, so the join is recorded here when the attempt begins,
/// which is the one moment both names are in the same hand.
#[derive(Debug, Default)]
pub(super) struct Attempts {
    by_target: HashMap<UserHash, TraversalAttempt>,
    by_low_id: HashMap<ClientId, UserHash>,
}

impl Attempts {
    /// Open an attempt toward `target`. The front calls it only for a target
    /// with no live attempt; a replaced entry would lose its server-id join.
    pub(super) fn begin(&mut self, target: UserHash, attempt: TraversalAttempt) {
        if let Some(AttemptCoordinator::Server { low_id }) =
            self.by_target.get(&target).map(|held| held.coordinator)
        {
            self.by_low_id.remove(&low_id);
        }
        if let AttemptCoordinator::Server { low_id } = attempt.coordinator {
            self.by_low_id.insert(low_id, target);
        }
        self.by_target.insert(target, attempt);
    }

    /// The attempt toward `target`, if one is open.
    pub(super) fn get(&self, target: &UserHash) -> Option<&TraversalAttempt> {
        self.by_target.get(target)
    }

    /// The client-UDP port `target` advertised, when the channel that named
    /// it carried one — the **Peer Mapping**'s advertised half (ADR-0091's
    /// port-prediction amendment). `None` with no attempt: a responder holds none.
    pub(super) fn advertised_udp(&self, target: &UserHash) -> Option<u16> {
        self.by_target
            .get(target)
            .and_then(|attempt| attempt.facts.advertised_udp)
    }

    /// Whether an attempt toward `target` is open — what keeps a retired
    /// target from being reported once a second forever.
    pub(super) fn contains(&self, target: &UserHash) -> bool {
        self.by_target.contains_key(target)
    }

    /// Which target a server-coordinated introduction naming `low_id`
    /// belongs to.
    pub(super) fn target_of(&self, low_id: ClientId) -> Option<UserHash> {
        self.by_low_id.get(&low_id).copied()
    }

    /// Move `target`'s attempt onto the buddy coordinator, releasing the
    /// server id it no longer answers to.
    pub(super) fn fall_through(
        &mut self,
        target: UserHash,
        buddy_id: [u8; BUDDY_ID_LEN],
        buddy_udp: Ipv4Endpoint,
    ) {
        let Some(attempt) = self.by_target.get_mut(&target) else {
            return;
        };
        if let AttemptCoordinator::Server { low_id } = attempt.coordinator {
            self.by_low_id.remove(&low_id);
        }
        attempt.coordinator = AttemptCoordinator::Buddy {
            buddy_id,
            buddy_udp,
        };
    }

    /// The server introduced `target` (a `0x61`): its leg is settled, so the
    /// attempt stops answering to the Low-ID. A `0x62` or an overdue silence
    /// naming that id later is about a request already answered — the `0x61`
    /// settles one only when exactly one is outstanding — and must not start
    /// a buddy rendezvous beside the dial the introduction armed.
    pub(super) fn introduced(&mut self, target: &UserHash) {
        if let Some(AttemptCoordinator::Server { low_id }) =
            self.by_target.get(target).map(|held| held.coordinator)
        {
            self.by_low_id.remove(&low_id);
        }
    }

    /// When the attempt toward `target` began, if one is open — what its dial
    /// budget is measured from.
    pub(super) fn began_at(&self, target: &UserHash) -> Option<Instant> {
        self.by_target.get(target).map(|attempt| attempt.began_at)
    }

    /// Attempts older than ADR-0091's 120 s run — the backstop the tick
    /// retires when no other clock holds them.
    pub(super) fn past_run(&self, now: Instant) -> Vec<UserHash> {
        self.by_target
            .iter()
            .filter(|(_, attempt)| {
                now.saturating_duration_since(attempt.began_at) >= RENDEZVOUS_TIMEOUT
            })
            .map(|(target, _)| *target)
            .collect()
    }

    /// Forget `target`'s attempt — it rose a Tunnel, it retired, or its run is
    /// over. Returns it, so the caller can say how long it lasted.
    pub(super) fn end(&mut self, target: &UserHash) -> Option<TraversalAttempt> {
        let attempt = self.by_target.remove(target)?;
        if let AttemptCoordinator::Server { low_id } = attempt.coordinator {
            self.by_low_id.remove(&low_id);
        }
        Some(attempt)
    }
}

impl<S: NattDatagramSink> NattFront<S> {
    /// Forget `target`'s attempt, any burst still held for it and its dial
    /// schedule — the one door every ending goes through, so no ending can
    /// leave a hold behind to dial a second Tunnel after the first has served
    /// Nor a schedule that re-dials for nobody and, at its
    /// budget, retires the target a second time.
    pub(super) fn end_attempt(&mut self, target: &UserHash) -> Option<TraversalAttempt> {
        self.held.cancel_peer(target);
        self.dials.forget(target);
        self.end_prediction(target, false);
        self.attempts.end(target)
    }

    /// The route tree chose NAT traversal toward `target` and picked
    /// `coordinator`: own the introduction from here.
    ///
    /// The server leg's `0x60` has already left through the server session —
    /// the front holds no server link — so a server-coordinated attempt begins
    /// with nothing on the wire and waits for the coordinator's own outcome.
    /// A buddy-coordinated one arms the **Rendezvous Schedule** and emits what
    /// the schedule asks for, which is what this front has always done.
    pub(super) async fn begin_attempt(
        &mut self,
        target: UserHash,
        coordinator: AttemptCoordinator,
        facts: NattFacts,
        ours: SelfReach,
        offer: RendezvousOffer,
        now: Instant,
    ) {
        if self.attempts.contains(&target) {
            // One attempt per peer at a time: a second download
            // falling to the same target joins the traversal already running.
            // Re-beginning would move a buddy leg back to the server, re-arm a
            // schedule mid-flight and leave the first leg's rendezvous with no
            // coordinator to re-emit it.
            tracing::debug!(
                ?coordinator,
                "a NAT traversal toward this target is already running; joined"
            );
            return;
        }
        self.attempts.begin(
            target,
            TraversalAttempt {
                coordinator,
                facts,
                ours,
                offer,
                began_at: now,
            },
        );
        self.wiring
            .diagnostics
            .count_natt_attempt(matches!(coordinator, AttemptCoordinator::Server { .. }));
        if let AttemptCoordinator::Buddy {
            buddy_id,
            buddy_udp,
        } = coordinator
        {
            let step = self
                .requester
                .begin(target, buddy_id, buddy_udp, now, os_punch_jitter());
            self.act_on_step(target, step, now).await;
        }
    }

    /// A coordinator settled an introduction without a transport: the server
    /// refused it (`0x62`), or fifteen seconds passed with nothing at all.
    ///
    /// The attempt decides; this enacts. A fall-through arms the buddy
    /// rendezvous exactly as the route tree's own buddy rung would — the same
    /// `RouteChosen` trigger on the same schedule, so a target that has
    /// already spent attempts does not get a fresh budget for changing
    /// coordinators.
    pub(super) async fn on_introduction_failed(
        &mut self,
        low_id: ClientId,
        failure: IntroductionFailure,
        now: Instant,
    ) {
        let Some(target) = self.attempts.target_of(low_id) else {
            // A refusal for an introduction this front never owned: a `0x60`
            // sent before the attempt existed, or one whose target carried no
            // User Hash to key an attempt by. Nothing to fall through.
            tracing::debug!(
                low_id = low_id.as_u32(),
                ?failure,
                "a settled server introduction names no traversal attempt"
            );
            return;
        };
        let Some(attempt) = self.attempts.get(&target) else {
            return;
        };
        match attempt.on_coordinator_failed(failure) {
            FallThrough::Buddy {
                buddy_id,
                buddy_udp,
            } => {
                self.attempts.fall_through(target, buddy_id, buddy_udp);
                self.wiring.diagnostics.count_natt_fallthrough();
                tracing::info!(
                    ?failure,
                    ?buddy_udp,
                    "the server could not introduce us; the attempt falls to the target's buddy"
                );
                let step =
                    self.requester
                        .begin(target, buddy_id, buddy_udp, now, os_punch_jitter());
                self.act_on_step(target, step, now).await;
            }
            FallThrough::Retire(retirement) => self.retire_attempt(target, retirement, now).await,
        }
    }

    /// End `target`'s attempt as *temporarily unreachable*, count it, and tell
    /// the download that claimed the target — if one did.
    ///
    /// The one exit for every way an attempt dies: a schedule that retired the
    /// target, a server refusal with no buddy behind it, and a dial budget
    /// spent. Reporting from here rather than from each of the three is what
    /// makes "a retirement reaches its claimant" a property of the front and
    /// not of whichever path happened to notice.
    pub(super) async fn retire_attempt(
        &mut self,
        target: UserHash,
        retirement: AttemptRetirement,
        now: Instant,
    ) {
        let began_at = self.end_attempt(&target).map(|attempt| attempt.began_at);
        self.wiring.diagnostics.record_natt_retirement(retirement);
        tracing::info!(
            ?retirement,
            spent = ?began_at.map(|at| now.saturating_duration_since(at)),
            "NAT traversal target temporarily unreachable"
        );
        // The claim table's lock is a plain mutex held for one map lookup and
        // a `try_send` — never a channel the front would wait on. A runner
        // that has stopped draining costs its own retirement notice, not the
        // front's whole loop.
        self.wiring.claims.retire(target, retirement).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_kad::KadId;

    use crate::callback::BuddyContact;

    use super::*;

    fn buddy_udp() -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 9000)
    }

    fn facts(buddy: Option<BuddyContact>) -> NattFacts {
        NattFacts {
            on_our_server: true,
            supports_natt: true,
            buddy,
            advertised_udp: None,
        }
    }

    fn ours() -> SelfReach {
        SelfReach {
            reachable: false,
            udp_on: true,
            kad_running: true,
            dial: crate::dialable::DialPosition::default(),
            server_punch: true,
        }
    }

    fn attempt(buddy: Option<BuddyContact>) -> TraversalAttempt {
        TraversalAttempt {
            coordinator: AttemptCoordinator::Server {
                low_id: ClientId::from_u32(42),
            },
            facts: facts(buddy),
            ours: ours(),
            offer: RendezvousOffer {
                our_user_hash: UserHash::from_bytes([0xAA; UserHash::BYTE_LEN]),
                options: rmule_peer::natt::NattConnectOptions::advertise(0, true, false),
                file_hash: None,
                claimed_endpoint: None,
                transport: rmule_peer::natt::NattTransport::Utp,
            },
            began_at: Instant::now(),
        }
    }

    fn known_buddy() -> BuddyContact {
        BuddyContact {
            buddy_id: KadId::from_bytes([0x7A; KadId::BYTE_LEN]),
            buddy_udp: Some(buddy_udp()),
        }
    }

    /// Both ways a server introduction dies reach the same second
    /// coordinator: a `0x62` with its reason, and fifteen seconds of nothing.
    /// The buddy the candidate named is what the attempt falls to, and
    /// nothing about the failure changes who that is.
    #[test]
    fn a_refused_and_a_silent_introduction_both_fall_to_the_candidates_buddy() {
        let attempt = attempt(Some(known_buddy()));
        let fell = FallThrough::Buddy {
            buddy_id: [0x7A; BUDDY_ID_LEN],
            buddy_udp: buddy_udp(),
        };
        for failure in [
            IntroductionFailure::Refused {
                reason: HolepunchFailReason::TargetNoUdp,
                permanent: true,
            },
            IntroductionFailure::Refused {
                reason: HolepunchFailReason::TargetNotConnected,
                permanent: false,
            },
            IntroductionFailure::Silence,
        ] {
            assert_eq!(attempt.on_coordinator_failed(failure), fell);
        }
    }

    /// With no buddy the attempt is over, and it retires carrying what the
    /// coordinator actually said: the server's own refusal reason, or the fact
    /// that it said nothing. "Attempts exhausted" would be a lie — not one
    /// rendezvous was ever sent.
    #[test]
    fn a_candidate_with_no_buddy_retires_with_the_servers_own_reason() {
        let attempt = attempt(None);
        assert_eq!(
            attempt.on_coordinator_failed(IntroductionFailure::Refused {
                reason: HolepunchFailReason::TargetIsHighId,
                permanent: true,
            }),
            FallThrough::Retire(AttemptRetirement::ServerRefused(
                HolepunchFailReason::TargetIsHighId
            ))
        );
        assert_eq!(
            attempt.on_coordinator_failed(IntroductionFailure::Silence),
            FallThrough::Retire(AttemptRetirement::ServerSilent)
        );
    }

    /// A buddy nobody holds an endpoint for is a Kad walk, and this front
    /// emits none — so it is not a coordinator it can fall to. And a buddy
    /// coordinator that failed falls to nobody: going back up to the server
    /// that already refused would loop (ADR-0091's ordering).
    #[test]
    fn an_unwalkable_buddy_and_a_failed_buddy_both_end_the_attempt() {
        let walk_only = attempt(Some(BuddyContact {
            buddy_udp: None,
            ..known_buddy()
        }));
        assert_eq!(
            walk_only.on_coordinator_failed(IntroductionFailure::Silence),
            FallThrough::Retire(AttemptRetirement::ServerSilent)
        );

        let on_the_buddy = TraversalAttempt {
            coordinator: AttemptCoordinator::Buddy {
                buddy_id: [0x7A; BUDDY_ID_LEN],
                buddy_udp: buddy_udp(),
            },
            ..attempt(Some(known_buddy()))
        };
        assert_eq!(
            on_the_buddy.on_coordinator_failed(IntroductionFailure::Silence),
            FallThrough::Retire(AttemptRetirement::ServerSilent)
        );
    }

    /// The join a `0x62` needs: an attempt opened on the server coordinator
    /// answers to the Low-ID the `0x60` named, and stops answering to it the
    /// moment it falls through — the buddy leg's failures are the schedule's,
    /// and a late refusal must not settle a leg it is not about.
    #[test]
    fn the_low_id_index_follows_the_coordinator_in_play() {
        let mut attempts = Attempts::default();
        let target = UserHash::from_bytes([0x44; UserHash::BYTE_LEN]);
        let low_id = ClientId::from_u32(42);
        attempts.begin(target, attempt(Some(known_buddy())));
        assert_eq!(attempts.target_of(low_id), Some(target));

        attempts.fall_through(target, [0x7A; BUDDY_ID_LEN], buddy_udp());
        assert_eq!(attempts.target_of(low_id), None);
        assert!(attempts.contains(&target));

        assert!(attempts.end(&target).is_some());
        assert!(!attempts.contains(&target));
    }
}
