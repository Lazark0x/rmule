//! The registry's table: every registration, and the two keys' indexes into
//! it, each kept in filing order per key. Everything here runs under the
//! registry's lock and returns what must be reported once it is released.

use std::collections::HashMap;

use rmule_primitives::UserHash;

use super::{
    AdoptSender, Adoption, AdoptionBrief, CallbackKey, InboundArrival, InboundVerdict, RetireSender,
};

pub(super) type RegistrationId = u64;

/// Every registration, and the two keys' indexes into them, each in filing
/// order per key.
#[derive(Default)]
pub(super) struct Registrations {
    next_id: RegistrationId,
    pub(super) held: HashMap<RegistrationId, Registration>,
    by_callback: HashMap<CallbackKey, Vec<RegistrationId>>,
    by_target: HashMap<UserHash, Vec<RegistrationId>>,
}

/// One download's wait on one pending callback. It outlives its roads: an
/// adoption spends the roads, the handle's drop ends the registration.
pub(super) struct Registration {
    callback: CallbackKey,
    adopt_tx: AdoptSender,
    retire_tx: RetireSender,
    relayed: Option<CallbackRoad>,
    claim: Option<ClaimRoad>,
}

/// The server-relayed road, filed under the key the peer's hello reports.
pub(super) struct CallbackRoad {
    pub(super) routing: CallbackKey,
    pub(super) brief: AdoptionBrief,
}

/// The tunnel road, filed under the target's User Hash.
pub(super) struct ClaimRoad {
    pub(super) target: UserHash,
    pub(super) brief: AdoptionBrief,
    pub(super) dial_back: bool,
}

/// Which road a connection was adopted down.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Road {
    Callback,
    DialedTunnel,
    DialBack,
}

/// What an adoption leaves to report once the lock is released.
pub(super) struct Landing {
    /// The road the connection came down.
    pub(super) road: Road,
    /// The claim the callback's own road outran, when it did.
    pub(super) let_go: Option<LetGo>,
}

/// A claim its own download dropped: on which target, and whether it was that
/// target's last.
pub(super) struct LetGo {
    pub(super) target: UserHash,
    pub(super) last: bool,
}

impl Registrations {
    /// Whether any registration holds a **Dial-Back Claim** — a peer that
    /// will dial us with nothing here having aimed at it.
    pub(super) fn awaits_dial_back(&self) -> bool {
        self.held
            .values()
            .any(|held| held.claim.as_ref().is_some_and(|claim| claim.dial_back))
    }

    pub(super) fn open(
        &mut self,
        callback: CallbackKey,
        adopt_tx: AdoptSender,
        retire_tx: RetireSender,
    ) -> RegistrationId {
        let id = self.next_id;
        self.next_id += 1;
        self.held.insert(
            id,
            Registration {
                callback,
                adopt_tx,
                retire_tx,
                relayed: None,
                claim: None,
            },
        );
        id
    }

    pub(super) fn file_callback(&mut self, id: RegistrationId, road: CallbackRoad) {
        let Some(registration) = self.held.get_mut(&id) else {
            return;
        };
        let routing = road.routing;
        match registration.relayed.replace(road) {
            Some(prior) if prior.routing == routing => {}
            Some(prior) => {
                unlist(&mut self.by_callback, prior.routing, id);
                self.by_callback.entry(routing).or_default().push(id);
            }
            None => self.by_callback.entry(routing).or_default().push(id),
        }
    }

    /// File `road`; a claim moved off another target lets that one go.
    pub(super) fn file_claim(&mut self, id: RegistrationId, mut road: ClaimRoad) -> Option<LetGo> {
        let registration = self.held.get_mut(&id)?;
        let target = road.target;
        match registration.claim.take() {
            Some(prior) if prior.target == target => {
                road.dial_back |= prior.dial_back;
                registration.claim = Some(road);
                None
            }
            Some(prior) => {
                registration.claim = Some(road);
                let last = unlist(&mut self.by_target, prior.target, id);
                self.by_target.entry(target).or_default().push(id);
                Some(LetGo {
                    target: prior.target,
                    last,
                })
            }
            None => {
                registration.claim = Some(road);
                self.by_target.entry(target).or_default().push(id);
                None
            }
        }
    }

    pub(super) fn retract_claim(&mut self, id: RegistrationId) -> Option<LetGo> {
        let claim = self.held.get_mut(&id)?.claim.take()?;
        let last = unlist(&mut self.by_target, claim.target, id);
        Some(LetGo {
            target: claim.target,
            last,
        })
    }

    pub(super) fn release(&mut self, id: RegistrationId) -> Option<LetGo> {
        let registration = self.held.remove(&id)?;
        if let Some(relayed) = registration.relayed {
            unlist(&mut self.by_callback, relayed.routing, id);
        }
        let claim = registration.claim?;
        let last = unlist(&mut self.by_target, claim.target, id);
        Some(LetGo {
            target: claim.target,
            last,
        })
    }

    /// The verdict, and the claim an adoption down the callback road let go.
    pub(super) fn triage(
        &mut self,
        arrival: InboundArrival,
        hello: UserHash,
        reported: CallbackKey,
    ) -> (InboundVerdict, Option<Landing>) {
        if let InboundArrival::DialedToward(target) = arrival
            && let Some(&oldest) = self.by_target.get(&target).and_then(|ids| ids.first())
        {
            if target != hello {
                return (InboundVerdict::Mismatch, None);
            }
            return self.adopt(oldest, Road::DialedTunnel);
        }
        if let Some(&oldest) = self.by_callback.get(&reported).and_then(|ids| ids.first()) {
            return self.adopt(oldest, Road::Callback);
        }
        let dial_back = self.by_target.get(&hello).and_then(|ids| {
            ids.iter().copied().find(|id| {
                self.held
                    .get(id)
                    .and_then(|registration| registration.claim.as_ref())
                    .is_some_and(|claim| claim.dial_back)
            })
        });
        match dial_back {
            Some(oldest) => self.adopt(oldest, Road::DialBack),
            None => (InboundVerdict::Unclaimed, None),
        }
    }

    /// Spend both of `id`'s roads, handing out the brief of the one that
    /// landed. The claim is let go only when the callback's own road landed:
    /// a claim that landed was answered, not abandoned.
    fn adopt(&mut self, id: RegistrationId, road: Road) -> (InboundVerdict, Option<Landing>) {
        let registration = self
            .held
            .get_mut(&id)
            .expect("an indexed registration is held");
        let relayed = registration.relayed.take();
        let claim = registration.claim.take();
        let callback = registration.callback;
        let adopt_tx = registration.adopt_tx.clone();
        if let Some(relayed) = &relayed {
            unlist(&mut self.by_callback, relayed.routing, id);
        }
        let mut let_go = None;
        if let Some(claim) = &claim {
            let last = unlist(&mut self.by_target, claim.target, id);
            if road == Road::Callback {
                let_go = Some(LetGo {
                    target: claim.target,
                    last,
                });
            }
        }
        let brief = match road {
            Road::Callback => relayed.map(|relayed| relayed.brief),
            Road::DialedTunnel | Road::DialBack => claim.map(|claim| claim.brief),
        }
        .expect("a road is adopted only through its own index");
        let adoption = Adoption {
            brief,
            callback,
            adopt_tx,
        };
        (
            InboundVerdict::Adopt(adoption),
            Some(Landing { road, let_go }),
        )
    }

    /// Every claimant of `target`, oldest first, with where to tell it.
    pub(super) fn claimants(&self, target: UserHash) -> Vec<(CallbackKey, RetireSender)> {
        self.by_target
            .get(&target)
            .into_iter()
            .flatten()
            .filter_map(|id| self.held.get(id))
            .map(|registration| (registration.callback, registration.retire_tx.clone()))
            .collect()
    }
}

/// Take `id` off `key`'s list: whether the list is now empty.
fn unlist<K: std::hash::Hash + Eq>(
    index: &mut HashMap<K, Vec<RegistrationId>>,
    key: K,
    id: RegistrationId,
) -> bool {
    let Some(ids) = index.get_mut(&key) else {
        return true;
    };
    ids.retain(|&held| held != id);
    if ids.is_empty() {
        index.remove(&key);
        true
    } else {
        false
    }
}
