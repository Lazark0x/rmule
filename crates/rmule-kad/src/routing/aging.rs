//! Per-contact aging and the two table operations that read and write it —
//! the small-timer pass and marking a contact alive (ADR-0067 amendment).
//! The aging is the one piece of aMule's `CContact`
//! type ladder the pass needs. aMule keeps
//! `m_type` (0..4), `m_expires`, `m_created` and `m_lastTypeSet` per contact
//! (`Contact.cpp:67`, kno `ab483654`); of those, only the expiry decides
//! whether `OnSmallTimer` hellos a bucket's oldest contact
//! (`RoutingZone.cpp:976-981`: not due while `m_expires >= now`), and only the
//! creation instant decides how long an answer keeps it out
//! (`CContact::UpdateType`, `Contact.cpp:101-119`). The type number itself is
//! not kept (nothing else rmule runs reads it — types 0..2 feed only aMule's
//! random-contact and big-timer selections, which stay parked), but rmule
//! keeps its dead-sweep guarantee: a lapsed contact gets a second hello with
//! its own check window before eviction, matching the two `CheckingType`
//! calls the most common (type-2, under-an-hour) band needs to reach type 4
//! (`RoutingZone.cpp:960-968`) — [`ContactAging::checks`] is that count, held
//! separately from the type number itself.

use std::time::Duration;

use super::KadRoutingTable;
use crate::{KadContact, KadId, KadInstant};

/// How long a small-timer hello keeps its contact out of the pass — aMule's
/// `CContact::CheckingType`, `m_expires = now + MIN2S(2)` (`Contact.cpp:95`).
const HELLO_CHECK_WINDOW: Duration = Duration::from_secs(2 * 60);

/// How long an answer keeps a contact out of the pass while it is under an
/// hour old — `UpdateType`'s `case 0: m_expires = now + HR2S(1)`.
const ALIVE_WINDOW_FIRST_HOUR: Duration = Duration::from_secs(60 * 60);

/// The same in the contact's second hour — `case 1: MIN2S(90)`.
const ALIVE_WINDOW_SECOND_HOUR: Duration = Duration::from_secs(90 * 60);

/// The same from its third hour on — `default: HR2S(2)`.
const ALIVE_WINDOW_LATER: Duration = Duration::from_secs(2 * 60 * 60);

/// How many unanswered checks a lapsed contact gets before the pass evicts it
/// — the second-hello ladder. aMule's own count varies with the band the
/// contact was last alive in (1 for a never-verified type-3 contact, up to 4
/// for one that aged past its third hour before going stale); rmule keeps
/// neither the type number nor the band, so it floors every lapsed contact at
/// the two checks the most common (type-2) band needs — never fewer than
/// aMule's minimum, so a good contact never loses its second chance to one
/// lost datagram.
const MAX_HELLO_CHECKS: u8 = 2;

/// One routing-table entry's aging state: when it entered the table, when it
/// next falls due for a small-timer hello, and how many unanswered checks
/// it has already had since its last answer.
#[derive(Clone, Copy, Debug)]
pub(super) struct ContactAging {
    /// aMule's `m_created`: the instant the entry entered the table. An
    /// in-place update of a known contact keeps it (aMule updates the stored
    /// `CContact`, never a fresh one).
    created: KadInstant,
    /// aMule's `m_expires`; `None` is its `0` — never checked, never answered.
    expires: Option<KadInstant>,
    /// Unanswered [`start_check`](Self::start_check) calls since the last
    /// [`mark_alive`](Self::mark_alive) — aMule's type number, floored to the
    /// two-step count [`MAX_HELLO_CHECKS`] needs rather than kept as a 0..4
    /// band (see the module doc).
    checks: u8,
}

impl ContactAging {
    /// A contact just admitted — aMule's constructor (`m_type = 3`,
    /// `m_expires = 0`), whatever path admitted it (merge, hearsay, hello).
    pub(super) const fn fresh(now: KadInstant) -> Self {
        Self {
            created: now,
            expires: None,
            checks: 0,
        }
    }

    /// Whether the pass may hello this contact now. A never-checked contact is
    /// due at once. aMule first stamps `m_expires = now` on the pass that finds
    /// it `0` and only hellos it on a later pass it fronts
    /// (`RoutingZone.cpp:970-981`); rmule skips that stamp so a table-seeded
    /// start greets its seeds on the first pass, one pass (≤ 1 min)
    /// earlier than aMule, never later.
    pub(super) fn is_due(&self, now: KadInstant) -> bool {
        self.expires.is_none_or(|expires| expires < now)
    }

    /// Whether a due contact has already used up its checks — the pass must
    /// evict rather than hello it again (`RoutingZone.cpp:960-968`'s type-4
    /// dead sweep).
    pub(super) fn is_exhausted(&self) -> bool {
        self.checks >= MAX_HELLO_CHECKS
    }

    /// The pass hellos this contact: hold it out for the check window —
    /// `CheckingType`'s expiry — and count the check. aMule's `m_lastTypeSet`
    /// 10-s guard only protects the type number, which rmule does not keep.
    pub(super) fn start_check(&mut self, now: KadInstant) {
        self.expires = Some(now + HELLO_CHECK_WINDOW);
        self.checks += 1;
    }

    /// The contact answered: hold it out by its age — `UpdateType`'s ladder,
    /// in whole hours since `created` — and clear its check count, the reset
    /// that lets an answer between two hellos save the contact.
    pub(super) fn mark_alive(&mut self, now: KadInstant) {
        let window = if now < self.created + Duration::from_secs(60 * 60) {
            ALIVE_WINDOW_FIRST_HOUR
        } else if now < self.created + Duration::from_secs(2 * 60 * 60) {
            ALIVE_WINDOW_SECOND_HOUR
        } else {
            ALIVE_WINDOW_LATER
        };
        self.expires = Some(now + window);
        self.checks = 0;
    }
}

/// One [`small_timer_pass`](KadRoutingTable::small_timer_pass)'s outcome:
/// contacts to hello now, and contacts the ladder has exhausted — already
/// removed from the table by the time this is returned, so the caller only
/// needs to emit [`ContactEvicted`](crate::KadEvent::ContactEvicted) for
/// each.
pub(crate) struct SmallTimerOutcome {
    pub(crate) due: Vec<KadContact>,
    pub(crate) evicted: Vec<KadId>,
}

impl KadRoutingTable {
    /// One small-timer pass over the table — aMule's
    /// `CRoutingZone::OnSmallTimer` (`RoutingZone.cpp:926-1010`, kno
    /// `ab483654`) with each non-empty bucket as a leaf zone. Each bucket's
    /// oldest contact is looked at once: still inside its expiry, it moves to
    /// the back unhelloed (`PushToBottom`); due and not yet exhausted, it is
    /// returned for a hello and held out for the 2-min check window, staying
    /// at the front — only an answer ([`mark_alive`](Self::mark_alive)) moves
    /// it; due and already exhausted (its second check window lapsed with no
    /// answer), it is evicted outright, the dead-entry sweep folded into the
    /// same look rather than aMule's separate per-entry loop. So a pass
    /// yields at most one hello or one eviction per bucket, and join state
    /// plays no part.
    pub(crate) fn small_timer_pass(&mut self, now: KadInstant) -> SmallTimerOutcome {
        let mut due = Vec::new();
        let mut evicted = Vec::new();
        for bucket in self.buckets.iter_mut().filter(|b| !b.contacts.is_empty()) {
            let oldest = &mut bucket.contacts[0];
            if !oldest.aging.is_due(now) {
                let entry = bucket.contacts.remove(0);
                bucket.contacts.push(entry);
            } else if oldest.aging.is_exhausted() {
                evicted.push(oldest.contact.id());
            } else {
                oldest.aging.start_check(now);
                due.push(oldest.contact);
            }
        }
        for id in &evicted {
            self.evict(*id);
        }
        SmallTimerOutcome { due, evicted }
    }

    /// Mark a stored contact alive — aMule's `CRoutingBin::SetAlive`
    /// (`RoutingBin.cpp:108-120`): `UpdateType` holds it out of the small-timer
    /// pass for 1 h, 1.5 h or 2 h by its age, and it moves to the back of its
    /// bucket. aMule reaches this only when a live datagram (a hello, or a
    /// bootstrap answer's sender) updates a contact it already held, never on
    /// a first admission. Returns whether the contact was stored.
    pub fn mark_alive(&mut self, now: KadInstant, id: KadId) -> bool {
        let Some(index) = self.bucket_index(id) else {
            return false;
        };
        let bucket = &mut self.buckets[index];
        let Some(position) = bucket.contacts.iter().position(|e| e.contact.id() == id) else {
            return false;
        };
        let mut entry = bucket.contacts.remove(position);
        entry.aging.mark_alive(now);
        bucket.contacts.push(entry);
        true
    }
}
