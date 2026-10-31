//! The **Callback Pace** (ADR-0061): the session's one gate on `0x52
//! KADEMLIA_CALLBACK_REQ`.
//!
//! Stock tracks the opcode per sender IP, across every file: one a minute,
//! strictly more than 60 s apart, and a packet counts even when it is dropped
//! (`PacketTracking.cpp:158-160`, `:188-215`), so an early send also costs the
//! next one. Every `0x52` the node sends is offered here first, whichever
//! download, source, reading or road it came from.
//!
//! An offer books the next free instant of its IP. That makes the rule one
//! line of arithmetic with no per-IP queue: sends to one IP leave
//! [`SPACING`] apart, in the order they were asked, and the instant an offer
//! is told is the instant it leaves. Time is the caller's, so the rule is
//! testable without sleeping.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::envelope::KadEnvelope;
use crate::{KadInstant, KadNodeEndpoint};

/// The stock window plus a margin for link jitter between our send and the
/// other side's tick.
const SPACING: Duration = Duration::from_secs(65);

/// How far ahead an offer may be booked. A held `0x52` holds a download slot,
/// so past this its road goes to the next candidate instead.
const MOST_AHEAD: Duration = SPACING.saturating_mul(4);

/// Sends held at once, across every IP.
const MOST_HELD: usize = 64;

/// IPs remembered at once, oldest out.
const MOST_IPS: usize = 1024;

/// A `0x52` ready to leave.
#[derive(Clone, Debug)]
pub(super) struct CallbackSend {
    pub(super) to: KadNodeEndpoint,
    pub(super) envelope: KadEnvelope,
    pub(super) road: CallbackSendRoad,
}

/// How a `0x52` leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CallbackSendRoad {
    /// Plain, as the endpoint-known send always is: nothing tells us the
    /// buddy's Kad version.
    Clear,
    /// Through the node's obfuscation matrix, as a walked contact's is.
    Contact,
}

/// What became of an offered send.
#[derive(Debug)]
pub(super) enum CallbackOffer {
    /// The IP's window is open: the send goes now.
    Leave(CallbackSend),
    /// Held; it comes out of [`CallbackPace::take_due`] after this long.
    Held(Duration),
    /// Past [`MOST_AHEAD`] or [`MOST_HELD`]: it was not kept.
    Refused,
}

/// Each IP's next free instant, and the sends waiting for theirs.
#[derive(Debug, Default)]
pub(super) struct CallbackPace {
    free_from: HashMap<Ipv4Addr, KadInstant>,
    /// Keyed by due instant, then offer order.
    held: BTreeMap<(KadInstant, u64), CallbackSend>,
    offers: u64,
}

impl CallbackPace {
    /// Book `send` on its IP's next free instant.
    pub(super) fn offer(&mut self, now: KadInstant, send: CallbackSend) -> CallbackOffer {
        let ip = send.to.ip();
        let leaves = self.free_from.get(&ip).map_or(now, |&free| free.max(now));
        if leaves <= now {
            self.book(ip, now);
            return CallbackOffer::Leave(send);
        }
        let wait = Duration::from_millis(leaves.as_millis() - now.as_millis());
        if wait > MOST_AHEAD || self.held.len() >= MOST_HELD {
            return CallbackOffer::Refused;
        }
        self.book(ip, leaves);
        self.offers += 1;
        self.held.insert((leaves, self.offers), send);
        CallbackOffer::Held(wait)
    }

    fn book(&mut self, ip: Ipv4Addr, leaves: KadInstant) {
        if self.free_from.len() >= MOST_IPS && !self.free_from.contains_key(&ip) {
            let oldest = self
                .free_from
                .iter()
                .min_by_key(|&(_, &free)| free)
                .map(|(&ip, _)| ip);
            if let Some(oldest) = oldest {
                self.free_from.remove(&oldest);
            }
        }
        self.free_from.insert(ip, leaves + SPACING);
    }

    /// The next send due at `now`, oldest booking first.
    pub(super) fn take_due(&mut self, now: KadInstant) -> Option<CallbackSend> {
        let entry = self.held.first_entry()?;
        (entry.key().0 <= now).then(|| entry.remove())
    }

    /// When the next held send falls due.
    pub(super) fn next_wake(&self) -> Option<KadInstant> {
        self.held.keys().next().map(|&(leaves, _)| leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KadId;
    use crate::buddy::BuddyMessage;

    fn send_to(ip: Ipv4Addr) -> CallbackSend {
        let request = BuddyMessage::CallbackReq {
            buddy_id: KadId::from_bytes([0x55; KadId::BYTE_LEN]),
            file_hash: rmule_primitives::FileHash::from_bytes([0x11; 16]),
            requester_tcp_port: 4662,
        };
        CallbackSend {
            to: KadNodeEndpoint::new(ip, 4672),
            envelope: request.encode(),
            road: CallbackSendRoad::Clear,
        }
    }

    #[test]
    fn the_ip_table_stays_bounded_and_forgets_the_oldest_first() {
        let mut pace = CallbackPace::default();
        let t0 = KadInstant::from_millis(1);
        let first = Ipv4Addr::from(1);
        pace.offer(t0, send_to(first));
        let later = t0 + Duration::from_secs(1);
        for n in 2..=u32::try_from(MOST_IPS + 1).unwrap() {
            pace.offer(later, send_to(Ipv4Addr::from(n)));
        }
        assert_eq!(pace.free_from.len(), MOST_IPS);
        assert!(!pace.free_from.contains_key(&first));
        assert!(pace.free_from.contains_key(&Ipv4Addr::from(2)));
    }

    #[test]
    fn a_full_hold_refuses_the_newcomer_and_keeps_every_held_send() {
        let mut pace = CallbackPace::default();
        let t0 = KadInstant::from_millis(1);
        for n in 1..=u32::try_from(MOST_HELD).unwrap() {
            let ip = Ipv4Addr::from(n);
            pace.offer(t0, send_to(ip));
            assert!(matches!(
                pace.offer(t0, send_to(ip)),
                CallbackOffer::Held(_)
            ));
        }
        let ip = Ipv4Addr::from(1);
        assert!(matches!(
            pace.offer(t0, send_to(ip)),
            CallbackOffer::Refused
        ));
        assert_eq!(pace.held.len(), MOST_HELD);
    }
}
