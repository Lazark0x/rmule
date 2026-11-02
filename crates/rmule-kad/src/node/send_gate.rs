//! The **Kad Send Gate** (ADR-0064): the node's one gate on what it sends,
//! keyed `(ip, opcode)` over the flood limiter's own table.
//!
//! Stock counts per sender IP and opcode: one count per packet, dropped or
//! not, one leak per `60 / rate` s, a drop past `rate` and a 2 h ban past five
//! times that (`PacketTracking.cpp:188-226`). It has no sender side, so a large
//! share or queue reaches peers as a burst. Every paced opcode rmule sends is
//! offered here first, whichever walk, download or road it came from.
//!
//! An offer books a key's next instant, one spacing after the last, so sends
//! to one key leave in the order they were asked and the instant an offer is
//! told is the instant it leaves. A key keeps `rate - 1` counts for a burst,
//! which leaves one of stock's unspent. That is what a Kad restart costs: the
//! gate dies with the node and the peer's count does not. Rate 1 has no count
//! to spare and is plain spacing, the **Callback Pace** (ADR-0061). Time is the
//! caller's, so the rule is testable without sleeping.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::envelope::KadEnvelope;
use crate::flood::request_rate_per_minute;
use crate::{KadInstant, KadNodeEndpoint};

/// Stock's window plus a margin for link jitter between our send and the
/// other side's tick: spacing is this over the opcode's rate.
const MINUTE_WITH_MARGIN: Duration = Duration::from_secs(65);

/// How many spacings ahead an offer may be booked. A held `0x52` holds a
/// download slot and a held `0x21` an α slot, so past this its owner moves on.
const MOST_SPACINGS_AHEAD: u32 = 4;

/// Sends held at once, across every key.
const MOST_HELD: usize = 256;

/// Keys remembered at once, oldest out.
const MOST_KEYS: usize = 4096;

/// A datagram ready to leave.
#[derive(Clone, Debug)]
pub(super) struct PacedSend {
    pub(super) to: KadNodeEndpoint,
    pub(super) envelope: KadEnvelope,
    pub(super) road: SendRoad,
}

/// How a paced send leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SendRoad {
    /// Plain, as the endpoint-known `0x52` always is: nothing tells us the
    /// buddy's Kad version.
    Clear,
    /// Through the node's obfuscation matrix, as a walked contact's is.
    Contact,
}

/// What became of an offered send.
#[derive(Debug)]
pub(super) enum SendOffer {
    /// The key has room: the send goes now.
    Leave(PacedSend),
    /// Held; it comes out of [`SendGate::take_due`] after this long.
    Held(Duration),
    /// Past the key's reach or [`MOST_HELD`]: it was not kept.
    Refused,
}

/// Each key's theoretical next send, and the sends waiting for theirs.
#[derive(Debug, Default)]
pub(super) struct SendGate {
    next_due: HashMap<(Ipv4Addr, u8), KadInstant>,
    /// Keyed by due instant, then offer order.
    held: BTreeMap<(KadInstant, u64), PacedSend>,
    offers: u64,
}

impl SendGate {
    /// Book `send` on its key's next instant. An opcode outside the flood
    /// table leaves at once.
    pub(super) fn offer(&mut self, now: KadInstant, send: PacedSend) -> SendOffer {
        let opcode = send.envelope.opcode();
        let Some(rate) = request_rate_per_minute(opcode) else {
            return SendOffer::Leave(send);
        };
        let spacing = MINUTE_WITH_MARGIN / rate;
        let burst = spacing * rate.saturating_sub(2);
        let key = (send.to.ip(), opcode);
        let due = self.next_due.get(&key).map_or(now, |&due| due.max(now));
        let leaves = due.as_millis().saturating_sub(as_millis(burst));
        let wait = Duration::from_millis(leaves.saturating_sub(now.as_millis()));
        if wait.is_zero() {
            self.book(key, due + spacing);
            return SendOffer::Leave(send);
        }
        if wait > spacing * MOST_SPACINGS_AHEAD || self.held.len() >= MOST_HELD {
            return SendOffer::Refused;
        }
        self.book(key, due + spacing);
        self.offers += 1;
        self.held
            .insert((KadInstant::from_millis(leaves), self.offers), send);
        SendOffer::Held(wait)
    }

    fn book(&mut self, key: (Ipv4Addr, u8), next_due: KadInstant) {
        if self.next_due.len() >= MOST_KEYS && !self.next_due.contains_key(&key) {
            let oldest = self
                .next_due
                .iter()
                .min_by_key(|&(_, &due)| due)
                .map(|(&key, _)| key);
            if let Some(oldest) = oldest {
                self.next_due.remove(&oldest);
            }
        }
        self.next_due.insert(key, next_due);
    }

    /// The next send due at `now`, oldest booking first.
    pub(super) fn take_due(&mut self, now: KadInstant) -> Option<PacedSend> {
        let entry = self.held.first_entry()?;
        (entry.key().0 <= now).then(|| entry.remove())
    }

    /// When the next held send falls due.
    pub(super) fn next_wake(&self) -> Option<KadInstant> {
        self.held.keys().next().map(|&(leaves, _)| leaves)
    }
}

fn as_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KadId;
    use crate::buddy::BuddyMessage;
    use crate::messages::Kad2Message;

    const FAR: u32 = 0x0B00_0001;

    fn callback_to(ip: Ipv4Addr) -> PacedSend {
        let request = BuddyMessage::CallbackReq {
            buddy_id: KadId::from_bytes([0x55; KadId::BYTE_LEN]),
            file_hash: rmule_primitives::FileHash::from_bytes([0x11; 16]),
            requester_tcp_port: 4662,
        };
        PacedSend {
            to: KadNodeEndpoint::new(ip, 4672),
            envelope: request.encode(),
            road: SendRoad::Clear,
        }
    }

    fn lookup_to(ip: Ipv4Addr) -> PacedSend {
        let target = KadId::from_bytes([0x77; KadId::BYTE_LEN]);
        PacedSend {
            to: KadNodeEndpoint::new(ip, 4672),
            envelope: Kad2Message::LookupReq {
                count: 2,
                target,
                check: target,
            }
            .encode(),
            road: SendRoad::Contact,
        }
    }

    fn leaves_at_once(offer: &SendOffer) -> bool {
        matches!(offer, SendOffer::Leave(_))
    }

    #[test]
    fn a_ten_a_minute_opcode_spends_nine_and_then_paces_inside_stocks_leak() {
        let mut gate = SendGate::default();
        let ip = Ipv4Addr::from(FAR);
        let t0 = KadInstant::from_millis(1);
        for sent in 0..9 {
            assert!(
                leaves_at_once(&gate.offer(t0, lookup_to(ip))),
                "send {sent} of the burst"
            );
        }
        let SendOffer::Held(wait) = gate.offer(t0, lookup_to(ip)) else {
            panic!("the tenth waits");
        };
        assert_eq!(wait, Duration::from_millis(6500));
        assert!(gate.take_due(t0 + Duration::from_secs(6)).is_none());
        assert!(gate.take_due(t0 + wait).is_some());
    }

    #[test]
    fn the_budget_is_per_ip_and_per_opcode() {
        let mut gate = SendGate::default();
        let t0 = KadInstant::from_millis(1);
        let ip = Ipv4Addr::from(FAR);
        for _ in 0..9 {
            gate.offer(t0, lookup_to(ip));
        }
        assert!(leaves_at_once(
            &gate.offer(t0, lookup_to(Ipv4Addr::from(FAR + 1)))
        ));
        assert!(leaves_at_once(&gate.offer(t0, callback_to(ip))));
    }

    #[test]
    fn a_callback_keeps_its_one_a_minute_spacing_and_its_refusal_at_four() {
        let mut gate = SendGate::default();
        let ip = Ipv4Addr::from(FAR);
        let t0 = KadInstant::from_millis(1);
        assert!(leaves_at_once(&gate.offer(t0, callback_to(ip))));
        for spacings in 1..=4_u32 {
            let SendOffer::Held(wait) = gate.offer(t0, callback_to(ip)) else {
                panic!("held inside four spacings");
            };
            assert_eq!(wait, MINUTE_WITH_MARGIN * spacings);
        }
        assert!(matches!(
            gate.offer(t0, callback_to(ip)),
            SendOffer::Refused
        ));
    }

    #[test]
    fn a_quiet_key_gets_its_burst_back() {
        let mut gate = SendGate::default();
        let ip = Ipv4Addr::from(FAR);
        let t0 = KadInstant::from_millis(1);
        for _ in 0..9 {
            gate.offer(t0, lookup_to(ip));
        }
        let later = t0 + Duration::from_secs(65);
        for _ in 0..9 {
            assert!(leaves_at_once(&gate.offer(later, lookup_to(ip))));
        }
    }

    #[test]
    fn the_key_table_stays_bounded_and_forgets_the_oldest_first() {
        let mut gate = SendGate::default();
        let t0 = KadInstant::from_millis(1);
        let first = Ipv4Addr::from(1);
        gate.offer(t0, callback_to(first));
        let later = t0 + Duration::from_secs(1);
        for n in 2..=u32::try_from(MOST_KEYS + 1).unwrap() {
            gate.offer(later, callback_to(Ipv4Addr::from(n)));
        }
        assert_eq!(gate.next_due.len(), MOST_KEYS);
        let opcode = callback_to(first).envelope.opcode();
        assert!(!gate.next_due.contains_key(&(first, opcode)));
        assert!(gate.next_due.contains_key(&(Ipv4Addr::from(2), opcode)));
    }

    #[test]
    fn a_full_hold_refuses_the_newcomer_and_keeps_every_held_send() {
        let mut gate = SendGate::default();
        let t0 = KadInstant::from_millis(1);
        for n in 1..=u32::try_from(MOST_HELD).unwrap() {
            let ip = Ipv4Addr::from(n);
            gate.offer(t0, callback_to(ip));
            assert!(matches!(
                gate.offer(t0, callback_to(ip)),
                SendOffer::Held(_)
            ));
        }
        let ip = Ipv4Addr::from(1);
        assert!(matches!(
            gate.offer(t0, callback_to(ip)),
            SendOffer::Refused
        ));
        assert_eq!(gate.held.len(), MOST_HELD);
    }
}
