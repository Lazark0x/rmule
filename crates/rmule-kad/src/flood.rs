//! ADR-0064: the per-`(IP, opcode)` leaky flood limiter and the port-53
//! entry gate for `KadNode`'s datagram entry point.
//!
//! Both gates are key-independent and explicit-time,
//! sans-I/O, mesh-sim floodable like the rest of the node: `KadNode::
//! handle_datagram` calls [`FloodTable::gate`] with the same `now` it was
//! given and reacts to the verdict. This module owns exactly the two entry
//! gates and the offender report they raise — not the core-owned `BanStore`
//! that later consumes that report (ADR-0064), and not the
//! verified-contact model the routing table gains later (ADR-0064).
//!
//! Semantics replicate aMule's `PacketTracking.cpp` verbatim: increment-
//! before-check, one count leaks every `60 / rate` seconds, over-limit
//! (`count > rate`) drops, `count > 5 × rate` additionally reports a flood
//! offender (aMule bans the IP at its eD2k client-list layer there; rmule
//! only reports it — see `KadEvent::FloodOffenderDetected`), a LAN sender is
//! exempt entirely, and an opportunistic sweep bounds the table's memory by
//! evicting fully-decayed buckets no more often than every 12 minutes.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_primitives::AccountingKey;

use crate::KadInstant;
use crate::opcode::{
    KADEMLIA2_BOOTSTRAP_REQ, KADEMLIA2_HELLO_REQ, KADEMLIA2_PING, KADEMLIA2_PUBLISH_KEY_REQ,
    KADEMLIA2_PUBLISH_NOTES_REQ, KADEMLIA2_PUBLISH_SOURCE_REQ, KADEMLIA2_REQ,
    KADEMLIA2_SEARCH_KEY_REQ, KADEMLIA2_SEARCH_NOTES_REQ, KADEMLIA2_SEARCH_SOURCE_REQ,
};
use crate::reachability::{KADEMLIA_FIREWALLED_REQ, KADEMLIA_FIREWALLED2_REQ};

/// The UDP source port a genuine Kad datagram never arrives from — a
/// DNS-confusion guard (`KademliaUDPListener.cpp#L216`). Plaintext-only rmule
/// degenerates to drop-all-port-53; the sender-key exemption activates once
/// ADR-0046 keys are armed.
pub(crate) const DNS_CONFUSION_PORT: u16 = 53;

/// How often the table's opportunistic cleanup sweep may run (aMule's 12-min
/// cleanup interval, `PacketTracking.cpp#L173`).
const SWEEP_INTERVAL: Duration = Duration::from_secs(12 * 60);

/// The report-threshold multiplier: aMule bans the IP at `count > 5 × rate`
/// (`PacketTracking.cpp#L212`); rmule only reports at the same threshold.
const OFFENDER_RATE_MULTIPLIER: u32 = 5;

/// A hard ceiling on the number of distinct `(IP, opcode)` buckets — a memory
/// bound aMule's `PacketTracking` lacks. A spoofed-source flood can touch an
/// unbounded set of IPs between the 12-min sweeps; without this cap the map
/// would grow with the attacker's packet rate (a slow memory-exhaustion DoS).
/// At ~40 bytes per entry this bounds the table to a couple of megabytes.
/// Eviction at the ceiling ([`FloodTable::make_room`]) always sacrifices the
/// least-abusive bucket, so an active offender keeps its enforced counter.
const MAX_BUCKETS: usize = 50_000;

/// The allowed requests per minute for a request opcode's leaky bucket
/// (aMule's `PacketTracking.cpp` table, ADR-0064). `None` means untracked:
/// every response opcode (solicitation correlation owns those, per the ADR)
/// and every request opcode this node does not dispatch.
///
/// The keyword (`0x33`/`0x43`) and notes (`0x35`/`0x45`) request buckets are
/// tracked because `node.rs` dispatches all four, and leaving them out left an
/// unthrottled UDP reflection vector (one `0x33` search reflects up to a full
/// keyword result budget). aMule rate-limits every `SEARCH_*` at 3/min, but
/// **not** every `PUBLISH_*` at 2 — `PUBLISH_KEY_REQ` is 3 where
/// `PUBLISH_SOURCE/NOTES_REQ` are 2, so a keyword publish gets its own bucket
/// here rather than riding the source/notes arm.
///
/// The `0x50`/`0x53` firewall checks share **one** bucket at 2/min, which is
/// why [`bucket_opcode`] canonicalises `0x53` onto `0x50` before keying.
///
/// Both of those were divergences until 2026-09-12 (found while reading
/// emule-qt's source as a reference, corroborated against ADR-0064 from
/// inside rmule): `PUBLISH_KEY_REQ` sat at 2 — one step *stricter* than aMule,
/// throttling legitimate keyword publishes — while
/// the firewall pair sat at 3/min in two separate buckets, which is *looser*
/// than aMule twice over, under a comment claiming aMule pinned no rate for
/// them. It does. eMule 0.70b has since moved `PUBLISH_KEY_REQ` to 4; that is
/// recorded as downstream drift and deliberately **not** adopted, because
/// following eMule here implies advertising a Kad version rmule cannot yet
/// support (`KADEMLIA_VERSION` stays at 8: a v9 node is published the `BSOB`
/// `TAG_KADAICHHASHPUB`, which rmule's tag lists step over rather than keep).
const fn request_rate_per_minute(opcode: u8) -> Option<u32> {
    match opcode {
        KADEMLIA2_BOOTSTRAP_REQ => Some(2),
        KADEMLIA2_HELLO_REQ => Some(3),
        KADEMLIA2_REQ => Some(10),
        KADEMLIA2_SEARCH_SOURCE_REQ | KADEMLIA2_SEARCH_KEY_REQ | KADEMLIA2_SEARCH_NOTES_REQ => {
            Some(3)
        }
        KADEMLIA2_PUBLISH_KEY_REQ => Some(3),
        KADEMLIA2_PUBLISH_SOURCE_REQ | KADEMLIA2_PUBLISH_NOTES_REQ => Some(2),
        KADEMLIA_FIREWALLED_REQ | KADEMLIA_FIREWALLED2_REQ => Some(2),
        KADEMLIA2_PING => Some(2),
        _ => None,
    }
}

/// The opcode a bucket is keyed by. Identity for every opcode except
/// `KADEMLIA_FIREWALLED2_REQ`, which shares `KADEMLIA_FIREWALLED_REQ`'s bucket:
/// aMule tracks the firewall-check pair as **one** 2/min bucket (ADR-0064),
/// so keying them separately would let a sender spend the allowance twice.
const fn bucket_opcode(opcode: u8) -> u8 {
    match opcode {
        KADEMLIA_FIREWALLED2_REQ => KADEMLIA_FIREWALLED_REQ,
        other => other,
    }
}

/// The gate verdict for one inbound request opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloodVerdict {
    /// Under the per-minute rate (or an untracked opcode): dispatch normally.
    Admit,
    /// Over the per-minute rate: drop before dispatch. `offender` is set once
    /// the bucket has also crossed the report threshold.
    Drop {
        /// Whether this touch also crossed `rate × 5` — the flood-offender
        /// report threshold.
        offender: bool,
    },
}

/// One `(ip, opcode)` bucket's leaky-counter state.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    count: u32,
    /// The next instant one count leaks; meaningless while `count == 0`
    /// (recomputed from `now` the moment the bucket goes active again, so a
    /// long-dormant bucket never leaks in an instant burst on its first
    /// touch back).
    next_leak: KadInstant,
}

impl Bucket {
    fn leak_interval(rate: u32) -> Duration {
        Duration::from_secs(60 / u64::from(rate))
    }

    /// Leak whole intervals elapsed since the last touch.
    fn decay(&mut self, now: KadInstant, rate: u32) {
        let interval = Self::leak_interval(rate);
        while self.count > 0 && self.next_leak <= now {
            self.count -= 1;
            self.next_leak = self.next_leak + interval;
        }
    }

    /// Decay to `now`, then increment-before-check (verbatim): the verdict
    /// reacts to the *post-increment* count.
    fn touch(&mut self, now: KadInstant, rate: u32) -> FloodVerdict {
        self.decay(now, rate);
        if self.count == 0 {
            self.next_leak = now + Self::leak_interval(rate);
        }
        self.count += 1;
        if self.count > rate * OFFENDER_RATE_MULTIPLIER {
            FloodVerdict::Drop { offender: true }
        } else if self.count > rate {
            FloodVerdict::Drop { offender: false }
        } else {
            FloodVerdict::Admit
        }
    }

    /// Whether the bucket has fully drained as of `now` — safe to evict: a
    /// future touch recreates it fresh, indistinguishably.
    fn is_drained(&mut self, now: KadInstant, rate: u32) -> bool {
        self.decay(now, rate);
        self.count == 0
    }
}

/// The per-`(IP, opcode)` leaky flood table (ADR-0064).
#[derive(Debug)]
pub(crate) struct FloodTable {
    buckets: HashMap<(AccountingKey, u8), Bucket>,
    last_swept: Option<KadInstant>,
}

impl FloodTable {
    pub(crate) fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            last_swept: None,
        }
    }

    /// Gate one inbound request opcode from `ip`. LAN exemption is the
    /// caller's job (the datagram entry point applies `net::is_lan_ip` before
    /// calling); an untracked opcode (every response, and every request opcode
    /// without a pinned bucket in [`request_rate_per_minute`]) always admits
    /// without allocating a bucket.
    pub(crate) fn gate(&mut self, now: KadInstant, ip: Ipv4Addr, opcode: u8) -> FloodVerdict {
        // Buckets key on the accounting key, not the address (ADR-0087): a
        // sender delegated a whole `/64` can mint a fresh address per datagram,
        // so a per-`/128` bucket would be no limit at all. Kad's own contacts
        // stay IPv4 (ADR-0085's invariant), so today every key is a `V4` — the
        // rule lives here so it cannot be forgotten the day that changes.
        let ip = AccountingKey::of(ip.into());
        let Some(rate) = request_rate_per_minute(opcode) else {
            return FloodVerdict::Admit;
        };
        self.sweep_if_due(now);
        let key = (ip, bucket_opcode(opcode));
        // Bound the table: a fresh key at the ceiling forces an eviction first,
        // so `buckets.len()` never exceeds `MAX_BUCKETS`.
        if !self.buckets.contains_key(&key) && self.buckets.len() >= MAX_BUCKETS {
            self.make_room(now);
        }
        self.buckets
            .entry(key)
            .or_insert_with(|| Bucket {
                count: 0,
                next_leak: now,
            })
            .touch(now, rate)
    }

    /// Free at least one slot at the [`MAX_BUCKETS`] ceiling. First evict every
    /// bucket that has drained as of `now` — a forced sweep, bypassing the
    /// [`SWEEP_INTERVAL`] throttle because we are provably at the cap. If every
    /// survivor is still live (a genuine broad flood), drop the single
    /// nearest-to-draining bucket (lowest `count`): the least-abusive victim,
    /// so the high-count buckets actively being rate-limited stay under
    /// enforcement. O(n) in the table size, but only on a novel key while
    /// saturated.
    fn make_room(&mut self, now: KadInstant) {
        let before = self.buckets.len();
        self.buckets.retain(|(_, opcode), bucket| {
            let rate = request_rate_per_minute(*opcode)
                .expect("only rate-tracked opcodes ever enter the table");
            !bucket.is_drained(now, rate)
        });
        if self.buckets.len() < before {
            return;
        }
        if let Some(victim) = self
            .buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.count)
            .map(|(key, _)| *key)
        {
            self.buckets.remove(&victim);
        }
    }

    /// Run the opportunistic cleanup sweep at most once per
    /// [`SWEEP_INTERVAL`], dropping every bucket that has fully drained as of
    /// `now` (a memory bound only — a drained bucket behaves identically to
    /// an absent one, so evicting it changes nothing observable).
    fn sweep_if_due(&mut self, now: KadInstant) {
        if self
            .last_swept
            .is_some_and(|last| now < last + SWEEP_INTERVAL)
        {
            return;
        }
        self.last_swept = Some(now);
        self.buckets.retain(|(_, opcode), bucket| {
            let rate = request_rate_per_minute(*opcode)
                .expect("only rate-tracked opcodes ever enter the table");
            !bucket.is_drained(now, rate)
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const T0: KadInstant = KadInstant::EPOCH;

    fn ip(host: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, host)
    }

    #[test]
    fn keyword_notes_and_firewall_request_opcodes_are_rate_tracked() {
        // Every request opcode `node.rs` dispatches must enter a bucket: at
        // `rate` touches the gate still admits, the touch past `rate` drops.
        // An opcode outside every bucket would leave the keyword search
        // (`0x33`) reflection vector unthrottled.
        let cases = [
            (KADEMLIA2_SEARCH_KEY_REQ, 3u32),
            (KADEMLIA2_SEARCH_NOTES_REQ, 3),
            (KADEMLIA2_PUBLISH_KEY_REQ, 3),
            (KADEMLIA2_PUBLISH_NOTES_REQ, 2),
            (KADEMLIA_FIREWALLED_REQ, 2),
            (KADEMLIA_FIREWALLED2_REQ, 2),
        ];
        for (opcode, rate) in cases {
            let mut table = FloodTable::new();
            for n in 1..=rate {
                assert_eq!(
                    table.gate(T0, ip(1), opcode),
                    FloodVerdict::Admit,
                    "opcode {opcode:#04x} touch {n} within rate {rate}"
                );
            }
            assert_eq!(
                table.gate(T0, ip(1), opcode),
                FloodVerdict::Drop { offender: false },
                "opcode {opcode:#04x} touch {} past rate {rate}",
                rate + 1
            );
        }
    }

    #[test]
    fn the_firewall_check_pair_shares_one_bucket() {
        // ADR-0064: aMule tracks `0x50`/`0x53` as one 2/min bucket, so the
        // allowance cannot be spent twice by alternating opcodes. Keyed
        // separately (as rmule did until 2026-09-12) this sender would get 4.
        let mut table = FloodTable::new();
        assert_eq!(
            table.gate(T0, ip(1), KADEMLIA_FIREWALLED_REQ),
            FloodVerdict::Admit
        );
        assert_eq!(
            table.gate(T0, ip(1), KADEMLIA_FIREWALLED2_REQ),
            FloodVerdict::Admit
        );
        assert_eq!(
            table.gate(T0, ip(1), KADEMLIA_FIREWALLED2_REQ),
            FloodVerdict::Drop { offender: false },
            "the third check in a minute is over the shared 2/min allowance"
        );
    }

    #[test]
    fn table_is_capped_and_evicts_the_least_abusive_bucket() {
        let mut table = FloodTable::new();
        // Fill to the ceiling with distinct source IPs, each touched once.
        for n in 0..MAX_BUCKETS as u32 {
            table.gate(T0, Ipv4Addr::from(n), KADEMLIA2_HELLO_REQ);
        }
        assert_eq!(table.buckets.len(), MAX_BUCKETS);

        // Drive one existing bucket well over its rate — an active offender.
        let offender = Ipv4Addr::from(0u32);
        for _ in 0..20 {
            table.gate(T0, offender, KADEMLIA2_HELLO_REQ);
        }
        assert!(matches!(
            table.gate(T0, offender, KADEMLIA2_HELLO_REQ),
            FloodVerdict::Drop { .. }
        ));

        // A novel key at the ceiling: the table must not grow, and the offender
        // must survive (a low-count bucket is sacrificed in its place).
        let newcomer = Ipv4Addr::new(198, 51, 100, 1);
        assert_eq!(
            table.gate(T0, newcomer, KADEMLIA2_HELLO_REQ),
            FloodVerdict::Admit
        );
        assert_eq!(table.buckets.len(), MAX_BUCKETS, "cap holds after eviction");
        assert!(
            matches!(
                table.gate(T0, offender, KADEMLIA2_HELLO_REQ),
                FloodVerdict::Drop { .. }
            ),
            "the active offender is never the eviction victim"
        );
    }
}
