//! The **Key Frame** bookkeeping: what a `0xB2 0xFF` frame taught us about an
//! endpoint, and when we may assert our own hash to one.
//!
//! Two timers, both eMuleAI's, and each bounds a different exposure. The
//! **10-minute learned-hash TTL** bounds how long a stale `(ip, port) → user
//! hash` mapping can key a send — after a NAT rebinds, that endpoint may be
//! somebody else. The **10-second per-endpoint send window** bounds what a
//! stranger can make us emit: a flood of forged `ST_SYN` frames costs one KEY
//! frame per ten seconds per source, not one per packet.
//!
//! Explicit time throughout — the caller reads the clock, so the whole table
//! is testable without sleeping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_primitives::{PeerEndpoint, UserHash};

/// How long a learned `(endpoint → user hash)` mapping is trusted to key a
/// send. eMuleAI prunes its `m_HashMap` on the same window.
pub const LEARNED_HASH_TTL: Duration = Duration::from_secs(600);

/// Minimum interval between two KEY frames to the same endpoint. The trigger
/// is a uTP `ST_SYN` or a QUIC long header, both of which a stranger can send
/// at will, so this window is the rate limit on our own emission.
pub const KEY_FRAME_INTERVAL: Duration = Duration::from_secs(10);

/// One endpoint's key state.
#[derive(Clone, Copy, Debug)]
struct KeyEntry {
    /// The hash this endpoint asserted, and when.
    learned: Option<(UserHash, Instant)>,
    /// When we last asserted our own hash to it.
    asserted_at: Option<Instant>,
}

/// The per-endpoint key table behind the NAT-T send path.
///
/// Keyed by endpoint rather than by peer, deliberately: a user hash learned
/// here is a claim about *who answers at this `(ip, port)`*, which is the only
/// thing a send can act on. Promoting it to a fact about the peer is the
/// session's business, not the transport's.
#[derive(Debug, Default)]
pub struct NattKeyTable {
    entries: HashMap<PeerEndpoint, KeyEntry>,
}

impl NattKeyTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adopt the hash a KEY frame carried, returning whether it was adopted.
    /// A later frame from the same endpoint replaces the earlier one *and*
    /// refreshes the TTL: the endpoint is the identity here, and it has just
    /// restated what answers there.
    ///
    /// Except while the endpoint `held` a tunnel: then a hash that differs
    /// from the live one is refused (ADR-0091, security rule 11). A NAT
    /// rebinding moves the endpoint, never the hash at one, so the only frame
    /// this refuses is one that would re-key a live tunnel to a stranger.
    pub fn learn(&mut self, peer: PeerEndpoint, hash: UserHash, held: bool, now: Instant) -> bool {
        if held && self.key_for(peer, now).is_some_and(|known| known != hash) {
            return false;
        }
        self.entries.entry(peer).or_insert(EMPTY).learned = Some((hash, now));
        self.prune(now);
        true
    }

    /// The hash to obfuscate a send to `peer` under, or `None` — plaintext
    /// then, which is the honest state for an endpoint that has never asserted
    /// one.
    #[must_use]
    pub fn key_for(&self, peer: PeerEndpoint, now: Instant) -> Option<UserHash> {
        self.entries
            .get(&peer)
            .and_then(|entry| entry.learned)
            .filter(|(_, at)| now.duration_since(*at) < LEARNED_HASH_TTL)
            .map(|(hash, _)| hash)
    }

    /// Whether a KEY frame to `peer` is due, and record it if so. One call,
    /// one decision: a "may I?" that did not also claim the window would let
    /// two concurrent sends both pass it.
    ///
    /// A new endpoint prunes the table first. The trigger is a packet any
    /// stranger can forge from any source, so without it a SYN flood grew one
    /// row per spoofed source until some KEY frame happened to be learned.
    pub fn claim_key_frame(&mut self, peer: PeerEndpoint, now: Instant) -> bool {
        if !self.entries.contains_key(&peer) {
            self.prune(now);
        }
        let entry = self.entries.entry(peer).or_insert(EMPTY);
        let due = entry
            .asserted_at
            .is_none_or(|at| now.duration_since(at) >= KEY_FRAME_INTERVAL);
        if due {
            entry.asserted_at = Some(now);
        }
        due
    }

    /// Give back the window [`claim_key_frame`](Self::claim_key_frame) took at
    /// `claimed_at` for a KEY frame that never left, so the next opening packet
    /// asserts our hash rather than the peer waiting out the window with no
    /// key. A window claimed since is left alone.
    pub fn unclaim_key_frame(&mut self, peer: PeerEndpoint, claimed_at: Instant) {
        if let Some(entry) = self.entries.get_mut(&peer)
            && entry.asserted_at == Some(claimed_at)
        {
            entry.asserted_at = None;
        }
    }

    /// Drop entries no longer doing anything: the learned hash has expired and
    /// the send window has too, so the row would be recreated identically on
    /// the next datagram. Run on every `learn` and on every claim for a new
    /// endpoint, so endpoint churn cannot grow the table without bound.
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            let hash_live = entry
                .learned
                .is_some_and(|(_, at)| now.duration_since(at) < LEARNED_HASH_TTL);
            let window_live = entry
                .asserted_at
                .is_some_and(|at| now.duration_since(at) < KEY_FRAME_INTERVAL);
            hash_live || window_live
        });
    }

    /// How many endpoints the table holds — the observable a prune test needs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

const EMPTY: KeyEntry = KeyEntry {
    learned: None,
    asserted_at: None,
};

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::Ipv4Endpoint;

    use super::*;

    fn endpoint(last: u8) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, last), 4672))
    }

    fn hash(fill: u8) -> UserHash {
        UserHash::from_bytes([fill; UserHash::BYTE_LEN])
    }

    /// A learned hash keys sends for ten minutes and not a moment longer: past
    /// the window the endpoint may be somebody else, and encrypting to the
    /// wrong key is worse than plaintext because the peer cannot tell the
    /// difference from a lost datagram.
    #[test]
    fn a_learned_hash_keys_sends_for_ten_minutes_then_stops() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        assert_eq!(table.key_for(endpoint(1), now), None);
        table.learn(endpoint(1), hash(0x42), false, now);
        assert_eq!(table.key_for(endpoint(1), now), Some(hash(0x42)));
        assert_eq!(
            table.key_for(
                endpoint(1),
                now + LEARNED_HASH_TTL - Duration::from_millis(1)
            ),
            Some(hash(0x42))
        );
        assert_eq!(table.key_for(endpoint(1), now + LEARNED_HASH_TTL), None);
    }

    /// A hash is learned per endpoint, never per address: the same host on a
    /// second port is a second mapping and says nothing about the first.
    #[test]
    fn two_endpoints_hold_two_independent_keys() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        table.learn(endpoint(1), hash(1), false, now);
        table.learn(endpoint(2), hash(2), false, now);
        assert_eq!(table.key_for(endpoint(1), now), Some(hash(1)));
        assert_eq!(table.key_for(endpoint(2), now), Some(hash(2)));
    }

    /// While the endpoint holds a tunnel its key is fixed: a KEY frame naming
    /// another hash is refused and the tunnel keeps obfuscating under the one
    /// it rose with, while a restatement of the same hash still refreshes it.
    #[test]
    fn a_held_endpoint_refuses_a_key_naming_another_hash() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        assert!(table.learn(endpoint(1), hash(1), true, now));
        let later = now + Duration::from_secs(500);
        assert!(!table.learn(endpoint(1), hash(9), true, later));
        assert_eq!(table.key_for(endpoint(1), later), Some(hash(1)));
        assert!(table.learn(endpoint(1), hash(1), true, later));
        assert_eq!(
            table.key_for(endpoint(1), now + LEARNED_HASH_TTL),
            Some(hash(1)),
            "the restatement refreshed the window"
        );
    }

    /// A restated hash replaces the old one and refreshes the window — an
    /// endpoint that speaks again is the most recent thing we know about it.
    #[test]
    fn a_second_key_frame_replaces_and_refreshes() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        table.learn(endpoint(1), hash(1), false, now);
        let later = now + Duration::from_secs(500);
        table.learn(endpoint(1), hash(9), false, later);
        assert_eq!(table.key_for(endpoint(1), later), Some(hash(9)));
        assert_eq!(
            table.key_for(endpoint(1), now + LEARNED_HASH_TTL),
            Some(hash(9)),
            "the fresh learn moved the expiry, it did not inherit the old one"
        );
    }

    /// The send window is claimed by the same call that tests it, so a flood of
    /// forged SYNs costs one KEY frame per ten seconds rather than one each.
    #[test]
    fn the_key_frame_window_is_claimed_not_merely_checked() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        assert!(table.claim_key_frame(endpoint(1), now));
        assert!(!table.claim_key_frame(endpoint(1), now));
        assert!(!table.claim_key_frame(
            endpoint(1),
            now + KEY_FRAME_INTERVAL - Duration::from_millis(1)
        ));
        assert!(table.claim_key_frame(endpoint(1), now + KEY_FRAME_INTERVAL));
    }

    /// The window is per endpoint: one peer's flood must not silence our KEY
    /// frame to a different one.
    #[test]
    fn one_endpoints_window_does_not_close_anothers() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        assert!(table.claim_key_frame(endpoint(1), now));
        assert!(table.claim_key_frame(endpoint(2), now));
    }

    /// An endpoint whose hash and window have both expired is forgotten, so
    /// churn cannot grow the table without bound.
    #[test]
    fn a_fully_expired_endpoint_is_pruned() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        table.learn(endpoint(1), hash(1), false, now);
        assert_eq!(table.len(), 1);
        table.learn(endpoint(2), hash(2), false, now + LEARNED_HASH_TTL);
        assert_eq!(table.len(), 1, "endpoint 1 aged out on the prune");
        assert!(!table.is_empty());
    }

    /// A flood of forged openers from distinct sources costs rows for one
    /// window, not forever: the claim for a new endpoint prunes the ones whose
    /// window has passed, with no KEY frame ever learned in between.
    #[test]
    fn claims_from_a_forged_flood_age_out_without_a_learn() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        for last in 1..=200 {
            assert!(table.claim_key_frame(endpoint(last), now));
        }
        assert_eq!(table.len(), 200);
        assert!(table.claim_key_frame(endpoint(201), now + KEY_FRAME_INTERVAL));
        assert_eq!(table.len(), 1, "only the fresh claim is left");
    }

    /// A window given back is due again at once; one claimed since is not
    /// touched by a stale give-back.
    #[test]
    fn an_unsent_key_frame_gives_its_window_back() {
        let now = Instant::now();
        let mut table = NattKeyTable::new();
        assert!(table.claim_key_frame(endpoint(1), now));
        table.unclaim_key_frame(endpoint(1), now);
        assert!(table.claim_key_frame(endpoint(1), now));

        let later = now + KEY_FRAME_INTERVAL;
        assert!(table.claim_key_frame(endpoint(2), now));
        assert!(table.claim_key_frame(endpoint(2), later));
        table.unclaim_key_frame(endpoint(2), now);
        assert!(!table.claim_key_frame(endpoint(2), later));
    }
}
