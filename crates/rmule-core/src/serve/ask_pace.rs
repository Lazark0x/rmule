//! The **Ask Pace** (ADR-0055 divergence 7): stock's aggressiveness score, the
//! one owner of how fast each client asks a serving node for something that
//! costs it. An ask under [`MIN_ASK_GAP`] after the last adds three, a later
//! one takes one off, and a client reaching [`BAN_SCORE`] is an offender
//! (`UploadClient.cpp:795-825`). Explicit time and bounded memory: a score
//! unheard for [`FORGET_AFTER`] is gone at its next ask, as a client object
//! ages out of stock's list, and a full table lets its oldest go first.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rmule_primitives::{AccountingKey, UserHash};

/// aMule's `MIN_REQUESTTIME` (`Constants.h:67`).
const MIN_ASK_GAP: Duration = Duration::from_secs(590);

/// What an ask inside [`MIN_ASK_GAP`] adds (`UploadClient.cpp:807`).
const IMPOLITE_ASK: u8 = 3;

/// The score that bans (`UploadClient.cpp:810`).
const BAN_SCORE: u8 = 10;

/// aMule's idle client object lifetime (`Constants.h:74`,
/// `ClientList.cpp:997-1003`): a score goes with it.
const FORGET_AFTER: Duration = Duration::from_secs(34 * 60);

/// The clients held at once: past the wait list and the links of any node, so
/// only a table under a stream of strangers meets it.
const MAX_TRACKED: usize = 4096;

/// A client as the score knows it: its User Hash from one address scope, so
/// the clients behind one NAT do not share a score. A client that changes its
/// hash on a link, or at a place tracked by a key proof or a slot it left, sheds
/// its score into the hash-change ban; a waiter that did neither is a new
/// client under the new hash, as a new client object is in stock.
type Asker = (AccountingKey, UserHash);

#[derive(Debug)]
struct Pace {
    last_ask: Instant,
    score: u8,
}

/// See the module docs.
#[derive(Debug, Default)]
pub(in crate::serve) struct AskPace {
    askers: HashMap<Asker, Pace>,
}

impl AskPace {
    /// One ask of `key`'s `user_hash` at `now`; `true` when it leaves the
    /// client at the score that bans. A client's first ask starts its clock
    /// and scores nothing, and one unheard for [`FORGET_AFTER`] asks its
    /// first again.
    pub(in crate::serve) fn ask(
        &mut self,
        now: Instant,
        key: AccountingKey,
        user_hash: UserHash,
    ) -> bool {
        let asker = (key, user_hash);
        let aged = self
            .askers
            .get(&asker)
            .is_some_and(|pace| now.saturating_duration_since(pace.last_ask) >= FORGET_AFTER);
        if aged {
            self.askers.remove(&asker);
        }
        if !self.askers.contains_key(&asker) {
            self.make_room(now);
        }
        let Some(pace) = self.askers.get_mut(&asker) else {
            self.askers.insert(
                asker,
                Pace {
                    last_ask: now,
                    score: 0,
                },
            );
            return false;
        };
        if now.saturating_duration_since(pace.last_ask) < MIN_ASK_GAP {
            pace.score = pace.score.saturating_add(IMPOLITE_ASK);
        } else {
            pace.score = pace.score.saturating_sub(1);
        }
        pace.last_ask = now;
        pace.score >= BAN_SCORE
    }

    /// Room for one more: what aged out goes, and in a table still full the
    /// asker unheard for longest.
    fn make_room(&mut self, now: Instant) {
        if self.askers.len() < MAX_TRACKED {
            return;
        }
        self.askers
            .retain(|_, pace| now.saturating_duration_since(pace.last_ask) < FORGET_AFTER);
        if self.askers.len() < MAX_TRACKED {
            return;
        }
        let oldest = self
            .askers
            .iter()
            .min_by_key(|(_, pace)| pace.last_ask)
            .map(|(asker, _)| *asker);
        if let Some(oldest) = oldest {
            self.askers.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn scope(last: u8) -> AccountingKey {
        AccountingKey::of(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)))
    }

    fn client(byte: u8) -> UserHash {
        UserHash::from_bytes([byte; UserHash::BYTE_LEN])
    }

    /// aMule's arithmetic: the first ask scores nothing, each fast one three,
    /// so the fifth ask reaches twelve and the score of ten is crossed there.
    #[test]
    fn fast_asks_reach_the_ban_on_the_fifth() {
        let mut pace = AskPace::default();
        let t = Instant::now();
        let bans: Vec<bool> = (0..5)
            .map(|n| pace.ask(t + Duration::from_secs(n), scope(1), client(1)))
            .collect();
        assert_eq!(bans, [false, false, false, false, true]);
    }

    /// A polite ask takes one off, so a fast one now and then never adds up.
    #[test]
    fn a_polite_ask_pays_a_score_down() {
        let mut pace = AskPace::default();
        let mut t = Instant::now();
        pace.ask(t, scope(1), client(1));
        for _ in 0..3 {
            t += Duration::from_secs(1);
            assert!(!pace.ask(t, scope(1), client(1)));
        }
        for _ in 0..3 {
            t += MIN_ASK_GAP;
            assert!(!pace.ask(t, scope(1), client(1)));
        }
        t += Duration::from_secs(1);
        assert!(!pace.ask(t, scope(1), client(1)), "six and three is nine");
        t += Duration::from_secs(1);
        assert!(pace.ask(t, scope(1), client(1)), "twelve is over");
    }

    /// Two clients behind one address are two scores: the wait-list cap
    /// admits three of them and 3.1.0 ended its address-wide lockout.
    #[test]
    fn clients_behind_one_address_do_not_share_a_score() {
        let mut pace = AskPace::default();
        let t = Instant::now();
        for byte in 1..=4 {
            for n in 0..4 {
                assert!(!pace.ask(t + Duration::from_secs(n), scope(1), client(byte)));
            }
        }
    }

    /// A client unheard past the age starts over at its next ask, however
    /// empty the table: its object went, and the score with it.
    #[test]
    fn a_score_ages_out_in_a_table_with_room() {
        let mut pace = AskPace::default();
        let t = Instant::now();
        for n in 0..4 {
            pace.ask(t + Duration::from_secs(n), scope(1), client(1));
        }
        let back = t + Duration::from_secs(3) + FORGET_AFTER;
        for n in 0..4 {
            assert!(!pace.ask(back + Duration::from_secs(n), scope(1), client(1)));
        }
    }

    /// The table holds its bound under a stream of strangers, and the entry
    /// that goes is the one unheard for longest.
    #[test]
    fn a_full_table_lets_its_oldest_go() {
        let mut pace = AskPace::default();
        let t = Instant::now();
        let stranger = |n: usize| {
            let mut bytes = [0; UserHash::BYTE_LEN];
            bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
            UserHash::from_bytes(bytes)
        };
        for n in 0..MAX_TRACKED {
            pace.ask(t + Duration::from_millis(n as u64), scope(1), stranger(n));
        }
        let later = t + Duration::from_secs(60);
        pace.ask(later, scope(1), stranger(MAX_TRACKED));
        assert_eq!(pace.askers.len(), MAX_TRACKED);
        assert!(!pace.askers.contains_key(&(scope(1), stranger(0))));
        assert!(pace.askers.contains_key(&(scope(1), stranger(1))));
    }

    /// An idle client's score goes with its object: past the age the table
    /// drops every entry that aged out in one sweep.
    #[test]
    fn what_aged_out_goes_first() {
        let mut pace = AskPace::default();
        let t = Instant::now();
        pace.ask(t, scope(1), client(1));
        pace.askers.reserve(MAX_TRACKED);
        for n in 1..MAX_TRACKED {
            let mut bytes = [0; UserHash::BYTE_LEN];
            bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
            pace.ask(t, scope(2), UserHash::from_bytes(bytes));
        }
        pace.ask(t + FORGET_AFTER, scope(3), client(3));
        assert_eq!(pace.askers.len(), 1);
    }
}
