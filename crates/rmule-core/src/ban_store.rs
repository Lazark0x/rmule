//! The core-owned **BanStore** (ADR-0064): where every ban and every **Hush**
//! lands, whoever raised it, for two hours by accounting key.
//!
//! What an offence earns follows what proved the sender. A finished connection
//! or a datagram with a valid receiver key earns the ban; a datagram that
//! proves nothing names an address anyone can forge, so it earns the Hush.
//!
//! `KadNode`'s flood limiter (ADR-0064, `rmule-kad`'s `flood.rs`) only
//! *reports* an offender IP via `KadEvent::FloodOffenderDetected`, and the serve
//! brain and a download's conviction raise their own: an `Arc<Mutex<_>>`-shared
//! pair of tables, consulted by every surface that enforces them — the
//! serve adapter's **Accept Gates** (refuse an inbound connection before the
//! serve loop sees it), `RuntimePeerTransferService::start_download_worker`
//! (skips dialing a banned candidate source entirely), the serve brain (a ban
//! reaches a live link and a waiter) and the client-UDP front (a banned
//! address's datagram stops there, Kad included, as `MuleUDPSocket.cpp:176-177`,
//! and a hushed address's stops unless it can prove a round trip).
//! The server UDP socket is the one door left open: it hears only servers we
//! asked.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_primitives::AccountingKey;
use tokio::sync::Mutex;

/// The core-owned BanStore, shared between what raises a ban and the surfaces
/// that enforce it (`Core::builder`'s single instance).
pub(crate) type SharedBanStore = Arc<Mutex<BanStore>>;

/// The rows a table holds at most, as `flood.rs` caps its buckets: each row is an
/// offence a stranger chose to commit, from an address it may rotate freely.
const BAN_ROWS: usize = 50_000;

/// How the client-UDP front treats one address's datagrams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DatagramStanding {
    /// Heard as any other.
    Open,
    /// Heard only with a round trip proven (ADR-0064's Hush).
    Hushed,
    /// Stopped unread.
    Banned,
}

/// One table of accounting key -> until, checked-then-evicted exactly like
/// aMule's `CClientList` ban list (`ClientList.cpp#L739`): a query past its
/// deadline evicts the entry as it reads it, rather than waiting for a sweep.
/// An [`AccountingKey`] is an IPv4 address or an IPv6 `/64`, as the flood
/// buckets and the wait list key a sender: a host delegated a `/64` would walk
/// past a row on one address. It unmaps first, so a mapped IPv4-in-IPv6 claim
/// cannot dodge a row placed on its plain IPv4.
#[derive(Debug, Default)]
struct Deadlines {
    until: HashMap<AccountingKey, Instant>,
}

impl Deadlines {
    fn set(&mut self, ip: IpAddr, until: Instant, now: Instant) {
        self.until.insert(AccountingKey::of(ip), until);
        if self.until.len() > BAN_ROWS {
            self.shed(now);
        }
    }

    /// Bring the map back within [`BAN_ROWS`]: the expired rows no query came
    /// for, and if every row is live, the eighth nearest its end, so a stranger
    /// rotating addresses pays a sweep once per eighth rather than once per row.
    fn shed(&mut self, now: Instant) {
        self.until.retain(|_, until| *until > now);
        if self.until.len() <= BAN_ROWS {
            return;
        }
        let mut ends: Vec<Instant> = self.until.values().copied().collect();
        let mut cut = ends.len() / 8;
        let (_, &mut last_cut, _) = ends.select_nth_unstable(cut - 1);
        // Counted, so rows ending at one instant still shed: a stranger's
        // rows reported in one tick would otherwise sweep the map per row.
        self.until.retain(|_, until| {
            let goes = cut > 0 && *until <= last_cut;
            cut -= usize::from(goes);
            !goes
        });
    }

    fn holds(&mut self, ip: IpAddr, now: Instant) -> bool {
        let key = AccountingKey::of(ip);
        match self.until.get(&key) {
            Some(&until) if until > now => true,
            Some(_) => {
                self.until.remove(&key);
                false
            }
            None => false,
        }
    }
}

/// The ban rows and the hush rows, apart: a forger mints hush rows at will, and
/// shedding those must never reach a ban a proven offender earned.
#[derive(Debug, Default)]
pub(crate) struct BanStore {
    banned: Deadlines,
    hushed: Deadlines,
}

impl BanStore {
    /// aMule's `CLIENTBANTIME` (`ed2k/Constants.h#L71`): how long an
    /// offender's address is refused once banned.
    pub(crate) const CLIENTBANTIME: Duration = Duration::from_secs(2 * 60 * 60);

    /// Ban `ip` for [`CLIENTBANTIME`](Self::CLIENTBANTIME) from `now` (aMule
    /// `AddBannedClient`). A repeat report overwrites rather than stacks —
    /// aMule does not extend a ban past one `CLIENTBANTIME` either; the
    /// window simply resets from the latest offense.
    ///
    /// Only a caller holding proof of the sender may ban (ADR-0064): anything a
    /// lone datagram raised goes to [`hush`](Self::hush).
    pub(crate) fn ban(&mut self, ip: IpAddr, now: Instant) {
        self.banned.set(ip, now + Self::CLIENTBANTIME, now);
    }

    /// Hush `ip` for [`CLIENTBANTIME`](Self::CLIENTBANTIME) from `now`: what an
    /// offence earns when no proof names the sender (ADR-0064). A repeat report
    /// resets the window, as [`ban`](Self::ban) does.
    pub(crate) fn hush(&mut self, ip: IpAddr, now: Instant) {
        self.hushed.set(ip, now + Self::CLIENTBANTIME, now);
    }

    /// Whether `ip` is currently banned. Checked-then-evicted (aMule
    /// `ClientList.cpp#L739`): an expired entry is removed as this reads it.
    /// A row nobody queries goes when the table sheds.
    ///
    /// The peer-TCP dial site queries this with a candidate source's *claimed*
    /// address, and nothing stops a banned host from reappearing as
    /// `::ffff:`-its-own-IPv4; the accounting key unmaps that claim.
    pub(crate) fn is_banned(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.banned.holds(ip, now)
    }

    /// What the client-UDP front does with a datagram from `ip`.
    pub(crate) fn datagram_standing(&mut self, ip: IpAddr, now: Instant) -> DatagramStanding {
        if self.banned.holds(ip, now) {
            DatagramStanding::Banned
        } else if self.hushed.holds(ip, now) {
            DatagramStanding::Hushed
        } else {
            DatagramStanding::Open
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(o: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, o))
    }

    fn row(n: usize) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::from((n as u128 + 1) << 64))
    }

    #[test]
    fn an_expired_row_nobody_asks_about_goes_once_the_map_is_past_its_size() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        for n in 0..BAN_ROWS {
            store.ban(row(n), t0);
        }

        store.ban(ip(1), t0 + BanStore::CLIENTBANTIME);

        assert_eq!(store.banned.until.len(), 1);
    }

    /// A rotating address buys no memory: past the size the rows nearest their
    /// end go, and the map never holds more than its size.
    #[test]
    fn live_rows_stay_within_the_size_and_the_soonest_to_end_go_first() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        for n in 0..BAN_ROWS * 2 {
            store.ban(row(n), t0 + Duration::from_millis(n as u64));
        }

        assert!(store.banned.until.len() <= BAN_ROWS);
        let latest = t0 + Duration::from_millis(BAN_ROWS as u64 * 2);
        assert!(store.is_banned(row(BAN_ROWS * 2 - 1), latest));
        assert!(
            !store
                .banned
                .until
                .contains_key(&AccountingKey::of(row(0)))
        );
    }

    #[test]
    fn a_freshly_banned_ip_is_refused_and_an_untouched_ip_is_not() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        assert!(!store.is_banned(ip(1), t0), "nothing banned yet");

        store.ban(ip(1), t0);
        assert!(store.is_banned(ip(1), t0), "banned immediately");
        assert!(
            !store.is_banned(ip(2), t0),
            "a different IP is never affected by another's ban"
        );
    }

    #[test]
    fn a_ban_lasts_exactly_client_ban_time_and_is_evicted_on_a_later_query() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        store.ban(ip(1), t0);

        assert!(
            store.is_banned(ip(1), t0 + BanStore::CLIENTBANTIME - Duration::from_secs(1)),
            "still inside the 2h window"
        );
        assert!(
            !store.is_banned(ip(1), t0 + BanStore::CLIENTBANTIME),
            "the window has fully elapsed"
        );
        // Checked-then-evicted: the entry is gone, not merely skipped — a
        // second past-expiry query reads the same not-banned answer.
        assert!(!store.is_banned(ip(1), t0 + BanStore::CLIENTBANTIME));
    }

    /// A ban placed on a plain IPv4 is not dodged by a dial
    /// candidate that claims the same host as `::ffff:`-mapped IPv6 — the
    /// dial site queries `is_banned` with whatever the candidate's source row
    /// claims, and a candidate is exactly the sort of thing that claims.
    #[test]
    fn a_mapped_claim_of_a_banned_ipv4_is_still_banned() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        store.ban(ip(1), t0);

        let mapped: IpAddr = "::ffff:203.0.113.1".parse().unwrap();
        assert!(store.is_banned(mapped, t0), "same host, mapped spelling");

        let different_mapped: IpAddr = "::ffff:203.0.113.2".parse().unwrap();
        assert!(!store.is_banned(different_mapped, t0));
    }

    /// A sender delegated a `/64` mints an address per connection, so a ban on
    /// one of them is a ban on all, and on nobody past the prefix.
    #[test]
    fn a_ban_and_a_hush_cover_the_whole_64() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        let at = |text: &str| text.parse::<IpAddr>().unwrap();
        store.ban(at("2001:db8:1:2::1"), t0);
        store.hush(at("2001:db8:7:2::1"), t0);

        assert!(store.is_banned(at("2001:db8:1:2:ffff::9"), t0));
        assert!(!store.is_banned(at("2001:db8:1:3::1"), t0));
        assert_eq!(
            store.datagram_standing(at("2001:db8:7:2:ffff::9"), t0),
            DatagramStanding::Hushed
        );
    }

    /// A forger's row closes no door a proven connection uses.
    #[test]
    fn a_hush_stops_datagrams_and_leaves_tcp_open_for_its_two_hours() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        store.hush(ip(1), t0);

        assert!(!store.is_banned(ip(1), t0), "accept and dial stay open");
        assert_eq!(
            store.datagram_standing(ip(1), t0),
            DatagramStanding::Hushed
        );
        assert_eq!(store.datagram_standing(ip(2), t0), DatagramStanding::Open);
        assert_eq!(
            store.datagram_standing(ip(1), t0 + BanStore::CLIENTBANTIME),
            DatagramStanding::Open
        );
    }

    #[test]
    fn a_hush_over_a_ban_leaves_the_ban_in_force() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        store.ban(ip(1), t0);
        store.hush(ip(1), t0);

        assert!(store.is_banned(ip(1), t0));
        assert_eq!(
            store.datagram_standing(ip(1), t0),
            DatagramStanding::Banned
        );
    }

    /// Hush rows are free to mint from any address; they must not shed a ban.
    #[test]
    fn rotating_hushes_push_out_no_ban() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        store.ban(ip(1), t0);

        for n in 0..BAN_ROWS * 2 {
            store.hush(row(n), t0);
        }

        assert!(store.hushed.until.len() <= BAN_ROWS);
        assert!(store.is_banned(ip(1), t0));
    }

    #[test]
    fn a_repeat_offender_report_resets_the_window_instead_of_stacking() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        store.ban(ip(1), t0);

        // A second offender report arrives partway through the first ban.
        let t1 = t0 + Duration::from_secs(60 * 60);
        store.ban(ip(1), t1);

        // The ban now runs CLIENTBANTIME from t1, not t0: at t0 +
        // CLIENTBANTIME (which would have expired the first ban outright)
        // the IP is still banned because the second report reset the window.
        assert!(store.is_banned(ip(1), t0 + BanStore::CLIENTBANTIME));
        assert!(!store.is_banned(ip(1), t1 + BanStore::CLIENTBANTIME));
    }
}
