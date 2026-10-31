//! The core-owned **BanStore** (ADR-0064): where every ban lands, whoever
//! raised it, for two hours by address.
//!
//! `KadNode`'s flood limiter (ADR-0064, `rmule-kad`'s `flood.rs`) only
//! *reports* an offender IP via `KadEvent::FloodOffenderDetected`, and the serve
//! brain and a download's conviction raise their own: an `Arc<Mutex<_>>`-shared
//! IP -> banned-until map, consulted by every surface that enforces it — the
//! serve adapter's **Accept Gates** (refuse an inbound connection before the
//! serve loop sees it), `RuntimePeerTransferService::start_download_worker`
//! (skips dialing a banned candidate source entirely), the serve brain (a ban
//! reaches a live link and a waiter) and the client-UDP front (a banned
//! address's datagram stops there, Kad included, as `MuleUDPSocket.cpp:176-177`).
//! The server UDP socket is the one door left open: it hears only servers we
//! asked.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// The core-owned BanStore, shared between what raises a ban and the surfaces
/// that enforce it (`Core::builder`'s single instance).
pub(crate) type SharedBanStore = Arc<Mutex<BanStore>>;

/// The rows the map holds at most, as `flood.rs` caps its buckets: each row is an
/// offence a stranger chose to commit, from an address it may rotate freely.
const BAN_ROWS: usize = 50_000;

/// IP -> banned-until (address-typed, so it applies to both families —
/// ADR-0085), checked-then-evicted exactly like aMule's
/// `CClientList` ban list (`ClientList.cpp#L739`): a query past its deadline
/// evicts the entry as it reads it, rather than waiting for a sweep. Keys are
/// stored and looked up in their [`IpAddr::to_canonical`] form,
/// so a mapped IPv4-in-IPv6 claim cannot dodge a ban placed on its plain IPv4.
#[derive(Debug, Default)]
pub(crate) struct BanStore {
    banned_until: HashMap<IpAddr, Instant>,
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
    /// `ip` is unmapped first: the Kad flood report this is fed
    /// from is always IPv4 today, so this is a no-op in practice, but keying
    /// on the canonical form is what keeps a later mapped-form report from
    /// opening a second, unbanned key for the same host.
    pub(crate) fn ban(&mut self, ip: IpAddr, now: Instant) {
        self.banned_until
            .insert(ip.to_canonical(), now + Self::CLIENTBANTIME);
        if self.banned_until.len() > BAN_ROWS {
            self.shed(now);
        }
    }

    /// Bring the map back within [`BAN_ROWS`]: the expired rows no query came
    /// for, and if every row is live, the eighth nearest its end, so a stranger
    /// rotating addresses pays a sweep once per eighth rather than once per row.
    fn shed(&mut self, now: Instant) {
        self.banned_until.retain(|_, until| *until > now);
        if self.banned_until.len() <= BAN_ROWS {
            return;
        }
        let mut ends: Vec<Instant> = self.banned_until.values().copied().collect();
        let cut = ends.len() / 8;
        let (_, &mut kept_from, _) = ends.select_nth_unstable(cut);
        self.banned_until.retain(|_, until| *until >= kept_from);
    }

    /// Whether `ip` is currently banned. Checked-then-evicted (aMule
    /// `ClientList.cpp#L739`): an expired entry is removed as this reads it.
    /// A row nobody queries goes when [`ban`](Self::ban) sheds.
    ///
    /// `ip` is unmapped first: the peer-TCP dial site queries
    /// this with a candidate source's *claimed* address, and nothing stops a
    /// banned host from reappearing as `::ffff:`-its-own-IPv4 — without the
    /// unmap that claim would look up a key the ban was never stored under.
    pub(crate) fn is_banned(&mut self, ip: IpAddr, now: Instant) -> bool {
        let ip = ip.to_canonical();
        match self.banned_until.get(&ip) {
            Some(&until) if until > now => true,
            Some(_) => {
                self.banned_until.remove(&ip);
                false
            }
            None => false,
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
        IpAddr::V6(std::net::Ipv6Addr::from(n as u128 + 1))
    }

    #[test]
    fn an_expired_row_nobody_asks_about_goes_once_the_map_is_past_its_size() {
        let mut store = BanStore::default();
        let t0 = Instant::now();
        for n in 0..BAN_ROWS {
            store.ban(row(n), t0);
        }

        store.ban(ip(1), t0 + BanStore::CLIENTBANTIME);

        assert_eq!(store.banned_until.len(), 1);
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

        assert!(store.banned_until.len() <= BAN_ROWS);
        let latest = t0 + Duration::from_millis(BAN_ROWS as u64 * 2);
        assert!(store.is_banned(row(BAN_ROWS * 2 - 1), latest));
        assert!(!store.banned_until.contains_key(&row(0)));
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
