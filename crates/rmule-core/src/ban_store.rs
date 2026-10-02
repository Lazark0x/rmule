//! The core-owned **BanStore** (ADR-0064): the peer-TCP enforcement half
//! of the Kad anti-flood stack.
//!
//! `KadNode`'s flood limiter (ADR-0064, `rmule-kad`'s `flood.rs`) only
//! *reports* an offender IP via `KadEvent::FloodOffenderDetected` — it never
//! enforces anything itself, and Kad keeps answering the IP's other opcodes
//! (the per-opcode bucket already contains the flood). This store is where
//! that report lands: an `Arc<Mutex<_>>`-shared IP -> banned-until map, fed by
//! the `RuntimeKadFactory` pump task's fold of every `FloodOffenderDetected`
//! event and consulted by the two peer-TCP surfaces that enforce it —
//! `RuntimeServeRuntimeService::accept` (refuses an accepted connection from a
//! banned IP) and `RuntimePeerTransferService::start_download_worker`
//! (skips dialing a banned candidate source entirely). Kad and the eD2k
//! server surface are untouched — aMule's own client ban gates neither.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// The core-owned BanStore, shared between the Kad event fold and the two
/// peer-TCP enforcement surfaces (`Core::builder`'s single instance).
pub(crate) type SharedBanStore = Arc<Mutex<BanStore>>;

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
    /// aMule's `CLIENTBANTIME` (`ed2k/Constants.h#L71`): how long a
    /// flood-offender IP is refused at the peer-TCP surface once banned.
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
    }

    /// Whether `ip` is currently banned. Checked-then-evicted (aMule
    /// `ClientList.cpp#L739`): an expired entry is removed as this reads it,
    /// so a stale ban never lingers past its own query.
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

    #[test]
    fn banning_an_ip_in_ban_store_has_no_effect_on_the_kad_datagram_path() {
        // ADR-0064: enforcement is peer-TCP only — there is no Kad ban gate.
        // `BanStore` carries no reference into `rmule-kad` at all, so this
        // demonstrates the property directly: banning an IP here changes
        // nothing about how a live `KadNode` treats datagrams from it.
        use rmule_kad::{
            Kad2Message, KadId, KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint, KadOutput,
        };
        use rmule_primitives::session::drain;

        let mut node = KadNode::new(KadNodeConfig {
            id: KadId::from_bytes([0xAA; KadId::BYTE_LEN]),
            tcp_port: 4662,
            udp_port: 4672,
            user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
        });
        let from = KadNodeEndpoint::new(std::net::Ipv4Addr::new(203, 0, 113, 9), 4909);

        let mut store = BanStore::default();
        store.ban(IpAddr::V4(from.ip()), Instant::now());
        assert!(store.is_banned(IpAddr::V4(from.ip()), Instant::now()));

        let message = Kad2Message::Ping;
        node.handle_datagram(KadInstant::EPOCH, from, &message.encode().encode());
        let outputs = drain(|| node.poll_output());
        let replied_to: Vec<_> = outputs
            .iter()
            .filter_map(|output| match output {
                KadOutput::Datagram { to, .. } => Some(*to),
                KadOutput::Event(_) => None,
            })
            .collect();
        assert_eq!(
            replied_to,
            vec![from],
            "Kad answers a ping from an IP the core BanStore has banned — \
             the ban never reaches the Kad datagram path"
        );
    }
}
