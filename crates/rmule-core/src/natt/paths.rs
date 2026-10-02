//! **Punched paths** and what keeps them open (ADR-0091): the 60 s keepalive,
//! and the PCP `PEER` pin asked for once when a path first works.
//!
//! A punch opens an *implicit* NAT mapping whose life is the router's UDP idle
//! timer. Two things hold it. The keepalive is rmule's own: an empty
//! `OP_HOLEPUNCH` — which every conforming peer already treats as a trigger
//! with no side effect beyond refreshing its expectation — on any path idle
//! for [`PUNCHED_PATH_KEEPALIVE`]. The pin is the router's: PCP `PEER` gives
//! the mapping a lease the router agreed to. The pin is asked for once and its
//! refusal is ordinary (NAT-PMP and UPnP cannot express it), so a path never
//! depends on it.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use rmule_net::portmap::PeerPinRequest;
use rmule_peer::natt::PUNCHED_PATH_KEEPALIVE;
use rmule_primitives::Ipv4Endpoint;

/// The lease a pin asks for. Comfortably above the keepalive so one lost
/// keepalive never costs the path, and short enough that a path rmule forgot
/// to release cleans itself up within minutes.
pub(crate) const PEER_PIN_LEASE: Duration = Duration::from_secs(10 * 60);

/// Every path a punch opened and a Tunnel still uses.
#[derive(Debug, Default)]
pub(crate) struct PunchedPaths {
    /// Per peer: when the path last carried anything in either direction.
    last_activity: HashMap<Ipv4Endpoint, Instant>,
}

impl PunchedPaths {
    /// A punch toward `peer` succeeded — a transport came up over it. Returns
    /// the pin to ask the port mapper's backend for, exactly once per path.
    ///
    /// `external_port` is the port our router maps the client-UDP bind to,
    /// when a **Mapping Grant** said so: suggesting it keeps the pin on the
    /// mapping the peer is already talking to rather than minting a second.
    pub(crate) fn on_path_open(
        &mut self,
        peer: Ipv4Endpoint,
        client_udp_port: u16,
        external_port: Option<u16>,
        now: Instant,
    ) -> Option<PeerPinRequest> {
        let fresh = self.last_activity.insert(peer, now).is_none();
        fresh.then_some(PeerPinRequest {
            internal_port: client_udp_port,
            suggested_external_port: external_port,
            remote: SocketAddrV4::new(peer.ip, peer.port),
            lease: PEER_PIN_LEASE,
        })
    }

    /// Whether this node holds a path to exactly `peer` — what tells a
    /// **Prediction Plan** ending on its clock that a Tunnel still rides one
    /// of its Fan sockets (ADR-0091's amendment). The whole endpoint:
    /// a path to another port on the same address belongs to another peer
    /// behind that address, or to an older session, and says nothing about
    /// this plan's sockets.
    pub(crate) fn holds(&self, peer: Ipv4Endpoint) -> bool {
        self.last_activity.contains_key(&peer)
    }

    /// The path carried a datagram. A busy Tunnel is its own keepalive.
    pub(crate) fn on_activity(&mut self, peer: Ipv4Endpoint, now: Instant) {
        if let Some(last) = self.last_activity.get_mut(&peer) {
            *last = now;
        }
    }

    /// The Tunnel over this path is gone; stop holding it.
    pub(crate) fn on_path_closed(&mut self, peer: Ipv4Endpoint) {
        self.last_activity.remove(&peer);
    }

    /// Paths idle for a full keepalive interval. Each is stamped as the
    /// keepalive is decided, so a caller that is slow to send does not get
    /// the same path back on its next poll.
    pub(crate) fn due_keepalives(&mut self, now: Instant) -> Vec<Ipv4Endpoint> {
        let mut due = Vec::new();
        for (peer, last) in &mut self.last_activity {
            if now.saturating_duration_since(*last) >= PUNCHED_PATH_KEEPALIVE {
                *last = now;
                due.push(*peer);
            }
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn peer(d: u8) -> Ipv4Endpoint {
        Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, d), 31999)
    }

    /// The pin names the five-tuple the punch is using and suggests the
    /// external port a grant reported; a path already open is not pinned
    /// twice.
    #[test]
    fn a_path_is_pinned_once_on_the_mapping_it_already_uses() {
        let mut paths = PunchedPaths::default();
        let t0 = Instant::now();
        assert_eq!(
            paths.on_path_open(peer(9), 4672, Some(40672), t0),
            Some(PeerPinRequest {
                internal_port: 4672,
                suggested_external_port: Some(40672),
                remote: SocketAddrV4::new(Ipv4Addr::new(45, 55, 200, 9), 31999),
                lease: PEER_PIN_LEASE,
            })
        );
        assert_eq!(paths.on_path_open(peer(9), 4672, Some(40672), t0), None);
    }

    /// A held path is matched on its whole endpoint: another port on the same
    /// address is another peer's path, and a closed one is nobody's.
    #[test]
    fn a_path_is_held_by_its_whole_endpoint_not_its_address() {
        let mut paths = PunchedPaths::default();
        let t0 = Instant::now();
        paths.on_path_open(peer(9), 4672, None, t0);
        assert!(paths.holds(peer(9)));
        assert!(!paths.holds(Ipv4Endpoint::new(peer(9).ip, 31998)));
        paths.on_path_closed(peer(9));
        assert!(!paths.holds(peer(9)));
    }

    /// Only an idle path is kept alive: traffic resets the clock, a keepalive
    /// decided is not decided again until another interval passes, and a
    /// closed path is never touched.
    #[test]
    fn only_an_idle_open_path_is_kept_alive() {
        let mut paths = PunchedPaths::default();
        let t0 = Instant::now();
        paths.on_path_open(peer(1), 4672, None, t0);
        paths.on_path_open(peer(2), 4672, None, t0);
        paths.on_path_open(peer(3), 4672, None, t0);

        paths.on_activity(peer(2), t0 + PUNCHED_PATH_KEEPALIVE / 2);
        paths.on_path_closed(peer(3));

        let at = t0 + PUNCHED_PATH_KEEPALIVE;
        assert_eq!(paths.due_keepalives(at), vec![peer(1)]);
        assert!(paths.due_keepalives(at).is_empty(), "stamped when decided");
        assert_eq!(
            paths.due_keepalives(t0 + PUNCHED_PATH_KEEPALIVE * 3 / 2),
            vec![peer(2)]
        );
    }
}
