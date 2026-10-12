//! The **Reask Routes** (ADR-0107): where a reask reply from the one shared
//! client-UDP socket goes when several downloads pool the same peer.
//!
//! The reply quartet (`OP_REASKACK` / `OP_QUEUEFULL` / `OP_FILENOTFOUND`,
//! `0x91`/`0x93`/`0x92`) names no file. aMule needs none: it has one client
//! object per peer with one requested file, pings only that file
//! (`DownloadClient.cpp:1356-1385`) and applies the reply to it
//! (`ClientUDPSocket.cpp:1062-1094`). rmule runs one standing per (peer,
//! download), so the reply's file is the one the ping in flight to that
//! endpoint named — and there is at most one such ping per endpoint, so the
//! answer is never ambiguous. A second download's ping to the same endpoint
//! waits for the first to be answered or to lapse; one that loses its 20 s
//! window rides its TCP full ask, as aMule's A4AF file is reached over TCP.
//!
//! A reply that matches no ping in flight is dropped: nothing asked for it, and
//! a standing fed by it would be a standing no ping earned.

use std::collections::HashMap;
use std::time::Instant;

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use crate::client_udp::ClientUdpDatagram;
use crate::download::source_book::UDP_REASK_LEAD;
use crate::service::DownloadId;

/// One `0x90` out, awaiting its reply.
#[derive(Clone, Copy, Debug)]
struct InFlightPing {
    download_id: DownloadId,
    sent_at: Instant,
}

impl InFlightPing {
    /// A ping unanswered for the 20 s UDP lead has lapsed: its download has
    /// already fallen to the TCP full ask, so the endpoint is free again.
    fn lapsed(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.sent_at) >= UDP_REASK_LEAD
    }
}

/// Every running download's reply sink, and the ping in flight per peer
/// client-UDP endpoint.
#[derive(Default)]
pub(crate) struct ReaskRoutes {
    installs: HashMap<DownloadId, mpsc::Sender<ClientUdpDatagram>>,
    in_flight: HashMap<PeerEndpoint, InFlightPing>,
}

impl ReaskRoutes {
    /// Route replies for `download_id` into `sink` for as long as it runs.
    pub(crate) fn install(
        &mut self,
        download_id: DownloadId,
        sink: mpsc::Sender<ClientUdpDatagram>,
    ) {
        self.installs.insert(download_id, sink);
    }

    /// `download_id` ended: its sink goes, and so do its pings in flight, so
    /// the endpoints they held are free for the downloads beside it.
    pub(crate) fn remove(&mut self, download_id: DownloadId) {
        self.installs.remove(&download_id);
        self.in_flight
            .retain(|_, ping| ping.download_id != download_id);
    }

    /// Whether `download_id` may send its `0x90` to `endpoint` at `now`, and if
    /// so, record it as the ping in flight there. Refused while another
    /// download's ping to that endpoint is unanswered and has not lapsed.
    pub(crate) fn claim_ping(
        &mut self,
        endpoint: PeerEndpoint,
        download_id: DownloadId,
        now: Instant,
    ) -> bool {
        if let Some(held) = self.in_flight.get(&endpoint)
            && held.download_id != download_id
            && !held.lapsed(now)
        {
            return false;
        }
        self.in_flight.insert(
            endpoint,
            InFlightPing {
                download_id,
                sent_at: now,
            },
        );
        true
    }

    /// The sink of the download whose ping `from` answers, spending that ping;
    /// `None` when no ping to `from` is in flight.
    pub(crate) fn route_reply(
        &mut self,
        from: PeerEndpoint,
        now: Instant,
    ) -> Option<mpsc::Sender<ClientUdpDatagram>> {
        let ping = self.in_flight.remove(&from)?;
        if ping.lapsed(now) {
            return None;
        }
        self.installs.get(&ping.download_id).cloned()
    }

    /// How many downloads hold a sink (test affordance).
    #[cfg(test)]
    pub(crate) fn installed(&self) -> usize {
        self.installs.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use rmule_primitives::Ipv4Endpoint;

    use super::*;

    fn endpoint(last: u8, port: u16) -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, last), port))
    }

    /// One peer queued for two downloads: the reply reaches the download whose
    /// ping is in flight and no other, and the second download's ping waits
    /// until the first is answered.
    #[test]
    fn a_reply_reaches_only_the_download_whose_ping_it_answers() {
        let (first_tx, mut first_rx) = mpsc::channel(1);
        let (second_tx, mut second_rx) = mpsc::channel(1);
        let (first, second) = (DownloadId::from_u64(3), DownloadId::from_u64(8));
        let mut routes = ReaskRoutes::default();
        routes.install(first, first_tx);
        routes.install(second, second_tx);
        let peer = endpoint(23, 4673);
        let now = Instant::now();

        assert!(routes.claim_ping(peer, first, now));
        assert!(
            !routes.claim_ping(peer, second, now),
            "one ping in flight per endpoint"
        );
        let sink = routes
            .route_reply(peer, now)
            .expect("the first download's ping");
        sink.try_send((peer, vec![0xC5, 0x91])).unwrap();
        assert!(first_rx.try_recv().is_ok());
        assert!(second_rx.try_recv().is_err());

        // Answered: the endpoint is free for the second download's ping.
        assert!(routes.claim_ping(peer, second, now));
        assert!(routes.route_reply(peer, now).is_some());
        assert!(
            routes.route_reply(peer, now).is_none(),
            "an unasked reply goes nowhere"
        );
    }

    /// A ping unanswered for the 20 s lead frees its endpoint, and its late
    /// reply is not taken as an answer to the next download's ping.
    #[test]
    fn a_lapsed_ping_frees_its_endpoint() {
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (first, second) = (DownloadId::from_u64(3), DownloadId::from_u64(8));
        let mut routes = ReaskRoutes::default();
        routes.install(first, first_tx);
        let peer = endpoint(24, 4673);
        let sent = Instant::now();
        assert!(routes.claim_ping(peer, first, sent));
        let lapsed = sent + UDP_REASK_LEAD + Duration::from_millis(1);
        assert!(routes.route_reply(peer, lapsed).is_none());
        assert!(routes.claim_ping(peer, second, lapsed));
    }

    /// A download that ends releases the endpoints its pings held.
    #[test]
    fn an_ended_download_frees_its_pings_and_its_sink() {
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (first, second) = (DownloadId::from_u64(3), DownloadId::from_u64(8));
        let mut routes = ReaskRoutes::default();
        routes.install(first, first_tx);
        let peer = endpoint(25, 4673);
        let now = Instant::now();
        assert!(routes.claim_ping(peer, first, now));
        routes.remove(first);
        assert_eq!(routes.installed(), 0);
        assert!(routes.claim_ping(peer, second, now));
    }
}
