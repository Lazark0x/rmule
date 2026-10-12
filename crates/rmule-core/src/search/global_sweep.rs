//! The **server-UDP sweep** (ADR-0051): one search's fan-out across the managed
//! server list, and the persistent forwarder that carries the answers back.
//!
//! A different activity from the connected-server search its parent runs. The
//! sweep is fire-and-forget in both directions — one `OP_GLOBSEARCHREQ`
//! datagram per server per timer tick, no retries, no per-server state; each
//! search sweeps on its own, beside the others, and an answer that proves no
//! live search is dropped and counted. It never
//! completes a search: [`SearchTask`](super::SearchTask)'s quiet timer owns
//! completion, and this module only feeds it.

use std::time::Duration;

use rmule_ed2k::{GlobSearchReq, GlobSearchRes, GlobSearchVariant, SearchRequest, ServerUdpFlags};
use rmule_primitives::{Ipv4Endpoint, KeywordQuery, ServerEndpoint};
use tokio::sync::mpsc;

use crate::adapters::ServerUdpTransport;
use crate::server_capabilities::{SharedServerCapabilities, capability_flags, server_tcp_key};
use crate::server_udp::{ServerUdpDatagram, ServerUdpSeal};

use super::LiveSearches;

/// The persistent consumer of the engine's `0x99` inbox (ADR-0051): decode
/// each demuxed datagram's packed result rows and hand them to **Search
/// Attribution** (ADR-0034). A `0x99` carries no search id and
/// no place — sweeps run side by side, and UDP answers arrive in any order — so
/// it has no owner: each row reaches the live keyword searches it proves. Runs
/// for the engine's lifetime; a malformed datagram is dropped.
pub(crate) async fn forward_global_search_answers(
    mut inbox: mpsc::Receiver<ServerUdpDatagram>,
    live: LiveSearches,
) {
    while let Some((datagram, server)) = inbox.recv().await {
        forward_one_answer(&datagram, server, &live);
    }
}

/// One datagram's forwarding step: decode, then attribute, naming the
/// server that answered by its standard endpoint.
pub(super) fn forward_one_answer(datagram: &[u8], from: Ipv4Endpoint, live: &LiveSearches) {
    match GlobSearchRes::decode_udp(datagram) {
        Ok(answer) => live.deliver_udp_answer(answer.results().to_vec(), from),
        Err(error) => tracing::trace!(%error, "malformed OP_GLOBSEARCHRES; dropped"),
    }
}

/// Pick the `OP_GLOBSEARCHREQ` wrapper for a server from its proven UDP flags
/// (ADR-0051 wire policy, aMule `SearchList.cpp` order): `0x90` when the
/// server advertises LargeFiles + ExtGetFiles, `0x92` when ExtGetFiles, `0x98`
/// baseline. A server with no capability record has no proven flags
/// (`GetUDPFlags() == 0`) and gets the baseline.
pub(super) fn select_variant(flags: Option<ServerUdpFlags>) -> GlobSearchVariant {
    let flags = flags.unwrap_or_default();
    if flags.supports_large_files() && flags.supports_ext_get_files() {
        GlobSearchVariant::LargeFiles
    } else if flags.supports_ext_get_files() {
        GlobSearchVariant::ExtGetFiles
    } else {
        GlobSearchVariant::Baseline
    }
}

/// The least time between two search datagrams to one server, across every
/// sweep: 200 a minute. ed2k-server bans an address for 24 h once 30 queries
/// in its 60 s window run above 600 a minute, or above 200 a minute with their
/// intervals spread under 50 ms (`bot_detector.rs:19-29`); bench run
/// 1790605441 drew that ban from 30 datagrams sent together. Lugdunum answers
/// no `0x98` and banned nothing.
pub(crate) const UDP_SEARCH_SPACING: Duration = Duration::from_millis(300);

/// When each server last received a search datagram, shared by every sweep so
/// searches started together still reach one server [`UDP_SEARCH_SPACING`]
/// apart.
#[derive(Clone, Default)]
pub(crate) struct UdpSearchPacer(
    std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<ServerEndpoint, tokio::time::Instant>>,
    >,
);

impl UdpSearchPacer {
    /// Book the next slot for `server`: when the datagram may go.
    fn book(&self, server: &ServerEndpoint) -> tokio::time::Instant {
        let now = tokio::time::Instant::now();
        let mut last = self.0.lock().expect("udp search pacer");
        let at = last
            .get(server)
            .map_or(now, |previous| (*previous + UDP_SEARCH_SPACING).max(now));
        last.insert(server.clone(), at);
        at
    }
}

/// One search's UDP sweep over the managed server list (ADR-0051): **one
/// server per timer tick** (aMule's 750 ms `m_searchTimer`), the connected
/// server skipped (it received the TCP search), each send fire-and-forget
/// with no retries; the sweep simply ends when the list is exhausted.
/// Skipping a server (connected, or a 64-bit packet it can't serve) does not
/// consume a tick — aMule's timer handler walks to the next sendable server.
pub(crate) struct GlobalSearchSweep<T> {
    /// Where each search datagram leaves.
    pub(crate) seal: ServerUdpSeal<T>,
    /// The managed server list, snapshotted at search start.
    pub(crate) servers: Vec<ServerEndpoint>,
    /// The capability store (ADR-0052) the variant selection reads.
    pub(crate) capabilities: SharedServerCapabilities,
    /// The connected server (already searched over TCP) — skipped.
    pub(crate) connected: ServerEndpoint,
    /// The query, encoded per server: its size bounds widen to 64 bits only
    /// toward a server that advertises large-file support over UDP.
    pub(crate) query: KeywordQuery,
    /// The per-server spacing every sweep keeps.
    pub(crate) pacer: UdpSearchPacer,
    pub(crate) tick: Duration,
}

impl<T: ServerUdpTransport> GlobalSearchSweep<T> {
    /// Ask every server but the connected one; how many were asked.
    pub(crate) async fn run(self) -> u32 {
        let mut asked = 0u32;
        let mut tick = tokio::time::interval(self.tick);
        for server in &self.servers {
            if *server == self.connected {
                continue;
            }
            // The swept list holds IPv4 literals at their standard port.
            let Some(key) = server_tcp_key(server) else {
                continue;
            };
            let flags = capability_flags(&self.capabilities, server);
            // Per addressee (ADR-0051): a size bound past
            // `u32::MAX` rides a `0x08` term toward a server that takes it and
            // clamps toward one that does not, so every server gets a question
            // it can read. aMule sizes one packet by the *connected* server's
            // TCP flag and skips the servers a 64-bit packet would confuse.
            let large_files = flags.is_some_and(|flags| flags.supports_large_files());
            let request = GlobSearchReq::new(
                SearchRequest::from_query(self.query.clone()).with_large_file_support(large_files),
            );
            // First tick fires immediately; each further server waits out the
            // pacing interval.
            tick.tick().await;
            tokio::time::sleep_until(self.pacer.book(server)).await;
            let datagram = request.encode_packet(select_variant(flags)).encode_udp();
            self.seal.send(key, datagram).await;
            asked = asked.saturating_add(1);
        }
        asked
    }
}
