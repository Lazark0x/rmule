//! The socket-owning demux half of the **Server-UDP Engine** (ADR-0051): one
//! task drains the transport, runs the dual-path receive (map the answering
//! UDP source back to a server and decrypt when the crypt layer is armed,
//! ADR-0046), and routes each datagram by its leading opcode — sources
//! and search to their consumers' inboxes, while the status chain (`0x97`
//! through the challenge gate into the capability store and the server facts,
//! ADR-0052/0080) and the description pair (`0xA2` auto-trigger + gated
//! `0xA3` consume, ADR-0068) are consumed in-engine.

use std::collections::HashMap;
use std::sync::Mutex;

use rmule_ed2k::{GlobServStatRes, Opcode, ServerDescReq, ServerDescRes};
use rmule_primitives::{
    Ipv4Endpoint, PacketProtocol, ServerCryptDirection, ServerEndpoint, decrypt_datagram_server,
};
use tokio::sync::mpsc;

use super::{ServerUdpDatagram, StatusChallenges};
use crate::adapters::{
    SERVER_UDP_OBFUSCATION_PORT_OFFSET, SERVER_UDP_PORT_OFFSET, ServerUdpTransport,
};
use crate::diagnostics::DiagnosticsState;
use crate::server_capabilities::{ServerCapabilities, SharedServerCapabilities};
use crate::server_list::ServerFacts;

#[cfg(test)]
mod tests;

/// How many demuxed datagrams a concern's inbox buffers before the engine
/// awaits it (the actor-channel depth used across `service`).
const INBOX_CAPACITY: usize = 16;

/// The demuxed inboxes [`ServerUdpEngine::new`] hands out, one per consuming
/// concern that runs outside the engine.
pub(crate) struct ServerUdpInboxes {
    /// `OP_GLOBFOUNDSOURCES` (`0x9B`) → the global Discovery Channel.
    pub(crate) sources: mpsc::Receiver<ServerUdpDatagram>,
    /// `OP_GLOBSEARCHRES` (`0x99`) → the global-search answer forwarder
    /// (ADR-0051, `search::forward_global_search_answers`).
    pub(crate) search: mpsc::Receiver<ServerUdpDatagram>,
}

/// Per-server description-request state (ADR-0068, held in-engine alongside
/// the status challenges): the unanswered `0xA2` challenge, and aMule's
/// `lastdescpingedcout` — incremented per valid `0x97`, firing the desc-req
/// while it stays below 2 and resetting on the reply that reaches it, so
/// desc-reqs ride every other status reply (`ServerUDPSocket.cpp`).
#[derive(Default)]
struct DescState {
    /// The challenge of the unanswered `0xA2`, cleared by the matching
    /// tagged `0xA3` (aMule `SetDescReqChallenge(0)` — one answer per ask).
    outstanding: Option<u32>,
    /// aMule's `lastdescpingedcout` (sic).
    pinged_count: u8,
}

/// The socket-owning demux engine. Construction hands out one inbox per
/// consuming concern; [`run`](Self::run) is spawned once and ends when the
/// transport closes, which drops every inbox sender so consumers wind down.
/// The status chain (`0x97`, ADR-0052) and the description pair (`0xA2`
/// trigger + `0xA3` consume, ADR-0068) run in-engine: challenge-gated store
/// populate plus the auto-fired desc-req, no separate consumer task.
pub(crate) struct ServerUdpEngine<T> {
    transport: T,
    /// `OP_GLOBFOUNDSOURCES` (`0x9B`) → the global Discovery Channel.
    sources_tx: mpsc::Sender<ServerUdpDatagram>,
    /// `OP_GLOBSEARCHRES` (`0x99`) → the global-search forwarder.
    search_tx: mpsc::Sender<ServerUdpDatagram>,
    /// The challenge gate a `0x97` must pass (ADR-0052).
    challenges: StatusChallenges,
    /// Where a gated `0x97` lands: server TCP endpoint → proven capabilities.
    capabilities: SharedServerCapabilities,
    /// Where the same reply's *dynamic* half lands (ADR-0080): the measured
    /// round trip, the reported counts, and the absolved failure tally.
    facts: ServerFacts,
    /// The desc pair's per-server challenge + trigger counter (ADR-0068).
    desc: Mutex<HashMap<Ipv4Endpoint, DescState>>,
    /// Entropy for desc-challenge minting — caller-supplied so the trigger
    /// stays deterministic under test ([`os_rand16`](super::status_challenge::os_rand16) in production).
    desc_entropy: fn() -> u16,
    /// Whether the server-UDP crypt layer is enabled (ADR-0046,
    /// `CoreConfig::server_udp_crypt()`, derived from `peer_crypt` / aMule
    /// `IsServerCryptLayerUDPEnabled`).
    /// Off ⇒ every datagram routes as the plaintext it already is (the shipped
    /// behavior); on ⇒ a crypt-eligible source's datagram is decrypted before
    /// routing (dual-path receive).
    crypt_enabled: bool,
    /// Where the transport closing is counted: the
    /// client-UDP front's twin, `count_server_udp_transport_ended`.
    diagnostics: DiagnosticsState,
    /// Our public IPv4, which a `0x97`'s `ServerUDPKey` is recorded under
    /// (ADR-0052: the key is good only while that address is ours).
    own: crate::own_identity::SharedOwnIdentity,
}

impl<T: ServerUdpTransport> ServerUdpEngine<T> {
    /// The engine plus the demuxed inboxes its routing feeds. `challenges`
    /// is the sweep-shared gate for `0x97` replies; `capabilities` the store
    /// they populate and `facts` the managed list's dynamic half they fill;
    /// `desc_entropy` mints the auto-fired `0xA2` challenges; `crypt_enabled`
    /// arms the dual-path receive (ADR-0046); `diagnostics` is where the
    /// transport closing is counted.
    pub(crate) fn new(
        transport: T,
        challenges: StatusChallenges,
        capabilities: SharedServerCapabilities,
        facts: ServerFacts,
        desc_entropy: fn() -> u16,
        crypt_enabled: bool,
        diagnostics: DiagnosticsState,
    ) -> (Self, ServerUdpInboxes) {
        let (sources_tx, sources_rx) = mpsc::channel(INBOX_CAPACITY);
        let (search_tx, search_rx) = mpsc::channel(INBOX_CAPACITY);
        (
            Self {
                transport,
                sources_tx,
                search_tx,
                challenges,
                capabilities,
                facts,
                desc: Mutex::default(),
                desc_entropy,
                crypt_enabled,
                diagnostics,
                own: crate::own_identity::SharedOwnIdentity::default(),
            },
            ServerUdpInboxes {
                sources: sources_rx,
                search: search_rx,
            },
        )
    }

    /// Drain the transport until it closes. Ending drops the inbox senders,
    /// so every consumer's next recv yields `None` — the same wind-down the
    /// discovery engine observed when it read the transport directly. In
    /// production the transport closes only when its receive-error budget
    /// is exhausted (`RuntimeServerUdpTransport::recv`), so this
    /// is the "the engine went dark" diagnostic — global search,
    /// get-sources and the status/desc chain all end with it.
    pub(crate) async fn run(self) {
        while let Some((datagram, udp_src)) = self.transport.recv().await {
            self.demux(datagram, udp_src).await;
        }
        self.diagnostics.count_server_udp_transport_ended();
    }

    /// Route one datagram by its leading packet's opcode, after the dual-path
    /// receive recovers its plaintext (ADR-0046). A server packs a
    /// datagram with packets of one opcode (aMule's per-opcode handlers walk
    /// the continuations themselves), so routing the whole datagram *is* the
    /// demux; the consumer owns the packet walk. Anything unroutable — header
    /// shorter than two bytes, a non-eD2k protocol byte, an opcode with no
    /// consumer yet — is dropped, as when the discovery channel's decoder was
    /// the only reader.
    pub(crate) async fn demux(&self, datagram: Vec<u8>, udp_src: Ipv4Endpoint) {
        let (datagram, server) = self.receive(datagram, udp_src);
        if datagram.len() < 2 {
            tracing::trace!(
                len = datagram.len(),
                "server-UDP datagram shorter than its header; dropped"
            );
            return;
        }
        let (protocol, opcode) = (datagram[0], datagram[1]);
        if protocol != PacketProtocol::Edonkey.as_byte() {
            tracing::trace!(protocol, "server-UDP datagram not eD2k-framed; dropped");
            return;
        }
        match Opcode::try_from_u8(opcode) {
            Some(Opcode::GlobFoundSources) => {
                // A dropped receiver (discovery gone) must not stop the
                // engine: other concerns keep receiving.
                let _ = self.sources_tx.send((datagram, udp_src)).await;
            }
            Some(Opcode::GlobSearchRes) => {
                let _ = self.search_tx.send((datagram, udp_src)).await;
            }
            Some(Opcode::GlobServStatRes) => match server {
                Some(server) => self.consume_status(&datagram, server).await,
                None => tracing::trace!(
                    port = udp_src.port,
                    "OP_GLOBSERVSTATRES from an unmappable UDP source; dropped"
                ),
            },
            Some(Opcode::ServerDescRes) => match server {
                Some(server) => self.consume_description(&datagram, server),
                None => tracing::trace!(
                    port = udp_src.port,
                    "OP_SERVER_DESC_RES from an unmappable UDP source; dropped"
                ),
            },
            _ => {
                tracing::trace!(opcode, "server-UDP datagram with unrouted opcode; dropped");
            }
        }
    }

    /// Dual-path receive (ADR-0046), mirroring aMule
    /// `CServerUDPSocket::OnPacketReceived`: map the answering UDP source back
    /// to a known server, and — when the crypt layer is enabled and that server
    /// is crypt-eligible — decrypt the datagram before routing. Returns the
    /// plaintext datagram (decrypted, or the original when it already is
    /// plaintext) and the resolved server TCP endpoint (the status/desc
    /// consumers' key; `None` when the source maps to no server).
    ///
    /// The plaintext discriminator is aMule's: a leading `OP_EDONKEYPROT`
    /// (`0xE3`) is never obfuscated (`DecryptReceivedServer` short-circuits on
    /// it), so it skips the decrypt attempt — this is the server socket's gate,
    /// not the peer/Kad `is_udp_plaintext_marker` bypass set. A crypt-eligible
    /// datagram that fails to decrypt (wrong key / not for us) passes through as
    /// plaintext and is dropped by the demux's `0xE3` check.
    fn receive(&self, datagram: Vec<u8>, udp_src: Ipv4Endpoint) -> (Vec<u8>, Option<Ipv4Endpoint>) {
        let resolved = self.resolve_source(udp_src);
        if !self.crypt_enabled || datagram.first() == Some(&PacketProtocol::Edonkey.as_byte()) {
            return (datagram, resolved.map(|(server, _)| server));
        }
        match resolved {
            Some((server, Some(base_key))) => {
                match decrypt_datagram_server(&datagram, base_key, ServerCryptDirection::FromServer)
                {
                    Some(plaintext) => (plaintext, Some(server)),
                    None => (datagram, Some(server)),
                }
            }
            Some((server, None)) => (datagram, Some(server)),
            None => (datagram, None),
        }
    }

    /// Map an answering UDP source to its server's TCP endpoint (the store /
    /// challenge key) plus the RC4 base key to decrypt with, mirroring aMule's
    /// `GetServerByIPUDP` three-way match (`ServerList.cpp:643-654`, kno's
    /// fork): TCP + 12, the server's advertised obfuscation UDP port, or TCP +
    /// 4. The key follows the receive gate (`ServerUDPSocket.cpp:80-92`):
    /// while a crypt-ping is outstanding for the matched server its challenge
    /// keys the reply, whichever port it came from; otherwise a reply from the
    /// obfuscation port is keyed on its `ServerUDPKey`, and one from TCP + 4
    /// is plaintext (`None`). The crypt relations are consulted only when the
    /// layer is enabled.
    fn resolve_source(&self, udp_src: Ipv4Endpoint) -> Option<(Ipv4Endpoint, Option<u32>)> {
        if self.crypt_enabled {
            let relations = [
                udp_src.port.checked_sub(SERVER_UDP_OBFUSCATION_PORT_OFFSET),
                udp_src.port.checked_sub(SERVER_UDP_PORT_OFFSET),
            ];
            for tcp in relations.into_iter().flatten() {
                let server = Ipv4Endpoint::new(udp_src.ip, tcp);
                if let Some(challenge) = self.challenges.crypt_base_key(server) {
                    return Some((server, Some(challenge)));
                }
            }
            if let Some((server, key)) = self.obfuscation_source(udp_src) {
                let key = self.challenges.crypt_base_key(server).or(key);
                return Some((server, key));
            }
        }
        let tcp = udp_src.port.checked_sub(SERVER_UDP_PORT_OFFSET)?;
        Some((Ipv4Endpoint::new(udp_src.ip, tcp), None))
    }

    /// The engine recording each `ServerUDPKey` under the public IPv4 `own`
    /// holds when the key arrives.
    pub(crate) fn keyed_under(mut self, own: crate::own_identity::SharedOwnIdentity) -> Self {
        self.own = own;
        self
    }

    /// The server whose obfuscation UDP port this source is, with the
    /// `ServerUDPKey` the receive gate allows — aMule's
    /// `ServerKeyUDP != 0 && SupportsObfuscationUDP`, the key learned under
    /// the public IPv4 we hold now (`ServerUDPSocket.cpp:71`,
    /// `Server.cpp:300-307`). This run's record is consulted first; a server
    /// this run has not heard is found by the port its row saved (ADR-0052's
    /// durable UDP crypt amendment). A server whose port matches but whose key the gate
    /// withholds is still found, keyed `None`: its outstanding crypt-ping may
    /// key it instead.
    fn obfuscation_source(&self, udp_src: Ipv4Endpoint) -> Option<(Ipv4Endpoint, Option<u32>)> {
        let own = self.own.public_ip();
        let heard = {
            let store = self.capabilities.lock().expect("server capabilities store");
            store.iter().find_map(|(server, caps)| {
                let crypt = caps.udp_crypt?;
                (server.ip == udp_src.ip && crypt.obfuscation_udp_port == udp_src.port)
                    .then(|| (*server, crypt.key_under(caps.udp_flags, own)))
            })
        };
        heard.or_else(|| {
            let (server, crypt, udp_flags) = self.facts.saved_udp_crypt_at(udp_src)?;
            Some((server, crypt.key_under(udp_flags, own)))
        })
    }

    /// Consume one `0x97` status reply (ADR-0052) for the already-resolved
    /// `server` TCP endpoint (the receive path maps the answering UDP source —
    /// plain TCP + 4, crypt-ping TCP + 12, or obfuscation port — back to it).
    /// Pass the challenge gate and populate the capability store. Any failure —
    /// malformed body, unknown/unpinged server, challenge mismatch — drops the
    /// datagram with **no state mutation**, so a forged reply can neither inject
    /// capabilities nor burn the outstanding challenge. A gated reply then
    /// runs the desc trigger (ADR-0068): aMule auto-fires `OP_SERVER_DESC_REQ`
    /// on every other valid `0x97` (the `lastdescpingedcout` alternation),
    /// and rmule mirrors that cadence.
    ///
    /// The gate is also where the **Ping** column is measured (ADR-0080): only
    /// a reply that echoes the outstanding challenge can time a round trip, so
    /// the same one check that keeps forged capabilities out keeps a forged
    /// measurement out.
    async fn consume_status(&self, datagram: &[u8], server: Ipv4Endpoint) {
        let status = match GlobServStatRes::decode_udp(datagram) {
            Ok(status) => status,
            Err(error) => {
                tracing::trace!(%error, "malformed OP_GLOBSERVSTATRES; dropped");
                return;
            }
        };
        let Some(round_trip) = self.challenges.settle(server, status.challenge()) else {
            tracing::trace!(
                ?server,
                challenge = status.challenge(),
                "OP_GLOBSERVSTATRES failed the challenge gate; dropped"
            );
            return;
        };
        // A reply is the listed row's: the row whose name resolved to this
        // address when there is one (ADR-0052's amendment).
        if let Some(endpoint) = self.facts.row_at(server)
            && let Err(error) = self
                .facts
                .answered(&endpoint, round_trip, &status, self.own.public_ip())
                .await
        {
            tracing::warn!(%error, ?server, "status reply recorded on the wire but not in the list");
        }
        {
            // A re-ping refreshes the status fields; the `0xA3` display
            // strings ride along untouched (ADR-0068: one record, merged).
            let mut store = self.capabilities.lock().expect("server capabilities store");
            let display = store
                .remove(&server)
                .map(|prior| prior.display)
                .unwrap_or_default();
            store.insert(
                server,
                ServerCapabilities::from_status(&status, display, self.own.public_ip()),
            );
        }
        let request = {
            let mut desc = self.desc.lock().expect("server description store");
            let state = desc.entry(server).or_default();
            state.pinged_count += 1;
            if state.pinged_count < 2 {
                let request = ServerDescReq::mint((self.desc_entropy)());
                state.outstanding = Some(request.challenge());
                Some(request)
            } else {
                state.pinged_count = 0;
                None
            }
        };
        if let Some(request) = request {
            let Ok(endpoint) = ServerEndpoint::new(server.ip.to_string(), server.port) else {
                return;
            };
            self.transport
                .send_to(endpoint, request.encode_packet().encode_udp())
                .await;
        }
    }

    /// Consume one `0xA3` description reply (ADR-0068). The tagged form must
    /// echo the outstanding desc challenge — a mismatch (a second answer from
    /// a multi-homed server, or a forgery) drops the packet and leaves the
    /// challenge standing, mirroring the `0x97` gate's semantics. The legacy
    /// form carries no challenge; aMule applies it from any known server, and
    /// rmule's known set is the `0x97`-proven capability store, so a reply
    /// for a server with no record drops. Either way a failure mutates
    /// nothing. `server` is the receive path's resolved TCP endpoint.
    fn consume_description(&self, datagram: &[u8], server: Ipv4Endpoint) {
        let reply = match ServerDescRes::decode_udp(datagram) {
            Ok(reply) => reply,
            Err(error) => {
                tracing::trace!(%error, "malformed OP_SERVER_DESC_RES; dropped");
                return;
            }
        };
        match reply {
            ServerDescRes::Tagged { challenge, tags } => {
                let matched = {
                    let mut desc = self.desc.lock().expect("server description store");
                    match desc.get_mut(&server) {
                        Some(state) if state.outstanding == Some(challenge) => {
                            state.outstanding = None;
                            true
                        }
                        _ => false,
                    }
                };
                if !matched {
                    tracing::trace!(
                        ?server,
                        challenge,
                        "OP_SERVER_DESC_RES failed the desc-challenge gate; dropped"
                    );
                    return;
                }
                // The version is a figure the list keeps.
                if let Some(version) = tags.version.clone()
                    && let Some(endpoint) = self.facts.row_at(server)
                {
                    self.facts.described(&endpoint, version);
                }
                if let Some(record) = self
                    .capabilities
                    .lock()
                    .expect("server capabilities store")
                    .get_mut(&server)
                {
                    record.apply_desc_tags(tags);
                }
            }
            ServerDescRes::Legacy { description, name } => {
                let mut store = self.capabilities.lock().expect("server capabilities store");
                let Some(record) = store.get_mut(&server) else {
                    tracing::trace!(
                        ?server,
                        "legacy OP_SERVER_DESC_RES from a server with no proven record; dropped"
                    );
                    return;
                };
                record.apply_legacy_desc(description, name);
            }
        }
    }
}
