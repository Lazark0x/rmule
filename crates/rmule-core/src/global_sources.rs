//! The server-UDP global source **Discovery Channel** (ADR-0051): the
//! [`SourceDiscovery`](crate::source_discovery) adapter that puts the **Server
//! Pace**'s asks on the wire, one `OP_GLOBGETSOURCES` datagram per step, and
//! maps each `OP_GLOBFOUNDSOURCES` answer's sources back to the answering
//! server's TCP endpoint. High-ID vs Low-ID filtering lives in
//! `DownloadState::on_sightings` (`Channel::Global`), so this adapter forwards every answered
//! source unchanged.
//!
//! The socket's receive side is not read here (ADR-0051): the
//! [`ServerUdpEngine`](crate::server_udp) owns it and demuxes by opcode, and
//! this channel consumes the engine's `0x9B` inbox. Asks go out through the
//! **Server-UDP Seal** (fire-and-forget sends need no demux), so this adapter
//! is purely ask forming + answer receive.
//!
//! It asks only while a server session is up (ADR-0051's amendment), as
//! aMule's `SendNextUDPPacket` does (`DownloadQueue.cpp:870`): the answers
//! are used through session facts — our own client ID.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

use rmule_ed2k::{GlobFoundSources, GlobGetSources, GlobGetSources2};
use rmule_primitives::{
    FileHash, Ipv4Endpoint, PeerSource, ServerEndpoint, ServerUdpFlags, SourceLookupTarget,
};
use tokio::sync::mpsc;

use crate::adapters::ServerUdpTransport;
use crate::server_capabilities::{SharedServerCapabilities, capability_flags, server_tcp_key};
use crate::server_pace::{UdpAsk, UdpRounds};
use crate::server_udp::{ServerUdpDatagram, ServerUdpSeal};
use crate::source_discovery::{DiscoveryChannel, DiscoveryRegistry};

/// A global answer routed to a download: sources tagged with the **source-server**
/// that answered (a Low-ID global source's callback must target its own
/// server). The runner feeds them to `DownloadState::on_sightings` (`Channel::Global`).
pub(crate) type GlobalAnswer = (Ipv4Endpoint, Vec<PeerSource>);

/// The per-download registry, in the shared engine's shape (the runner
/// registers `(file_hash → (size, sink))`; the global channel ignores the size).
pub(crate) type GlobalSourceRegistry = DiscoveryRegistry<GlobalAnswer>;

/// The swept list both global sweeps UDP-query: the level's projection of the
/// Managed Server List, minus the dead and the IP-filtered (ADR-0051). Empty
/// while no live server is listed — the sweeps then have nothing to query.
pub(crate) type SharedServerList = Arc<Mutex<Vec<ServerEndpoint>>>;

/// The global **Discovery Channel** adapter: asks through a [`ServerUdpSeal`],
/// receives from the [`ServerUdpEngine`](crate::server_udp)'s `0x9B` inbox.
pub(crate) struct GlobalDiscoveryChannel<T> {
    seal: ServerUdpSeal<T>,
    servers: SharedServerList,
    /// The level whose connected server gates every ask: nobody is asked
    /// while no server session is up.
    session: crate::diagnostics::DiagnosticsState,
    /// The capability store (ADR-0052) gating each server's ask form: the
    /// `0x94` upgrade, the large-file skip, and the per-datagram packing.
    capabilities: SharedServerCapabilities,
    /// The UDP rounds, one step per sweep of the engine.
    rounds: Mutex<UdpRounds>,
    /// The engine's demuxed `OP_GLOBFOUNDSOURCES` datagrams (ADR-0051). A
    /// tokio mutex because `next_answer` awaits while holding it — harmless,
    /// as only the one discovery task ever takes it.
    inbox: tokio::sync::Mutex<mpsc::Receiver<ServerUdpDatagram>>,
    /// Decoded answers from a received datagram, drained one per `next_answer`
    /// (a datagram may pack several `OP_GLOBFOUNDSOURCES`, one per file).
    pending: Mutex<VecDeque<(FileHash, GlobalAnswer)>>,
}

impl<T: ServerUdpTransport> GlobalDiscoveryChannel<T> {
    /// `server`'s UDP flags: what it proved this run, else what its row holds
    /// from an earlier run or `server.met`, as aMule reads its flags from
    /// there, else none: the legacy form.
    fn flags_of(&self, server: &ServerEndpoint) -> ServerUdpFlags {
        capability_flags(&self.capabilities, server)
            .or_else(|| {
                let key = server_tcp_key(server)?;
                self.session.listed_udp_flags(key)
            })
            .unwrap_or_default()
    }

    pub(crate) fn new(
        seal: ServerUdpSeal<T>,
        servers: SharedServerList,
        session: crate::diagnostics::DiagnosticsState,
        capabilities: SharedServerCapabilities,
        rounds: UdpRounds,
        inbox: mpsc::Receiver<ServerUdpDatagram>,
    ) -> Self {
        Self {
            seal,
            servers,
            session,
            capabilities,
            rounds: Mutex::new(rounds),
            inbox: tokio::sync::Mutex::new(inbox),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// Decode every `OP_GLOBFOUNDSOURCES` packet in a received datagram and
    /// buffer each source batch, tagged with the **source-server's standard
    /// endpoint**, for `next_answer` to hand out one at a time.
    ///
    /// The engine hands the datagram over tagged with that endpoint, mapped
    /// back from whichever server port it came from (standard port + 4, or
    /// the obfuscation port for a sealed answer). A Low-ID source's
    /// namespace is keyed on it, which is what a called-back aMule
    /// peer reports as its `connected_server` (`BaseClient.cpp:1168-1169`
    /// writes `GetCurrentServer()->GetPort()`, the standard port, never the
    /// one it dialed). A datagram may pack several packets (one per file),
    /// each delimited by its own body (no length prefix); decode by the
    /// consumed length and advance until an unexpected opcode or malformed
    /// remainder ends the loop — eMule likewise breaks on an unexpected
    /// opcode.
    fn buffer_datagram(&self, datagram: &[u8], source_server: Ipv4Endpoint) {
        let mut buf = datagram;
        let mut pending = self.pending.lock();
        while let Ok((found, consumed)) = GlobFoundSources::decode_udp(buf) {
            buf = &buf[consumed..];
            pending.push_back((found.file_hash(), (source_server, found.sources().to_vec())));
        }
    }
}

impl<T: ServerUdpTransport> DiscoveryChannel for GlobalDiscoveryChannel<T> {
    type Answer = GlobalAnswer;

    /// One step of the UDP round: the Server Pace says who hears what, and
    /// this forms it for that server's proven capabilities (ADR-0052, aMule
    /// `SendNextUDPPacket`): `ExtGetSources2` advertised → the `0x94`
    /// size-extended query (unlocking files past 4 GiB); otherwise the legacy
    /// bare-hash `0x9A`. The swept list holds IPv4 literals at their standard
    /// port; a row with no literal is not asked.
    async fn ask(&self, targets: &[SourceLookupTarget]) {
        let swept: Vec<ServerEndpoint> = self
            .servers
            .lock()
            .iter()
            .filter(|server| server_tcp_key(server).is_some())
            .cloned()
            .collect();
        let ask = self.rounds.lock().next_ask(
            tokio::time::Instant::now(),
            self.session.server_session_up(),
            &swept,
            targets,
            |server| self.flags_of(server),
        );
        let Some(UdpAsk {
            server,
            flags,
            targets,
        }) = ask
        else {
            return;
        };
        let Some(key) = server_tcp_key(&server) else {
            return;
        };
        let datagram = if flags.supports_ext_get_sources2() {
            GlobGetSources2::new(targets).encode_packet().encode_udp()
        } else {
            let hashes: Vec<FileHash> = targets.iter().map(|target| target.file_hash()).collect();
            GlobGetSources::new(hashes).encode_packet().encode_udp()
        };
        self.seal.send(key, datagram).await;
    }

    async fn next_answer(&self) -> Option<(FileHash, GlobalAnswer)> {
        loop {
            // Hand out one buffered answer per call (a datagram may pack several).
            let buffered = self.pending.lock().pop_front();
            if let Some(answer) = buffered {
                return Some(answer);
            }
            // Nothing buffered: await the engine's next demuxed datagram. A
            // closed inbox means the engine ended (transport closed), the same
            // wind-down as when this channel read the transport directly.
            let (datagram, source_server) = self.inbox.lock().await.recv().await?;
            self.buffer_datagram(&datagram, source_server);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::server_pace::{SourceCount, UDP_SOURCE_GATE};
    use crate::server_udp::ServerUdpEngine;
    use crate::server_udp::tests::{plain_seal, seal_over, udp};
    use crate::source_discovery::{Discoverable, SourceDiscovery};
    use rmule_ed2k::Opcode;
    use rmule_primitives::{
        ClientId, Packet, PacketProtocol, ServerCryptDirection, decrypt_datagram_server,
        encrypt_datagram_server,
    };

    /// Rounds that step at every ask, one round per test.
    fn test_rounds() -> UdpRounds {
        UdpRounds::new(Duration::from_secs(3600), Duration::ZERO)
    }

    /// Step `channel` through more asks than any test's round has datagrams.
    async fn walk_round<T: ServerUdpTransport>(
        channel: &GlobalDiscoveryChannel<T>,
        targets: &[SourceLookupTarget],
    ) {
        for _ in 0..8 {
            channel.ask(targets).await;
        }
    }

    /// A fake transport: on any `send_to`, it enqueues one `OP_GLOBFOUNDSOURCES`
    /// datagram answering `known_hash` with `source` from where the ask went
    /// (mirrors a server replying to our query). With `answer_key` set it is a
    /// server holding that UDP key: it answers only an ask sealed under it, and
    /// answers sealed. `recv` drains those answers.
    struct FakeTransport {
        known_hash: FileHash,
        source: PeerSource,
        answer_key: Option<u32>,
        answers_tx: mpsc::Sender<(Vec<u8>, Ipv4Endpoint)>,
        // tokio mutex: `recv` awaits while holding it (the registry/servers use a
        // std mutex because they are only ever briefly snapshotted).
        answers_rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, Ipv4Endpoint)>>,
    }

    impl FakeTransport {
        fn new(known_hash: FileHash, source: PeerSource) -> Self {
            let (answers_tx, answers_rx) = mpsc::channel(8);
            Self {
                known_hash,
                source,
                answer_key: None,
                answers_tx,
                answers_rx: tokio::sync::Mutex::new(answers_rx),
            }
        }

        fn glob_found_sources_datagram(&self) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(self.known_hash.as_bytes());
            payload.push(1);
            payload.extend_from_slice(&self.source.wire_id().to_le_bytes());
            payload.extend_from_slice(&self.source.tcp_port().to_le_bytes());
            Packet::new(
                PacketProtocol::Edonkey,
                Opcode::GlobFoundSources.as_u8(),
                payload,
            )
            .encode_udp()
        }
    }

    impl ServerUdpTransport for FakeTransport {
        async fn send_to(&self, to: Ipv4Endpoint, datagram: Vec<u8>) {
            let mut answer = self.glob_found_sources_datagram();
            if let Some(key) = self.answer_key {
                if decrypt_datagram_server(&datagram, key, ServerCryptDirection::ToServer).is_none()
                {
                    return;
                }
                let nonce = rmule_primitives::DatagramNonce {
                    marker_byte: 0x51,
                    random_key: 0xBEEF,
                    padding: Vec::new(),
                };
                answer =
                    encrypt_datagram_server(&answer, key, ServerCryptDirection::FromServer, &nonce);
            }
            // The answer arrives from where the ask went; the engine maps it
            // back to the server's standard endpoint.
            let _ = self.answers_tx.send((answer, to)).await;
        }

        async fn recv(&self) -> Option<(Vec<u8>, Ipv4Endpoint)> {
            self.answers_rx.lock().await.recv().await
        }
    }

    #[tokio::test]
    async fn discovers_and_routes_a_high_id_global_source() {
        let file_hash = FileHash::from_bytes([0x77; FileHash::BYTE_LEN]);
        let source = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), 4662);
        let transport = Arc::new(FakeTransport::new(file_hash, source));

        let registry: GlobalSourceRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (sink_tx, mut sink_rx) = mpsc::channel(8);
        registry.lock().insert(
            file_hash,
            Discoverable {
                file_size: 4096,
                sink: sink_tx,
                sources: SourceCount::default(),
            },
        );

        let servers: SharedServerList = Arc::new(Mutex::new(vec![
            ServerEndpoint::new("127.0.0.1", 4661).unwrap(),
        ]));
        // The production wiring (ADR-0051): the engine owns the receive side
        // and demuxes; the channel asks on the shared transport and consumes
        // the engine's `0x9B` inbox.
        let seal = plain_seal(Arc::clone(&transport));
        let (engine, inboxes) = ServerUdpEngine::new(
            Arc::clone(&transport),
            seal.clone(),
            crate::server_udp::StatusChallenges::default(),
            SharedServerCapabilities::default(),
            crate::server_list::ServerFacts::default(),
            crate::server_udp::os_rand16,
            crate::diagnostics::DiagnosticsState::new(),
        );
        let engine_task = tokio::spawn(engine.run());
        // An empty capability store: every ask stays on the legacy 0x9A form.
        let channel = GlobalDiscoveryChannel::new(
            seal,
            servers,
            in_session(),
            SharedServerCapabilities::default(),
            test_rounds(),
            inboxes.sources,
        );
        let task = tokio::spawn(
            SourceDiscovery::new(
                channel,
                registry,
                Duration::from_millis(10),
                crate::source_discovery::AskClock::shared(Duration::ZERO),
                UDP_SOURCE_GATE,
            )
            .run(),
        );

        let (server, routed) = tokio::time::timeout(Duration::from_secs(2), sink_rx.recv())
            .await
            .expect("a global source routed within 2s")
            .expect("sink stayed open");
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].client_id(), source.client_id());
        // The answering server's TCP endpoint (UDP source 4665 − 4) is threaded
        // through to the sink — the namespace of a Low-ID source's id, matched
        // against a called-back peer's reported `connected_server`.
        assert_eq!(
            server,
            Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, 4661)
        );

        task.abort();
        engine_task.abort();
    }

    /// A server whose UDP key we hold — learned under the address we still
    /// hold, UDP obfuscation advertised — is asked sealed at its obfuscation
    /// port and answers sealed from it. The answer's sources still name the
    /// server by its standard endpoint: the namespace of a Low-ID source.
    #[tokio::test]
    async fn a_keyed_server_is_asked_sealed_and_its_sealed_answer_names_its_standard_endpoint() {
        const KEY: u32 = 0x05A6_8835;
        let ours = std::net::Ipv4Addr::new(203, 0, 113, 3);
        let standard = Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, 4661);
        let file_hash = FileHash::from_bytes([0x77; FileHash::BYTE_LEN]);
        let source = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), 4662);
        let transport = Arc::new(FakeTransport {
            answer_key: Some(KEY),
            ..FakeTransport::new(file_hash, source)
        });
        let capabilities = SharedServerCapabilities::default();
        let mut record = crate::server_capabilities::test_record_with_flags(
            rmule_ed2k::ServerUdpFlags::UDPOBFUSCATION,
        );
        record.udp_crypt = Some(crate::server_list::ServerUdpCrypt {
            obfuscation_udp_port: 4675,
            obfuscation_tcp_port: 4661,
            udp_key: KEY,
            key_ip: Some(ours),
        });
        capabilities.lock().insert(standard, record);
        let own = crate::own_identity::SharedOwnIdentity::default();
        own.addresses()
            .observe(crate::address_learning::AddressObservation::server_high_id(
                ours,
            ));
        let seal = seal_over(
            Arc::clone(&transport),
            crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                rmule_net::peer::ObfuscationPolicy::Requested,
            )),
            own,
            Arc::clone(&capabilities),
            crate::server_list::ServerFacts::default(),
        );
        let (engine, inboxes) = ServerUdpEngine::new(
            Arc::clone(&transport),
            seal.clone(),
            crate::server_udp::StatusChallenges::default(),
            Arc::clone(&capabilities),
            crate::server_list::ServerFacts::default(),
            crate::server_udp::os_rand16,
            crate::diagnostics::DiagnosticsState::new(),
        );
        let engine_task = tokio::spawn(engine.run());
        let registry: GlobalSourceRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (sink_tx, mut sink_rx) = mpsc::channel(8);
        registry.lock().insert(
            file_hash,
            Discoverable {
                file_size: 4096,
                sink: sink_tx,
                sources: SourceCount::default(),
            },
        );
        let channel = GlobalDiscoveryChannel::new(
            seal,
            Arc::new(Mutex::new(vec![
                ServerEndpoint::new("127.0.0.1", 4661).unwrap(),
            ])),
            in_session(),
            capabilities,
            test_rounds(),
            inboxes.sources,
        );
        let task = tokio::spawn(
            SourceDiscovery::new(
                channel,
                registry,
                Duration::from_millis(10),
                crate::source_discovery::AskClock::shared(Duration::ZERO),
                UDP_SOURCE_GATE,
            )
            .run(),
        );

        let (server, routed) = tokio::time::timeout(Duration::from_secs(2), sink_rx.recv())
            .await
            .expect("the sealed answer routed within 2s")
            .expect("sink stayed open");
        assert_eq!(routed[0].client_id(), source.client_id());
        assert_eq!(server, standard);

        task.abort();
        engine_task.abort();
    }

    /// A send-only transport recording every `(destination, datagram)`.
    struct RecordingTransport {
        sends: Mutex<Vec<(Ipv4Endpoint, Vec<u8>)>>,
    }

    impl ServerUdpTransport for RecordingTransport {
        async fn send_to(&self, to: Ipv4Endpoint, datagram: Vec<u8>) {
            self.sends.lock().push((to, datagram));
        }

        async fn recv(&self) -> Option<(Vec<u8>, Ipv4Endpoint)> {
            std::future::pending().await
        }
    }

    /// A level with a server session up.
    fn in_session() -> crate::diagnostics::DiagnosticsState {
        let level = crate::diagnostics::DiagnosticsState::new();
        level.set_connected_server(Some((
            ServerEndpoint::new("10.0.0.1", 4661).unwrap(),
            rmule_ed2k::ServerGrants::default(),
        )));
        level
    }

    fn channel_with_caps(
        transport: Arc<RecordingTransport>,
        servers: Vec<ServerEndpoint>,
        caps: &[(std::net::Ipv4Addr, u16, u32)],
    ) -> GlobalDiscoveryChannel<Arc<RecordingTransport>> {
        channel_in(in_session(), transport, servers, caps)
    }

    fn channel_in(
        session: crate::diagnostics::DiagnosticsState,
        transport: Arc<RecordingTransport>,
        servers: Vec<ServerEndpoint>,
        caps: &[(std::net::Ipv4Addr, u16, u32)],
    ) -> GlobalDiscoveryChannel<Arc<RecordingTransport>> {
        let capabilities = SharedServerCapabilities::default();
        for (ip, port, bits) in caps {
            capabilities.lock().insert(
                Ipv4Endpoint::new(*ip, *port),
                crate::server_capabilities::test_record_with_flags(*bits),
            );
        }
        // The ask path never reads the inbox; a parked receiver suffices.
        let (_inbox_tx, inbox_rx) = mpsc::channel(1);
        GlobalDiscoveryChannel::new(
            plain_seal(transport),
            Arc::new(Mutex::new(servers)),
            session,
            capabilities,
            test_rounds(),
            inbox_rx,
        )
    }

    /// With no server session nobody is asked, as in aMule; the first ask
    /// after a login goes out.
    #[tokio::test]
    async fn nobody_is_asked_while_no_server_session_is_up() {
        let transport = Arc::new(RecordingTransport {
            sends: Mutex::new(Vec::new()),
        });
        let level = crate::diagnostics::DiagnosticsState::new();
        let swept = ServerEndpoint::new("10.0.0.3", 4661).unwrap();
        let channel = channel_in(level.clone(), Arc::clone(&transport), vec![swept], &[]);
        let due = [SourceLookupTarget::new(
            FileHash::from_bytes([0x11; 16]),
            4096,
        )];

        channel.ask(&due).await;
        assert!(transport.sends.lock().is_empty());

        level.set_connected_server(Some((
            ServerEndpoint::new("10.0.0.1", 4661).unwrap(),
            rmule_ed2k::ServerGrants::default(),
        )));
        channel.ask(&due).await;
        assert_eq!(transport.sends.lock().len(), 1);
    }

    /// A server not yet heard this run is asked in the form its row holds
    /// from an earlier run or `server.met`, as aMule reads its flags from
    /// there: one datagram for both files, not one for each.
    #[tokio::test]
    async fn a_server_not_heard_this_run_is_asked_in_the_form_its_row_holds() {
        let transport = Arc::new(RecordingTransport {
            sends: Mutex::new(Vec::new()),
        });
        let listed = ServerEndpoint::new("10.0.0.7", 4661).unwrap();
        let row = crate::server_list::ManagedServer {
            listed_udp_flags: Some(ServerUdpFlags::from_bits(ServerUdpFlags::EXT_GETSOURCES)),
            ..crate::server_list::ManagedServer::listed(listed.clone())
        };
        let (_facts, level) = crate::server_list::test_facts_rows(vec![row]);
        level.set_connected_server(Some((
            ServerEndpoint::new("10.0.0.1", 4661).unwrap(),
            rmule_ed2k::ServerGrants::default(),
        )));
        let channel = channel_in(level, Arc::clone(&transport), vec![listed], &[]);

        let targets = [
            SourceLookupTarget::new(FileHash::from_bytes([0x11; 16]), 4096),
            SourceLookupTarget::new(FileHash::from_bytes([0x22; 16]), 8192),
        ];
        walk_round(&channel, &targets).await;

        let sends = transport.sends.lock().clone();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].1.len(), 2 + 16 + 16);
    }

    #[tokio::test]
    async fn ask_upgrades_to_0x94_per_server_and_skips_large_files_elsewhere() {
        use rmule_ed2k::ServerUdpFlags;
        let transport = Arc::new(RecordingTransport {
            sends: Mutex::new(Vec::new()),
        });
        let upgraded = ServerEndpoint::new("10.0.0.2", 4661).unwrap();
        let legacy = ServerEndpoint::new("10.0.0.3", 4661).unwrap();
        let channel = channel_with_caps(
            Arc::clone(&transport),
            vec![upgraded.clone(), legacy.clone()],
            &[(
                std::net::Ipv4Addr::new(10, 0, 0, 2),
                4661,
                ServerUdpFlags::EXT_GETSOURCES
                    | ServerUdpFlags::EXT_GETSOURCES2
                    | ServerUdpFlags::LARGEFILES,
            )],
        );

        let small = SourceLookupTarget::new(FileHash::from_bytes([0x11; 16]), 4096);
        // Large is aMule's `IsLargeFile`: one byte past OLD_MAX_FILE_SIZE is
        // large though a `u32` still holds it.
        let large_size = rmule_primitives::OLD_MAX_FILE_SIZE + 1;
        let large = SourceLookupTarget::new(FileHash::from_bytes([0x22; 16]), large_size);
        walk_round(&channel, &[small, large]).await;

        let sends = transport.sends.lock().clone();
        assert_eq!(sends.len(), 2, "one datagram per server this round");

        // The upgraded server gets one 0x94 with both entries — the large
        // file in its [0 u32][u64] escape form.
        let (server, datagram) = &sends[0];
        assert_eq!(server, &udp(&upgraded, 4));
        let mut expected = vec![0xE3, 0x94];
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&4096_u32.to_le_bytes());
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&0_u32.to_le_bytes());
        expected.extend_from_slice(&large_size.to_le_bytes());
        assert_eq!(datagram, &expected);

        // The capability-less server stays on bare-hash 0x9A, without the
        // large file ("UDP Request for sources on a large file ignored").
        let (server, datagram) = &sends[1];
        assert_eq!(server, &udp(&legacy, 4));
        let mut expected = vec![0xE3, 0x9A];
        expected.extend_from_slice(&[0x11; 16]);
        assert_eq!(datagram, &expected);
    }

    #[tokio::test]
    async fn ask_packs_one_file_per_datagram_without_ext_get_sources() {
        use rmule_ed2k::ServerUdpFlags;
        let transport = Arc::new(RecordingTransport {
            sends: Mutex::new(Vec::new()),
        });
        let bare = ServerEndpoint::new("10.0.0.3", 4661).unwrap();
        let batched = ServerEndpoint::new("10.0.0.4", 4661).unwrap();
        let channel = channel_with_caps(
            Arc::clone(&transport),
            vec![bare.clone(), batched.clone()],
            &[(
                std::net::Ipv4Addr::new(10, 0, 0, 4),
                4661,
                ServerUdpFlags::EXT_GETSOURCES,
            )],
        );

        let targets = [
            SourceLookupTarget::new(FileHash::from_bytes([0x11; 16]), 4096),
            SourceLookupTarget::new(FileHash::from_bytes([0x22; 16]), 8192),
        ];
        walk_round(&channel, &targets).await;

        let sends = transport.sends.lock().clone();
        let to_bare: Vec<_> = sends.iter().filter(|(s, _)| s == &udp(&bare, 4)).collect();
        let to_batched: Vec<_> = sends
            .iter()
            .filter(|(s, _)| s == &udp(&batched, 4))
            .collect();
        // No EXT_GETSOURCES → one file per datagram (aMule's
        // GetMaxFilesPerUDPServerPacket returns 1); with it, one batch.
        assert_eq!(to_bare.len(), 2);
        assert!(to_bare.iter().all(|(_, d)| d.len() == 2 + 16));
        assert_eq!(to_batched.len(), 1);
        assert_eq!(to_batched[0].1.len(), 2 + 16 + 16);
    }
}
