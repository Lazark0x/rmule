//! The **Server-UDP Engine** (ADR-0051): the single owner of the server-UDP
//! socket's receive side. One Core task drains the transport and demuxes each
//! datagram on its leading packet's opcode to the concern that consumes it —
//! get-sources (`0x9B`) to the global Discovery Channel, global search
//! (`0x99`) to the answer forwarder, while the status chain (`0x97`,
//! ADR-0052) and the description pair (`0xA2` trigger + `0xA3` consume,
//! ADR-0068) run in-engine. The [`StatusPingSweep`] paces the `0x96` pings
//! that solicit it all (ADR-0052 breakdown 3) and, with that gate, is where
//! the managed list's dynamic facts come from — ping, users, files and the
//! failure tally (ADR-0080 §Dynamic server facts). Sends need no such owner: they
//! are fire-and-forget datagrams each consumer fires over the shared
//! transport (`Arc<T>`, the global-callback-relay precedent). Receive is what
//! must be owned once, because eD2k UDP packets carry no length prefix —
//! only a datagram's leading `[protocol][opcode]` header is layout-known, and
//! the packet boundaries inside it are the consuming concern's decode. Wire
//! pinned in `docs/reference/notes/server-udp.md`; cite-and-rewrite only
//! (ADR-0004).

use rmule_primitives::Ipv4Endpoint;

mod engine;
mod status_challenge;
mod status_ping_sweep;

pub(crate) use engine::ServerUdpEngine;
pub(crate) use status_challenge::{StatusChallenges, os_rand16};
pub(crate) use status_ping_sweep::{CryptPingArm, StatusPingSweep, os_crypt_ping_nonce};

/// One received server-UDP datagram, tagged with the answering server's UDP
/// source endpoint — the engine's demuxed hand-off unit.
pub(crate) type ServerUdpDatagram = (Vec<u8>, Ipv4Endpoint);

/// Shared fixtures for the submodules' tests — the scripted transport both
/// halves drive, the golden `0x97` builder, fixed entropy — plus the
/// round-trip tests that need a sweep and an engine wired to one gate.
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rmule_ed2k::Opcode;
    use rmule_primitives::{PacketProtocol, ServerEndpoint};
    use tokio::sync::mpsc;

    use super::status_ping_sweep::{CryptPingNonce, SweepState};
    use super::*;
    use crate::adapters::ServerUdpTransport;
    use crate::diagnostics::{DiagnosticsState, ServerDiagnostics};
    use crate::name_resolver::FakeNameResolver;
    use crate::own_identity::SharedOwnIdentity;
    use crate::server_capabilities::SharedServerCapabilities;
    use crate::server_list::{ResolvedAddress, test_facts};
    use std::net::Ipv4Addr;

    /// A transport preloaded with a datagram script; `recv` drains it in
    /// order, then reports the transport closed. Plain sends and obfuscated
    /// crypt-pings are recorded separately so tests can tell the +4 and +12
    /// paths apart.
    pub(crate) struct ScriptedTransport {
        pub(crate) script: tokio::sync::Mutex<mpsc::Receiver<ServerUdpDatagram>>,
        pub(crate) sends: Mutex<Vec<(ServerEndpoint, Vec<u8>)>>,
        pub(crate) crypt_pings: Mutex<Vec<(ServerEndpoint, Vec<u8>)>>,
    }

    pub(crate) fn scripted(datagrams: Vec<ServerUdpDatagram>) -> ScriptedTransport {
        let (tx, rx) = mpsc::channel(datagrams.len().max(1));
        for datagram in datagrams {
            tx.try_send(datagram).expect("script fits the channel");
        }
        // `tx` drops here, so the script's end closes the transport.
        ScriptedTransport {
            script: tokio::sync::Mutex::new(rx),
            sends: Mutex::default(),
            crypt_pings: Mutex::default(),
        }
    }

    /// The surfaced row for `endpoint` — the join a consumer reads.
    pub(crate) fn row(
        diagnostics: &DiagnosticsState,
        endpoint: &ServerEndpoint,
    ) -> ServerDiagnostics {
        diagnostics
            .snapshot()
            .servers
            .into_iter()
            .find(|row| &row.server.endpoint == endpoint)
            .expect("the server is listed")
    }

    impl ServerUdpTransport for ScriptedTransport {
        async fn send_to(&self, server: ServerEndpoint, datagram: Vec<u8>) {
            self.sends.lock().unwrap().push((server, datagram));
        }

        async fn send_crypt_ping(&self, server: ServerEndpoint, datagram: Vec<u8>) {
            self.crypt_pings.lock().unwrap().push((server, datagram));
        }

        async fn recv(&self) -> Option<ServerUdpDatagram> {
            self.script.lock().await.recv().await
        }
    }

    /// A disabled crypt-ping arm — the shipped plain-only sweep. Fixed
    /// entropy keeps the golden datagrams deterministic.
    pub(crate) fn plain_arm() -> CryptPingArm {
        CryptPingArm {
            enabled: false,
            own: SharedOwnIdentity::default(),
            grace: Duration::from_secs(20),
            nonce: fixed_crypt_ping_nonce,
        }
    }

    /// Deterministic crypt-ping nonce: challenge `0x0BADF00D`, two padding
    /// bytes.
    pub(crate) fn fixed_crypt_ping_nonce() -> CryptPingNonce {
        CryptPingNonce {
            challenge: 0x0BAD_F00D,
            padding: vec![0xDE, 0xAD],
        }
    }

    /// Deterministic challenge entropy: desc challenges mint `0xABCD_F0FF`,
    /// status challenges `0x55AA_ABCD`.
    pub(crate) fn fixed_entropy() -> u16 {
        0xABCD
    }

    /// One `0x97` datagram from a server: `challenge`, `users`, files 2000,
    /// then max/soft/hard and flags `0x20` (`EXT_GETSOURCES2`) — a 28-byte
    /// body, one of the progressive boundaries.
    pub(crate) fn stat_res_datagram(challenge: u32, users: u32) -> Vec<u8> {
        let mut datagram = vec![
            PacketProtocol::Edonkey.as_byte(),
            Opcode::GlobServStatRes.as_u8(),
        ];
        datagram.extend_from_slice(&challenge.to_le_bytes());
        datagram.extend_from_slice(&users.to_le_bytes());
        datagram.extend_from_slice(&2000_u32.to_le_bytes());
        datagram.extend_from_slice(&3000_u32.to_le_bytes());
        datagram.extend_from_slice(&4000_u32.to_le_bytes());
        datagram.extend_from_slice(&5000_u32.to_le_bytes());
        datagram.extend_from_slice(&rmule_ed2k::ServerUdpFlags::EXT_GETSOURCES2.to_le_bytes());
        datagram
    }

    pub(crate) fn server(host: &str, port: u16) -> ServerEndpoint {
        ServerEndpoint::new(host, port).expect("valid endpoint")
    }

    /// A plain sweep over `listed`, sharing its gate and its facts seam with
    /// an engine — the two halves of one status round trip.
    pub(crate) fn round_trip_harness(
        listed: &[ServerEndpoint],
    ) -> (
        StatusPingSweep<Arc<ScriptedTransport>>,
        ServerUdpEngine<Arc<ScriptedTransport>>,
        DiagnosticsState,
    ) {
        resolving_harness(listed, FakeNameResolver::knowing(&[]))
    }

    /// [`round_trip_harness`] whose sweep resolves names through `resolver`.
    fn resolving_harness(
        listed: &[ServerEndpoint],
        resolver: Arc<FakeNameResolver>,
    ) -> (
        StatusPingSweep<Arc<ScriptedTransport>>,
        ServerUdpEngine<Arc<ScriptedTransport>>,
        DiagnosticsState,
    ) {
        let (facts, diagnostics) = test_facts(listed);
        let challenges = StatusChallenges::default();
        let transport = Arc::new(scripted(vec![]));
        let sweep = StatusPingSweep {
            transport: Arc::clone(&transport),
            facts: facts.clone(),
            challenges: challenges.clone(),
            entropy: fixed_entropy,
            first_contact_tick: Duration::from_millis(250),
            tick: Duration::from_secs(5),
            reask: Duration::from_secs(1_200),
            crypt: plain_arm(),
            resolver,
        };
        let (engine, _inboxes) = ServerUdpEngine::new(
            transport,
            challenges,
            SharedServerCapabilities::default(),
            facts,
            fixed_entropy,
            false,
            diagnostics.clone(),
        );
        (sweep, engine, diagnostics)
    }

    /// Where `server`'s `0x97` comes from: its TCP port + 4.
    pub(crate) fn udp_source(server: &ServerEndpoint) -> Ipv4Endpoint {
        Ipv4Endpoint::new(server.host().parse().unwrap(), server.port() + 4)
    }

    /// Long enough for every ping sent so far to have its verdict.
    pub(crate) const VERDICTS_DUE: Duration = Duration::from_secs(90);

    /// The dynamic half of a listed row, both ends of one round trip
    /// (ADR-0080): a ping going out counts nothing, and the gated reply lands
    /// the measured ping and the load the server reported, and absolves the
    /// tally a failed connect left.
    #[tokio::test]
    async fn an_answer_lands_the_measurement_and_absolves_the_tally() {
        let listed = server("127.0.0.1", 4661);
        let (sweep, engine, diagnostics) = round_trip_harness(std::slice::from_ref(&listed));
        sweep.facts.silent(&listed).await.unwrap();

        sweep.ping_next(&mut SweepState::default()).await;

        let pinged = row(&diagnostics, &listed);
        assert_eq!(pinged.server.fail_count, 1, "sending a ping counts nothing");
        assert_eq!(
            (pinged.ping, pinged.users, pinged.files),
            (None, None, None),
            "an unanswered ping measures nothing — unknown, not zero"
        );

        // The server answers the challenge the fixed entropy minted.
        engine
            .demux(stat_res_datagram(0x55AA_ABCD, 1000), udp_source(&listed))
            .await;

        let answered = row(&diagnostics, &listed);
        assert_eq!(
            answered.server.fail_count, 0,
            "the answer absolves the whole tally"
        );
        assert!(answered.ping.is_some(), "the gate timed the round trip");
        assert_eq!(answered.users, Some(1000));
        assert_eq!(answered.files, Some(2000));
    }

    /// A silence counts against its server when a ping sent near it was
    /// answered: the network worked, the server did not.
    #[tokio::test(start_paused = true)]
    async fn a_silence_counts_when_a_neighbour_answered() {
        let (answers, silent) = (server("127.0.0.1", 4661), server("127.0.0.2", 4242));
        let (sweep, engine, diagnostics) = round_trip_harness(&[answers.clone(), silent.clone()]);
        let mut state = SweepState::default();

        sweep.ping_next(&mut state).await;
        tokio::time::advance(Duration::from_millis(250)).await;
        sweep.ping_next(&mut state).await;
        engine
            .demux(stat_res_datagram(0x55AA_ABCD, 700), udp_source(&answers))
            .await;
        tokio::time::advance(VERDICTS_DUE).await;
        sweep.ping_next(&mut state).await;

        assert_eq!(row(&diagnostics, &silent).server.fail_count, 1);
        assert_eq!(row(&diagnostics, &answers).server.fail_count, 0);
        assert!(!diagnostics.snapshot().status_sweep_unheard);
    }

    /// When every ping of a pass goes unanswered the network is down, not the
    /// servers: nobody's tally moves, and the level says the sweep hears
    /// nobody — until an answer comes.
    #[tokio::test(start_paused = true)]
    async fn when_nobody_answers_no_tally_moves() {
        let (first, second) = (server("127.0.0.1", 4661), server("127.0.0.2", 4242));
        let (sweep, engine, diagnostics) = round_trip_harness(&[first.clone(), second.clone()]);
        let mut state = SweepState::default();

        sweep.ping_next(&mut state).await;
        tokio::time::advance(Duration::from_millis(250)).await;
        sweep.ping_next(&mut state).await;
        tokio::time::advance(VERDICTS_DUE).await;
        sweep.ping_next(&mut state).await;

        assert_eq!(row(&diagnostics, &first).server.fail_count, 0);
        assert_eq!(row(&diagnostics, &second).server.fail_count, 0);
        assert!(diagnostics.snapshot().status_sweep_unheard);

        tokio::time::advance(sweep.reask).await;
        sweep.ping_next(&mut state).await;
        engine
            .demux(stat_res_datagram(0x55AA_ABCD, 700), udp_source(&first))
            .await;
        tokio::time::advance(Duration::from_secs(1)).await;
        sweep.ping_next(&mut state).await;
        assert!(!diagnostics.snapshot().status_sweep_unheard);
    }

    /// The human's run: a live server answered eight minutes ago, then the
    /// steady pace pinged a dead server alone and it stayed silent. Nobody
    /// live went unanswered, so the network is not said to be down, and the
    /// dead server's tally does not move.
    #[tokio::test(start_paused = true)]
    async fn a_dead_server_pinged_alone_does_not_say_the_network_is_down() {
        let (live, dead) = (server("127.0.0.1", 4661), server("127.0.0.2", 4799));
        let (sweep, engine, diagnostics) = round_trip_harness(&[live.clone(), dead.clone()]);
        let mut state = SweepState::default();

        sweep.ping_next(&mut state).await;
        engine
            .demux(stat_res_datagram(0x55AA_ABCD, 700), udp_source(&live))
            .await;
        tokio::time::advance(Duration::from_secs(8 * 60)).await;
        for _ in 0..sweep.facts.policy().dead_after {
            sweep.facts.silent(&dead).await.unwrap();
        }
        let tally = row(&diagnostics, &dead).server.fail_count;

        sweep.ping_next(&mut state).await;
        tokio::time::advance(VERDICTS_DUE).await;
        sweep.ping_next(&mut state).await;

        assert!(!diagnostics.snapshot().status_sweep_unheard);
        assert_eq!(row(&diagnostics, &dead).server.fail_count, tally);
        let pings = sweep
            .transport
            .sends
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, d)| d.get(1) == Some(&0x96))
            .count();
        assert_eq!(pings, 2, "a dead server's silence asks nobody to vouch");
    }

    /// A forged reply moves nothing: the challenge gate that keeps injected
    /// capabilities out keeps an injected measurement, and an absolution,
    /// out too.
    #[tokio::test]
    async fn a_forged_reply_neither_measures_a_ping_nor_absolves_the_tally() {
        let listed = server("127.0.0.1", 4661);
        let (sweep, engine, diagnostics) = round_trip_harness(std::slice::from_ref(&listed));
        sweep.facts.silent(&listed).await.unwrap();

        sweep.ping_next(&mut SweepState::default()).await;
        engine
            .demux(stat_res_datagram(0x55AA_0BAD, 66_666), udp_source(&listed))
            .await;

        let forged = row(&diagnostics, &listed);
        assert_eq!(forged.server.fail_count, 1, "the tally stands");
        assert_eq!((forged.ping, forged.users), (None, None));
    }

    // ----- ADR-0052's amendment: a server listed by host name -----

    /// A row listed by name is pinged at the address its name resolves to,
    /// and the answer from that address lands on the row the operator listed
    /// — its key stays the name, the address rides beside it.
    #[tokio::test]
    async fn a_named_server_is_pinged_at_its_address_and_its_row_takes_the_answer() {
        let named = server("srv.example.org", 4661);
        let resolver =
            FakeNameResolver::knowing(&[("srv.example.org", Ipv4Addr::new(127, 0, 0, 9))]);
        let (sweep, engine, diagnostics) =
            resolving_harness(std::slice::from_ref(&named), resolver);

        sweep.ping_next(&mut SweepState::default()).await;

        let sends = sweep.transport.sends.lock().unwrap().clone();
        assert_eq!(sends.len(), 1);
        assert_eq!(
            sends[0].0,
            server("127.0.0.9", 4661),
            "the ping goes to the address"
        );
        assert_eq!(
            row(&diagnostics, &named).resolved_address,
            Some(ResolvedAddress::Resolved(Ipv4Addr::new(127, 0, 0, 9)))
        );

        engine
            .demux(
                stat_res_datagram(0x55AA_ABCD, 1000),
                Ipv4Endpoint::new(Ipv4Addr::new(127, 0, 0, 9), 4665),
            )
            .await;

        let answered = row(&diagnostics, &named);
        assert!(answered.ping.is_some(), "the named row shows its ping");
        assert_eq!((answered.users, answered.files), (Some(1000), Some(2000)));
        assert_eq!(
            diagnostics.snapshot().servers.len(),
            1,
            "no row for the address"
        );
    }

    /// A name that gives no address costs its row one failure for the pass,
    /// judged like a silent ping — here a neighbour answered, so it counts —
    /// and nothing is sent anywhere for it.
    #[tokio::test(start_paused = true)]
    async fn a_name_that_does_not_resolve_is_one_failure_when_a_neighbour_answered() {
        let (answers, gone) = (server("127.0.0.1", 4661), server("gone.example.org", 4661));
        let (sweep, engine, diagnostics) = resolving_harness(
            &[answers.clone(), gone.clone()],
            FakeNameResolver::knowing(&[]),
        );
        let mut state = SweepState::default();

        sweep.ping_next(&mut state).await;
        tokio::time::advance(Duration::from_millis(250)).await;
        sweep.ping_next(&mut state).await;
        engine
            .demux(stat_res_datagram(0x55AA_ABCD, 700), udp_source(&answers))
            .await;
        tokio::time::advance(VERDICTS_DUE).await;
        sweep.ping_next(&mut state).await;

        let unresolved = row(&diagnostics, &gone);
        assert_eq!(unresolved.server.fail_count, 1);
        assert_eq!(
            unresolved.resolved_address,
            Some(ResolvedAddress::DoesNotResolve)
        );
        assert_eq!(row(&diagnostics, &answers).server.fail_count, 0);
        assert!(
            sweep
                .transport
                .sends
                .lock()
                .unwrap()
                .iter()
                .all(|(to, _)| to == &answers),
            "nothing is sent for a name without an address"
        );
    }

    /// A network that is down fails every lookup too: a name that does not
    /// resolve while nobody answers moves no tally.
    #[tokio::test(start_paused = true)]
    async fn a_name_that_does_not_resolve_while_nobody_answers_moves_no_tally() {
        let (silent, gone) = (server("127.0.0.2", 4242), server("gone.example.org", 4661));
        let (sweep, _engine, diagnostics) = resolving_harness(
            &[silent.clone(), gone.clone()],
            FakeNameResolver::knowing(&[]),
        );
        let mut state = SweepState::default();

        sweep.ping_next(&mut state).await;
        tokio::time::advance(Duration::from_millis(250)).await;
        sweep.ping_next(&mut state).await;
        tokio::time::advance(VERDICTS_DUE).await;
        sweep.ping_next(&mut state).await;

        assert_eq!(row(&diagnostics, &gone).server.fail_count, 0);
        assert_eq!(row(&diagnostics, &silent).server.fail_count, 0);
        assert!(diagnostics.snapshot().status_sweep_unheard);
    }

    /// A resolved address is reused for aMule's `DNS_SOLVE_TIME` (30 min):
    /// the refresh 20 min later pings the address it had, and the one 40 min
    /// later asks the name again and follows it to where it went.
    #[tokio::test(start_paused = true)]
    async fn a_resolved_address_is_reused_for_thirty_minutes_then_asked_again() {
        let named = server("srv.example.org", 4661);
        let resolver =
            FakeNameResolver::knowing(&[("srv.example.org", Ipv4Addr::new(127, 0, 0, 9))]);
        let (sweep, _engine, _diagnostics) =
            resolving_harness(std::slice::from_ref(&named), resolver.clone());
        let mut state = SweepState::default();

        sweep.ping_next(&mut state).await;
        resolver.answer("srv.example.org", Some(Ipv4Addr::new(127, 0, 0, 10)));
        tokio::time::advance(sweep.reask).await;
        sweep.ping_next(&mut state).await;
        tokio::time::advance(sweep.reask).await;
        sweep.ping_next(&mut state).await;

        let sent_to = sweep
            .transport
            .sends
            .lock()
            .unwrap()
            .iter()
            .map(|(to, _)| to.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            sent_to,
            [
                server("127.0.0.9", 4661),
                server("127.0.0.9", 4661),
                server("127.0.0.10", 4661)
            ]
        );
        assert_eq!(resolver.asked().len(), 2);
    }
}
