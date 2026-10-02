//! The server-UDP front: the status chain, the crypt-ping sweep, the global
//! search answer forwarder and the global source discovery, spawned once per Core start
//! (carved out of `actor.rs` at the file ceiling; every name resolves through
//! the parent module).

use super::*;

/// Bring up the server-UDP front on the one bound socket, shared by an `Arc`
/// for sends: the discovery channel asks on it, the global-callback relay sends
/// `OP_GLOBCALLBACKREQUEST` on it, and each search's sweep fires its variant
/// datagrams on it. The receive side has one owner (ADR-0051): the server-UDP
/// engine demuxes each datagram by opcode — `0x9B` feeds the discovery
/// channel's inbox, `0x99` the search forwarder's, and `0x97` plus the `0xA3`
/// desc reply are consumed in-engine (ADR-0068). `diagnostics` is where the
/// engine counts its transport ending. Returns the
/// global-search context every `StartSearch` sweeps through, with the tasks
/// quit retires.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_server_udp_front(
    transport: Arc<RuntimeServerUdpTransport>,
    config: &CoreConfig,
    server_facts: &ServerFacts,
    own_identity: &SharedOwnIdentity,
    global_callback_rx: mpsc::Receiver<GlobCallbackSend>,
    global_source_servers: &SharedServerList,
    global_source_registry: &GlobalSourceRegistry,
    diagnostics: crate::diagnostics::DiagnosticsState,
    live_searches: &LiveSearches,
) -> ServerUdpFront {
    let mut tasks = Vec::with_capacity(5);
    tasks.push(tokio::spawn(relay_global_callbacks(
        Arc::clone(&transport),
        global_callback_rx,
    )));
    // The status chain's per-server state (ADR-0052): the sweep registers
    // outstanding challenges here, and a gated `0x97` populates the capability
    // store the `0x94` upgrade and search variant selection read — then
    // auto-fires the `0xA2` desc-req whose `0xA3` reply lands the display
    // fields (ADR-0068).
    let status_challenges = StatusChallenges::default();
    let server_capabilities = SharedServerCapabilities::default();
    let (server_udp_engine, inboxes) = ServerUdpEngine::new(
        Arc::clone(&transport),
        status_challenges.clone(),
        Arc::clone(&server_capabilities),
        server_facts.clone(),
        crate::server_udp::os_rand16,
        config.server_udp_crypt(),
        diagnostics.clone(),
    );
    let server_udp_engine = server_udp_engine.keyed_under(own_identity.clone());
    tasks.push(tokio::spawn(server_udp_engine.run()));
    tasks.push(tokio::spawn(
        crate::server_udp::StatusPingSweep {
            transport: Arc::clone(&transport),
            // The sweep walks the *managed* list (ADR-0080), not the narrower
            // source-sweep list below: this is list health, measured for
            // every listed server.
            facts: server_facts.clone(),
            challenges: status_challenges,
            entropy: crate::server_udp::os_rand16,
            first_contact_tick: config.status_ping_first_contact_tick,
            tick: config.status_ping_tick,
            reask: config.status_ping_reask,
            crypt: crate::server_udp::CryptPingArm {
                enabled: config.server_udp_crypt(),
                // The crypt-ping probe's public-IP precondition (ADR-0046,
                // aMule `theApp->GetPublicIP()`), fed by the live session's
                // High-ID IDCHANGE (ADR-0047 `public_ip`) through the shared
                // self-facts cell.
                own: own_identity.clone(),
                grace: config.crypt_ping_grace,
                nonce: crate::server_udp::os_crypt_ping_nonce,
            },
            resolver: crate::name_resolver::system_resolver(),
        }
        .run(),
    ));
    tasks.push(tokio::spawn(crate::search::forward_global_search_answers(
        inboxes.search,
        live_searches.clone(),
    )));
    let global_search = GlobalSearchContext {
        transport: Arc::clone(&transport),
        capabilities: Arc::clone(&server_capabilities),
        pacer: crate::search::UdpSearchPacer::default(),
    };
    tasks.push(tokio::spawn(
        SourceDiscovery::new(
            GlobalDiscoveryChannel::new(
                transport,
                global_source_servers.clone(),
                // The level's connected server gates every ask (ADR-0051's
                // session-only amendment).
                diagnostics,
                // The same store gates the ask form per server (the 0x94
                // upgrade, ADR-0052).
                server_capabilities,
                inboxes.sources,
            ),
            global_source_registry.clone(),
            config.global_source_interval,
            // Global cadence: re-ask every sweep (ADR-0051).
            Duration::ZERO,
        )
        .run(),
    ));
    ServerUdpFront {
        search: global_search,
        tasks,
    }
}

impl ServerUdpFront {
    /// Quit's retire (ADR-0093): abort every task and wait for each to be
    /// dropped, so nothing it held — the server list's store view above all —
    /// outlives `Core::shutdown`. Aborting is enough: every write these tasks
    /// make is one transaction inside a single poll, so an abort between
    /// awaits leaves no half-written row.
    pub(super) async fn retire(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }
}
