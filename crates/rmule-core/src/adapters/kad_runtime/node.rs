//! The production Kad runtime: spawn an `rmule-net-kad` node, seed it from the
//! stored contact table and the bootstrap list, and pump its events onto the
//! core-facing source, keyword, reachability, and buddy channels.

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::ClientId;
use tokio::sync::{Mutex, mpsc};

use crate::CoreError;
use crate::adapters::kad_runtime::connect_options::ConnectOptionsFeed;
use crate::adapters::kad_runtime::{
    ClientUdpBind, KadEnableConfig, KadPumpCommand, KadRuntimeFactory, RuntimeKadChannel,
};
use crate::buddy::BuddyIdentity;

mod factory;
mod pump;

pub use factory::RuntimeKadFactory;

impl KadRuntimeFactory for RuntimeKadFactory {
    type Channel = RuntimeKadChannel;

    fn adopt_cells(&mut self, cells: &crate::adapters::AdapterCells) {
        self.adopt(cells);
    }

    fn kad_reach(&self) -> crate::KadReachLevel {
        crate::KadReachLevel::published(self.kad_verdicts.clone())
    }

    fn has_had_contact(&self) -> bool {
        self.had_contact.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn contact_count(&self) -> usize {
        self.contact_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn keywords_stored(&self) -> usize {
        self.keywords_stored
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn kad_traffic(&self) -> crate::diagnostics::KadTraffic {
        self.kad_traffic.totals()
    }

    fn install_diagnostics(&mut self, diagnostics: crate::diagnostics::DiagnosticsState) {
        self.diagnostics = diagnostics;
    }

    fn take_handoff_handle(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        self.handoff_handle.take()
    }

    /// The **Kad Presence** cell this runtime's surfaces read:
    /// handed to every surface that must answer "is Kad running, as whom"
    /// from a task of its own — the serve bridge's and the firewalled
    /// front's `0x99` consumes — and leased by the actor's Kad Activity.
    fn kad_presence(&self) -> crate::adapters::kad_runtime::KadPresenceView {
        self.kad_presence.clone()
    }

    async fn start(
        &mut self,
        config: &KadEnableConfig,
        bind: ClientUdpBind,
    ) -> Result<RuntimeKadChannel, CoreError> {
        // The one UDP port (ADR-0057): the node advertises, and is reached at,
        // the port the core already bound — never a second number of its own.
        let kad_udp_port = bind.socket.local_port();
        let identity = self.node_identity(config)?;
        let (user_hash, own_tcp_port) = (identity.user_hash(), identity.tcp_port());
        // The inbound half the demux front fills. Installed *after* the node
        // is up, so the front can never hand a datagram to a driver that has
        // not begun its run.
        let (inlet_tx, inlet_rx) = mpsc::channel(rmule_net::kad::KAD_INLET_CAPACITY);
        // The external Kad Shutdown Lever, split for the pump task below.
        let (kad_stop_rx, kad_stopped_tx) =
            crate::adapters::kad_runtime::split_kad_shutdown(config);
        let verify_keys = config.verify_keys(self.hello.crypt_policy, self.own.public_ip());
        let handle = rmule_net::kad::spawn_over(
            rmule_net::kad::KadNetConfig {
                node: rmule_kad::KadNodeConfig {
                    id: config.kad_id,
                    tcp_port: own_tcp_port,
                    udp_port: kad_udp_port,
                    user_hash,
                },
                capture_dir: config.kad_capture_dir.clone(),
                // Persist the routing table where the front-end asked;
                // `None` (tests, public smoke) keeps the node ephemeral.
                nodes_dat_path: config.nodes_dat_path.clone(),
                // The ADR-0058 requester self-check runs on every node that has to
                // *derive* its own position — which is every node but the stimulus.
                //
                // This was first gated off because the two legs a check concludes
                // on were not live: nothing enacted the responder's dial-back, and
                // nothing consumed the v7+ `OP_KAD_FWTCPCHECK_ACK`. Both are wired
                // now (`enact_tcp_dial_back` and `KadPumpCommand::TcpFirewallAck`),
                // so the gate has nothing left to protect — and ADR-0086 gave the
                // check a new caller that needs it live: a fresh `Exact` mapping
                // grant fires a recheck, which a dormant requester silently drops.
                //
                // The one node that keeps it dormant is the **Core-Pumped Stimulus
                // Node**, which *declares* its verdicts rather than deriving them
                // Running a check that a two-node swarm can never
                // conclude would only walk the declaration back to firewalled.
                firewall_self_check: !config.assume_open_reachability,
                // Kad-UDP crypt under the core's one obfuscation policy
                // The keys ride inside the crypt header, so the
                // two arm together.
                datagram_obfuscation: verify_keys.is_some(),
                verify_keys,
                // The Kad half of the IP filter (aMule's four `kademlia/` `IsFiltered` sites):
                // the node consults the live
                // core-owned table at every contact intake, so a filter reload
                // will reach Kad with no re-arm. Uses the *client* gate — aMule's
                // Kad checks call `IsFiltered(ip)` with `isServer` defaulted false.
                contact_admission: Some(rmule_kad::KadContactAdmission::new({
                    let ip_filter = self.ip_filter.clone();
                    move |ip| {
                        !ip_filter
                            .read()
                            .expect("ip filter lock")
                            .is_filtered_client(ip)
                    }
                })),
            },
            rmule_net::kad::KadInlet {
                datagrams: inlet_rx,
                socket: std::sync::Arc::clone(&bind.socket),
                traffic: self.kad_traffic.clone(),
            },
        )
        .await
        .map_err(|error| CoreError::KadUnavailable(error.to_string()))?;
        // The front's gate opens here: from now on a `0xE4`/`0xE5` — or an
        // unclaimed byte that may be obfuscated Kad — reaches this node.
        if let Ok(mut slot) = bind.kad_inlet.lock() {
            *slot = Some(inlet_tx);
        }

        // The published Kad verdicts start fresh and reset at the node's end
        // through the Kad Activity's one lease (ADR-0093), taken
        // by the actor before this `start` and dropped by its retire — a
        // stopped node reads firewalled (aMule's `IsFirewalledKad`), never
        // the last verdict it held.
        // **Self Reach**: every reachability question this pump
        // asks — the direct-callback bit, the buddy row, the recruit gate,
        // the FINDBUDDY posture — goes to the one owner.
        let reach = bind.reach.clone();
        // What every source publish states in `TAG_ENCRYPTION`,
        // set before any publish can be issued: the NAT-T bit is what
        // gives a Low-ID downloader a road to this node's buddy row. The pump
        // re-derives it on every Reach Generation from here on.
        let mut options_feed = ConnectOptionsFeed::new(self.hello.crypt_policy);
        options_feed.start(&reach, &handle).await;

        // Contacts that already carry an earned Kad ID go straight into the
        // routing table (ADR-0065 "v1/v2-merge"): this is the reload half
        // of the nodes.dat persistence the driver writes, so a
        // restart resumes with its old neighbourhood instead of re-dialing for
        // one. Ordered before the dial-list seed because a merged table is what
        // ends the empty-table fast cadence.
        if !config.contacts.is_empty() {
            let _ = handle
                .command(rmule_kad::KadCommand::MergeContacts {
                    contacts: config.contacts.clone(),
                })
                .await;
        }

        // Feed the configured seeds into the one Bootstrap Dial List (ADR-0067
        // s2): the node dials them one at a time on the 15 s / 2 s cadence until
        // it joins — not all at once — and unifies them with any file-loaded v3
        // nodes.dat candidates seeded through the same command.
        if !config.bootstrap.is_empty() {
            let candidates = config
                .bootstrap
                .iter()
                .map(|endpoint| {
                    rmule_kad::KadBootstrapNode::new(
                        rmule_kad::KadNodeEndpoint::new(*endpoint.ip(), endpoint.port()),
                        None,
                    )
                })
                .collect();
            let _ = handle
                .command(rmule_kad::KadCommand::SeedBootstrapDialList { candidates })
                .await;
        }

        let (commands_tx, commands_rx) = mpsc::channel::<KadPumpCommand>(32);
        let (sources_tx, sources_rx) = mpsc::channel(32);

        self.handoff_handle =
            Some(super::handoff::spawn(&self.kad_bootstrap, commands_tx.clone()).await);
        // The out-of-band signal sink (ADR-0086's recheck, ADR-0058's `0xA8`
        // ack): filling it is what opens the gate — a grant or an ack that lands
        // while Kad is off answers nothing, and an empty sink says so with no
        // "is Kad running" question.
        if let Ok(mut slot) = self.kad_pump.lock() {
            *slot = Some(commands_tx.clone());
        }

        let ban_store = self.ban_store.clone();
        // ADR-0046 "Test Connections": the helpers asked, mirrored for the
        // listener; this pump is the helper half's one writer.
        let awaited_testers = self.own.awaited_testers().clone();
        // The ADR-0058 dial-back's eD2k hello context: the identity rmule presents
        // when it connects back to a firewalled requester to prove its TCP port.
        // Kad is serverless, so there is no High-ID and no connected server.
        let dial_back_ctx = PeerHandshakeContext {
            identity,
            client_id: ClientId::from_u32(0),
            connected_server: None,
        };
        // Our open-node buddy identity (ADR-0061): the client hash + advertised TCP
        // port a `0x5A` accept carries back.
        let our_buddy_identity = BuddyIdentity {
            our_hash: user_hash,
            our_tcp_port: own_tcp_port,
        };
        // The shared enacted buddy slot (ADR-0061): recruit decisions and the
        // 0x52 relay run through it; a fresh Kad start begins with an empty slot.
        let buddy_slot = self.buddy_slot.clone();
        buddy_slot.reset();
        // And its firewalled mirror, re-seated with *this* node's
        // Kad ID: every `0x5A` and `0x99` check inverts the echoed ID against
        // it, so a slot carrying a previous node's ID could verify nothing.
        let firewalled_slot = self.hello.firewalled_slot.clone();
        firewalled_slot.reset(config.kad_id);
        let firewalled_front = self.firewalled_front.clone();
        // The dial identity the firewalled front presents to the buddy it
        // dials, read live at the dial as every other dial reads it:
        // the live session's id and server, or none between sessions.
        firewalled_front.send(crate::firewalled::front::FirewalledCommand::KadStarted(
            Box::new(crate::server_session::HelloSource::live(
                dial_back_ctx.identity.clone(),
                self.own.clone(),
            )),
        ));
        // Our own recruitment posture beyond the two verdicts (ADR-0061):
        // `Required` forecloses the whole buddy mechanism —
        // aMule's own limitation, callback requests are not obfuscatable —
        // `Supported`/`Requested`/unset leave the gate unchanged, since a
        // node that only *prefers* crypt still falls back to plaintext for a
        // callback the same way it does for everything else.
        let crypt_required =
            self.hello.crypt_policy == Some(rmule_net::peer::ObfuscationPolicy::Required);
        // The ADR-0058 dial-back broker's own two-reading input:
        // our policy, read fresh per request the same way the recruit gate
        // above reads it, and the diagnostics handle that counts its
        // incompatible leg.
        let dial_back_crypt_policy = self.hello.crypt_policy;
        let dial_back_diagnostics = self.diagnostics.clone();
        // Where `KadEvent::Diagnostic` lands: a hostile or
        // malformed datagram is never a panic — the node's own diagnostic and
        // carries on — but until this handle existed the adapter dropped the
        // event in its catch-all arm, leaving a crypt-armed run's decode
        // failures unfalsifiable in either direction.
        let envelope_diagnostics = self.diagnostics.clone();
        // A restart is a new start (ADR-0067: `HasHadContact` is "since the
        // node started"): the latch resets with the buddy slot, as the
        // published verdicts do at the Kad Activity's lease.
        self.had_contact
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let published = self.kad_verdicts.clone();
        let assume_open_reachability = config.assume_open_reachability;
        // The `HasHadContact` latch (ADR-0067): the pump is its sole writer,
        // `RuntimeKadFactory::has_had_contact` its reader. The contact count
        // keeps the same discipline, reset with it — a restart's table
        // starts empty.
        let had_contact = std::sync::Arc::clone(&self.had_contact);
        self.contact_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let contact_count = std::sync::Arc::clone(&self.contact_count);
        self.keywords_stored
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let keywords_stored = std::sync::Arc::clone(&self.keywords_stored);
        // No bind is recorded here any more (ADR-0084/0057): Kad took no
        // socket of its own, so the one **Address Learning** bind row is the
        // core's client-UDP one, written where that socket actually came up.
        // A Kad `0x58`/`0x61` observation is therefore a vote about the *same*
        // External Endpoint the server's `0x9F` observation and a mapping
        // grant are about — which is the whole point of unifying them.
        let addresses = self.addresses.clone();
        let ipv6_advert = self.hello.ipv6.clone();
        // Every hello this pump's own dials send — the firewall-check
        // dial-back and the UDP-check helper dial — starts from the one read
        // every other hello does.
        let hello = self.hello.clone();
        // Cleared when this node's pump ends: the socket outlives the node, so
        // a stale sender would hand datagrams to a driver that has stopped.
        let kad_inlet = bind.kad_inlet.clone();
        let kad_pump_slot = self.kad_pump.clone();
        let kad_bootstrap = self.kad_bootstrap.clone();
        // The ADR-0058 requester gate: consulted before ever
        // dialling an engaged helper candidate.
        let peer_roster = self.peer_roster.clone();
        // The **Reach Generation**: one wake for any family's
        // move — this pump's own verdict writes, a login or re-assignment, the
        // NAT-T front's end — on which the byte and the buddy row re-derive.
        let reach_generation = reach.changes();
        // The self-facts cell the own-IPv4 level reads: cloned
        // rather than watched, because Address Learning's IPv4 verdict has no
        // dedicated change watch (see `PublicIpFeed`'s module docs).
        let own = self.own.clone();
        // The dial-back broker's guard feed (aMule `RequestTCP`): the busy
        // guard is LIVE — the registry tracks every enactment in flight
        // (per-endpoint dedupe + the concurrent budget), each task's entry
        // retiring on its end. The outstanding-check guard is the node's, and
        // the node applies it before it ever raises `DialBackRequested`.
        let dial_back = pump::DialBack {
            registry: crate::reachability::DialBackRegistry::default(),
            ctx: dial_back_ctx,
            crypt_policy: dial_back_crypt_policy,
            diagnostics: dial_back_diagnostics,
            own: own.clone(),
            own_tcp_port,
            hello: hello.clone(),
        };
        let buddy_service = pump::BuddyService {
            slot: buddy_slot,
            identity: our_buddy_identity,
            own: own.clone(),
            own_tcp_port,
        };
        tokio::spawn(
            pump::Pump {
                dial_back,
                buddy_service,
                kad_udp_port,
                kad_stop_rx,
                kad_stopped_tx,
                handle,
                commands_rx,
                sources_tx,
                ban_store,
                awaited_testers,
                firewalled_slot,
                firewalled_front,
                crypt_required,
                envelope_diagnostics,
                published,
                assume_open_reachability,
                had_contact,
                contact_count,
                keywords_stored,
                addresses,
                ipv6_advert,
                hello,
                kad_inlet,
                kad_pump_slot,
                kad_bootstrap,
                peer_roster,
                reach_generation,
                own,
                options_feed,
                reach,
            }
            .run(),
        );

        Ok(RuntimeKadChannel {
            commands: commands_tx,
            sources: Mutex::new(sources_rx),
        })
    }
}
