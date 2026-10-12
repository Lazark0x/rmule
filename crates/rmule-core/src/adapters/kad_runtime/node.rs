//! The production Kad runtime: spawn an `rmule-net-kad` node, seed it from the
//! stored contact table and the bootstrap list, and pump its events onto the
//! core-facing source, keyword, reachability, and buddy channels.

use tokio::sync::{Mutex, mpsc};

use crate::CoreError;
use crate::adapters::kad_runtime::pump_state::{KadPumpConfig, KadPumpState};
use crate::adapters::kad_runtime::{
    ClientUdpBind, KadCells, KadEnableConfig, KadNodeIdentity, KadPumpCommand, KadRuntimeFactory,
    RuntimeKadChannel,
};
use crate::buddy::BuddyIdentity;

mod pump;

/// How many of the Firewalled Front's adopt verdicts wait for the pump. One
/// per `0x5A` a walk drew — a handful at most, since one walk asks one node.
const VERDICT_QUEUE_LEN: usize = 8;

/// Starts the real `rmule_net::kad` driver on `EnableKad`. It holds nothing:
/// everything a node publishes into or shares with the peer surfaces arrives
/// in the [`KadCells`] core lends each `start`, so no runtime holds a private
/// copy of a cell the node owns.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeKadFactory;

/// The wire identity this node's Kad dials present: the credentials as the
/// node's hash, fixed at build (ADR-0048 "Identity ownership") — also the Kad
/// source ID and the buddy identity's hash. Its port is the one peers dial;
/// aMule's `RequestTCP` self-connect guard compares a requester against it
/// together with the live public IPv4 — Address Learning's projection,
/// re-read at every guard check — and matches on port alone while no IPv4 is
/// known yet.
fn node_identity(
    own: &crate::own_identity::SharedOwnIdentity,
    node: &KadNodeIdentity,
) -> Result<rmule_primitives::ClientIdentity, CoreError> {
    let user_hash = own.user_hash().ok_or_else(|| {
        CoreError::KadUnavailable("no node user hash: never adopted by a builder".into())
    })?;
    Ok(node.peer_credentials.identity(user_hash))
}

impl KadRuntimeFactory for RuntimeKadFactory {
    type Channel = RuntimeKadChannel;

    async fn start(
        &mut self,
        config: &KadEnableConfig,
        node: &KadNodeIdentity,
        bind: ClientUdpBind,
        cells: &KadCells,
    ) -> Result<RuntimeKadChannel, CoreError> {
        let adapters = &cells.adapters;
        let own = adapters.own_identity();
        // The one UDP port (ADR-0057): the node advertises, and is reached at,
        // the port the core already bound — never a second number of its own.
        let kad_udp_port = bind.socket.local_port();
        let identity = node_identity(own, node)?;
        let (user_hash, own_tcp_port) = (identity.user_hash(), identity.tcp_port());
        // The inbound half the demux front fills. Installed *after* the node
        // is up, so the front can never hand a datagram to a driver that has
        // not begun its run.
        let (inlet_tx, inlet_rx) = mpsc::channel(rmule_net::kad::KAD_INLET_CAPACITY);
        // The external Kad Shutdown Lever, split for the pump task below.
        let (kad_stop_rx, kad_stopped_tx) =
            crate::adapters::kad_runtime::split_kad_shutdown(config);
        let handle = rmule_net::kad::spawn_over(
            rmule_net::kad::KadNetConfig {
                node: rmule_kad::KadNodeConfig {
                    id: node.kad_id,
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
                // The keys are held under every policy; the policy decides
                // only whether datagrams leave obfuscated.
                // Armed from the first datagram as the policy stands now;
                // the pump re-arms the node whenever it changes.
                obfuscation: Some(
                    node.kad_crypt(adapters.hello_adverts.obfuscation.get(), own.public_ip()),
                ),
                // The Kad half of the IP filter (aMule's four `kademlia/` `IsFiltered` sites):
                // the node consults the live
                // core-owned table at every contact intake, so a filter reload
                // will reach Kad with no re-arm. Uses the *client* gate — aMule's
                // Kad checks call `IsFiltered(ip)` with `isServer` defaulted false.
                contact_admission: Some(rmule_kad::KadContactAdmission::new({
                    let ip_filter = adapters.ip_filter.clone();
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
                traffic: cells.facts.traffic.clone(),
            },
        )
        .await
        .map_err(|error| CoreError::KadUnavailable(error.to_string()))?;
        // The front's gate opens here: from now on a `0xE4`/`0xE5` — or an
        // unclaimed byte that may be obfuscated Kad — reaches this node.
        let inlet_lease = bind.kad_inlet.install(inlet_tx);

        // The published Kad verdicts start fresh and reset at the node's end
        // through the Kad Activity's one lease (ADR-0093), taken
        // by the actor before this `start` and dropped by its retire — a
        // stopped node reads firewalled (aMule's `IsFirewalledKad`), never
        // the last verdict it held.
        // **Self Reach**: every reachability question this pump
        // asks — the direct-callback bit, the buddy row, the recruit gate,
        // the FINDBUDDY posture — goes to the one owner.
        let reach = bind.reach.clone();

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

        let (handoff, bootstrap_lease) =
            super::handoff::spawn(&adapters.kad_bootstrap, commands_tx.clone()).await;
        cells.handoff.put(handoff);
        // The out-of-band signal sink (ADR-0086's recheck, ADR-0058's `0xA8`
        // ack): filling it is what opens the gate — a grant or an ack that lands
        // while Kad is off answers nothing, and an empty sink says so with no
        // "is Kad running" question.
        let pump_lease = adapters.kad_pump.install(commands_tx.clone());

        // ADR-0046 "Test Connections": the helpers asked, mirrored for the
        // listener; this pump is the helper half's one writer.
        let awaited_testers = own.awaited_testers().clone();
        // The hello this node's dials present — the ADR-0058 dial-back to a
        // requester proving its TCP port, and the buddy dial: our identity
        // under Self Reach's Presented Client ID and the live session's
        // server, read at each dial.
        let presents = crate::server_session::HelloSource::live(identity, reach.clone());
        // The shared enacted buddy slot (ADR-0061): recruit decisions and the
        // 0x52 relay run through it; a fresh Kad start begins with an empty slot.
        let buddy_slot = adapters.buddy_slot.clone();
        buddy_slot.reset();
        // And its firewalled mirror, which the Firewalled Front owns: it
        // re-seats its slot with *this* node's Kad ID — every `0x5A` and
        // `0x99` check inverts the echoed ID against it, so a slot carrying a
        // previous node's ID could verify nothing — and reads the hello it
        // presents to the buddy live at the dial, as every other dial reads
        // it. A cell rather than a command, so a full front inbox
        // cannot lose it; published before this node's pump exists, and the
        // front applies an unseen start before any command it takes, so no
        // adopt this pump asks for can overtake it.
        adapters
            .firewalled_front
            .kad_started(crate::firewalled::front::KadStart {
                hello: presents.clone(),
                kad_id: node.kad_id,
            });
        // The front's verdicts on the buddies this node's walks draw.
        let (verdicts, verdicts_rx) = mpsc::channel(VERDICT_QUEUE_LEN);
        // A restart is a new start: the contact count and the keyword index
        // size reset with the buddy slot, as the published verdicts — the
        // join latch among them (ADR-0067: `HasHadContact` is "since the node
        // started") — do at the Kad Activity's lease. The pump is their sole
        // writer, the diagnostics state their reader.
        cells
            .facts
            .contact_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        cells
            .facts
            .keywords_stored
            .store(0, std::sync::atomic::Ordering::Relaxed);
        // The three leases clear their cells when this node's pump ends, and
        // only while the cells still hold this node's senders: the socket
        // outlives the node, so a stale sender would hand datagrams to a
        // driver that has stopped, but a successor's must stay.
        // The **Reach Generation**: one wake for any family's
        // move — this pump's own verdict writes, a login or re-assignment, the
        // NAT-T front's end — on which the brain re-samples the owner.
        let reach_generation = reach.changes();
        // The dial-back broker's guard feed (aMule `RequestTCP`): the busy
        // guard is LIVE — the registry tracks every enactment in flight
        // (per-endpoint dedupe + the concurrent budget), each task's entry
        // retiring on its end. The outstanding-check guard is the node's, and
        // the node applies it before it ever raises `DialBackRequested`.
        let dial_back = pump::DialBack {
            registry: crate::reachability::DialBackRegistry::default(),
            presents,
            diagnostics: cells.diagnostics.clone(),
            own: own.clone(),
            own_tcp_port,
            hello: adapters.hello_adverts.clone(),
        };
        // Our open-node buddy identity (ADR-0061): the client hash + advertised
        // TCP port a `0x5A` accept carries back.
        let buddy_service = pump::BuddyService {
            slot: buddy_slot,
            identity: BuddyIdentity {
                our_hash: user_hash,
                our_tcp_port: own_tcp_port,
            },
            own: own.clone(),
            own_tcp_port,
        };
        let enactor = pump::Enactor {
            sources_tx,
            dial_back,
            buddy_service,
            ban_store: adapters.ban_store.clone(),
            awaited_testers,
            firewalled_front: adapters.firewalled_front.clone(),
            verdicts,
            diagnostics: cells.diagnostics.clone(),
            published: cells.verdicts.writer(),
            contact_count: std::sync::Arc::clone(&cells.facts.contact_count),
            keywords_stored: std::sync::Arc::clone(&cells.facts.keywords_stored),
            // No bind is recorded here (ADR-0084/0057): Kad took no socket of
            // its own, so a Kad `0x58`/`0x61` observation is a vote about the
            // *same* External Endpoint the server's `0x9F` observation and a
            // mapping grant are about.
            addresses: adapters.addresses().clone(),
            own: own.clone(),
            reach,
            hello: adapters.hello_adverts.clone(),
            peer_roster: adapters.peer_roster.clone(),
            hello_refusals: adapters.hello_refusals.clone(),
            pump_sink: pump_lease.weak(),
        };
        // The brain: the obfuscation policy, sampled live, arms the node's datagram
        // crypt and fixes the publish byte's ladder, the buddy dial's side of
        // the crypt rule and the recruit gate's `Required` refusal — aMule's
        // own limitation, callback requests are not obfuscatable.
        let state = KadPumpState::new(KadPumpConfig {
            kad_udp_key: node.kad_udp_key,
            kad_udp_port,
            assume_open_reachability: config.assume_open_reachability,
            kad_id: node.kad_id,
        });
        tokio::spawn(
            pump::Pump {
                handle,
                state,
                enactor,
                commands_rx,
                verdicts_rx,
                kad_stop_rx,
                kad_stopped_tx,
                reach_generation,
                inlet_lease,
                pump_lease,
                bootstrap_lease,
            }
            .run(),
        );

        Ok(RuntimeKadChannel {
            commands: commands_tx,
            sources: Mutex::new(sources_rx),
        })
    }
}
