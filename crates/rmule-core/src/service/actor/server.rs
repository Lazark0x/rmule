//! The server-facing command arms: the server policy, the server-list
//! commands themselves, and the operator's connect — one dial at a time, to a
//! listed server only.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use rmule_primitives::ServerEndpoint;
use tokio::sync::mpsc;

use crate::CoreError;
use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::server_list::{
    ErasedFetcher, ServerListFetcher, ServerListUpdateError, ServerMerge, SharedServerListStore,
    acquire_server_met, install_server_met_plan, mutate_and_publish,
};
use crate::service::{
    CoreCommandRejectReason, CoreEvent, LoginStep, ServerListCommand, ServerListEvent,
};

use super::{CoreActor, send_event};

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Take up the operator's server policy (ADR-0052, ADR-0099): every
    /// row's health and the swept list follow it at once, and so does what
    /// the live session is told of the share set.
    pub(super) fn on_set_server_policy(&mut self, policy: crate::ServerPolicy) {
        self.diagnostics.set_server_policy(policy);
        self.wiring
            .shared_server_session
            .set_withhold_shares(policy.withhold_from_related_search);
    }

    /// Enact one server-list command against the managed list.
    pub(super) async fn on_server_list_command(&mut self, command: ServerListCommand) {
        handle_server_list_command(
            command,
            ServerListContext {
                store: &self.wiring.server_list,
                fetcher: self.wiring.server_list_fetcher.as_ref(),
                in_flight: &self.server_list_update_in_flight,
                max_server_met_bytes: self.wiring.config.max_server_met_bytes,
                diagnostics: &self.diagnostics,
                evt_tx: &self.evt_tx,
            },
        )
        .await;
    }

    /// Dial a listed server for the session slot — one connect at a time.
    pub(super) async fn on_connect_to_server(&mut self, server: ServerEndpoint) {
        // Only a listed server can be connected to, the same
        // invariant every other server command holds: the list
        // is what an operator picks from, and a row the
        // operator cannot see is a row they cannot have meant.
        // An unreadable store is refused rather than assumed
        // empty — a connect is not the place to guess.
        let listed = self
            .wiring
            .server_list
            .servers()
            .map(|rows| rows.iter().any(|row| row.endpoint == server));
        match listed {
            Err(error) => {
                reject_server_list_store(&self.evt_tx, &error).await;
                return;
            }
            Ok(false) => {
                send_event(
                    &self.evt_tx,
                    CoreEvent::CommandRejected {
                        reason: CoreCommandRejectReason::UnknownServer,
                    },
                )
                .await;
                return;
            }
            Ok(true) => {}
        }
        if self.server_connect_in_flight.swap(true, Ordering::SeqCst) {
            send_event(
                &self.evt_tx,
                CoreEvent::CommandRejected {
                    reason: CoreCommandRejectReason::ServerConnectInFlight,
                },
            )
            .await;
            return;
        }
        // The operator's word: stay connected to this server.
        self.begin_intent(server.clone()).await;
        self.establish(server).await;
    }

    /// The one establishment (ADR-0095): listen, wait for the listener's
    /// mapping, log in — for the operator's connect and for every re-make of
    /// a session the operator's intent keeps. The caller holds the in-flight
    /// flag; the dial's outcome reaches the intent ledger. The login presents
    /// the Core Settings' credentials.
    pub(super) async fn establish(&mut self, server: ServerEndpoint) {
        // Off the actor, like the list update: a dial is a
        // multi-second round trip, and the whole point of the
        // Servers tab is that the rest of the UI keeps
        // answering while it runs. The trail is the reply, and
        // it reaches the same bus from the session layer.
        //
        // The claim is taken HERE, before the spawn:
        // a `StartSearch` queued right behind this
        // command must find the connect already holding
        // establishment authority, not race the unpolled task
        // for the session slot and dial a rival session the
        // connect would then kill. Moved into the task, its
        // drop releases the waiters however the connect ends.
        let claim = self.wiring.shared_server_session.claim_connect();
        // **Listen Before Login** (ADR-0086): the server's High-ID port check dials the port this
        // login advertises, so the listener binds first — here, on the actor,
        // before the dial is spawned.
        let listener_port = self.listen_before_login().await;
        // The **Login Mapping Wait**: with a mapping runtime running, the
        // listener's row must settle before the login leaves, or a gateway
        // still granting the port is raced by the server's port check.
        let mapping = listener_port.zip(self.port_mapping.as_ref().map(|handle| handle.rows()));
        let session = self.wiring.shared_server_session.clone();
        let ip_filter = self.wiring.ip_filter.clone();
        let in_flight = Arc::clone(&self.server_connect_in_flight);
        let identity = self.identity();
        let (epoch, news) = self.intent.reporter();
        let evt_tx = self.evt_tx.clone();
        tokio::spawn(async move {
            if let Some((port, rows)) = mapping {
                let settled = crate::adapters::await_listener_mapping(rows, port).await;
                let step = LoginStep::MappingWait { port, settled };
                let event = CoreEvent::ServerLogin {
                    server: server.clone(),
                    step,
                };
                send_event(&evt_tx, event).await;
            }
            let outcome =
                crate::server_session::connect_to_server(&session, server, identity, &ip_filter)
                    .await;
            in_flight.store(false, Ordering::SeqCst);
            drop(claim);
            let _ = news.send(match outcome {
                Ok(session) => super::server_intent::IntentNews::Established { epoch, session },
                Err(_) => super::server_intent::IntentNews::Failed { epoch },
            });
        });
    }

    /// The operator's connect installed a session (the **Session
    /// Generation** moved, ADR-0095): the searches that waited for one start
    /// on it, and a High ID landing while Kad's TCP verdict reads firewalled
    /// asks Kad to check again — the server has just reached our listener on
    /// the port Kad advertises, so that verdict is stale.
    pub(super) async fn on_session_established(&mut self) {
        let high_id_server = self
            .wiring
            .shared_server_session
            .session_in_slot()
            .await
            .filter(|session| session.client_id().is_high_id())
            .map(|session| session.server().clone());
        if let Some(server) = high_id_server
            && self.self_reach.kad_running()
            && !self.self_reach.kad_tcp_open()
        {
            crate::adapters::request_kad_recheck(&self.wiring.kad_pump);
            let event = CoreEvent::ServerLogin {
                server,
                step: LoginStep::KadRecheck,
            };
            send_event(&self.evt_tx, event).await;
        }
        self.start_waiting_searches().await;
    }

    /// Make sure the eD2k listener is up before a login — or a Kad start
    /// with an injected port of `0`, which has no port to present without
    /// it — and answer the port it listens on: `None` when it could not
    /// bind, which the serve start has already reported (`ServingFailed`);
    /// the login still goes out, Low ID, as aMule's does (`amule.cpp:1688`). The listener is the Serve
    /// activity's (ADR-0095), started here on the Core Settings' TCP port —
    /// the port the login and the Kad firewall check advertise; an injected
    /// `0` takes one the OS assigns the first time, and they advertise the
    /// port bound. A listener that stops and starts again rebinds that same
    /// port, so neither the Kad node nor a live login goes stale.
    pub(super) async fn listen_before_login(&mut self) -> Option<u16> {
        if self.activities.serving().is_none() {
            let listen_addr = self.settings_listen_addr();
            self.start_serving(listen_addr).await;
        }
        self.activities
            .serving()
            .map(crate::service::activity::ServeActivity::bound_listen_port)
    }
}

/// Everything a [`ServerListCommand`] is answered from (ADR-0080): the list
/// the actor owns, its optional fetch capability, the one-at-a-time update
/// guard, the level to republish, and the event sink. Grouped so the actor's
/// arm stays one call.
struct ServerListContext<'a> {
    store: &'a SharedServerListStore,
    fetcher: Option<&'a Arc<dyn ServerListFetcher>>,
    in_flight: &'a Arc<std::sync::atomic::AtomicBool>,
    max_server_met_bytes: usize,
    diagnostics: &'a crate::diagnostics::DiagnosticsState,
    evt_tx: &'a mpsc::Sender<CoreEvent>,
}

/// Apply one server-list command (ADR-0080).
///
/// Every arm follows the same shape: mutate the store and republish the level
/// in one critical section ([`mutate_and_publish`]), then report — the edge
/// event when something changed, a rejection when the row was not there or the
/// store refused. The only asynchronous arm is the update, which leaves the
/// actor immediately.
async fn handle_server_list_command(command: ServerListCommand, ctx: ServerListContext<'_>) {
    match command {
        ServerListCommand::AddServer { server } => {
            // The operator's word, judged as aMule's `AddServer` judges every
            // server with no dynamic IP (`ServerList.cpp:206`, ADR-0085). A
            // named server is resolved when dialed.
            let reserved = server
                .endpoint
                .host()
                .parse()
                .is_ok_and(|ip| !rmule_primitives::Informant::Own.admits(ip));
            if reserved {
                send_event(
                    ctx.evt_tx,
                    CoreEvent::CommandRejected {
                        reason: CoreCommandRejectReason::ServerAddressReserved,
                    },
                )
                .await;
                return;
            }
            let endpoint = server.endpoint.clone();
            let merged = mutate_and_publish(ctx.store, ctx.diagnostics, |store| {
                store.merge_server(server)
            });
            match merged {
                Ok(ServerMerge::Added) => {
                    send_event(
                        ctx.evt_tx,
                        ServerListEvent::ServerAdded { server: endpoint }.into(),
                    )
                    .await;
                }
                Ok(ServerMerge::Updated) => {
                    send_event(
                        ctx.evt_tx,
                        ServerListEvent::ServerUpdated { server: endpoint }.into(),
                    )
                    .await;
                }
                Err(error) => reject_server_list_store(ctx.evt_tx, &error).await,
            }
        }
        ServerListCommand::RemoveServer { server } => {
            // aMule's `RemoveServer`: the row goes, a live session to it does
            // not. Nothing here reaches the session slot.
            let removed = mutate_and_publish(ctx.store, ctx.diagnostics, |store| {
                store.remove_server(&server)
            });
            report_row_mutation(
                ctx.evt_tx,
                removed,
                ServerListEvent::ServerRemoved { server },
            )
            .await;
        }
        ServerListCommand::SetServerPriority { server, priority } => {
            let changed = mutate_and_publish(ctx.store, ctx.diagnostics, |store| {
                store.set_server_priority(&server, priority)
            });
            report_row_mutation(
                ctx.evt_tx,
                changed,
                ServerListEvent::ServerPriorityChanged { server, priority },
            )
            .await;
        }
        ServerListCommand::SetServerStatic { server, is_static } => {
            let changed = mutate_and_publish(ctx.store, ctx.diagnostics, |store| {
                store.set_server_static(&server, is_static)
            });
            report_row_mutation(
                ctx.evt_tx,
                changed,
                ServerListEvent::ServerStaticChanged { server, is_static },
            )
            .await;
        }
        ServerListCommand::UpdateServerList { url } => {
            let Some(fetcher) = ctx.fetcher else {
                send_event(
                    ctx.evt_tx,
                    CoreEvent::CommandRejected {
                        reason: CoreCommandRejectReason::ServerListFetchUnavailable,
                    },
                )
                .await;
                return;
            };
            if ctx.in_flight.swap(true, Ordering::SeqCst) {
                send_event(
                    ctx.evt_tx,
                    CoreEvent::CommandRejected {
                        reason: CoreCommandRejectReason::ServerListUpdateInFlight,
                    },
                )
                .await;
                return;
            }
            send_event(
                ctx.evt_tx,
                ServerListEvent::ServerListUpdateStarted { url: url.clone() }.into(),
            )
            .await;
            // Off the actor: the fetch is a network round trip with a
            // multi-second deadline, and the list stays editable while it runs.
            tokio::spawn(run_server_list_update(
                Arc::clone(ctx.store),
                Arc::clone(fetcher),
                url,
                ctx.max_server_met_bytes,
                ctx.diagnostics.clone(),
                ctx.evt_tx.clone(),
                Arc::clone(ctx.in_flight),
            ));
        }
    }
}

/// Report a single-row mutation: the edge when the row was there, an
/// `UnknownServer` rejection when it was not, a store rejection when the write
/// itself failed. The three outcomes of every `Result<bool, _>` mutator on
/// [`ServerListStore`](crate::ServerListStore).
async fn report_row_mutation(
    evt_tx: &mpsc::Sender<CoreEvent>,
    outcome: Result<bool, CoreError>,
    event: ServerListEvent,
) {
    match outcome {
        Ok(true) => send_event(evt_tx, event.into()).await,
        Ok(false) => {
            send_event(
                evt_tx,
                CoreEvent::CommandRejected {
                    reason: CoreCommandRejectReason::UnknownServer,
                },
            )
            .await;
        }
        Err(error) => reject_server_list_store(evt_tx, &error).await,
    }
}

/// A storage fault, not a caller mistake: the store's own reason is traced,
/// and the caller is told the write did not happen.
async fn reject_server_list_store(evt_tx: &mpsc::Sender<CoreEvent>, error: &CoreError) {
    tracing::warn!(%error, "managed server list store refused a write");
    send_event(
        evt_tx,
        CoreEvent::CommandRejected {
            reason: CoreCommandRejectReason::ServerListStoreFailed,
        },
    )
    .await;
}

/// The off-actor half of an on-demand server-list update (ADR-0080): run it,
/// release the one-at-a-time guard, report the outcome.
async fn run_server_list_update(
    store: SharedServerListStore,
    fetcher: Arc<dyn ServerListFetcher>,
    url: String,
    max_server_met_bytes: usize,
    diagnostics: crate::diagnostics::DiagnosticsState,
    evt_tx: mpsc::Sender<CoreEvent>,
    in_flight: Arc<std::sync::atomic::AtomicBool>,
) {
    let outcome = acquire_and_install(&store, &fetcher, &url, max_server_met_bytes, &diagnostics)
        .await
        .map_or_else(
            |error| {
                tracing::warn!(%error, %url, "the server list update failed");
                ServerListEvent::ServerListUpdateFailed {
                    reason: error.failure(),
                }
            },
            |update| ServerListEvent::ServerListUpdated {
                added: update.added,
                updated: update.updated,
                total: update.total,
            },
        );
    in_flight.store(false, Ordering::SeqCst);
    send_event(&evt_tx, outcome.into()).await;
}

/// Read the installed list, fetch and merge, install and republish — two
/// store transactions, one before and one after the fetch, **never one across
/// it**.
///
/// A CRUD command that lands in the gap is neither blocked nor lost: the
/// install is a fold keyed by endpoint, so a server added meanwhile stays, and
/// one the download also carries simply folds.
async fn acquire_and_install(
    store: &SharedServerListStore,
    fetcher: &Arc<dyn ServerListFetcher>,
    url: &str,
    max_server_met_bytes: usize,
    diagnostics: &crate::diagnostics::DiagnosticsState,
) -> Result<crate::server_list::ServerListUpdate, ServerListUpdateError> {
    let installed = store.servers()?;
    let plan = acquire_server_met(
        &ErasedFetcher(Arc::clone(fetcher)),
        url,
        max_server_met_bytes,
        &installed,
    )
    .await?;
    let update = mutate_and_publish(store, diagnostics, |store| {
        install_server_met_plan(store, &plan)
    })?;
    Ok(update)
}
