//! The serve command arms: what joins or leaves the share set, and the start
//! and stop of the one serve activity a session runs — the listener, its
//! announce, and the uploader-side reask surface it takes over. The activity
//! borrows both one-per-core resources and gives them back when it ends
//! Which is what makes a second start a first start.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch};
use tracing::Instrument;

use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::address_learning::SocketRole;
use crate::directory_scan::{FsDirectorySource, file_gone};
use crate::registry::SharedFileRegistry;
use crate::service::activity::ServeActivity;
use crate::service::{
    CoreEvent, ServeCommand, ServeEvent, ServeStartFailure, ServeStopReason, ShareRejectReason,
};

use super::{CoreActor, send_event};

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Enact one serve command against the live activity ledger.
    pub(super) async fn on_serve_command(&mut self, command: ServeCommand) {
        match command {
            ServeCommand::UnshareFile { file_hash } => {
                // An unshare of a file still on disk is the operator's choice
                // and leaves no trace; one whose file is already gone is a
                // vanish the command noticed, so the hash joins the Had Set.
                let registry = &self.wiring.registry;
                let left = match registry.get(file_hash) {
                    Ok(Some(row)) if file_gone(&FsDirectorySource, &row.path) => {
                        registry.gone(file_hash, &row.path)
                    }
                    Ok(_) => registry.unshare(file_hash),
                    Err(error) => Err(error),
                };
                let reason = match left {
                    Ok(true) => return self.row_left(file_hash, left).await,
                    Ok(false) => ShareRejectReason::NotShared,
                    Err(_) => ShareRejectReason::RegistryError,
                };
                send_event(&self.evt_tx, ServeEvent::ShareRejected { reason }.into()).await;
            }
            ServeCommand::StartServing { listen_addr } => {
                self.start_serving(listen_addr).await;
            }
            ServeCommand::StopServing => {
                self.stop_serve().await;
                // A stop with nothing serving is already what it asks for:
                // whatever ended the last activity cleared its installs.
                // Either way the identity stays — a node that stopped serving
                // is still itself, and its Kad and CAPS answers need the user
                // hash. It has only stopped listening, and let the serve's
                // server session go with the activity.
            }
        }
    }

    /// Bind the eD2k listener at attach on the Core Settings' TCP port
    /// (ADR-0095, "Connecting is the operator's act"; aMule listens from
    /// `OnInit`, `amule.cpp:917`, `:1631`), so a Kad-only run accepts peers and
    /// the mapping starts before any login. A core not built to restore at
    /// attach binds on its first connect or `StartServing` instead. A failed bind is
    /// reported as `ServingFailed`, and the operator's connect tries again.
    pub(super) async fn listen_at_attach(&mut self) {
        if !self.wiring.restore_at_attach {
            return;
        }
        let listen_addr = self.settings_listen_addr();
        self.start_serving(listen_addr).await;
    }

    /// Where the listener binds when the Core Settings name it
    /// ([`listen_tcp_port`](crate::server_session::listen_tcp_port)): their
    /// TCP port, or, when they hold `0`, the port this process's listener
    /// first bound, so one that stopped and starts again rebinds the port it
    /// had.
    pub(super) fn settings_listen_addr(&self) -> std::net::SocketAddrV4 {
        let port = crate::server_session::listen_tcp_port(
            self.wiring.settings.credentials.tcp_port(),
            &self.own_identity,
        );
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port)
    }

    /// Start the serve activity: bind the listener on `listen_addr` and
    /// announce the bind. It dials no server (ADR-0095). Its hellos present
    /// the Core Settings' credentials.
    /// Idempotent while one runs — the answer is the bind fact the first start
    /// earned.
    pub(super) async fn start_serving(&mut self, listen_addr: std::net::SocketAddrV4) {
        if let Some(serve) = self.activities.serving() {
            // Idempotent, and it says so: the command
            // asked for serving on this identity, serving is up, and
            // the answer is the same bind fact the first one earned.
            // A silent no-op here would make a front end's retry —
            // after a login failure the serve survived, say —
            // indistinguishable from a core that stopped listening.
            let listen_addr = serve.bound();
            send_event(
                &self.evt_tx,
                ServeEvent::ServingStarted { listen_addr }.into(),
            )
            .await;
            return;
        }
        let Some(mut serve_runtime) = self.wiring.serve_runtime.take() else {
            // One serve adapter per core, and an activity that ends
            // hands it back — so the only way to be here
            // is a serve task that died abnormally with it. Said out
            // loud rather than returned in silence.
            send_event(
                &self.evt_tx,
                ServeEvent::ServingFailed {
                    reason: ServeStartFailure::Adapter,
                }
                .into(),
            )
            .await;
            return;
        };
        // The bind happens *here*, on the actor, not inside the task:
        // it is a syscall, not a round trip, and a bind that
        // fails must leave the adapter where it was, or the retry the
        // failure invites could only ever be answered with silence.
        let bound = match serve_runtime.start(self.identity(), listen_addr).await {
            Ok(bound) => bound,
            Err(error) => {
                let reason = match error {
                    crate::CoreError::ListenerBind(kind) => ServeStartFailure::Bind(kind),
                    // Only a non-production adapter reaches here; the
                    // runtime one fails a start in exactly one way.
                    other => {
                        tracing::warn!(error = %other, "serve adapter refused to start");
                        ServeStartFailure::Adapter
                    }
                };
                self.wiring.serve_runtime = Some(serve_runtime);
                send_event(&self.evt_tx, ServeEvent::ServingFailed { reason }.into()).await;
                return;
            }
        };
        let (stop_tx, serve_stop_rx) = watch::channel(false);
        let (share_changed_tx, share_changed_rx) = mpsc::channel(8);
        // Same-socket serve: install the sink so each
        // dialed download connection's serve half reaches this
        // serve task's queue; cleared on StopServing.
        let (dialed_serve_tx, dialed_serve_rx) = mpsc::channel(32);
        let dialed_sink = self.wiring.dialed_serve_sink.install(dialed_serve_tx);
        // The one roster the builder made and every adapter adopted
        // — inbound triage's helper-bias read
        // included — never a copy an adapter hands back.
        let peer_roster = self.wiring.peer_roster.clone();
        let task = crate::serve::ServeTask {
            registry: Arc::clone(&self.wiring.registry),
            serve_runtime,
            queue: crate::upload_queue::UploadSlotQueue::new(
                self.wiring.config.upload_slot_budget,
                self.wiring.config.max_upload_queue_len,
            ),
            evt_tx: self.evt_tx.clone(),
            stop_rx: serve_stop_rx,
            share_changed_rx,
            dialed_serve_rx: Some(dialed_serve_rx),
            credit: Arc::clone(&self.wiring.credit),
            bans: self.wiring.kad_cells.adapters.ban_store.clone(),
            rerank_interval: self.wiring.config.queue_rerank_interval,
            // The live client-UDP front (ADR-0057): the demuxed
            // `0x90` reask stream feeds the serve reply matrix, and
            // each `SendClientUdp` reply rides the shared socket
            // back out. `take()` hands the single reask inbox to this
            // serve task, which hands it back in its outcome — so a later re-serve answers `0x90`
            // too. Both are `None` when the client-UDP socket failed to bind.
            reask_rx: self.client_udp_reask_rx.take(),
            client_udp_tx: self.client_udp_reply_tx.clone(),
            purge_interval: self.wiring.config.upload_purge_interval,
            purge_after: self.wiring.config.upload_reask_purge_after,
            // The same shared counter state the download
            // runners and `Core::diagnostics_snapshot` hold
            // (ADR-0077), so upload rows and the session up
            // total answer the sync accessor.
            diagnostics: self.diagnostics.clone(),
            // The session's self-facts: the Low-ID abuse guard
            // reads our own id and server from the one cell the login
            // writes them to.
            own_identity: Some(self.own_identity.clone()),
            peer_roster,
            withheld: self.registry_check.withheld.clone(),
            read_failed_tx: Some(self.registry_check.inputs()),
            served: self.wiring.served_downloads.clone(),
        };
        let serve_span = tracing::info_span!("serve", %bound);
        // The bump rides *outside* the activity's own future: it must be the last thing that
        // happens, after the adapter is released, so the arm it wakes finds a handle that
        // is already resolving rather than a task still tearing down.
        let ended = Arc::clone(&self.serve_ended_tx);
        self.activity_generation += 1;
        let generation = self.activity_generation;
        // The bind fact is the activity's first word (ADR-0031):
        // the task's own first act announces the share set, and on a
        // multi-thread runtime a spawned task can send before the
        // actor's next line runs — so the task waits for the actor to
        // have said `ServingStarted` before it runs at all. A dropped
        // sender (the actor is gone) releases it rather than hangs it.
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = started_rx.await;
            let outcome = task.run().instrument(serve_span).await;
            ended.send_replace(generation);
            outcome
        });
        // The exact handle a download's live Callback
        // Capability reads, bound the moment the ledger names this
        // activity — never a separate flag that a start or stop path
        // could forget to flip.
        self.download_runtime
            .shared
            .reach
            .listener()
            .bind(&handle, bound.port());
        self.activities.serve_started(ServeActivity::new(
            generation,
            stop_tx,
            share_changed_tx,
            handle,
            bound,
            dialed_sink,
        ));
        // The bind fact, at the bind — and only once the
        // activity is in the ledger, so a consumer that answers
        // `ServingStarted` with another command finds it there.
        send_event(
            &self.evt_tx,
            ServeEvent::ServingStarted { listen_addr: bound }.into(),
        )
        .await;
        let _ = started_tx.send(());
        // The eD2k listener's **Half-Bound Pair** fact,
        // read back from **Address Learning** right here: the serve
        // runtime's `record_bind` (inside `serve_runtime.start` above)
        // already settled it, exactly as the client-UDP bind settles
        // its own (`service/actor.rs`) — so this is a read of the one
        // fact the bind wrote, not a second derivation of it. A
        // listener that comes up without IPv4 forfeits every High ID
        // (ADR-0086), which is worth more than a diagnostics row an
        // operator has to go looking for.
        if let Some(half_bound) = self.own_identity.addresses().half_bound(SocketRole::Tcp) {
            tracing::warn!(%half_bound, "eD2k listener Family Pair came up half");
            send_event(
                &self.evt_tx,
                CoreEvent::SocketBoundWithoutFamily { half_bound },
            )
            .await;
        }
        // The eD2k listener is the mapping that earns a High-ID
        // (ADR-0086), and it only exists from here — but the **Desired
        // Mapping Set** is told nothing about it *here*: the serve
        // runtime's `record_bind` above is itself the trigger. A notice sent from this site would
        // be a second path to the same fact, and the one that can race it.
        //
        // Honest Capability Advertisement (ADR-0057): now that the
        // reask uploader answers `0x90` on the bound port, light
        // the `CT_EMULE_UDPPORTS` advert so peers' hellos learn the
        // real reask endpoint. Kad half 0 (Core's Kad node, when
        // enabled, binds its own socket). No socket ⇒ no advert.
        //
        // *Which* port goes on the wire is the Advertised Endpoints
        // chooser's call, made at every hello against Address
        // Learning (ADR-0084): this publishes only the
        // bound port that serving is on.
        if let Some(bound) = self.client_udp_port() {
            self.wiring.udp_ports_advert.set_serving(bound);
        }
    }

    /// Stop the serve activity (ADR-0093): retire it, which signals it. A
    /// no-op when nothing serves.
    pub(super) async fn stop_serve(&mut self) {
        if let Some(serve) = self.activities.take_serve() {
            self.finish_serve(serve).await;
        }
    }

    /// The serve task of activity `generation` ended on its own — the
    /// listener closed or the task failed. A death is a stop
    /// (ADR-0093): the same retire, only the reason differs. A bump for an
    /// activity the `StopServing` arm already retired names a generation the
    /// ledger no longer holds and retires nothing.
    pub(super) async fn on_serve_ended(&mut self, generation: u64) {
        if let Some(serve) = self.activities.take_ended_serve(generation) {
            self.finish_serve(serve).await;
        }
    }

    /// Wind one ended-or-ending serve activity down: take its adapter back,
    /// undo every install its start made, and say so.
    ///
    /// Awaiting the task's end is what makes `ServingStopped` mean
    /// *startable again* rather than *stopping*; the activity's own
    /// [`end`](ServeActivity::end) bounds the wait, whether the task has
    /// already finished (a death) or is being told to stop (the `StopServing`
    /// and quit roads).
    async fn finish_serve(&mut self, serve: ServeActivity<L>) {
        // Withdraw the live Callback Capability's listener
        // conjunct the instant the ledger gives this activity up — on both
        // roads, the requested stop and the reclaim of one that died on its
        // own.
        self.download_runtime.shared.reach.listener().clear();
        let reason = match serve.end().await {
            Ok(outcome) => {
                // Back where a failed start already puts it, so the next
                // `StartServing` is a first start in every respect.
                self.wiring.serve_runtime = Some(outcome.serve_runtime);
                // And the one-shot reask inbox with it (ADR-0057): the next
                // activity answers `0x90` rather than running reask-less.
                self.client_udp_reask_rx = outcome.reask_rx;
                outcome.reason
            }
            Err(error) => {
                // The task took the adapter down with it. Named rather than
                // logged alone: it is the one end from which serving does not
                // recover, and a front end that keeps retrying deserves to
                // know which kind of silence it is hearing.
                tracing::error!(%error, "the serve task ended abnormally; the adapter is lost");
                ServeStopReason::TaskFailed
            }
        };
        // The listener's bind leaves Address Learning with the listener
        // (ADR-0093), so its Desired Mapping Set row departs and the lease is
        // released (ADR-0086) — on every road, the lost-adapter one too.
        self.own_identity
            .addresses()
            .forget_bind(crate::address_learning::SocketRole::Tcp);
        // Stop advertising a reask endpoint we no longer answer (Honest
        // Capability Advertisement).
        self.wiring.udp_ports_advert.clear();
        // Every row this activity's slot holders left open closes with it
        // `close_upload` only fires on `UploadSlotReleased`,
        // which the connection writers this activity fed never got the
        // chance to emit — they end with the task, silently, from the
        // snapshot's point of view.
        self.diagnostics.close_all_uploads(reason);
        send_event(&self.evt_tx, ServeEvent::ServingStopped { reason }.into()).await;
    }
}
