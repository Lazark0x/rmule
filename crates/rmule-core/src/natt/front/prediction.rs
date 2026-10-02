//! The front's half of **Port Prediction** (ADR-0091's amendment): one
//! **Prediction Plan** per introduced peer, decided when the introduction
//! arrives, driven by the front's tick and ended with the attempt it rides.
//!
//! The policy is `rmule_peer::natt`'s and the sockets are
//! `rmule_net::ed2k::ClientUdpSocket`'s. What lives here is the join between
//! them: which peer a plan is for, which Fans it opened (so its end can close
//! them), which tasks are sending for it (so its end can stop them), and
//! which Probe Set a returning punch is checked against. The paced sends take
//! seconds, so each attempt runs on a task of its own. This loop may not
//! await them: it is the only one that feeds the demux (see `front.rs`,
//! "What this loop may never await").
//!
//! **What may start a plan**. A plan is armed only for
//! a peer this node holds a **Traversal Attempt** toward — an introduction
//! this node asked for — and only at an endpoint a coordinator *observed*.
//! An introduction on the Responder road has no attempt behind it and could
//! be driven by any stranger who knows a buddy pairing, and a claimed
//! endpoint is the requester's own word; neither may open sockets or scan
//! ports here. Plans are then capped node-wide: [`PREDICTION_PLANS_MAX`]
//! live at once, of which [`PREDICTION_FAN_PLANS_MAX`] may be Fans, and the
//! Fan sockets themselves under `rmule_net`'s `PREDICTION_SOCKET_BUDGET`. A
//! Probe fires only once the peer has punched us from the target's address,
//! so no coordinator's word alone can make this node send 256 datagrams at
//! an address. Every refusal is counted.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmule_net::ed2k::{ClientUdpSocket, PredictionFanId};
use rmule_net::natt::NattDatagramSink;
use rmule_peer::natt::{
    PREDICTION_FAN_SOCKETS, PREDICTION_PACE, PeerMapping, PortPrediction, PredictionPlan,
    PredictionRng, PredictionRole, PredictionStep, PunchTargetSource, holepunch_datagram,
    prediction_role, probe_ports, punch_burst,
};
use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::task::AbortHandle;

use super::NattFront;
use crate::address_learning::SocketRole;
use crate::diagnostics::DiagnosticsState;

/// Live plans at once, node-wide, in either role.
pub(crate) const PREDICTION_PLANS_MAX: usize = 4;

/// Live Fan-role plans at once, node-wide: one Fan plan is up to 512 open
/// sockets, and a second would double that against the same file-descriptor
/// table every accept, dial and part file draws on.
pub(crate) const PREDICTION_FAN_PLANS_MAX: usize = 1;

/// Why an introduction got no plan, or a plan's attempt did not fire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredictionRefusal {
    /// No Traversal Attempt of ours toward the peer: an introduction this
    /// node did not ask for (the Responder road) plans nothing.
    NoAttempt,
    /// The punch target is the requester's own claim, not an endpoint a
    /// coordinator observed.
    ClaimedTarget,
    /// `PREDICTION_PLANS_MAX` plans are live.
    PlanCap,
    /// A Fan plan is live already (`PREDICTION_FAN_PLANS_MAX`).
    FanCap,
    /// `rmule_net`'s socket budget had no room for a Fan.
    SocketBudget,
    /// A Fan could not bind its sockets.
    FanBind,
    /// A Probe attempt was due before the peer had punched us from the
    /// target's address; it fires when the peer does, or never.
    PeerSilent,
}

/// What the front needs to predict at all: the knob, and the client-UDP
/// socket whose Fans and Routes it drives. `None` in the wiring is the knob
/// off, and then nothing below runs.
pub(crate) struct PredictionWiring {
    /// `natt.port_prediction`.
    pub(crate) knob: PortPrediction,
    /// The one bound client-UDP socket.
    pub(crate) socket: Arc<ClientUdpSocket>,
}

/// Every live plan, by the peer it was decided for.
#[derive(Default)]
pub(super) struct Predictions {
    plans: HashMap<UserHash, ActivePlan>,
}

impl Predictions {
    fn fan_plans(&self) -> usize {
        self.plans
            .values()
            .filter(|active| active.plan.role() == PredictionRole::Fan)
            .count()
    }
}

/// One running plan.
struct ActivePlan {
    plan: PredictionPlan,
    /// The punch target the introduction named.
    target: Ipv4Endpoint,
    /// The Fans its attempts opened, shared with the tasks that open them.
    fans: Arc<Mutex<FanLedger>>,
    /// The tasks sending for it, one per attempt fired; stopped when the
    /// plan ends.
    tasks: Vec<AbortHandle>,
    /// Every port this plan's Probe Sets drew, across both attempts: a punch
    /// can come back from an attempt-1 port after attempt 2 has drawn.
    probed: HashSet<u16>,
    /// The ports on the target's address this side has punched and not yet
    /// answered: the baseline burst's and every Probe Set's. A punch from one
    /// of them is answered once (see [`NattFront::note_probe_answer`]).
    answerable: HashSet<u16>,
    /// Whether a punch has arrived from the target's address since the plan
    /// began — what a Probe attempt waits for.
    peer_heard: bool,
    /// The Probe attempt last deferred for the peer's silence, so the
    /// deferral is counted once per attempt rather than once per tick.
    deferred: Option<u8>,
    rng: PredictionRng,
}

/// The Fans one plan opened, and whether the plan has already ended. A task
/// still binding its Fan when the plan ends closes that Fan itself.
#[derive(Default)]
struct FanLedger {
    fans: Vec<PredictionFanId>,
    /// `Some(keep_routes)` once the plan ended.
    ended: Option<bool>,
}

impl<S: NattDatagramSink> NattFront<S> {
    /// A coordinator introduced `peer` at `target`, chosen by `source`:
    /// decide the role and, if there is one, start the plan. Only an
    /// endpoint a coordinator observed may start one.
    pub(super) fn plan_introduced_prediction(
        &mut self,
        peer: UserHash,
        target: Ipv4Endpoint,
        source: PunchTargetSource,
        now: Instant,
    ) {
        if self.wiring.prediction.is_none() {
            return;
        }
        if source != PunchTargetSource::Observed {
            self.refuse_prediction(PredictionRefusal::ClaimedTarget, target);
            return;
        }
        self.plan_prediction(peer, target, now);
    }

    /// A believed endpoint hint, or an observed introduction, named `target`
    /// for `peer`: decide the role and, if there is one and the caps allow,
    /// start the plan. The Fan's first attempt fires at once.
    pub(super) fn plan_prediction(&mut self, peer: UserHash, target: Ipv4Endpoint, now: Instant) {
        let Some(wiring) = &self.wiring.prediction else {
            return;
        };
        if self.predictions.plans.contains_key(&peer) {
            return;
        }
        let own = self.wiring.addresses.own_mapping(SocketRole::Udp);
        let peer_mapping =
            PeerMapping::from_ports(Some(target.port), self.attempts.advertised_udp(&peer));
        let Some(role) = prediction_role(wiring.knob, own, peer_mapping) else {
            tracing::debug!(
                ?target,
                ?own,
                ?peer_mapping,
                "no port-prediction role; the baseline burst stands alone"
            );
            return;
        };
        let refusal = if !self.attempts.contains(&peer) {
            Some(PredictionRefusal::NoAttempt)
        } else if self.predictions.plans.len() >= PREDICTION_PLANS_MAX {
            Some(PredictionRefusal::PlanCap)
        } else if role == PredictionRole::Fan
            && self.predictions.fan_plans() >= PREDICTION_FAN_PLANS_MAX
        {
            Some(PredictionRefusal::FanCap)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            self.refuse_prediction(refusal, target);
            return;
        }
        tracing::debug!(?target, ?own, ?peer_mapping, ?role, "port-prediction plan");
        self.predictions.plans.insert(
            peer,
            ActivePlan {
                plan: PredictionPlan::new(role, now),
                target,
                fans: Arc::default(),
                tasks: Vec::new(),
                probed: HashSet::new(),
                answerable: match role {
                    PredictionRole::Probe => punch_burst(target).map(|at| at.port).collect(),
                    PredictionRole::Fan => HashSet::new(),
                },
                peer_heard: false,
                deferred: None,
                rng: PredictionRng::new(os_seed()),
            },
        );
        self.drive_predictions(now);
    }

    fn refuse_prediction(&self, refusal: PredictionRefusal, target: Ipv4Endpoint) {
        self.wiring
            .diagnostics
            .record_natt_prediction_refusal(refusal);
        tracing::debug!(?refusal, ?target, "port-prediction plan refused");
    }

    /// Fire every attempt that is due and end every plan whose time is up.
    /// A Probe attempt due before the peer has punched us waits for that
    /// punch instead.
    pub(super) fn drive_predictions(&mut self, now: Instant) {
        let Some(wiring) = &self.wiring.prediction else {
            return;
        };
        let mut expired = Vec::new();
        let mut deferred = Vec::new();
        for (peer, active) in &mut self.predictions.plans {
            match active.plan.poll(now) {
                PredictionStep::Fire { attempt } => {
                    if active.plan.role() == PredictionRole::Probe && !active.peer_heard {
                        if active.deferred != Some(attempt) {
                            active.deferred = Some(attempt);
                            deferred.push(active.target);
                        }
                        continue;
                    }
                    fire(active, &wiring.socket, &self.wiring.diagnostics);
                    active.plan.on_fired();
                }
                PredictionStep::Wait(_) => {}
                PredictionStep::Expired => expired.push(*peer),
            }
        }
        for target in deferred {
            self.refuse_prediction(PredictionRefusal::PeerSilent, target);
        }
        for peer in expired {
            self.end_prediction(&peer, false);
        }
    }

    /// End `peer`'s plan: stop its tasks and close its Fans. A socket a
    /// Tunnel rides is kept: `tunnel_up` says so for a Tunnel rising now,
    /// and a path already held to the target's own endpoint says so for one
    /// that rose unattributed. A path to another port on the same address is
    /// another peer's, or an older session's, and keeps nothing.
    pub(super) fn end_prediction(&mut self, peer: &UserHash, tunnel_up: bool) {
        let Some(active) = self.predictions.plans.remove(peer) else {
            return;
        };
        for task in &active.tasks {
            task.abort();
        }
        let keep_routes = tunnel_up || self.paths.holds(active.target);
        let Some(wiring) = &self.wiring.prediction else {
            return;
        };
        let mut ledger = active.fans.lock().expect("prediction fan ledger");
        ledger.ended = Some(keep_routes);
        for fan in ledger.fans.drain(..) {
            wiring.socket.close_prediction_fan(fan, keep_routes);
        }
    }

    /// A punch arrived from `observed`. Every Probe plan aimed at that
    /// address has now heard its peer. One from a port this plan punched is
    /// a hit: it is counted, and answered **once** with an empty `0xA1` back
    /// to that port. Returns whether to answer.
    ///
    /// The answer is what makes a hit a Tunnel in either order. When our probe
    /// reached the peer's gateway before the Fan socket behind that port
    /// existed, it died there and only opened our own filter; the Fan's later
    /// `0xA1` then reaches us, and without an answer the Fan side would never
    /// learn which socket works. Bounded like the Fan's: only to a port on the
    /// peer's address we already sent to, once per port.
    pub(super) fn note_probe_answer(&mut self, observed: Ipv4Endpoint) -> bool {
        let mut hit = false;
        for active in self.predictions.plans.values_mut() {
            if active.plan.role() != PredictionRole::Probe || active.target.ip != observed.ip {
                continue;
            }
            active.peer_heard = true;
            hit |= active.answerable.remove(&observed.port);
        }
        if hit {
            self.wiring.diagnostics.count_natt_prediction_hit();
        }
        hit
    }

    /// The punched path at `at` closed: its Prediction Route, if any, goes.
    pub(super) fn release_prediction_route(&self, at: Ipv4Endpoint) {
        if let Some(wiring) = &self.wiring.prediction {
            wiring
                .socket
                .release_prediction_route(SocketAddrV4::new(at.ip, at.port));
        }
    }
}

/// Fire one attempt of `active`'s role on a task of its own, and keep its
/// handle so the plan's end can stop it.
fn fire(active: &mut ActivePlan, socket: &Arc<ClientUdpSocket>, diagnostics: &DiagnosticsState) {
    let target = active.target;
    let socket = Arc::clone(socket);
    let diagnostics = diagnostics.clone();
    let task = match active.plan.role() {
        PredictionRole::Fan => {
            let ledger = Arc::clone(&active.fans);
            tokio::spawn(async move {
                if socket.open_prediction_sockets() >= rmule_net::ed2k::PREDICTION_SOCKET_BUDGET {
                    diagnostics.record_natt_prediction_refusal(PredictionRefusal::SocketBudget);
                    return;
                }
                let hits = diagnostics.clone();
                let opened = socket
                    .open_prediction_fan(
                        SocketAddrV4::new(target.ip, target.port),
                        PREDICTION_FAN_SOCKETS,
                        holepunch_datagram(),
                        Arc::new(move |_| hits.count_natt_prediction_hit()),
                    )
                    .await;
                let fan = match opened {
                    Ok(fan) => fan,
                    Err(error) => {
                        diagnostics.record_natt_prediction_refusal(PredictionRefusal::FanBind);
                        tracing::debug!(%error, "a prediction fan could not bind its sockets");
                        return;
                    }
                };
                {
                    let mut ledger = ledger.lock().expect("prediction fan ledger");
                    if let Some(keep_routes) = ledger.ended {
                        socket.close_prediction_fan(fan, keep_routes);
                        return;
                    }
                    ledger.fans.push(fan);
                }
                let sent = socket
                    .prediction_fan_burst(
                        fan,
                        SocketAddrV4::new(target.ip, target.port),
                        &holepunch_datagram(),
                        PREDICTION_PACE,
                    )
                    .await;
                diagnostics.record_natt_prediction_attempt(sent as u64);
            })
        }
        PredictionRole::Probe => {
            let ports = probe_ports(&mut active.rng);
            active.probed.extend(ports.iter().copied());
            active.answerable.extend(ports.iter().copied());
            tokio::spawn(async move {
                let punch = holepunch_datagram();
                let mut sent = 0u64;
                for (index, port) in ports.into_iter().enumerate() {
                    if index > 0 {
                        tokio::time::sleep(PREDICTION_PACE).await;
                    }
                    let to = PeerEndpoint::V4(Ipv4Endpoint::new(target.ip, port));
                    if socket.send_to_peer(to, &punch).await.is_ok() {
                        sent += 1;
                    }
                }
                diagnostics.record_natt_prediction_attempt(sent);
            })
        }
    };
    active.tasks.push(task.abort_handle());
}

/// A fresh seed for one plan's Probe Sets.
fn os_seed() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("OS entropy for a probe set");
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
impl Predictions {
    /// Every port `peer`'s plan has probed, when a plan runs for it.
    pub(super) fn probe_set(&self, peer: &UserHash) -> Option<&HashSet<u16>> {
        self.plans.get(peer).map(|active| &active.probed)
    }

    /// How many plans are live.
    pub(super) fn len(&self) -> usize {
        self.plans.len()
    }
}
