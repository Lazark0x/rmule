//! The buddy this node holds (ADR-0061, the firewalled half): the adopt a
//! verified `0x5A` asks for, the dial it starts, the link a dial holds, the
//! keepalive the clock paces on that link, and every way the buddy is let go
//! — a lost link, a failed dial, an open Kad TCP verdict, a stopped node.
//!
//! Every write to the slot that changes *which* buddy is held happens here;
//! what arrives on the held link is the inlets' (`super::inlets`).

use std::sync::Arc;
use std::time::Instant;

use rmule_net::peer::ObfuscationPolicy;
use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent, SideCommand, SideEvent};
use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use super::dialer::{BuddyLink, Dialed, Dialer};
use super::{AdoptVerdict, BUDDY_DIAL_TIMEOUT, DialOutcome, FirewalledFront, runtime_now};
use crate::CoreEvent;
use crate::firewalled::link::RecruitedBuddy;
use crate::firewalled::recruit::{AdoptOutcome, FindBuddyRes};
use crate::server_session::HelloSource;
use crate::service::BuddyDialFailure;

impl<D: Dialer> FirewalledFront<D> {
    /// Seat a `0x5A` the Kad pump's walk drew, answer the pump, and dial
    /// what was seated.
    ///
    /// Our side of the buddy's crypt rule is the obfuscation policy as it
    /// stands now — the same read the dial's options take. A buddy refused on
    /// that rule is a dial that never happens, counted beside the other
    /// buddy-dial refusals so an operator can see their policy turning
    /// buddies away.
    pub(super) async fn adopt(
        &mut self,
        answer: &FindBuddyRes,
        buddy: RecruitedBuddy,
        verdict: &mpsc::WeakSender<AdoptVerdict>,
        now: Instant,
    ) {
        let ours = ObfuscationPolicy::stance_of(self.wiring.hello.obfuscation.get());
        let outcome = self.slot.adopt_buddy(answer, buddy, ours);
        if outcome == AdoptOutcome::CryptIncompatible {
            self.wiring
                .diagnostics
                .record_buddy_dial_crypt_incompatible();
        }
        // `try_send`: the pump never waits on this front, and this front must
        // not wait on a pump busy elsewhere.
        if let Some(pump) = verdict.upgrade() {
            let answered = pump.try_send(AdoptVerdict {
                buddy,
                outcome,
                snapshot: self.slot.snapshot(),
            });
            if answered.is_err() {
                tracing::debug!("buddy verdict not delivered: the Kad pump's inbox is full");
            }
        }
        if outcome != AdoptOutcome::Adopted {
            return;
        }
        // Read at use: a buddy adopted while Self Reach already reads
        // Kad-open is let go rather than dialed — the generation that
        // announced the open verdict may have been served before this
        // command.
        if self.wiring.reach.kad_tcp_open() {
            self.release_buddy(now).await;
        } else {
            self.dial_buddy(now);
        }
    }

    /// Dial the buddy the slot holds and, once it identifies, hold the link.
    /// aMule dials its buddy on the `0x5A` (`ClientList.cpp#L877`); the dial
    /// runs on its own task so a slow connect never stalls the consumes.
    pub(super) fn dial_buddy(&mut self, now: Instant) {
        let (Some(buddy), Some(ctx)) =
            (self.slot.buddy(), self.hello.as_ref().map(HelloSource::now))
        else {
            return;
        };
        if self.link.is_some() {
            // One buddy, one link. A second adopt while a link is held would
            // open a socket the slot could never hold.
            return;
        }
        if self.wiring.kad_presence.running_as().is_none() {
            // The buddy mechanism is Kad-scoped (ADR-0061): with no node
            // running, a relay could never reach us. Let the buddy go now
            // rather than dial a link the Kad Presence release (`select!`ed
            // beside this command) could only tear down.
            self.slot.release(now);
            return;
        }
        if !self.slot.begin_dial(buddy) {
            // A second adopt (a re-adopt, a duplicate `0x5A`) while the first
            // dial to this buddy is in flight: that dial will hold the link,
            // and a second would only race it.
            self.wiring.diagnostics.record_buddy_dial_refused();
            tracing::debug!(?buddy.tcp, "buddy dial refused: one already in flight");
            return;
        }
        let peer = PeerEndpoint::V4(buddy.tcp);
        let dialed = self.dialed_tx.clone();
        let dialer = Arc::clone(&self.dialer);
        // The one hello every outbound connection sends: our
        // ports, Kad version, IPv6, crypt policy and SUI, read now. Our crypt
        // meets the stance the buddy's `0x5A` stated, keyed on the hash it
        // carried (aMule `RequestBuddy` → `SetConnectOptions`, `ClientList.cpp:1141-1144`):
        // obfuscated when both support and one
        // asks, plaintext otherwise. A pair that cannot meet never reaches
        // here — the slot refused it unseated — and a `Required` node
        // recruits no buddy at all.
        let options = rmule_net::peer::ConnectOptions {
            connect_timeout: BUDDY_DIAL_TIMEOUT,
            // No buddy tags, stated rather than left to the read:
            // this hello is what makes the link, and aMule and emule-qt name a
            // buddy only once its handshake completes (`m_pBuddy` linked at
            // `KS_CONNECTED_BUDDY`, aMule `ClientList.cpp:807-816`, emule-qt
            // `ClientList.cpp:567-571`). One buddy, one link, so no other
            // buddy can be held while this one is dialed.
            serving_buddy: None,
            ..self.wiring.hello.connect_options(buddy.peer_crypt())
        };
        tokio::spawn(async move {
            let outcome = match dialer.dial(peer, ctx, options).await {
                Ok(Dialed {
                    link,
                    user_hash,
                    claimed_ipv6,
                }) if user_hash == buddy.hash => DialOutcome::Held {
                    link,
                    claimed_ipv6,
                    buddy,
                },
                Ok(Dialed { link, .. }) => {
                    // The node that answered is not the one the `0x5A` named.
                    // aMule keys its buddy by hash, so a mismatched link could
                    // never carry a relay the `0x99` check would accept.
                    link.shutdown().await;
                    tracing::debug!(?peer, "buddy dial reached a stranger; link dropped");
                    DialOutcome::Failed {
                        buddy,
                        cause: BuddyDialFailure::Stranger,
                    }
                }
                Err(cause) => DialOutcome::Failed { buddy, cause },
            };
            let _ = dialed.send(outcome).await;
        });
    }

    /// A buddy dial finished.
    pub(super) async fn on_dialed(&mut self, outcome: DialOutcome<D::Link>, now: Instant) {
        match outcome {
            DialOutcome::Held {
                link,
                claimed_ipv6,
                buddy,
            } => {
                let remote = link.remote();
                if !self
                    .slot
                    .hold_link(buddy, remote, link.commands(), claimed_ipv6, now)
                {
                    // Released or replaced while the dial was in flight, or a
                    // link to it is already held: a link the
                    // slot does not hold would only keep a socket open.
                    link.shutdown().await;
                    tracing::debug!(
                        ?remote,
                        "buddy dial landed for a buddy let go or already linked"
                    );
                    return;
                }
                self.link = Some(link);
                self.wiring.diagnostics.record_buddy_link(true);
                tracing::info!(?remote, "buddy link held (ADR-0061 firewalled node)");
            }
            DialOutcome::Failed { buddy, cause } => {
                self.wiring.diagnostics.record_buddy_dial_failed();
                if let Some(events) = self
                    .wiring
                    .events
                    .as_ref()
                    .and_then(mpsc::WeakSender::upgrade)
                {
                    let failed = CoreEvent::BuddyDialFailed {
                        buddy: buddy.tcp,
                        cause,
                    };
                    let _ = events.send(failed).await;
                }
                // The buddy we dialed is one we cannot reach: free it and arm
                // an instant recruit, exactly as a lost link does — unless it
                // was let go (and perhaps replaced) while the dial was in
                // flight, when the slot is no longer this dial's to free.
                if !self.slot.on_dial_failed(buddy, now) {
                    tracing::debug!(?buddy.tcp, "buddy dial failed after its buddy was let go");
                }
            }
        }
    }

    /// One event from the held buddy link.
    pub(super) async fn on_link_event(&mut self, event: Option<PeerEvent>, now: Instant) {
        let Some(event) = event else {
            return self.on_link_lost(now).await;
        };
        match event {
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => {
                self.on_link_lost(now).await
            }
            PeerEvent::Side(SideEvent::BuddyCallbackReceived { callback }) => {
                self.on_relayed_callback(&callback);
            }
            PeerEvent::Side(SideEvent::BuddyReaskCallbackReceived { relay }) => {
                self.on_relayed_reask(relay, now).await;
            }
            // Everything else on this link is the ordinary session's — a
            // buddy that also downloads from us is served by nobody here, and
            // the session's own rules already answered or dropped it.
            _ => {}
        }
    }

    /// The held link ended, for any reason: free the slot, whose published
    /// loss lets the pump's next recruit tick walk again at once.
    pub(super) async fn on_link_lost(&mut self, now: Instant) {
        let Some(link) = self.link.take() else { return };
        let remote = link.remote();
        link.shutdown().await;
        if self.slot.on_link_closed(remote, now) {
            self.wiring.diagnostics.record_buddy_link(false);
            tracing::info!(?remote, "buddy link lost; recruitment re-armed");
        }
    }

    /// Release the buddy on purpose — we became reachable, or Kad stopped.
    pub(super) async fn release_buddy(&mut self, now: Instant) {
        let had_link = self.slot.release(now).is_some();
        if let Some(link) = self.link.take() {
            link.shutdown().await;
        }
        if had_link {
            self.wiring.diagnostics.record_buddy_link(false);
            tracing::info!("buddy released: this node no longer needs a relay");
        }
    }

    /// Kad Presence changed. With the `KadStopped` command gone, this
    /// is where a stopped node's buddy is let go — at once
    /// Not on the next tick: the buddy mechanism is Kad-scoped
    /// (ADR-0061), so a relay could never reach us, and a `0x99` would be
    /// dropped `KadDown` anyway once Kad Presence reads no node.
    pub(super) async fn on_kad_presence(&mut self) {
        if (self.link.is_some() || self.slot.buddy().is_some())
            && self.wiring.kad_presence.running_as().is_none()
        {
            self.release_buddy(runtime_now()).await;
        }
    }

    /// Self Reach moved. An open Kad TCP verdict releases the
    /// buddy we hold — an open node needs none (ADR-0061's recruit gate read
    /// the other way round), and holding one would keep a stranger's socket
    /// busy for a relay nobody will use.
    pub(super) async fn on_reach(&mut self) {
        if self.wiring.reach.kad_tcp_open() {
            self.release_buddy(runtime_now()).await;
        }
    }

    /// The front's clock: the buddy-link keepalive, and the one place the
    /// buddy level is copied into the diagnostics snapshot — the slot's state
    /// from this task's own slot, the walk and the last refusal from the Kad
    /// pump's Recruit Status.
    pub(super) async fn on_tick(&mut self, now: Instant) {
        let snapshot = self.slot.snapshot();
        let recruit = self.shared.recruit_status();
        self.wiring.diagnostics.set_buddy_state(
            snapshot.state_while(recruit.walking),
            snapshot.held_since,
            recruit.refusal,
        );
        let Some(commands) = self.slot.due_keepalive(now) else {
            return;
        };
        // `try_send`, so a driver whose inbox is momentarily full costs one
        // ping rather than the tick; the next one is one interval away.
        if commands
            .try_send(PeerCommand::Side(SideCommand::SendBuddyPing))
            .is_err()
        {
            tracing::debug!("buddy keepalive not queued; the link driver is busy or gone");
        }
    }
}
