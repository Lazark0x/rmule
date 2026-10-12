//! What arrives for the firewalled front and is answered (ADR-0061,
//! ADR-0091): the held link's relayed `0x99` and `0x9A`, and the client-UDP
//! surface's standalone `0xA0` rendezvous and `0x95` direct callback. Each is
//! settled by the slot's consume and enacted as a dial-back through the
//! Dialer seam or a punch through the NAT-T front; none of them changes which buddy
//! is held.

use std::time::Instant;

use rmule_peer::natt::RendezvousBody;
use rmule_primitives::PeerEndpoint;

use super::dialer::Dialer;
use super::{FirewalledCommand, FirewalledFront, SharedFirewalledFront};
use crate::firewalled::direct_callback::{
    DirectCallbackConsume, DirectCallbackContext, DirectCallbackRefusal, DirectCallbackVerdict,
};
use crate::firewalled::link::ReaskRelayConsume;
use crate::firewalled::relayed_callback::{CallbackConsume, CallbackDrop, CallbackVerdict};
use crate::natt::front::NattCommand;

impl<D: Dialer> FirewalledFront<D> {
    /// A standalone `0xC5 0xA0` `OP_RENDEZVOUS` from the client-UDP surface:
    /// the acting path with the UDP carrier, gated on our buddy's exact UDP
    /// endpoint.
    pub(super) fn on_standalone_rendezvous(
        &mut self,
        from: PeerEndpoint,
        body: &RendezvousBody,
        now: Instant,
    ) {
        let verdict = {
            let addresses = self.wiring.addresses.clone();
            self.slot.consume_standalone_rendezvous(
                body,
                from,
                crate::natt::front::RMULE_NATT_CLAIM.quic,
                |ip| addresses.holds_interface(ip),
                now,
            )
        };
        self.enact_acting_verdict(verdict);
    }

    /// An `OP_CALLBACK` (`0x99`) our buddy relayed.
    pub(super) fn on_relayed_callback(&self, callback: &rmule_peer::Callback) {
        let verdict = self.slot.consume_callback(
            &CallbackConsume {
                check_id: rmule_kad::KadId::from_bytes(callback.buddy_id),
                // aMule's `GetFileByID` across shared files and the download
                // queue: the mirrored predicate, read inline —
                // never a round trip through the actor, which could stall the loop.
                file_shared_or_downloading: self.wiring.file_known.contains(callback.file_hash),
                requester: callback.requester,
            },
            self.wiring.kad_presence.running_as().is_some(),
        );
        match verdict {
            CallbackVerdict::Dial {
                requester,
                swapped_spelling,
            } => {
                self.wiring.diagnostics.record_relayed_callback(true);
                if swapped_spelling {
                    self.wiring
                        .diagnostics
                        .record_relayed_callback_swapped_spelling();
                }
                // Plaintext, and it is the wire that says so: the `0x99` body is
                // `<buddyID><fileHash><reqIP><reqTCP>` and names no user hash
                // and no connect-options, so there is no key to derive and no
                // stance to honour. aMule reaches the same place from the other
                // end — its `OP_CALLBACK` arm builds a `CUpDownClient` with no
                // hash, and `Connect`'s `HasValidHash()` leg then dials in the
                // clear (`ClientTCPSocket.cpp#L1655`).
                self.dialer.dial_back(PeerEndpoint::V4(requester), None);
            }
            CallbackVerdict::Drop { reason } => {
                self.wiring.diagnostics.record_relayed_callback(false);
                if reason == CallbackDrop::NoBuddyHeld {
                    // Our own state, not a counterparty error: counted apart
                    // so a bench run can tell "nobody addressed us wrong" from
                    // "we have no buddy to address".
                    self.wiring.diagnostics.record_relayed_callback_no_buddy();
                }
                tracing::debug!(?reason, "relayed 0x99 callback dropped (ADR-0061)");
            }
        }
    }

    /// An `OP_REASKCALLBACKTCP` (`0x9A`) our buddy relayed.
    pub(super) async fn on_relayed_reask(
        &mut self,
        relay: rmule_peer::ReaskCallbackTcp,
        now: Instant,
    ) {
        let consume = {
            let addresses = self.wiring.addresses.clone();
            self.slot.consume_reask_relay(
                relay,
                crate::natt::front::RMULE_NATT_CLAIM.quic,
                |ip| addresses.holds_interface(ip),
                now,
            )
        };
        match consume {
            ReaskRelayConsume::Reask {
                requester,
                forwarded,
            } => {
                // The forwarded tail is the ping's *body*: re-framed, one
                // shape reaches `ServeState`, whether it arrived by socket or
                // by relay, with the injected requester as its source.
                let datagram = rmule_peer::peer_udp::responder::relayed_ping(&forwarded);
                let sent = match self.wiring.reask_ping.upgrade() {
                    Some(inbox) => inbox.send((requester, datagram)).await.is_ok(),
                    None => false,
                };
                if !sent {
                    tracing::debug!("relayed reask dropped: the serve inbox is gone");
                }
            }
            ReaskRelayConsume::Rendezvous(verdict) => self.enact_acting_verdict(verdict),
            ReaskRelayConsume::MalformedRendezvous => {
                self.wiring.diagnostics.record_acting_refusal(None);
                tracing::debug!("malformed embedded rendezvous on the buddy link; dropped");
            }
            ReaskRelayConsume::NoHeldLink => {}
        }
    }

    /// An `OP_DIRECTCALLBACKREQ` (`0x95`): the buddy-free route.
    pub(super) fn on_direct_callback(&mut self, req: &DirectCallbackConsume, now: Instant) {
        let verdict = self.slot.consume_direct_callback(
            req,
            &DirectCallbackContext {
                tcp: self.wiring.reach.kad_tcp(),
                kad_running: self.wiring.kad_presence.running_as().is_some(),
                crypt: self.wiring.hello.obfuscation.get(),
            },
            now,
        );
        match verdict {
            DirectCallbackVerdict::DialBack {
                requester,
                obfuscate_toward,
            } => {
                self.wiring.diagnostics.record_direct_callback(true);
                if obfuscate_toward.is_some() {
                    self.wiring.diagnostics.record_direct_callback_obfuscated();
                }
                self.dialer.dial_back(requester, obfuscate_toward);
            }
            DirectCallbackVerdict::Refuse { reason } => {
                self.wiring.diagnostics.record_direct_callback(false);
                if reason == DirectCallbackRefusal::CryptIncompatible {
                    // Our own policy turned a requester away, not the network:
                    // counted apart so an operator can see the cost of the
                    // obfuscation setting they chose.
                    self.wiring
                        .diagnostics
                        .record_direct_callback_crypt_incompatible();
                }
                tracing::debug!(?reason, "0x95 direct callback refused (ADR-0061)");
            }
        }
    }

    /// Turn one [`ActingVerdict`] into a punch, or count the refusal.
    ///
    /// [`ActingVerdict`]: crate::natt::acting::ActingVerdict
    pub(super) fn enact_acting_verdict(&self, verdict: crate::natt::acting::ActingVerdict) {
        use crate::natt::acting::ActingVerdict;
        match verdict {
            ActingVerdict::Punch {
                requester, target, ..
            } => {
                // The requester asked for this introduction, so **it** dials
                // and we accept (ADR-0091). The burst is the
                // front's to fire: it owns the send half the pinhole belongs
                // to and the path ledger the burst opens.
                let sent = self.wiring.natt.send(NattCommand::Introduced {
                    peer_hash: requester,
                    target: target.endpoint,
                    role: rmule_ed2k::HolepunchRole::Responder,
                    burst: true,
                    source: target.source,
                });
                self.wiring.diagnostics.record_acting_punch(sent);
                if !sent {
                    tracing::debug!(
                        ?target,
                        "acting punch dropped: no NAT-T front to fire the burst"
                    );
                }
            }
            ActingVerdict::Refuse(refusal) => {
                self.wiring.diagnostics.record_acting_refusal(Some(refusal));
                tracing::debug!(?refusal, "relayed rendezvous not acted on (ADR-0091)");
            }
        }
    }
}

/// Route one standalone `0xC5 0xA0` `OP_RENDEZVOUS` to the front, reporting
/// whether it took it. Family-generic: the acting path's carrier gate compares
/// the whole source endpoint against our buddy's, and an IPv6 source simply
/// never matches an IPv4 buddy — a refusal the gate already states, not a
/// dialect gap this front should invent a second answer for.
pub(crate) fn route_standalone_rendezvous(
    front: &SharedFirewalledFront,
    udp_src: PeerEndpoint,
    datagram: &[u8],
) -> bool {
    match RendezvousBody::decode_standalone(datagram) {
        Ok(body) => front.send(FirewalledCommand::StandaloneRendezvous {
            from: udp_src,
            body: Box::new(body),
        }),
        Err(error) => {
            tracing::debug!(%udp_src, %error, "malformed standalone 0xA0 rendezvous dropped");
            false
        }
    }
}

/// Route one `OP_DIRECTCALLBACKREQ` (`0x95`) to the front. `udp_src` is the
/// datagram's source — the body names no address, so the source *is* the
/// requester and the body only supplies the TCP port to dial. Family-generic
/// for exactly that reason: an IPv6 requester is dialed back where it stands.
pub(crate) fn route_direct_callback(
    front: &SharedFirewalledFront,
    udp_src: PeerEndpoint,
    datagram: &[u8],
) -> bool {
    match rmule_peer::DirectCallbackReq::decode_udp(datagram) {
        Ok(req) => front.send(FirewalledCommand::DirectCallback(DirectCallbackConsume {
            requester: udp_src.with_port(req.our_tcp_port),
            user_hash: req.our_user_hash,
            connect_options: req.connect_options,
        })),
        Err(error) => {
            tracing::trace!(%udp_src, %error, "malformed 0x95 direct callback dropped");
            false
        }
    }
}
