//! The ADR-0058 responder's dial-back: the node already answered the
//! requester; the pump brokers the dial-back and, on a `Dial` verdict,
//! connects back to the requester's TCP port and delivers the ack.

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{Ipv4Endpoint, UserHash};

use crate::adapters::peer_transfer::enact_tcp_dial_back;
use crate::reachability::{
    DialBackGuards, DialBackRefusal, DialBackRegistry, DialBackRequest, DialBackVerdict,
    FwCheckAck, OwnListenEndpoint, broker_dial_back,
};

/// What the pump's dial-backs are brokered and dialed with.
pub(crate) struct DialBack {
    /// The dial-backs in flight: per-endpoint dedupe and the concurrent budget.
    pub(crate) registry: DialBackRegistry,
    /// The identity rmule presents when it connects back.
    pub(crate) ctx: PeerHandshakeContext,
    /// Our obfuscation policy, read per request.
    pub(crate) crypt_policy: Option<rmule_net::peer::ObfuscationPolicy>,
    /// Where a requester our own policy turned away is counted.
    pub(crate) diagnostics: crate::diagnostics::DiagnosticsState,
    /// The self-facts the self-connect guard and the hello read.
    pub(crate) own: crate::own_identity::SharedOwnIdentity,
    /// Our advertised eD2k TCP port.
    pub(crate) own_tcp_port: u16,
    /// The hello every dial of this pump sends.
    pub(crate) hello: crate::adapters::HelloAdverts,
}

impl DialBack {
    /// A requester asked this node to dial it back.
    pub(super) fn requested(
        &self,
        requester: Ipv4Endpoint,
        connect_options: Option<u8>,
        user_hash: Option<UserHash>,
    ) {
        let Self {
            registry: dial_back_registry,
            ctx: dial_back_ctx,
            crypt_policy: dial_back_crypt_policy,
            diagnostics: dial_back_diagnostics,
            own,
            own_tcp_port,
            hello,
        } = self;
        let (dial_back_crypt_policy, own_tcp_port) = (*dial_back_crypt_policy, *own_tcp_port);
        // ADR-0058 responder enactment: the sans-I/O node
        // already answered `0x58`; now broker the dial-back and, on
        // a `Dial` verdict, connect back to the requester's TCP port
        // over the reusable peer-TCP dial surface, complete the
        // hello, and deliver the version-gated ack. A guarded or
        // failed dial is silent, exactly like aMule's `RequestTCP`.
        let request = DialBackRequest {
            requester,
            connect_options,
            user_hash,
        };
        let engaged = dial_back_registry.engaged();
        let guards = DialBackGuards {
            own: OwnListenEndpoint::current(own, own_tcp_port),
            busy: &engaged,
            crypt: dial_back_crypt_policy,
        };
        match broker_dial_back(&request, &guards) {
            DialBackVerdict::Dial {
                requester,
                requester_crypt,
                ack: FwCheckAck::TcpLink,
            } => {
                // v7+ `0x53`: the connect-back ack rides the dialed
                // TCP link (`OP_KAD_FWTCPCHECK_ACK`). Fire-and-forget
                // — the responder already answered `0x58`, so the
                // dial runs off the pump's critical path. The claimed
                // ticket bounds the fan-out (per-endpoint dedupe +
                // the concurrent budget) and retires when the
                // enactment task ends, however it ends.
                if let Some(ticket) = dial_back_registry.begin(requester) {
                    // The live session's id and server, as
                    // every hello names them.
                    let ctx = crate::server_session::live_peer_handshake_context(
                        &dial_back_ctx.identity,
                        own,
                    );
                    let hello = hello.clone();
                    tokio::spawn(async move {
                        enact_tcp_dial_back(requester, requester_crypt, &hello, ctx).await;
                        drop(ticket);
                    });
                } else {
                    tracing::debug!(
                        ?requester,
                        "kad firewall dial-back refused: enactment budget spent"
                    );
                }
            }
            DialBackVerdict::Dial {
                requester,
                ack: FwCheckAck::Udp,
                ..
            } => {
                // Legacy `0x50` (v<7): the ack is a `0x59` to the
                // requester's Kad UDP port, not a TCP-link packet.
                // `[pending]` a Kad-UDP `0x59` emit command — the
                // aMule 2.3.3 capture path is v7+/TCP-link.
                tracing::debug!(
                    ?requester,
                    "kad firewall dial-back: legacy 0x59 UDP ack leg deferred (v<7)"
                );
            }
            DialBackVerdict::Refuse { reason } => {
                // aMule's `RequestTCP` guarded early return: no dial,
                // no reply.
                if reason == DialBackRefusal::CryptIncompatible {
                    // Our own policy turned a requester away, not the
                    // network: counted apart so an operator can see
                    // the cost of the obfuscation setting they chose
                    // (the `0x95` route's precedent).
                    dial_back_diagnostics.record_kad_dial_back_crypt_incompatible();
                }
                tracing::debug!(
                    requester = ?request.requester,
                    connect_options = ?request.connect_options,
                    names_user_hash = request.user_hash.is_some(),
                    ?reason,
                    "kad firewall dial-back silently refused (ADR-0058 guard)"
                );
            }
        }
    }
}
