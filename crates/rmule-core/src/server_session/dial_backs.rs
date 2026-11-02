//! The **Server Callback Dial-Backs** a session owes (ADR-0061): where an
//! `OP_CALLBACKREQUESTED` (`0x35`) or `0x26` the server relays is answered.
//!
//! The decision is [`consume_server_callback`]'s, pure. This is its
//! enactment: our crypt policy and whether the node serves, read at the
//! request; the in-flight bound, one dial per endpoint and at most
//! [`DialBackRegistry`]'s budget at once, so a server cannot fan one session
//! out into unbounded outbound dials; and the dial itself, through the serve
//! pipeline's admit seam, so the requester meets the IP filter, the ban store
//! and the inbound triage exactly as if it had dialed us. Fire-and-forget, as
//! aMule's refused `TryToConnect` is silent: the requester's own wait is what
//! notices.

use std::sync::{Arc, OnceLock};

use rmule_primitives::{ClientId, Informant, PeerEndpoint};

use crate::adapters::SharedTunnelAdmit;
use crate::firewalled::server_callback::{
    ServerCallbackConsume, ServerCallbackContext, ServerCallbackRefusal, ServerCallbackVerdict,
    consume_server_callback,
};
use crate::obfuscation_policy::SharedObfuscationPolicy;
use crate::reachability::{DialBackRegistry, OwnListenEndpoint};

/// One core's answer to every server-relayed callback, shared by each session
/// it logs in: every clone shares the dials in flight.
#[derive(Clone, Default)]
pub(crate) struct ServerCallbackDialBacks {
    /// The serve pipeline's admit seam, installed once the core is woven.
    /// Unset reads as a node that does not serve.
    admit: Arc<OnceLock<SharedTunnelAdmit>>,
    /// **Our own** obfuscation policy, the cell every hello and the login
    /// read.
    obfuscation: SharedObfuscationPolicy,
    /// The dials in flight, by the endpoint each goes to.
    in_flight: DialBackRegistry<PeerEndpoint>,
}

impl ServerCallbackDialBacks {
    /// Dial-backs keyed under `obfuscation`, with no admit seam yet.
    pub(crate) fn new(obfuscation: SharedObfuscationPolicy) -> Self {
        Self {
            obfuscation,
            ..Self::default()
        }
    }

    /// Install where a dial-back enters the serve pipeline. Idempotent: one
    /// seam per core.
    pub(crate) fn install_admit(&self, admit: SharedTunnelAdmit) {
        let _ = self.admit.set(admit);
    }

    /// Answer one server-relayed callback for a session holding `session_id`
    /// whose server is `server`, with `own` our listen endpoint now: decide,
    /// and on a dial claim the endpoint and dial in the background. Returns
    /// what was decided, the enactment's own [`Busy`] included.
    ///
    /// [`Busy`]: ServerCallbackRefusal::Busy
    pub(crate) fn answer(
        &self,
        req: &ServerCallbackConsume,
        session_id: ClientId,
        server: Informant,
        own: OwnListenEndpoint,
    ) -> ServerCallbackVerdict {
        let admit = self.admit.get().filter(|admit| admit.is_serving());
        let verdict = consume_server_callback(
            req,
            &ServerCallbackContext {
                session_id,
                server,
                own,
                serving: admit.is_some(),
                crypt: self.obfuscation.get(),
            },
        );
        let (
            ServerCallbackVerdict::DialBack {
                requester,
                obfuscate_toward,
            },
            Some(admit),
        ) = (verdict, admit)
        else {
            return verdict;
        };
        let Some(ticket) = self.in_flight.begin(requester) else {
            return ServerCallbackVerdict::Refuse {
                reason: ServerCallbackRefusal::Busy,
            };
        };
        let admit = admit.clone();
        tokio::spawn(async move {
            admit.callback_dial_back(requester, obfuscate_toward).await;
            drop(ticket);
        });
        verdict
    }
}

#[cfg(test)]
mod tests;
