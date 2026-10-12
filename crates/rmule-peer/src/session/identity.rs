//! The peer's identity on this connection: read off its hello into the one
//! [`PeerIdentity`] the session keeps, and kept current — every revision an
//! `OP_EMULEINFO` or `OP_CHANGE_CLIENT_IP` makes is applied to that copy and
//! reported whole, so a consumer never pieces a peer together from parts.

use std::net::Ipv6Addr;

use super::{PeerEvent, PeerSession, State};
use crate::capability::{MiscOptions1, MiscOptions2, ModMiscOptions};
use crate::hello::PeerHelloBody;
use crate::identity::PeerIdentity;
use crate::{ConnectionEvent, IdentityChange};

impl PeerSession {
    /// Role-neutral identify step shared by the inbound `OP_HELLO` and
    /// outbound `OP_HELLOANSWER` paths: project the peer's hello body to a
    /// `PeerIdentity`, enter the session, and emit `Identified`. The
    /// caller has already folded the hello into `peer_software`, on top of
    /// what an `OP_EMULEINFO` said before it — which only a dialed peer can
    /// send before its answer; the capabilities a legacy block named stand
    /// when the hello names none.
    pub(super) fn identify_peer(&mut self, body: &PeerHelloBody) {
        let mut identity =
            PeerIdentity::from_hello_body(body).with_software(self.peer_software.software());
        self.peer_hello_named_reask = identity.client_udp_reask().is_some();
        if !self.peer_hello_named_reask
            && let Some((udp_port, udp_version)) = self.peer_legacy_reask
        {
            identity.revise_reask_contact(udp_port, udp_version);
        }
        self.peer_misc_options = MiscOptions1::from_tags(&body.tags).or(self.peer_misc_options);
        self.peer_misc_options2 = MiscOptions2::from_tags(&body.tags);
        let identity = identity.with_source_exchange(self.source_exchange_support());
        self.state = State::Identified;
        self.peer_identity = Some(identity.clone());
        self.core
            .push_event(PeerEvent::Connection(ConnectionEvent::Identified {
                identity,
            }));
        self.maybe_start_secure_ident();
    }

    /// Apply one revision to an identified peer's identity and, when it
    /// changed anything, report the identity whole with `what` it changed.
    /// Before the peer has identified there is nothing to revise: its hello
    /// names it afresh.
    pub(super) fn revise_identity(
        &mut self,
        what: IdentityChange,
        apply: impl FnOnce(&mut PeerIdentity) -> bool,
    ) {
        if !matches!(self.state, State::Identified) {
            return;
        }
        let Some(identity) = self.peer_identity.as_mut() else {
            return;
        };
        if apply(identity) {
            let identity = identity.clone();
            self.core
                .push_event(PeerEvent::Connection(ConnectionEvent::IdentityRevised {
                    identity,
                    what,
                }));
        }
    }

    /// The peer's **Static Capability Claim** (`CT_MOD_MISCOPTIONS`,
    /// ADR-0087), `None` before it identified or when its hello sent none.
    pub(super) fn peer_mod_misc(&self) -> Option<ModMiscOptions> {
        self.peer_identity
            .as_ref()
            .and_then(PeerIdentity::mod_misc_options)
    }

    /// `OP_CHANGE_CLIENT_IP` (`0xAC`): the peer's Known IPv6 changed
    /// mid-session (ADR-0087). Wire-silent; the identity takes the address the
    /// peer now holds, so its owner dials it there rather than where the hello
    /// said. The address has already passed `IsUsableTagIdentity`.
    pub(super) fn on_change_client_ipv6(&mut self, address: Ipv6Addr) {
        self.revise_identity(IdentityChange::Ipv6, |identity| {
            identity.revise_peer_ipv6(address)
        });
    }
}
