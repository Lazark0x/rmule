//! The **Publish Connect Options** crossing into the live Kad node over the
//! node's whole life, not only at its start: the
//! one place the pump reads each bit's owner and tells the node the byte its
//! source publishes carry as `TAG_ENCRYPTION`.
//!
//! Three owners, none of them the node:
//!
//! - the crypt ladder — `CoreConfig::peer_crypt`, the policy every other
//!   advert surface reads;
//! - the direct-UDP-callback bit —
//!   [`SharedSelfReach::accepts_direct_udp_callback`], the one owner of our
//!   own reachability (ADR-0060 "Self Reach"). It moves as the
//!   self-checks conclude and as the **Server High ID** comes and goes
//!   (aMule's `IsFirewalled()` union), which is why the byte is
//!   re-derived on every **Reach Generation** rather than stated once;
//! - the NAT-T transports — [`RMULE_NATT_CLAIM`] while the front on the bind
//!   this node rides is still running (the owner's `natt_live`, read on every
//!   compose, never a bind-time snapshot, and announced by the generation when it ends),
//!   neither otherwise. The claim, not a literal: QUIC stays dark there until
//!   a harness-proven handshake (ADR-0091).
//!
//! [`publish_connect_options`] composes them.

use rmule_peer::natt::HelloNattClaim;

use crate::adapters::kad_runtime::buddy_publish::publish_connect_options;
use crate::natt::front::RMULE_NATT_CLAIM;
use crate::reachability::SharedSelfReach;

/// The pump's single writer of the Publish Connect Options: the owners' facts
/// it holds and the byte the node was last told.
pub(super) struct ConnectOptionsFeed {
    /// Our crypt policy, `None` when obfuscation is off entirely.
    crypt: Option<rmule_net::peer::ObfuscationPolicy>,
    /// What the node holds, `None` until a command lands.
    told: Option<u8>,
}

impl ConnectOptionsFeed {
    /// A feed for a node that has been told nothing yet.
    pub(super) fn new(crypt: Option<rmule_net::peer::ObfuscationPolicy>) -> Self {
        Self { crypt, told: None }
    }

    /// State the byte before the pump starts, so no publish can leave
    /// without it — read from the owner like every later
    /// [`sync`](Self::sync), so a server High ID held at start already
    /// withdraws the direct-callback bit.
    pub(super) async fn start(
        &mut self,
        reach: &SharedSelfReach,
        handle: &rmule_net::kad::KadNetHandle,
    ) {
        let options = self.compose(reach);
        if handle
            .command(rmule_kad::KadCommand::SetPublishConnectOptions {
                options: Some(options),
            })
            .await
            .is_ok()
        {
            self.told = Some(options);
        }
    }

    /// Re-derive the byte from Self Reach and tell the node when it moved.
    ///
    /// Called on every **Reach Generation** and on the pump's recruit tick.
    /// Non-blocking for the reason `TcpVerdictFeed::sync` gives: a full inbox
    /// leaves `told` where it was, so the next call sends the byte again.
    pub(super) fn sync(&mut self, reach: &SharedSelfReach, handle: &rmule_net::kad::KadNetHandle) {
        let options = self.compose(reach);
        if self.told == Some(options) {
            return;
        }
        match handle.try_command(rmule_kad::KadCommand::SetPublishConnectOptions {
            options: Some(options),
        }) {
            Ok(true) => self.told = Some(options),
            Err(_) => {}
            Ok(false) => tracing::warn!(
                options,
                "kad command inbox full; publish connect options deferred to the next recruit tick"
            ),
        }
    }

    fn compose(&self, reach: &SharedSelfReach) -> u8 {
        let natt = if reach.natt_live() {
            RMULE_NATT_CLAIM
        } else {
            HelloNattClaim::default()
        };
        publish_connect_options(self.crypt, reach.accepts_direct_udp_callback(), natt)
    }
}

/// The connect-options byte follows the front's own liveness, on every
/// compose — not a bind-time snapshot (`ClientUdpBind`'s
/// old `natt_armed: bool`, frozen the moment a front was ever installed).
#[cfg(test)]
mod tests {
    use rmule_net::peer::ObfuscationPolicy;
    use rmule_primitives::SourceCryptOptions;
    use tokio::sync::mpsc;

    use super::ConnectOptionsFeed;
    use crate::natt::front::{NattCommand, SharedNattFront};
    use crate::reachability::SharedSelfReach;

    /// A `SharedNattFront` with an installed sender and the receiver that
    /// keeps it open — standing in for a spawned front's `run` loop without
    /// spinning one up, exactly as `SharedNattFront::is_live` reads a real
    /// one: live while the receiver survives, dead the moment it drops (the
    /// front's `run` returning is what drops it in production).
    fn armed_front() -> (SharedNattFront, mpsc::Receiver<NattCommand>) {
        let front = SharedNattFront::default();
        let (commands, receiver) = mpsc::channel(1);
        front.install(commands);
        (front, receiver)
    }

    #[test]
    fn a_front_that_ends_drops_the_utp_bit_at_the_next_sync_while_the_crypt_ladder_stays() {
        let (front, receiver) = armed_front();
        let feed = ConnectOptionsFeed::new(Some(ObfuscationPolicy::Requested));
        let reach = SharedSelfReach::new(
            crate::KadReachLevel::fixed(false),
            crate::own_identity::SharedOwnIdentity::default(),
            front,
        );

        let armed = SourceCryptOptions::from_byte(feed.compose(&reach));
        assert!(
            armed.supports_natt_utp(),
            "the front is live: the byte states uTP: {:#04x}",
            armed.as_byte()
        );
        assert!(armed.requests_crypt() && !armed.requires_crypt());

        // The front's task ending: `run` returning drops its `commands`
        // receiver, exactly what this drop stands in for.
        drop(receiver);

        let ended = SourceCryptOptions::from_byte(feed.compose(&reach));
        assert!(
            !ended.supports_natt_utp(),
            "the front ended: the next compose drops uTP: {:#04x}",
            ended.as_byte()
        );
        assert_eq!(
            (ended.requests_crypt(), ended.requires_crypt()),
            (armed.requests_crypt(), armed.requires_crypt()),
            "the crypt ladder has its own owner and is untouched by the front ending"
        );
    }
}
