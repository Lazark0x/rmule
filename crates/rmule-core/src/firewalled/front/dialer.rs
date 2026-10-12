//! The **Dialer** seam: every connection the firewalled front opens — its
//! buddy link, and the callback dial-backs it owes a requester — and what it
//! then drives on the buddy link.
//!
//! Two adapters. [`TcpDialer`] is the real one: the buddy dial is
//! `PeerConnection::connect_identified` over TCP with the crypt layer the
//! options name, and a dial-back is the serve pipeline's admit seam
//! (`SharedTunnelAdmit::spawn_callback_dial_back`), so a requester that asked
//! us to connect meets the IP filter, the ban store and the triage exactly as
//! if it had dialed us. A test scripts its own, so a front leg moves a buddy
//! link through dial, hold, relay and loss, and reads every dial-back the
//! front asked for, without a socket. The front decides everything on either
//! side of the seam — which buddy to dial, whether the identity that answered
//! is that buddy, what a link event means, whom to dial back and under which
//! key — so a scripted dial is the same front, not a mock of it.

use std::future::Future;
use std::net::Ipv6Addr;

use rmule_net::peer::{ConnectOptions, Connection as PeerConnection, PeerNetError};
use rmule_peer::{PeerCommand, PeerEvent, PeerHandshakeContext};
use rmule_primitives::{PeerEndpoint, UserHash};
use tokio::sync::mpsc;

use crate::adapters::SharedTunnelAdmit;
use crate::service::{BuddyDialFailure, DialFailure};

/// A buddy link that came up and identified.
pub(crate) struct Dialed<L> {
    /// The link, as the front drives it.
    pub(crate) link: L,
    /// The user hash the answering peer's hello proved — the front holds the
    /// link only when it is the hash the `0x5A` named.
    pub(crate) user_hash: UserHash,
    /// The `CT_MOD_IP_V6` that hello carried, already past
    /// `IsUsableTagIdentity` — the `bi6` candidate.
    pub(crate) claimed_ipv6: Option<Ipv6Addr>,
}

/// How a buddy link comes up.
pub(crate) trait Dialer: Send + Sync + 'static {
    /// The link a dial yields.
    type Link: BuddyLink;

    /// Dial `peer` with `hello` and `options` and wait for it to identify;
    /// why not, when it does not.
    fn dial(
        &self,
        peer: PeerEndpoint,
        hello: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> impl Future<Output = Result<Dialed<Self::Link>, BuddyDialFailure>> + Send;

    /// Dial `requester` back for a callback it asked for (ADR-0061 routes
    /// 2/4) — obfuscated toward `obfuscate_toward` when the verdict named a
    /// key, plaintext otherwise — and hand the stream to the serve pipeline as
    /// the dialer's side. Fire-and-forget: aMule treats a refused callback
    /// dial as silent, and the requester's own timeout is what notices.
    fn dial_back(&self, requester: PeerEndpoint, obfuscate_toward: Option<UserHash>);
}

/// What the front drives on a held buddy link.
pub(crate) trait BuddyLink: Send + 'static {
    /// The endpoint the link runs to — what a close is matched on.
    fn remote(&self) -> PeerEndpoint;

    /// A command sender into the link — the keepalive's road.
    fn commands(&self) -> mpsc::Sender<PeerCommand>;

    /// The link's next event; `None` once it has ended. Cancel-safe: the
    /// front races it against its other inlets.
    fn next_event(&mut self) -> impl Future<Output = Option<PeerEvent>> + Send;

    /// Shut the link down.
    fn shutdown(self) -> impl Future<Output = ()> + Send;
}

/// The real dials: the buddy over TCP with the crypt layer the options name,
/// a dial-back through the serve pipeline's admit seam.
pub(crate) struct TcpDialer {
    /// Where a dial-back enters the serve pipeline — the one enactment a
    /// served link's `0x99` shares.
    pub(crate) admit: SharedTunnelAdmit,
}

impl Dialer for TcpDialer {
    type Link = PeerConnection;

    async fn dial(
        &self,
        peer: PeerEndpoint,
        hello: PeerHandshakeContext,
        options: ConnectOptions,
    ) -> Result<Dialed<PeerConnection>, BuddyDialFailure> {
        match PeerConnection::connect_identified(peer, hello, options).await {
            Ok((link, identity)) => Ok(Dialed {
                user_hash: identity.user_hash(),
                claimed_ipv6: identity.peer_ipv6(),
                link,
            }),
            Err(error) => {
                tracing::debug!(?peer, %error, "buddy dial refused (ADR-0061)");
                Err(buddy_dial_failure(&error))
            }
        }
    }

    fn dial_back(&self, requester: PeerEndpoint, obfuscate_toward: Option<UserHash>) {
        self.admit
            .spawn_callback_dial_back(requester, obfuscate_toward);
    }
}

impl BuddyLink for PeerConnection {
    fn remote(&self) -> PeerEndpoint {
        self.peer_endpoint()
    }

    fn commands(&self) -> mpsc::Sender<PeerCommand> {
        self.command_sender()
    }

    // `Connection::next_event` is an `mpsc::Receiver::recv`, so it is
    // cancel-safe.
    async fn next_event(&mut self) -> Option<PeerEvent> {
        PeerConnection::next_event(self).await
    }

    async fn shutdown(self) {
        let _ = PeerConnection::shutdown(self).await;
    }
}

/// Why a buddy dial's connect returned `error`.
fn buddy_dial_failure(error: &PeerNetError) -> BuddyDialFailure {
    use rmule_net::driver::DriverError;
    let dial = |cause| BuddyDialFailure::Dial { cause };
    match error {
        PeerNetError::Connect { source } | PeerNetError::Driver(DriverError::Io(source)) => {
            dial(DialFailure::Os {
                kind: source.kind(),
                os_code: source.raw_os_error(),
            })
        }
        PeerNetError::Driver(DriverError::ConnectTimeout) => dial(DialFailure::TimedOut),
        PeerNetError::HandshakeIncomplete(_) => BuddyDialFailure::HelloIncomplete,
        PeerNetError::CryptIncompatible => BuddyDialFailure::CryptIncompatible,
        // A dial surfaces none of the listener's errors; `PeerNetError` is
        // non-exhaustive, so what remains is a driver that ended.
        _ => dial(DialFailure::DriverEnded),
    }
}
