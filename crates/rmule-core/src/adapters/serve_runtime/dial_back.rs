//! The serve side's dial to a waiter it promoted while no link of it was up
//! (ADR-0057): aMule's `AddUpNextClient` finding the client unconnected and
//! `TryToConnect` reaching it (`UploadQueue.cpp:206-210`).
//!
//! The dial meets what every dial meets — the IP filter and the ban list
//! before any socket (`BaseClient.cpp:1427`, `:1437`), the outbound crypt rule
//! toward the crypt stance and User Hash the waiter's hello named (ADR-0049),
//! and the Peer Links, where it is filed as a Dial in Flight so a download of
//! the peer waits on it rather than dialing a second link (ADR-0107) — and
//! nothing a download's dial is paced by: aMule's `TryToConnect(true)` skips
//! `TooManySockets` (`BaseClient.cpp:1398`), and the Connection Budget paces
//! only what downloads open (ADR-0116). Once the peer's hello is in, the link
//! is driven as a served Peer Link the serve side holds from the dial, and its
//! serve connection goes to the serve task with the hello, which grants on it.

use rmule_net::peer::{Connection as PeerConnection, ObfuscationPolicy, PeerNetError};
use rmule_peer::PeerIdentity;
use rmule_primitives::{PeerCrypt, PeerEndpoint};
use tokio::sync::mpsc;

use super::ServeConnection;
use crate::adapters::hello_wait::{Opening, await_hello};
use crate::adapters::kad_runtime::broker_peer_kad_handoff;
use crate::adapters::peer_link::{LinkName, Reach};
use crate::adapters::peer_transfer::dial_end::{
    closed_before_hello, connect_failure, crypt_refusal,
};
use crate::adapters::served_link::drive_served_link;
use crate::adapters::{HelloAdverts, InboundPeerDeps};
use crate::ban_store::SharedBanStore;
use crate::ip_filter::SharedIpFilter;
use crate::server_session::HelloSource;
use crate::service::DialEnd;

/// A waiter the serve side promoted with no link of it up, to be dialed
/// back (ADR-0057) — what
/// [`ServeRuntimeService::dial_back`](super::ServeRuntimeService::dial_back)
/// is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialBack {
    /// The waiter as the serve side keys it: the link it waited on.
    pub waiter: PeerEndpoint,
    /// Where a dial reaches it: its link's address with its hello's listen
    /// port, or its IPv6 (`PeerIdentity::source_coordinate`).
    pub at: PeerEndpoint,
    /// Its crypt side as its hello stated it, with its User Hash: what the
    /// outbound rule meets, and a name its dial is filed under.
    pub crypt: PeerCrypt,
}

/// How a [`DialBack`] ended, as the serve task reads it.
pub enum DialBackOutcome {
    /// The dial came up and the peer said hello: the link's serve connection,
    /// keyed where it was dialed, and the identity its hello read. The link is
    /// a Peer Link already, filed under that hello's names.
    Linked {
        /// The waiter the dial was for.
        waiter: PeerEndpoint,
        /// The dialed link's serve half.
        conn: ServeConnection,
        /// The peer as its hello named it.
        identity: Box<PeerIdentity>,
    },
    /// The dial ended before a hello, for `cause`.
    Failed {
        /// The waiter the dial was for.
        waiter: PeerEndpoint,
        /// Why it ended.
        cause: DialEnd,
    },
}

/// Everything one dial-back reads, taken from the serve adapter at the dial.
pub(super) struct DialBackRoad {
    pub(super) hello: HelloSource,
    pub(super) adverts: HelloAdverts,
    pub(super) ip_filter: SharedIpFilter,
    pub(super) ban_store: SharedBanStore,
    pub(super) deps: InboundPeerDeps,
}

impl DialBackRoad {
    /// Dial `dial`'s waiter and drive the link it makes, saying how the dial
    /// ended on `outcomes`. A link or a dial already filed under the
    /// waiter's names is not dialed around (ADR-0107 invariant 7): nothing is
    /// said, and the grant goes on that link once its hello reaches the serve
    /// side.
    pub(super) async fn run(self, dial: DialBack, outcomes: mpsc::Sender<DialBackOutcome>) {
        let Self {
            hello,
            adverts,
            ip_filter,
            ban_store,
            deps,
        } = self;
        let DialBack { waiter, at, crypt } = dial;
        let failed = |cause| DialBackOutcome::Failed { waiter, cause };
        // The verdict is bound first so the read guard never crosses an await.
        let filtered = ip_filter
            .read()
            .expect("ip filter lock")
            .is_filtered_peer(at);
        if filtered {
            let _ = outcomes.send(failed(DialEnd::IpFiltered)).await;
            return;
        }
        if ban_store
            .lock()
            .await
            .is_banned(at.ip(), std::time::Instant::now())
        {
            let _ = outcomes.send(failed(DialEnd::Banned)).await;
            return;
        }
        let mut names = vec![LinkName::Endpoint(at)];
        names.extend(crypt.user_hash().map(LinkName::User));
        let in_flight = match deps.peer_links.reach(at, &names) {
            Reach::Dial(in_flight) => in_flight,
            Reach::Found(found) => {
                tracing::debug!(
                    ?waiter,
                    link = ?found.remote,
                    "dial-back finds a link of the waiter; the grant goes on it"
                );
                return;
            }
        };
        let options = adverts.connect_options(crypt);
        let ours = ObfuscationPolicy::stance_of(options.obfuscation.map(|config| config.policy));
        let mut conn = match PeerConnection::connect(at, hello.now(), options).await {
            Ok(conn) => conn,
            // Refused before any socket: no dial was in flight.
            Err(PeerNetError::CryptIncompatible) => {
                drop(in_flight);
                let _ = outcomes.send(failed(crypt_refusal(crypt, ours))).await;
                return;
            }
            Err(error) => {
                let cause = connect_failure(&error);
                in_flight.failed(cause);
                let _ = outcomes.send(failed(cause)).await;
                return;
            }
        };
        let identity = match await_hello(&mut conn, &deps.hello_refusals, |_| {}).await {
            Opening::Identified(identity) => *identity,
            Opening::Closed(reason) => {
                let cause = closed_before_hello(reason);
                in_flight.failed(cause);
                let _ = conn.shutdown().await;
                let _ = outcomes.send(failed(cause)).await;
                return;
            }
            Opening::Ended => {
                in_flight.failed(DialEnd::ClosedBeforeHello);
                let _ = conn.shutdown().await;
                let _ = outcomes.send(failed(DialEnd::ClosedBeforeHello)).await;
                return;
            }
        };
        // What every identified link feeds, as a download's dialed link does.
        broker_peer_kad_handoff(&deps.kad_bootstrap, at, &identity).await;
        crate::address_learning::record_peer_ipv6_vote(&deps.addresses, at, &identity);
        let (command_tx, command_rx) = mpsc::channel(16);
        let (event_tx, event_rx) = mpsc::channel(16);
        let linked = DialBackOutcome::Linked {
            waiter,
            conn: ServeConnection::new(at, command_tx, event_rx),
            identity: Box::new(identity.clone()),
        };
        if outcomes.send(linked).await.is_err() {
            // The serve activity ended under the dial: nothing grants here.
            in_flight.failed(DialEnd::ClosedLocally);
            let _ = conn.shutdown().await;
            return;
        }
        let _ =
            drive_served_link(conn, identity, command_rx, event_tx, deps, Some(in_flight)).await;
    }
}
