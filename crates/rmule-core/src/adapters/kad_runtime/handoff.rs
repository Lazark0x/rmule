//! The ed2k→Kad handoff forwarder (ADR-0067): the task that drains the
//! handoff sink and turns each brokered peer endpoint into a
//! `BootstrapFromPeer` pump command. Split out of `node.rs`'s `start` to
//! keep that file under the size guard.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::mailbox::Lease;

use rmule_primitives::Ipv4Endpoint;

use super::{KadPumpCommand, SharedKadBootstrap};

/// Install a fresh sender into `kad_bootstrap` — opening the handoff gate's
/// **running** leg, since the sink was empty (peer hints dropped) until Kad
/// started here — and spawn the forwarder that drains it into `commands` as
/// `BootstrapFromPeer`, where the node applies the not-joined + shared 10 s
/// throttle. The returned `JoinHandle` is `RuntimeKadFactory`'s to track:
/// the forwarder ends once `kad_bootstrap` is cleared back to `None`, which
/// `node.rs`'s own teardown now does on a clean stop rather
/// than only ever on the next `start`'s overwrite. The lease on the
/// installed sender comes back with it, so the node's teardown clears the
/// cell only while it still holds this one.
pub(super) async fn spawn(
    kad_bootstrap: &SharedKadBootstrap,
    commands: mpsc::Sender<KadPumpCommand>,
) -> (JoinHandle<()>, Lease<Ipv4Endpoint>) {
    let (handoff_tx, mut handoff_rx) = mpsc::channel::<Ipv4Endpoint>(32);
    let lease = kad_bootstrap.install(handoff_tx);
    let forwarder = tokio::spawn(async move {
        while let Some(peer) = handoff_rx.recv().await {
            if commands
                .send(KadPumpCommand::BootstrapFromPeer(peer))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    (forwarder, lease)
}
