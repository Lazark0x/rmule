//! The **Secured Identity** binder (ADR-0041, "One verification per link,
//! bound by the link"): the one cell every peer link binds the Secure User
//! Identification its session verified through. The link binds it the moment
//! its session reports it, so the binding happens once whichever halves hold
//! the link, and a half that lets the link go at that moment drops nothing.
//! aMule keeps the same state once per client, on its credit record
//! (`BaseClient.cpp:2576-2578`, `ClientCreditsList.cpp:433-437`).
//!
//! Created once by the builder and cloned into the adapters that hold peer
//! links (the Adapter Cells), then installed by the actor's prologue with the
//! credit ledger and the event bus. The prologue runs before any adapter can
//! open a connection; a cell never installed binds nothing.

use std::sync::{Arc, Mutex};

use rmule_primitives::UserHash;
use tokio::sync::mpsc;

use crate::credit::{KeyBinding, SharedCreditStore};
use crate::service::CoreEvent;

/// Where a link binds its verified identity (see the module docs).
#[derive(Clone, Default)]
pub(crate) struct SharedSecuredIdentities {
    installed: Arc<Mutex<Option<Installed>>>,
}

#[derive(Clone)]
struct Installed {
    credit: SharedCreditStore,
    events: mpsc::WeakSender<CoreEvent>,
}

impl SharedSecuredIdentities {
    /// Bind the cell to the credit ledger and the event bus. The sender is
    /// weak so this cell never keeps the bus open past the actor.
    pub(crate) fn install(&self, credit: SharedCreditStore, events: mpsc::WeakSender<CoreEvent>) {
        *self
            .installed
            .lock()
            .expect("secured identity cell poisoned") = Some(Installed { credit, events });
    }

    /// Bind `public_key`, which a link's session proved `user_hash` holds,
    /// as that client's Secured Identity through the ledger's compare-and-set
    /// (ADR-0041). A key that differs from the one bound is eMule's
    /// `IS_IDFAILED`: the stored key stays, and the theft is raised as
    /// [`CoreEvent::SecuredIdentityMismatch`]. Whether the client is
    /// identified now — its key adopted, or bound already.
    pub(crate) async fn bind(&self, user_hash: UserHash, public_key: &[u8]) -> bool {
        let installed = self
            .installed
            .lock()
            .expect("secured identity cell poisoned")
            .clone();
        let Some(installed) = installed else {
            return false;
        };
        match installed.credit.bind_public_key(user_hash, public_key) {
            Ok(KeyBinding::Adopted | KeyBinding::AlreadyBound) => true,
            Ok(KeyBinding::Mismatch) => {
                if let Some(events) = installed.events.upgrade() {
                    let _ = events
                        .send(CoreEvent::SecuredIdentityMismatch { user_hash })
                        .await;
                }
                false
            }
            Err(error) => {
                tracing::warn!(%error, "a verified identity could not be bound");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmule_primitives::UserHash;
    use tokio::sync::mpsc;

    use super::SharedSecuredIdentities;
    use crate::credit::SharedCreditStore;
    use crate::service::CoreEvent;
    use crate::store::credit::DurableCreditStore;
    use crate::store::open_durable_store_in_memory;

    const PEER: UserHash = UserHash::from_bytes([0x42; UserHash::BYTE_LEN]);

    fn ledger() -> SharedCreditStore {
        Arc::new(DurableCreditStore::new(
            open_durable_store_in_memory().unwrap(),
        ))
    }

    #[tokio::test]
    async fn a_verified_key_is_bound_and_a_different_one_is_refused_and_raised_once() {
        let credit = ledger();
        let (events_tx, mut events) = mpsc::channel(4);
        let secured = SharedSecuredIdentities::default();
        secured.install(Arc::clone(&credit), events_tx.downgrade());

        assert!(secured.bind(PEER, b"first-key").await, "first proof binds");
        assert!(secured.bind(PEER, b"first-key").await, "the same key again");
        assert!(
            !secured.bind(PEER, b"thief-key").await,
            "another key under the hash is refused"
        );
        assert_eq!(
            credit.public_key(PEER).unwrap().as_deref(),
            Some(&b"first-key"[..]),
            "the stored key never changes"
        );
        assert!(matches!(
            events.try_recv(),
            Ok(CoreEvent::SecuredIdentityMismatch { user_hash }) if user_hash == PEER
        ));
        assert!(events.try_recv().is_err(), "the theft is raised once");
    }
}
