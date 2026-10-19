//! A download's dial the peer's own link overtakes (ADR-0107 invariant 7):
//! the far side attaches a socket at the `OP_HELLO` on it, deleting the one it
//! held for the client, connecting or connected (`ClientTCPSocket.cpp:391`,
//! `ClientList.cpp:400-403`). So until a download's dial has sent its hello —
//! its connect, or its crypt handshake, still running — it yields to the
//! peer's accepted link filed under one of its names: the dial closes,
//! retiring nobody, and the dialing download and its waiters move onto that
//! link, as aMule's connecting client carries on over the socket the peer
//! opened (`BaseClient.cpp:1692-1698`). Once the dial's hello is out the far
//! side keeps the dial, and so does rmule.
//!
//! An uploader dialing a waiter it promoted grants at its hello
//! (`BaseClient.cpp:1707-1716`), so the link holds an unasked grant read
//! before the moving downloads have joined it until they have.

use tokio::sync::mpsc;

use super::{Book, DialInFlight, Filed, FoundLink, LinkJoin};

/// The downloads moving over from the dials a link overtook, and an unasked
/// grant the link holds for them meanwhile.
#[derive(Default)]
pub(in crate::adapters) struct Moving {
    joins: Option<mpsc::Receiver<LinkJoin>>,
    grant_held: bool,
}

impl Moving {
    /// Whether downloads are still moving over.
    pub(in crate::adapters) fn coming(&self) -> bool {
        self.joins.is_some()
    }

    /// The next download moving over, or `None` once, when every one has
    /// joined; never resolves after that.
    pub(in crate::adapters) async fn next(&mut self) -> Option<LinkJoin> {
        let Some(joins) = self.joins.as_mut() else {
            return std::future::pending().await;
        };
        let join = joins.recv().await;
        if join.is_none() {
            self.joins = None;
        }
        join
    }

    /// An unasked grant read while nobody rides the link: whether it is held
    /// for the downloads still moving over.
    pub(in crate::adapters) fn hold_grant(&mut self) -> bool {
        self.grant_held |= self.coming();
        self.grant_held
    }

    /// Every download moved over: whether a grant was held for them, which
    /// is now the rider's, or nobody's.
    pub(in crate::adapters) fn release_grant(&mut self) -> bool {
        std::mem::take(&mut self.grant_held)
    }
}

impl Book {
    /// The link `by` was just filed under names the filings `took_from` held:
    /// every download dial among them whose hello has not gone out yields to
    /// it, and the downloads moving over arrive on the returned [`Moving`].
    pub(super) fn overtake(&mut self, took_from: &[u64], by: &Filed) -> Moving {
        let mut joins = None;
        for filing in took_from {
            let Some(yielding) = self.yielding.remove(filing) else {
                continue;
            };
            let (move_tx, _) = joins.get_or_insert_with(|| mpsc::channel(4));
            let _ = yielding.send(FoundLink {
                remote: by.remote,
                join_tx: move_tx.clone(),
            });
        }
        Moving {
            joins: joins.map(|(_, move_rx)| move_rx),
            grant_held: false,
        }
    }
}

impl DialInFlight {
    /// Resolves with the peer's own link when it is filed under one of the
    /// dial's names before the dial's hello went out; never resolves for a
    /// dial that does not yield.
    pub(in crate::adapters) async fn overtaken(&mut self) -> FoundLink {
        if let Some(told) = self.overtaken.as_mut()
            && let Ok(link) = told.await
        {
            return link;
        }
        self.overtaken = None;
        std::future::pending().await
    }

    /// Give the dial up for the link that overtook it: unfiled, nobody
    /// retired, and the downloads that waited on it handed back in their
    /// order, to follow the dialing download onto that link.
    pub(in crate::adapters) fn yielded(self) -> mpsc::Receiver<LinkJoin> {
        let Self {
            filing, mut joins, ..
        } = self;
        drop(filing);
        joins.close();
        joins
    }
}
