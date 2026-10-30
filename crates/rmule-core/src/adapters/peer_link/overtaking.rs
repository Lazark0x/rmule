//! A dial the peer's own link overtakes (ADR-0107 invariant 7): the far side
//! attaches a socket at the `OP_HELLO` on it, deleting the one it held for the
//! client, connecting or connected (`ClientTCPSocket.cpp:391`,
//! `ClientList.cpp:400-403`). So until a dial has sent its hello — its
//! connect, or its crypt handshake, still running — it yields to the peer's
//! accepted link filed under one of its names: the dial closes, retiring
//! nobody, and the dialing download and its waiters move onto that link, as
//! aMule's connecting client carries on over the socket the peer opened
//! (`BaseClient.cpp:1692-1698`); a serve side's dial-back leaves its grant to
//! that link. Once its hello is out the peer's hello waits for it instead
//! (`crossing`). A dial that was answered and has since died at the far end
//! is let go for the peer's link, so whatever rides it leaves it now.
//!
//! The hello is claimed under the same lock an overtaking link files under,
//! so a link filed while the dial's socket came up still overtakes it.
//!
//! An uploader dialing a waiter it promoted grants at its hello
//! (`BaseClient.cpp:1707-1716`), so the link holds an unasked grant read
//! before the moving downloads have joined it until they have.

use std::time::Instant;

use tokio::sync::mpsc;

use super::{Book, DialInFlight, FarEnd, Filed, FoundLink, LinkJoin};

/// The downloads moving over from the dials a link overtook, and an unasked
/// grant the link holds for them meanwhile.
#[derive(Default)]
pub(in crate::adapters) struct Moving {
    joins: Option<mpsc::Receiver<LinkJoin>>,
    grant_held: bool,
    /// The dials dead at the far end this link took names from.
    dead_dials: Vec<FarEnd>,
}

impl Moving {
    /// Let the dials this link found dead go: called once the serve side has
    /// heard this link's hello, so their standing moves here, not out.
    pub(in crate::adapters) fn let_dead_dials_go(&mut self) {
        for far_end in self.dead_dials.drain(..) {
            far_end.let_go();
        }
    }

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
    /// The link `by` was just filed at `now` under names the filings
    /// `took_from` held: every dial among them whose hello has not gone out
    /// yields to it, the downloads moving over arrive on the returned
    /// [`Moving`], and a dial dead at the far end is noted for letting go.
    pub(super) fn overtake(&mut self, took_from: &[u64], by: &Filed, now: Instant) -> Moving {
        let mut joins = None;
        let mut dead_dials = Vec::new();
        for filing in took_from {
            if let Some(far_end) = self.live.get(filing).and_then(|held| held.far_end.as_ref())
                && far_end.dead_at(now).is_some()
                && !dead_dials.iter().any(|dead: &FarEnd| dead.same_as(far_end))
            {
                dead_dials.push(far_end.clone());
            }
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
            dead_dials,
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

    /// Claim the hello for a dial whose socket came up: from here the dial no
    /// longer yields. `Err` with the peer's own link when that link overtook
    /// the dial first, while its socket came up: no byte of the hello may go
    /// out then, and the dial gives way as before its socket was up.
    pub(in crate::adapters) fn claim_hello(&mut self) -> Result<(), FoundLink> {
        let Some(told) = self.overtaken.as_mut() else {
            return Ok(());
        };
        if self.filing.hello_out() {
            self.overtaken = None;
            return Ok(());
        }
        // The overtaking link was told under the same lock that took the
        // dial off the yielding list.
        match told.try_recv() {
            Ok(link) => Err(link),
            Err(_) => Ok(()),
        }
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
