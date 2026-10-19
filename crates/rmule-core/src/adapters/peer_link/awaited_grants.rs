//! The **Awaited Grants** (ADR-0107): each source a download waits for in its
//! RemoteQueued stage (ADR-0057), filed in the Peer Links under the names its
//! record knows, so a link nobody rides that reads an uploader's unasked
//! `OP_ACCEPTUPLOADREQ` hands it to the download it is for, and a grant on
//! the peer's **Queue Standing** calls the downloads waiting on it to the
//! holder's link.
//!
//! aMule's uploader promotes a waiter it is not connected to by dialing it
//! and granting once the hellos are done (`UploadQueue.cpp:206-210`,
//! `BaseClient.cpp:1707-1716`); its downloader takes the grant for the file
//! the client is queued for (`ClientTCPSocket.cpp:635-645`), and finds the
//! client by address and port, then by user hash (`ClientList.cpp:253-347`).
//! Several downloads queued at one peer file under one name: the standing's
//! holder takes the grant first, then the oldest still running.

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use super::{LinkName, SharedPeerLinks};

/// What a link hands a run about the source it waits for at an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkOffer {
    /// An unasked grant on a link nobody rides: the record's worker rides it.
    Grant(PeerEndpoint),
    /// The standing's holder was granted a slot on its link: the record's
    /// worker joins that link and waits on it.
    Call(PeerEndpoint),
}

/// Where a link hands an offer: to the run that filed the wait.
pub(crate) type GrantSender = mpsc::Sender<LinkOffer>;

/// One filed wait for a grant.
#[derive(Clone)]
pub(super) struct Awaiting {
    filing: u64,
    at: PeerEndpoint,
    holds: bool,
    grants: GrantSender,
}

/// A source's place among the Awaited Grants, given up when dropped.
pub(crate) struct AwaitedGrant {
    links: SharedPeerLinks,
    filing: u64,
    names: Vec<LinkName>,
    holds: bool,
}

impl SharedPeerLinks {
    /// File a wait for a grant from the source waiting at `at`, under
    /// `names`, for as long as the returned place lives; `holds` when its
    /// download holds the peer's Queue Standing. An offer goes to `grants`
    /// naming `at`.
    pub(crate) fn await_grant(
        &self,
        at: PeerEndpoint,
        names: Vec<LinkName>,
        holds: bool,
        grants: GrantSender,
    ) -> AwaitedGrant {
        let mut book = self.book.lock().expect("peer links lock");
        book.filed += 1;
        let filing = book.filed;
        let awaiting = Awaiting {
            filing,
            at,
            holds,
            grants,
        };
        for name in &names {
            book.awaited
                .entry(*name)
                .or_default()
                .push(awaiting.clone());
        }
        AwaitedGrant {
            links: self.clone(),
            filing,
            names,
            holds,
        }
    }

    /// Every wait filed under any of `names`, once each, the standing's
    /// holder first and then in filing order.
    fn awaiting(&self, names: &[LinkName]) -> Vec<Awaiting> {
        let mut awaiting: Vec<Awaiting> = {
            let book = self.book.lock().expect("peer links lock");
            names
                .iter()
                .filter_map(|name| book.awaited.get(name))
                .flatten()
                .cloned()
                .collect()
        };
        awaiting.sort_by_key(|wait| wait.filing);
        awaiting.dedup_by_key(|wait| wait.filing);
        awaiting.sort_by_key(|wait| !wait.holds);
        awaiting
    }

    /// Hand an unasked grant read on a link proving `names` to the wait filed
    /// under any of them whose run still takes it — the standing holder's
    /// first, then the oldest; whether one did.
    pub(crate) fn offer_grant(&self, names: &[LinkName]) -> bool {
        self.awaiting(names)
            .into_iter()
            .any(|wait| wait.grants.try_send(LinkOffer::Grant(wait.at)).is_ok())
    }

    /// Call every wait filed under any of `names` to the link the peer's
    /// standing holder was just granted a slot on (ADR-0107).
    pub(crate) fn call_waiters(&self, names: &[LinkName]) {
        for wait in self.awaiting(names) {
            let _ = wait.grants.try_send(LinkOffer::Call(wait.at));
        }
    }
}

impl AwaitedGrant {
    /// Mark this wait as the standing holder's, or as a waiter's.
    pub(crate) fn set_holds(&mut self, holds: bool) {
        if self.holds == holds {
            return;
        }
        self.holds = holds;
        if let Ok(mut book) = self.links.book.lock() {
            for name in &self.names {
                if let Some(waits) = book.awaited.get_mut(name) {
                    for wait in waits.iter_mut().filter(|wait| wait.filing == self.filing) {
                        wait.holds = holds;
                    }
                }
            }
        }
    }
}

impl Drop for AwaitedGrant {
    fn drop(&mut self) {
        if let Ok(mut book) = self.links.book.lock() {
            for name in &self.names {
                if let Some(waits) = book.awaited.get_mut(name) {
                    waits.retain(|wait| wait.filing != self.filing);
                    if waits.is_empty() {
                        book.awaited.remove(name);
                    }
                }
            }
        }
    }
}
