//! The **Awaited Grants** (ADR-0107): each source a download waits for in its
//! RemoteQueued stage (ADR-0057), filed in the Peer Links under the names its
//! record knows, so a link nobody rides that reads an uploader's unasked
//! `OP_ACCEPTUPLOADREQ` hands it to the download it is for.
//!
//! aMule's uploader promotes a waiter it is not connected to by dialing it
//! and granting once the hellos are done (`UploadQueue.cpp:206-210`,
//! `BaseClient.cpp:1707-1716`); its downloader takes the grant for the file
//! the client is queued for (`ClientTCPSocket.cpp:635-645`). Two downloads
//! queued at one peer file under one name in the order they filed; the oldest
//! still running takes the grant.

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

use super::{LinkName, SharedPeerLinks};

/// Where a link hands a grant: the endpoint the record waits at, to the run
/// that filed it.
pub(crate) type GrantSender = mpsc::Sender<PeerEndpoint>;

/// One filed wait for a grant.
#[derive(Clone)]
pub(super) struct Awaiting {
    filing: u64,
    at: PeerEndpoint,
    grants: GrantSender,
}

/// A source's place among the Awaited Grants, given up when dropped.
pub(crate) struct AwaitedGrant {
    links: SharedPeerLinks,
    filing: u64,
    names: Vec<LinkName>,
}

impl SharedPeerLinks {
    /// File a wait for a grant from the source waiting at `at`, under
    /// `names`, for as long as the returned place lives; a grant goes to
    /// `grants` as `at`.
    pub(crate) fn await_grant(
        &self,
        at: PeerEndpoint,
        names: Vec<LinkName>,
        grants: GrantSender,
    ) -> AwaitedGrant {
        let mut book = self.book.lock().expect("peer links lock");
        book.filed += 1;
        let filing = book.filed;
        let awaiting = Awaiting { filing, at, grants };
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
        }
    }

    /// Hand an unasked grant read on a link proving `names` to the oldest wait
    /// filed under any of them whose run still takes it; whether one did.
    pub(crate) fn offer_grant(&self, names: &[LinkName]) -> bool {
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
        awaiting
            .into_iter()
            .any(|wait| wait.grants.try_send(wait.at).is_ok())
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
