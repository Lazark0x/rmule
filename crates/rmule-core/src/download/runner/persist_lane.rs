//! One run's part boundary, off its brain: the **Persist Lane**. A finished
//! part is hashed on the blocking pool, written through the Held Part File and
//! recorded at the store's own durability (a kill -9 loses at most the part in
//! hand), one part at a time, in the order they finished. The brain goes on
//! taking blocks and hears each landing as a fact. The lane holds
//! [`MOST_WAITING`] parts behind the one it works on, and past that the drain
//! waits, which stops the workers and, through them, the sockets.

use rmule_peer::PartIndex;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;

use rmule_primitives::{Ed2kFileLink, PeerEndpoint};

use super::{RunnerContext, served};
use crate::download::persist::{Landed, PersistError, persist_streamed_part};
use crate::hashing::ResolvedHashSet;
use crate::service::DownloadId;

/// The finished parts a lane holds behind the one it works on.
const MOST_WAITING: usize = 2;

/// One finished part on its way to the store.
pub(super) struct PartToLand {
    pub(super) part_index: PartIndex,
    pub(super) peer: PeerEndpoint,
    pub(super) offset: u64,
    pub(super) bytes: Vec<u8>,
}

/// How a part's landing ended, for the brain.
pub(super) struct Landing {
    pub(super) part_index: PartIndex,
    pub(super) peer: PeerEndpoint,
    pub(super) result: Result<Landed, PersistError>,
}

type Working<'a> = Pin<Box<dyn Future<Output = Landing> + Send + 'a>>;

/// A run's lane: at most one part landing, the rest in order behind it.
pub(super) struct PersistLane<'a> {
    working: Option<Working<'a>>,
    waiting: VecDeque<(PartToLand, ResolvedHashSet)>,
}

impl PersistLane<'_> {
    pub(super) fn new() -> Self {
        Self {
            working: None,
            waiting: VecDeque::new(),
        }
    }

    /// Whether a part is on the lane.
    pub(super) fn busy(&self) -> bool {
        self.working.is_some()
    }

    /// Whether the next part must wait for a landing first.
    pub(super) fn full(&self) -> bool {
        self.waiting.len() >= MOST_WAITING
    }
}

impl<'a> PersistLane<'a> {
    /// Put `part` on the lane under the `resolved` set in force.
    pub(super) fn take<S, P>(
        &mut self,
        runner: &'a RunnerContext<S, P>,
        download_id: DownloadId,
        file: &'a Ed2kFileLink,
        part: PartToLand,
        resolved: ResolvedHashSet,
    ) where
        S: Send + 'a,
        P: Send + 'a,
    {
        self.waiting.push_back((part, resolved));
        self.start_next(runner, download_id, file);
    }

    fn start_next<S, P>(
        &mut self,
        runner: &'a RunnerContext<S, P>,
        download_id: DownloadId,
        file: &'a Ed2kFileLink,
    ) where
        S: Send + 'a,
        P: Send + 'a,
    {
        if self.working.is_some() {
            return;
        }
        let Some((part, resolved)) = self.waiting.pop_front() else {
            return;
        };
        self.working = Some(Box::pin(land(runner, download_id, file, part, resolved)));
    }

    /// The part on the lane landed; the next one starts. Pends for ever on an
    /// idle lane: read it only while [`Self::busy`].
    pub(super) async fn landed<S, P>(
        &mut self,
        runner: &'a RunnerContext<S, P>,
        download_id: DownloadId,
        file: &'a Ed2kFileLink,
    ) -> Landing
    where
        S: Send + 'a,
        P: Send + 'a,
    {
        let Some(working) = self.working.as_mut() else {
            return std::future::pending().await;
        };
        let landing = working.await;
        self.working = None;
        self.start_next(runner, download_id, file);
        landing
    }
}

async fn land<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    part: PartToLand,
    resolved: ResolvedHashSet,
) -> Landing
where
    S: Send,
    P: Send,
{
    let PartToLand {
        part_index,
        peer,
        offset,
        bytes,
    } = part;
    let result = persist_streamed_part(
        runner,
        download_id,
        file,
        &resolved,
        part_index,
        offset,
        bytes,
    )
    .await;
    if result.is_ok() {
        served::part_written(runner).await;
    }
    // Before the brain hears it, so no status the run sends names a part the
    // serve side lacks (ADR-0113).
    served::rule_range(runner, download_id, &resolved.hashes);
    Landing {
        part_index,
        peer,
        result,
    }
}
