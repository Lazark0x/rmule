//! One run's disk, off its brain: the **Persist Lane** (ADR-0029, ADR-0117 §4).
//! Everything a run asks of its part file is one job in one queue, worked one
//! at a time on the blocking pool: bytes written through the Held Part File, a
//! finished part read back, hashed and recorded at the store's own durability
//! (a kill -9 loses at most the part in hand), a recovery answer judged, a
//! checkpoint synced and committed. A part's check is queued behind its last
//! bytes and a checkpoint behind every byte it claims, by that order alone. The
//! brain goes on taking blocks and hears each landing as a fact.
//!
//! Arrivals gather until [`WRITE_AT`] bytes or the next tick, and go to the file
//! in order of offset. The lane holds [`MOST_WAITING`] parts behind the one it
//! works on, and its bytes count against the **Write Cache**; past either the
//! drain waits, which stops the workers and, through them, the sockets.
//!
//! The first write the volume refuses ends the lane: nothing behind it runs, so
//! no part is checked over bytes that never landed and no checkpoint claims
//! them.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use rmule_peer::PartIndex;
use rmule_primitives::{AichRootHash, Ed2kFileLink, PeerEndpoint};

use super::{RunnerContext, served};
use crate::assembly::{ArrivedPart, CellHash};
use crate::download::persist::{
    Landed, PersistError, check_recovery, checkpoint, persist_streamed_part, write_blocks,
};
use crate::download::write_cache::{CachedBytes, RUN_SHARE_BYTES};
use crate::error::DownloadFailure;
use crate::hashing::ResolvedHashSet;
use crate::planning::{PartPlan, part_plan};
use crate::service::DownloadId;

/// The finished parts a lane holds behind the one it works on.
const MOST_WAITING: usize = 2;

/// The bytes a run gathers before it writes them: below this a tick does.
const WRITE_AT: usize = 1024 * 1024;

/// How long a run with bytes written goes without a checkpoint.
const CHECKPOINT_EVERY: Duration = Duration::from_secs(30);

/// How many bytes a run writes between checkpoints.
const CHECKPOINT_BYTES: u64 = 256 * 1024 * 1024;

/// One finished part on its way to the store.
pub(super) struct PartToLand {
    pub(super) plan: PartPlan,
    pub(super) peer: Option<PeerEndpoint>,
    pub(super) read_cells: bool,
}

/// One recovery answer on its way to its verdict.
pub(super) struct RecoveryToCheck {
    pub(super) plan: PartPlan,
    pub(super) root: AichRootHash,
    pub(super) recovery_data: Vec<u8>,
}

/// How a part's landing ended, for the brain.
pub(super) struct Landing {
    pub(super) part_index: PartIndex,
    pub(super) peer: Option<PeerEndpoint>,
    pub(super) result: Result<Landed, PersistError>,
    pub(super) cells: Option<Vec<CellHash>>,
}

/// What one job of the lane came to, for the run.
pub(super) enum LaneFact {
    /// Bytes reached the file, or a checkpoint the store: nothing for the
    /// brain.
    Done,
    /// A part landed, or could not.
    Landing(Landing),
    /// A recovery answer was judged.
    Recovery {
        part_index: PartIndex,
        bad_blocks: Option<Vec<u16>>,
    },
    /// The disk refused: the lane stands, and the run ends on this.
    Ended(DownloadFailure),
}

enum Job {
    Write(Vec<(u64, Vec<u8>)>, Vec<CachedBytes>),
    Part(PartToLand, ResolvedHashSet),
    Recovery(PartIndex, RecoveryToCheck),
    Checkpoint(Vec<ArrivedPart>),
}

/// A job at work: what it came to, and the bytes it took off the lane.
type Working<'a> = Pin<Box<dyn Future<Output = (LaneFact, usize)> + Send + 'a>>;

/// A run's lane: at most one job at work, the rest in order behind it.
pub(super) struct PersistLane<'a> {
    start: Box<dyn Fn(Job) -> Working<'a> + Send + 'a>,
    working: Option<Working<'a>>,
    waiting: VecDeque<Job>,
    /// Arrivals not yet a job.
    gathered: Vec<(u64, Vec<u8>)>,
    gathered_cached: Vec<CachedBytes>,
    gathered_bytes: usize,
    /// Parts waiting behind the job at work.
    parts_waiting: usize,
    /// Bytes on the lane, from their arrival to the end of their write: the
    /// lane's count of the Write Cache.
    held_bytes: usize,
    /// Bytes gathered since the last checkpoint.
    unclaimed_bytes: u64,
    /// When the last checkpoint was asked.
    claimed_at: Instant,
    /// The disk refused: nothing runs behind it.
    ended: bool,
}

impl<'a> PersistLane<'a> {
    /// The lane of `download_id`'s run.
    pub(super) fn new<S, P>(
        runner: &'a RunnerContext<S, P>,
        download_id: DownloadId,
        file: &'a Ed2kFileLink,
    ) -> Self
    where
        S: Send + 'a,
        P: Send + 'a,
    {
        Self {
            start: Box::new(move |job| Box::pin(work(runner, download_id, file, job))),
            working: None,
            waiting: VecDeque::new(),
            gathered: Vec::new(),
            gathered_cached: Vec::new(),
            gathered_bytes: 0,
            parts_waiting: 0,
            held_bytes: 0,
            unclaimed_bytes: 0,
            claimed_at: Instant::now(),
            ended: false,
        }
    }

    /// Whether a job is on the lane.
    pub(super) fn busy(&self) -> bool {
        self.working.is_some()
    }

    /// Whether the next part must wait for a landing first.
    pub(super) fn full(&self) -> bool {
        self.parts_waiting >= MOST_WAITING
    }

    /// Whether the run holds its share of the Write Cache: the next arrival
    /// waits for its own writes first.
    pub(super) fn over_share(&self) -> bool {
        self.held_bytes >= RUN_SHARE_BYTES
    }

    /// Whether the disk refused and the lane stands.
    pub(super) fn ended(&self) -> bool {
        self.ended
    }

    /// Take `bytes` at `offset`, their share of the cache `cached`. A lane that
    /// ended takes nothing: the run is over, and these bytes count as absent.
    pub(super) fn gather(&mut self, offset: u64, bytes: Vec<u8>, cached: CachedBytes) {
        if self.ended {
            return;
        }
        self.gathered_bytes += bytes.len();
        self.held_bytes += bytes.len();
        self.unclaimed_bytes += bytes.len() as u64;
        self.gathered.push((offset, bytes));
        self.gathered_cached.push(cached);
        if self.gathered_bytes >= WRITE_AT {
            self.write_gathered();
        }
    }

    /// Put what is gathered on the lane.
    pub(super) fn write_gathered(&mut self) {
        if self.gathered.is_empty() {
            return;
        }
        let blocks = std::mem::take(&mut self.gathered);
        let cached = std::mem::take(&mut self.gathered_cached);
        self.gathered_bytes = 0;
        self.enqueue(Job::Write(blocks, cached));
    }

    /// Drop what is gathered: a cancel's bytes never reach the file.
    pub(super) fn drop_gathered(&mut self) {
        self.held_bytes -= self.gathered_bytes;
        self.gathered_bytes = 0;
        self.gathered.clear();
        self.gathered_cached.clear();
    }

    /// Put `part` on the lane under the `resolved` set in force, behind its
    /// bytes.
    pub(super) fn take_part(&mut self, part: PartToLand, resolved: ResolvedHashSet) {
        self.write_gathered();
        self.parts_waiting += 1;
        self.enqueue(Job::Part(part, resolved));
    }

    /// Put a recovery answer for `part_index` on the lane, behind every byte.
    pub(super) fn take_recovery(&mut self, part_index: PartIndex, recovery: RecoveryToCheck) {
        self.write_gathered();
        self.enqueue(Job::Recovery(part_index, recovery));
    }

    /// Whether a checkpoint is due at `at`: bytes went to the file and the
    /// clock or their count says so.
    pub(super) fn checkpoint_due(&self, at: Instant) -> bool {
        self.unclaimed_bytes >= CHECKPOINT_BYTES
            || (self.unclaimed_bytes > 0
                && at.saturating_duration_since(self.claimed_at) >= CHECKPOINT_EVERY)
    }

    /// Put a checkpoint of `parts` on the lane, behind every byte it claims.
    pub(super) fn take_checkpoint(&mut self, at: Instant, parts: Vec<ArrivedPart>) {
        self.write_gathered();
        self.unclaimed_bytes = 0;
        self.claimed_at = at;
        if !parts.is_empty() {
            self.enqueue(Job::Checkpoint(parts));
        }
    }

    fn enqueue(&mut self, job: Job) {
        if self.ended {
            return;
        }
        self.waiting.push_back(job);
        self.start_next();
    }

    fn start_next(&mut self) {
        if self.working.is_some() {
            return;
        }
        if let Some(job) = self.waiting.pop_front() {
            if matches!(job, Job::Part(..)) {
                self.parts_waiting -= 1;
            }
            self.working = Some((self.start)(job));
        }
    }

    /// The job at work ended; the next one starts. Pends for ever on an idle
    /// lane: read it only while [`Self::busy`].
    pub(super) async fn next_fact(&mut self) -> LaneFact {
        let Some(working) = self.working.as_mut() else {
            return std::future::pending().await;
        };
        let (fact, wrote) = working.await;
        self.working = None;
        self.held_bytes -= wrote.min(self.held_bytes);
        if matches!(fact, LaneFact::Ended(_)) {
            self.ended = true;
            self.waiting.clear();
            self.parts_waiting = 0;
            self.drop_gathered();
            self.held_bytes = 0;
        }
        self.start_next();
        fact
    }
}

async fn work<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    job: Job,
) -> (LaneFact, usize)
where
    S: Send,
    P: Send,
{
    let fact = match job {
        Job::Write(blocks, cached) => {
            let bytes = blocks.iter().map(|(_, bytes)| bytes.len()).sum();
            let written = write_blocks(runner, download_id, blocks).await;
            // The bytes are the file's: their share of the cache goes back.
            drop(cached);
            return (
                written.map_or_else(LaneFact::Ended, |()| LaneFact::Done),
                bytes,
            );
        }
        Job::Part(part, resolved) => land(runner, download_id, file, part, resolved).await,
        Job::Recovery(part_index, recovery) => {
            let RecoveryToCheck {
                plan,
                root,
                recovery_data,
            } = recovery;
            match check_recovery(runner, file.size(), plan, root, recovery_data).await {
                Ok(bad_blocks) => LaneFact::Recovery {
                    part_index,
                    bad_blocks,
                },
                Err(failure) => LaneFact::Ended(failure),
            }
        }
        Job::Checkpoint(parts) => checkpoint(runner, download_id, parts)
            .await
            .map_or_else(LaneFact::Ended, |()| LaneFact::Done),
    };
    (fact, 0)
}

async fn land<S, P>(
    runner: &RunnerContext<S, P>,
    download_id: DownloadId,
    file: &Ed2kFileLink,
    part: PartToLand,
    resolved: ResolvedHashSet,
) -> LaneFact
where
    S: Send,
    P: Send,
{
    let PartToLand {
        plan,
        peer,
        read_cells,
    } = part;
    let checked =
        persist_streamed_part(runner, download_id, file, &resolved, plan, read_cells).await;
    if checked.result.is_ok() {
        served::part_written(runner).await;
    }
    // Before the brain hears it, so no status the run sends names a part the
    // serve side lacks (ADR-0113).
    served::rule_range(runner, download_id, &resolved.hashes);
    LaneFact::Landing(Landing {
        part_index: plan.part_index,
        peer,
        result: checked.result,
        cells: checked.cells,
    })
}

/// The plan of `part_index`, for a decision that names a part.
pub(super) fn plan_of(file: &Ed2kFileLink, part_index: PartIndex) -> PartPlan {
    part_plan(file.size(), part_index)
}
