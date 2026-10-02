//! How each download of one `download start` run ended. Every download ends
//! on its own — one failing leaves the others running — and the run ends when
//! every download it queued has ended; the verdict then says whether any
//! failed.

use rmule_core::{DownloadEvent, DownloadId};

/// How one download ended.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ending {
    Completed,
    Cancelled,
    Failed(String),
}

/// The run's downloads, in `--file` order, and how each that has ended ended.
#[derive(Debug)]
pub(super) struct Endings {
    /// How many downloads the run started.
    expected: usize,
    /// Each queued download, in the order it was queued — `--file` order, so
    /// a position names its `--out`.
    queued: Vec<DownloadId>,
    ended: Vec<(DownloadId, Ending)>,
}

/// What one event did to the run.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Noted {
    /// Nothing that ends a download.
    Nothing,
    /// A download completed; `position` is its place in `--file` order.
    Completed {
        id: DownloadId,
        position: Option<usize>,
    },
    /// A download ended short of completion.
    EndedShort,
}

impl Endings {
    /// A run that started `expected` downloads, none queued yet.
    pub(super) const fn new(expected: usize) -> Self {
        Self {
            expected,
            queued: Vec::new(),
            ended: Vec::new(),
        }
    }

    /// Take `event` in. A download's second ending is not counted: the first
    /// is the one that ended it.
    pub(super) fn observe(&mut self, event: &DownloadEvent) -> Noted {
        let (id, ending) = match event {
            DownloadEvent::DownloadQueued { download_id, .. } => {
                if !self.queued.contains(download_id) {
                    self.queued.push(*download_id);
                }
                return Noted::Nothing;
            }
            DownloadEvent::DownloadCompleted { download_id } => (*download_id, Ending::Completed),
            DownloadEvent::DownloadCancelled { download_id } => (*download_id, Ending::Cancelled),
            DownloadEvent::DownloadFailed {
                download_id,
                reason,
            } => (*download_id, Ending::Failed(reason.to_string())),
            _ => return Noted::Nothing,
        };
        if self.ended.iter().any(|(ended, _)| *ended == id) {
            return Noted::Nothing;
        }
        let completed = ending == Ending::Completed;
        self.ended.push((id, ending));
        if completed {
            Noted::Completed {
                id,
                position: self.queued.iter().position(|queued| *queued == id),
            }
        } else {
            Noted::EndedShort
        }
    }

    /// Every download the run started has ended.
    pub(super) fn all_ended(&self) -> bool {
        self.ended.len() >= self.expected
    }

    /// The first queued download, for the deadline marker.
    pub(super) fn first(&self) -> Option<DownloadId> {
        self.queued.first().copied()
    }

    /// The ids queued so far.
    pub(super) fn queued(&self) -> impl Iterator<Item = u64> + '_ {
        self.queued.iter().map(|id| id.as_u64())
    }

    /// `Ok` when no download that ended ended short; otherwise each one that
    /// did, with why.
    pub(super) fn verdict(&self) -> anyhow::Result<()> {
        let short: Vec<String> = self
            .ended
            .iter()
            .filter_map(|(id, ending)| match ending {
                Ending::Completed => None,
                Ending::Cancelled => Some(format!("id={} cancelled", id.as_u64())),
                Ending::Failed(reason) => Some(format!("id={} failed: {reason}", id.as_u64())),
            })
            .collect();
        if short.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "{} of {} downloads did not complete: {}",
                short.len(),
                self.expected,
                short.join("; ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_core::DownloadFailure;

    use super::*;

    /// Two downloads from one run, the first failing before the second
    /// completes: the failure ends only its own download, the run goes on
    /// until the second ends too, and the verdict says one failed.
    #[test]
    fn one_failed_download_ends_only_itself_and_the_run_says_so() {
        let first = DownloadId::from_u64(7);
        let second = DownloadId::from_u64(12);
        let mut endings = Endings::new(2);
        for id in [first, second] {
            let queued = DownloadEvent::DownloadQueued {
                download_id: id,
                file_hash: rmule_primitives::FileHash::from_bytes(std::array::from_fn(|at| {
                    u8::try_from(at * 13).unwrap() ^ u8::try_from(id.as_u64()).unwrap()
                })),
                metadata: rmule_core::DownloadMetadata::unnamed(9_728_000),
            };
            assert_eq!(endings.observe(&queued), Noted::Nothing);
        }

        let failed = DownloadEvent::DownloadFailed {
            download_id: first,
            reason: DownloadFailure::NoUsableSources,
        };
        assert_eq!(endings.observe(&failed), Noted::EndedShort);
        assert!(!endings.all_ended(), "the second download still runs");
        assert_eq!(endings.observe(&failed), Noted::Nothing, "counted once");
        assert!(!endings.all_ended());

        let completed = DownloadEvent::DownloadCompleted {
            download_id: second,
        };
        assert_eq!(
            endings.observe(&completed),
            Noted::Completed {
                id: second,
                position: Some(1)
            }
        );
        assert!(endings.all_ended());
        let verdict = endings.verdict().unwrap_err().to_string();
        assert!(
            verdict.starts_with("1 of 2 downloads did not complete: id=7 failed: "),
            "{verdict}"
        );
    }

    /// Every download completing is a clean run.
    #[test]
    fn a_run_whose_downloads_all_complete_passes() {
        let mut endings = Endings::new(2);
        for raw in [3, 9] {
            endings.observe(&DownloadEvent::DownloadCompleted {
                download_id: DownloadId::from_u64(raw),
            });
        }
        assert!(endings.all_ended());
        endings.verdict().unwrap();
    }
}
