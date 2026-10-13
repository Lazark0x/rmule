//! The words for the **Hole Verdict** (ADR-0111): the one note a run on a
//! disk that holds no holes sends, and the Transfers details modal's On disk
//! row.

use std::path::Path;

use rmule_core::HoleVerdict;

use super::super::Sentence;
use super::super::os::kind_words;
use super::super::units::human_size;

/// The run's Hole Probe found a disk that holds no holes (ADR-0111): said
/// once per run, naming the download and its part file's directory. The
/// Temp Directory decides where a download's part file lies when it starts,
/// so only downloads started after it moves avoid this.
#[must_use]
pub fn hole_less_destination(name: &str, directory: &Path) -> Sentence {
    Sentence::owned(format!(
        "{name}: {}; the download goes on — {HOLE_LESS_REMEDY}",
        hole_less_where(directory)
    ))
}

/// Where the part file lies, and what the disk there costs it.
pub(super) fn hole_less_where(directory: &Path) -> String {
    format!("its part file lies in {}; {HOLE_LESS}", directory.display())
}

/// The `HoleLess` verdict: what a disk that holds no holes costs the part
/// file there. The edge's sentence and the On disk row both say it.
const HOLE_LESS: &str = "this disk holds no holes, so the part file takes its full length on disk up to its last verified part";

/// How the operator keeps the next downloads off a disk that holds no holes.
pub(super) const HOLE_LESS_REMEDY: &str =
    "downloads started with the Temp Directory on another disk avoid this";

/// The Transfers details modal's On disk row (ADR-0111, "What the operator
/// reads"): the part file's Allocated Bytes as read, above its length
/// included, and what the run's Hole Verdict means. A reading or a verdict
/// not yet taken is a dash, and no state reads as an all-clear.
#[must_use]
pub fn on_disk(allocated: Option<u64>, verdict: Option<HoleVerdict>) -> String {
    const DASH: &str = "—";
    let verdict = verdict.map(|verdict| match verdict {
        HoleVerdict::HoldsHoles => {
            "this disk holds holes, so the part file takes only the parts written".to_string()
        }
        HoleVerdict::HoleLess => HOLE_LESS.to_string(),
        HoleVerdict::Unknown(kind) => {
            format!("the disk was not measured: {}", kind_words(kind))
        }
    });
    match (allocated, verdict) {
        (None, None) => DASH.to_string(),
        (allocated, verdict) => format!(
            "{}; {}",
            allocated.map_or_else(
                || DASH.to_string(),
                |bytes| format!("{} allocated", human_size(bytes))
            ),
            verdict.as_deref().unwrap_or(DASH)
        ),
    }
}
