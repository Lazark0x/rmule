//! The words for a download's part file and the parts it holds: what a run
//! found changed at its path and what that cost, checked parts that no
//! longer match, parts a hash set or the finished file's hash disproved,
//! and what a Restart kept or started over from.

use rmule_core::{PartFault, PartFileChange, PartsLost, RestartOutcome};

use super::super::Sentence;
use super::super::units::{count, human_size};
use super::{integrity_fault_words, part_fault_words};

/// What a run found at its part file's path.
#[must_use]
pub fn part_file_change_words(found: PartFileChange) -> String {
    match found {
        PartFileChange::Gone => "part file removed".to_string(),
        PartFileChange::Replaced => "part file replaced by another file".to_string(),
        PartFileChange::Truncated { len } => {
            format!("part file cut short to {}", human_size(len))
        }
    }
}

/// What a changed part file cost, or that the store could not say.
#[must_use]
pub fn parts_lost_words(lost: PartsLost) -> String {
    match lost {
        PartsLost::Counted { parts, bytes } => parts_to_fetch_again(parts, bytes),
        PartsLost::NotCounted => {
            "rmule's store could not say which verified parts were lost, so the download stopped"
                .to_string()
        }
    }
}

/// What a loss costs.
#[must_use]
pub fn parts_to_fetch_again(parts: u32, bytes: u64) -> String {
    match parts {
        0 => "no verified part was lost".to_string(),
        1 => format!("1 verified part ({}) to fetch again", human_size(bytes)),
        n => format!("{n} verified parts ({}) to fetch again", human_size(bytes)),
    }
}

/// "1 checked part" / "N checked parts".
fn checked_parts(parts: u32) -> String {
    count(u64::from(parts), "checked part", "checked parts")
}

/// What a Restart did: continued from what holds, or started over with
/// nothing on disk to continue from — and the cost.
#[must_use]
pub fn restart_words(outcome: &RestartOutcome) -> String {
    match outcome {
        RestartOutcome::Continued {
            kept_parts: 0,
            dropped_parts: 0,
            ..
        } => "nothing was checked yet; it starts from 0 %".to_string(),
        RestartOutcome::Continued {
            kept_parts,
            kept_bytes,
            dropped_parts: 0,
            ..
        } => format!(
            "continuing from {} ({})",
            checked_parts(*kept_parts),
            human_size(*kept_bytes)
        ),
        RestartOutcome::Continued {
            kept_parts,
            kept_bytes,
            dropped_parts,
            dropped_bytes,
        } => format!(
            "continuing from {} ({}); {} damaged ({}) dropped, fetched again",
            checked_parts(*kept_parts),
            human_size(*kept_bytes),
            checked_parts(*dropped_parts),
            human_size(*dropped_bytes)
        ),
        RestartOutcome::StartedOver {
            fault,
            dropped_parts,
            dropped_bytes,
        } => {
            let why = integrity_fault_words(fault);
            match dropped_parts {
                0 => format!("nothing on disk to continue from ({why}), starting from 0 %"),
                _ => format!(
                    "nothing on disk to continue from ({why}), starting from 0 %; {} ({}) fetched again",
                    checked_parts(*dropped_parts),
                    human_size(*dropped_bytes)
                ),
            }
        }
    }
}

/// Checked parts that no longer matched on disk were dropped.
#[must_use]
pub fn damaged_parts(name: &str, damaged: &[PartFault]) -> Sentence {
    let details = damaged
        .iter()
        .map(part_fault_words)
        .collect::<Vec<_>>()
        .join("; ");
    Sentence::owned(format!(
        "{name}: {} no longer matched on disk and will be fetched again ({details})",
        checked_parts(u32::try_from(damaged.len()).unwrap_or(u32::MAX))
    ))
}

/// The part file changed under the run (ADR-0094): said at once, with what it
/// cost.
#[must_use]
pub fn part_file_lost(name: &str, found: PartFileChange, lost: PartsLost) -> Sentence {
    Sentence::owned(format!(
        "{name}: {} — {}",
        part_file_change_words(found),
        parts_lost_words(lost)
    ))
}

/// The finished file did not match its hash and no part could be named.
#[must_use]
pub fn finished_file_rejected(name: &str, parts: u32, bytes: u64) -> Sentence {
    Sentence::owned(format!(
        "{name}: the finished file did not match its hash and no part could be named — {}",
        parts_to_fetch_again(parts, bytes)
    ))
}

/// Parts fetched before the file's part hash set arrived did not match it
/// when it did, and are fetched again.
#[must_use]
pub fn parts_disproved(name: &str, parts: u32, bytes: u64) -> Sentence {
    Sentence::owned(format!(
        "{name}: parts fetched before the file's part hash set arrived did not match it — {}",
        parts_to_fetch_again(parts, bytes)
    ))
}

/// What the operator's Restart did.
#[must_use]
pub fn restarted(name: &str, outcome: &RestartOutcome) -> Sentence {
    Sentence::owned(format!("{name} restarted: {}", restart_words(outcome)))
}
