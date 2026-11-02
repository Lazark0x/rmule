//! The Viewport's words: the count a scrollable list carries on its bottom
//! border (ADR-0072, "Viewport").

/// Where the operator is in a list: item `at` (1-based) of `of`, the
/// numbers as plain counts.
#[must_use]
pub fn count(at: usize, of: usize) -> String {
    format!("{at} / {of}")
}
