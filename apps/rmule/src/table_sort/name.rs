//! How a sort compares text: case-folded, accent-folded, and with digit runs
//! read as numbers, so `file2` comes before `File10` and `Éclair` sits beside
//! `eclair`.
//!
//! The fold is computed once per row ([`NameKey::new`]); comparing two keys
//! walks them in step, switching to numeric comparison wherever both sides
//! stand at a digit.

use std::cmp::Ordering;

use icu_normalizer::DecomposingNormalizerBorrowed;

/// Text folded for comparison. Equality is the comparison's: `file01` and
/// `file1` are equal names, and the Tie Chain's identity link parts them.
#[derive(Debug)]
pub(super) struct NameKey(String);

impl NameKey {
    /// Fold `text`: decompose (NFD), drop the combining marks the
    /// decomposition split off, lowercase what is left.
    pub(super) fn new(text: &str) -> Self {
        // Nothing in ASCII decomposes, and file names are mostly ASCII.
        if text.is_ascii() {
            return Self(text.to_ascii_lowercase());
        }
        let decomposed = DecomposingNormalizerBorrowed::new_nfd().normalize(text);
        Self(
            decomposed
                .chars()
                .filter(|c| !is_combining_mark(*c))
                .flat_map(char::to_lowercase)
                .collect(),
        )
    }
}

/// `text` with case and accents folded away, as the sort reads a name.
#[must_use]
pub(crate) fn fold(text: &str) -> String {
    NameKey::new(text).0
}

/// The combining-mark blocks an NFD decomposition of a Latin, Greek or
/// Cyrillic accented letter splits into.
fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

impl Ord for NameKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // UTF-8 orders as its code points do and a digit is one byte, so the
        // walk is over bytes.
        let (mut a, mut b) = (self.0.as_bytes(), other.0.as_bytes());
        loop {
            let same = a.iter().zip(b).take_while(|(x, y)| x == y).count();
            // A digit run can start before where they part: `19` and `2`.
            let digits = a[..same].iter().rev().take_while(|c| c.is_ascii_digit());
            let start = same - digits.count();
            (a, b) = (&a[start..], &b[start..]);
            let at_digits = a.first().is_some_and(u8::is_ascii_digit)
                && b.first().is_some_and(u8::is_ascii_digit);
            if !at_digits {
                return a.cmp(b);
            }
            let (x, rest_a) = digit_run(a);
            let (y, rest_b) = digit_run(b);
            let ordering = x.len().cmp(&y.len()).then_with(|| x.cmp(y));
            if ordering != Ordering::Equal {
                return ordering;
            }
            (a, b) = (rest_a, rest_b);
        }
    }
}

impl PartialEq for NameKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for NameKey {}

impl PartialOrd for NameKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The ASCII digits `text` opens with, leading zeros dropped, and what follows
/// them: read as a value by length then bytes, never parsed, because a 40-digit
/// run in a file name must not overflow anything.
fn digit_run(text: &[u8]) -> (&[u8], &[u8]) {
    let end = text.iter().take_while(|c| c.is_ascii_digit()).count();
    let (run, rest) = text.split_at(end);
    let zeros = run.iter().take_while(|c| **c == b'0').count();
    (&run[zeros..], rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_runs_compare_by_value_wherever_the_names_part() {
        let rising = [
            "", "a", "a1", "a1b", "a2", "a02b", "a9", "a10", "a19", "a100", "b", "é1", "é2", "z",
        ];
        for (at, low) in rising.iter().enumerate() {
            for high in &rising[at + 1..] {
                let (a, b) = (NameKey::new(low), NameKey::new(high));
                assert_eq!(a.cmp(&b), Ordering::Less, "{low} before {high}");
                assert_eq!(b.cmp(&a), Ordering::Greater, "{high} after {low}");
            }
        }
        assert_eq!(
            NameKey::new("a007b").cmp(&NameKey::new("A7B")),
            Ordering::Equal
        );
    }
}
