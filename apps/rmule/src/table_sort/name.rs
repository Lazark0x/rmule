//! How a sort compares text: case-folded, accent-folded, and with digit runs
//! read as numbers, so `file2` comes before `File10` and `Éclair` sits beside
//! `eclair`.
//!
//! The fold is computed once per row ([`NameKey::new`]); comparing two keys
//! walks them in step, switching to numeric comparison wherever both sides
//! stand at a digit.

use std::cmp::Ordering;
use std::iter::Peekable;
use std::str::Chars;

use icu_normalizer::DecomposingNormalizerBorrowed;

/// Text folded for comparison. Equality is the comparison's: `file01` and
/// `file1` are equal names, and the Tie Chain's identity link parts them.
#[derive(Debug)]
pub(super) struct NameKey(String);

impl NameKey {
    /// Fold `text`: decompose (NFD), drop the combining marks the
    /// decomposition split off, lowercase what is left.
    pub(super) fn new(text: &str) -> Self {
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
        let (mut a, mut b) = (self.0.chars().peekable(), other.0.chars().peekable());
        loop {
            let ordering = match (a.peek().copied(), b.peek().copied()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                    digit_run(&mut a).cmp_numeric(&digit_run(&mut b))
                }
                (Some(x), Some(y)) => {
                    a.next();
                    b.next();
                    x.cmp(&y)
                }
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
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

/// A run of ASCII digits, leading zeros dropped, compared by value without
/// parsing — a 40-digit run in a file name must not overflow anything.
struct DigitRun(String);

impl DigitRun {
    fn cmp_numeric(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

fn digit_run(chars: &mut Peekable<Chars<'_>>) -> DigitRun {
    let mut digits = String::new();
    while let Some(c) = chars.next_if(char::is_ascii_digit) {
        if !(digits.is_empty() && c == '0') {
            digits.push(c);
        }
    }
    DigitRun(digits)
}
