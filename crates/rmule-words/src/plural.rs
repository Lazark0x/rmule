//! One count in words, the only way a word is chosen by a number. English
//! has two forms; CLDR gives Russian and Polish four and Arabic six, so a
//! count names its form by the language's category, never by `n == 1`, and
//! a translation fills the forms its language has.

use std::fmt::Display;

/// A language's plural category for a count (CLDR).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    /// Zero, where the language has a form for it.
    Zero,
    /// One.
    One,
    /// Two.
    Two,
    /// A few.
    Few,
    /// Many.
    Many,
    /// Every other count, and the form each language has.
    Other,
}

/// The category of `n` in the language these words are written in.
#[must_use]
pub const fn category(n: u64) -> Category {
    if n == 1 {
        Category::One
    } else {
        Category::Other
    }
}

/// A phrase in every form a language gives it, `{n}` where the count goes: a
/// whole phrase, so a verb can agree and the count can stand anywhere. A
/// category without a form takes [`Plural::other`].
#[derive(Clone, Copy, Debug)]
pub struct Plural {
    /// The form for [`Category::Zero`].
    pub zero: Option<&'static str>,
    /// The form for [`Category::One`].
    pub one: Option<&'static str>,
    /// The form for [`Category::Two`].
    pub two: Option<&'static str>,
    /// The form for [`Category::Few`].
    pub few: Option<&'static str>,
    /// The form for [`Category::Many`].
    pub many: Option<&'static str>,
    /// The form every language has.
    pub other: &'static str,
}

impl Plural {
    /// A phrase with the forms English has.
    #[must_use]
    pub const fn new(one: &'static str, other: &'static str) -> Self {
        Self {
            zero: None,
            one: Some(one),
            two: None,
            few: None,
            many: None,
            other,
        }
    }

    /// The form for `category`.
    #[must_use]
    pub const fn form(&self, category: Category) -> &'static str {
        let form = match category {
            Category::Zero => self.zero,
            Category::One => self.one,
            Category::Two => self.two,
            Category::Few => self.few,
            Category::Many => self.many,
            Category::Other => None,
        };
        match form {
            Some(form) => form,
            None => self.other,
        }
    }

    /// The phrase said of `n`.
    #[must_use]
    pub fn of<N: Copy + Display + TryInto<u64>>(&self, n: N) -> String {
        let category = n.try_into().map_or(Category::Other, category);
        self.form(category).replace("{n}", &n.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A language with more forms than English fills them with no change to
    /// a caller, and the count may stand anywhere in the phrase.
    #[test]
    fn a_form_is_found_by_category_and_falls_back_on_other() {
        let russian = Plural {
            few: Some("{n} файла"),
            many: Some("{n} файлов"),
            ..Plural::new("{n} файл", "{n} файла")
        };
        assert_eq!(russian.form(Category::Few), "{n} файла");
        assert_eq!(russian.form(Category::Many), "{n} файлов");
        assert_eq!(russian.form(Category::Two), "{n} файла");
    }

    #[test]
    fn english_says_one_only_of_one() {
        let peers = Plural::new("{n} peer", "{n} peers");
        assert_eq!(peers.of(1_u32), "1 peer");
        assert_eq!(peers.of(0_usize), "0 peers");
        assert_eq!(peers.of(2_u64), "2 peers");
    }
}
