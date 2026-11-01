//! A directory field's `Tab`: as much of the typed path as the disk settles.
//!
//! The typed prefix is kept as typed, a `~` included, and only the last
//! component grows. One read of one directory, once per press.

use std::path::is_separator;

use crate::config::expand_home;
use crate::words::Sentence;
use crate::words::app as words;

/// What a `Tab` did to a directory field.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Completion {
    /// The field's new text, when the disk settled more of it.
    pub text: Option<String>,
    /// What the operator has left to choose from, or why nothing came.
    pub note: Option<Sentence>,
}

/// Complete `typed` to the directories its last component begins.
pub(crate) fn complete_directory(typed: &str) -> Completion {
    if typed.is_empty() || typed == "~" {
        return Completion {
            text: Some(format!("~{}", std::path::MAIN_SEPARATOR)),
            note: None,
        };
    }
    let split = typed.rfind(is_separator).map_or(0, |at| at + 1);
    let (head, stem) = typed.split_at(split);
    let parent = if head.is_empty() { "." } else { head };
    let Ok(entries) = std::fs::read_dir(expand_home(parent)) else {
        return Completion {
            text: None,
            note: Some(words::path_unreadable(head)),
        };
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(stem) && (stem.starts_with('.') || !name.starts_with('.')))
        .collect();
    names.sort();
    match names.as_slice() {
        [] => Completion {
            text: None,
            note: Some(words::NO_DIRECTORY_MATCHES),
        },
        [only] => Completion {
            text: Some(format!("{head}{only}{}", std::path::MAIN_SEPARATOR)),
            note: None,
        },
        several => Completion {
            text: Some(format!("{head}{}", common_start(several))),
            note: Some(words::directories_match(several)),
        },
    }
}

/// The start every name shares.
fn common_start(names: &[String]) -> String {
    let Some((first, rest)) = names.split_first() else {
        return String::new();
    };
    let shared = first
        .char_indices()
        .map(|(at, c)| at + c.len_utf8())
        .take_while(|end| rest.iter().all(|name| name.starts_with(&first[..*end])))
        .last()
        .unwrap_or(0);
    first[..shared].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch tree with these directories under it and a file `notes.txt`.
    fn tree(name: &str, dirs: &[&str]) -> String {
        let root = std::env::temp_dir().join(format!("rmule-path-{name}-{}", std::process::id()));
        for dir in dirs {
            std::fs::create_dir_all(root.join(dir)).expect("make a scratch directory");
        }
        std::fs::write(root.join("notes.txt"), "not a directory").expect("write a scratch file");
        let mut text = root.display().to_string();
        text.push(std::path::MAIN_SEPARATOR);
        text
    }

    #[test]
    fn one_match_completes_with_its_separator() {
        let root = tree("one", &["films", "music"]);
        let completion = complete_directory(&format!("{root}fi"));
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(completion.text, Some(format!("{root}films{sep}")));
        assert_eq!(completion.note, None);
    }

    #[test]
    fn several_matches_grow_to_what_they_share_and_are_named() {
        let root = tree("several", &["anime-new", "anime-old", "books"]);
        let completion = complete_directory(&format!("{root}a"));
        assert_eq!(completion.text, Some(format!("{root}anime-")));
        let note = completion.note.expect("the choices are said").to_string();
        assert!(
            note.contains("anime-new") && note.contains("anime-old"),
            "{note}"
        );
    }

    #[test]
    fn a_file_is_no_completion_and_nothing_changes() {
        let root = tree("file", &["music"]);
        let completion = complete_directory(&format!("{root}no"));
        assert_eq!(completion.text, None);
        assert_eq!(completion.note, Some(words::NO_DIRECTORY_MATCHES));
    }

    #[test]
    fn a_hidden_directory_takes_a_typed_dot() {
        let root = tree("hidden", &[".cache", "cachet"]);
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            complete_directory(&format!("{root}.c")).text,
            Some(format!("{root}.cache{sep}"))
        );
        assert_eq!(
            complete_directory(&root).text,
            Some(format!("{root}cachet{sep}")),
            "and stays out of an empty stem"
        );
    }

    #[test]
    fn an_empty_field_starts_from_home() {
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(complete_directory("").text, Some(format!("~{sep}")));
        assert_eq!(complete_directory("~").text, Some(format!("~{sep}")));
    }
}
