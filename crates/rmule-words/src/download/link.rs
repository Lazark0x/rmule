//! The words for the Transfers tab's Add-link form: why it refused what was
//! pasted, the fields a link carried that no client reads, and a link for a
//! download already running.

use super::super::Sentence;
use super::super::units::count;

/// A re-add of a file already downloading.
#[must_use]
pub fn already_downloading(name: &str) -> Sentence {
    Sentence::owned(format!("already downloading as {name} — see Transfers (3)"))
}

/// Why the Transfers tab's Add-link form refused what was pasted: each code
/// the form can reach, so its sentence is chosen here and nowhere else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkRefusal {
    /// Nothing was pasted.
    Empty,
    /// The text does not read as an eD2k link at all, or breaks its layout.
    Unreadable,
    /// The file hash or a part hash does not read.
    BadHash,
    /// The size is past what eD2k carries.
    TooLarge,
    /// The size is zero.
    ZeroSize,
    /// A field appears twice; the name is the link's own text.
    DuplicateField(String),
    /// A server or server-list link: it names no file.
    NotAFileLink,
    /// A download of the file is in Transfers and the link names no source
    /// that could join it (a link that does is sent: core adds its sources).
    AlreadyDownloading {
        /// The name the download runs under.
        name: String,
    },
}

/// The Add-link form's refusal, under its field.
#[must_use]
pub fn link_refused(refusal: &LinkRefusal) -> Sentence {
    Sentence::owned(match refusal {
        LinkRefusal::Empty => "paste an eD2k file link: ed2k://|file|name|size|hash|/".to_string(),
        LinkRefusal::Unreadable => {
            "not a readable eD2k link — check that it was copied whole".to_string()
        }
        LinkRefusal::BadHash => {
            "the link's hash does not read — check that it was copied whole".to_string()
        }
        LinkRefusal::TooLarge => {
            "the link names a file larger than eD2k allows (256 GiB)".to_string()
        }
        LinkRefusal::ZeroSize => "the link names a file of zero bytes".to_string(),
        LinkRefusal::DuplicateField(field) => {
            format!("the link carries its `{field}` field twice")
        }
        LinkRefusal::NotAFileLink => {
            "a server link, not a file link — add servers in Networks (1)".to_string()
        }
        LinkRefusal::AlreadyDownloading { name } => {
            format!("already downloading as {name}; the link names no source to add")
        }
    })
}

/// The fields a pasted link carried that no client reads, said once it is
/// added (ADR-0089); `None` when it carried none.
#[must_use]
pub fn link_fields_skipped(fields: &[String]) -> Option<Sentence> {
    let quoted: Vec<String> = fields.iter().map(|name| format!("`{name}`")).collect();
    match quoted.as_slice() {
        [] => None,
        [one] => Some(Sentence::owned(format!(
            "ignored the field {one} the link carried, which no client reads"
        ))),
        many => Some(Sentence::owned(format!(
            "ignored the fields {} the link carried, which no client reads",
            many.join(", ")
        ))),
    }
}

/// A second link for a running download: its sources joined the run instead
/// of a second download being made (ADR-0089). `new` counts
/// only the sources the run did not already know.
#[must_use]
pub fn link_sources_added(name: &str, new: usize) -> Sentence {
    Sentence::owned(format!(
        "already downloading {name}; {} from the link",
        count(
            u64::try_from(new).unwrap_or(u64::MAX),
            "new source",
            "new sources"
        )
    ))
}
