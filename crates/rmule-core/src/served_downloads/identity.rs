//! Which file a Served Download's bytes are read from, and how a read checks
//! it opened that file (ADR-0113 §"Reading a part file").

use std::path::PathBuf;
use std::time::SystemTime;

use crate::file_key::FileKey;

/// The file a Served Download's verified bytes are read from, as the writer
/// that last held it read it through its handle. Memory only: every start
/// re-reads the parts it vouches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PartFileIdentity {
    /// Which file it is.
    pub(crate) key: FileKey,
    /// Its length and modification time as the run left it; `None` while a
    /// run writes it, when only the key is compared.
    pub(crate) at_rest: Option<AtRest>,
}

/// A file's length and modification time with nobody writing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AtRest {
    /// Its length in bytes.
    pub(crate) len: u64,
    /// When it was last written.
    pub(crate) modified: SystemTime,
}

impl PartFileIdentity {
    /// The identity of the file `key` names while a run writes it: only its
    /// key is compared.
    pub(crate) const fn while_written(key: FileKey) -> Self {
        Self { key, at_rest: None }
    }

    /// The identity of the file `meta` describes, `key` its file key, with
    /// nobody writing it: its length and time are compared too. `None` when
    /// the system keeps no modification time.
    pub(crate) fn at_rest(key: FileKey, meta: &std::fs::Metadata) -> Option<Self> {
        Some(Self {
            key,
            at_rest: Some(AtRest {
                len: meta.len(),
                modified: meta.modified().ok()?,
            }),
        })
    }

    /// Whether the file an opened handle reports — `key`, and `meta` for its
    /// length and time — is this one: the key always, the length and time
    /// only when the identity holds them, since a run moves both as it
    /// writes.
    pub(crate) fn holds(&self, key: FileKey, meta: &std::fs::Metadata) -> bool {
        self.key == key
            && self.at_rest.is_none_or(|rest| {
                rest.len == meta.len() && meta.modified().ok() == Some(rest.modified)
            })
    }
}

/// How a read of a Served Download's bytes is checked before it reads
/// (ADR-0113 §"Reading a part file"): the file it opens must be the one the
/// identity names, and a path that names nothing gives way to the other
/// once — the completion move puts the bytes at one of the two at every
/// instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadCheck {
    /// The file the entry's range was read from; `None` reads nothing.
    pub(crate) identity: Option<PartFileIdentity>,
    /// The download's other path.
    pub(crate) other: PathBuf,
}
