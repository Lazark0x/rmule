//! **A download row's part path slot**: the `.part` file a row names, or the
//! record that a terminal row gave that path up.
//!
//! The slot is one unique-index value, so a released row must still hold a
//! text no other row can hold. Stored, the two states are one string: a held
//! path's own text, and for a released one `"\0released:{key}"` — a NUL cannot
//! occur in a path. That encoding is what store version 9 writes and must not
//! move; only this file reads or writes it.

use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Where a row's `.part` file lives, or that no file does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::store::download) enum PartPathSlot {
    /// The path the row writes, stored lossily as text.
    Held(String),
    /// The path was given up to a new row; `key` is the row's own primary
    /// key, and `stand_in` its stored text, the only value the unique index
    /// sees.
    Released { key: u64, stand_in: String },
}

const RELEASED_PREFIX: &str = "\0released:";

impl PartPathSlot {
    pub(in crate::store::download) fn held(path: &Path) -> Self {
        Self::Held(path.to_string_lossy().into_owned())
    }

    /// The slot of the row keyed `key` once it has given its path up.
    pub(in crate::store::download) fn released(key: u64) -> Self {
        Self::Released {
            key,
            stand_in: format!("{RELEASED_PREFIX}{key}"),
        }
    }

    /// The path a row still writes; `None` once it was released.
    pub(in crate::store::download) fn held_path(&self) -> Option<&str> {
        match self {
            Self::Held(path) => Some(path),
            Self::Released { .. } => None,
        }
    }

    /// The unique index's value: the path's text, or the stand-in.
    pub(in crate::store::download) fn index_text(&self) -> &str {
        match self {
            Self::Held(path) => path,
            Self::Released { stand_in, .. } => stand_in,
        }
    }

    /// The slot a stored text stands for.
    pub(in crate::store::download) fn from_stored(text: String) -> Self {
        let key = text
            .strip_prefix(RELEASED_PREFIX)
            .and_then(|key| key.parse().ok());
        match key {
            Some(key) => Self::Released {
                key,
                stand_in: text,
            },
            None => Self::Held(text),
        }
    }
}

impl Serialize for PartPathSlot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.index_text())
    }
}

impl<'de> Deserialize<'de> for PartPathSlot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from_stored)
    }
}
