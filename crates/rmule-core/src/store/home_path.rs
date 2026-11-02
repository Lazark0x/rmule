//! **A path as the store keeps it**: relative to the Data Directory when it
//! lies inside it, so moving that directory carries it; absolute otherwise,
//! since a directory the operator set keeps what was placed in it (ADR-0083).
//! Stored, it is the path's text and nothing else, lossy where the path is
//! not valid UTF-8. The one rule for a download row's paths and the Temp
//! Directory setting.

use std::path::{Path, PathBuf};

use rmule_store::Store;
use serde::{Deserialize, Serialize};

/// A path text read against the Data Directory of the store that holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(in crate::store) struct HomePath(String);

impl HomePath {
    /// The Data Directory `store` lies in; `None` for a store with no file.
    pub(in crate::store) fn home_of(store: &Store) -> Option<&Path> {
        store.file().and_then(Path::parent)
    }

    /// `path` as the store keeps it, `home` being the Data Directory of a
    /// store that has one.
    pub(in crate::store) fn new(path: &Path, home: Option<&Path>) -> Self {
        let stored = home
            .and_then(|home| path.strip_prefix(home).ok())
            .unwrap_or(path);
        Self(stored.to_string_lossy().into_owned())
    }

    /// A text the store already holds.
    pub(in crate::store) const fn from_stored(text: String) -> Self {
        Self(text)
    }

    /// The path, read against `home`.
    pub(in crate::store) fn path(&self, home: Option<&Path>) -> PathBuf {
        home.map_or_else(|| self.0.as_str().into(), |home| home.join(&self.0))
    }

    /// The stored text.
    pub(in crate::store) fn text(&self) -> &str {
        &self.0
    }
}
