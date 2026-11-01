//! **A path as a download row stores it**: relative to the Data Directory
//! when it lies inside it, so moving that directory carries every download;
//! absolute otherwise, since a directory the operator set keeps what was
//! placed in it (ADR-0083). Stored, it is the path's text and nothing else,
//! lossy where the path is not valid UTF-8.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A path text read against the Data Directory of the store that holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(in crate::store::download) struct HomePath(String);

impl HomePath {
    /// `path` as a row stores it, `home` being the Data Directory of a store
    /// that has one.
    pub(in crate::store::download) fn new(path: &Path, home: Option<&Path>) -> Self {
        let stored = home
            .and_then(|home| path.strip_prefix(home).ok())
            .unwrap_or(path);
        Self(stored.to_string_lossy().into_owned())
    }

    /// A text a row already holds.
    pub(in crate::store::download) const fn from_stored(text: String) -> Self {
        Self(text)
    }

    /// The path, read against `home`.
    pub(in crate::store::download) fn path(&self, home: Option<&Path>) -> PathBuf {
        home.map_or_else(|| self.0.as_str().into(), |home| home.join(&self.0))
    }

    /// The stored text.
    pub(in crate::store::download) fn text(&self) -> &str {
        &self.0
    }
}
