//! The one thing the legs of this binary share: reading the TOML case files
//! under `tests/fixtures/`, which three legs did with three copies of the same
//! `read_dir` body.
//!
//! Nothing outside this crate reads these fixtures, so they stay here — a
//! second crate wanting them would move this to `rmule-testkit`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

/// Every `.toml` case under `tests/fixtures/<family>`, sorted by path so a
/// failure names the same case on every run. A leg wanting a sidecar file
/// next to the case (`.bin`, say) reads the paths and parses them itself with
/// [`case`]; one wanting the cases alone takes [`cases`].
pub fn case_paths(family: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(family);
    let mut entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{family} fixture directory: {error}"))
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

/// One case parsed into the shape the leg asserts against; a malformed file
/// names itself in the panic.
pub fn case<T: DeserializeOwned>(path: &Path) -> T {
    let raw = fs::read_to_string(path).expect("read fixture");
    toml::from_str(&raw).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Every case of a family, parsed.
pub fn cases<T: DeserializeOwned>(family: &str) -> Vec<T> {
    case_paths(family).iter().map(|path| case(path)).collect()
}
