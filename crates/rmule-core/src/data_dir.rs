//! Where rmule keeps its data, and where the operator's home is: the one rule
//! every front end resolves by, so `rmule` and `rmule-cli` open the same
//! Durable Store. Pure: the caller hands in how a variable is read, and core
//! never reads the environment itself.
//!
//! On Unix the data directory is the first of `--data-dir`, `RMULE_DATA`,
//! `$XDG_DATA_HOME/rmule` and `$HOME/.local/share/rmule`. On Windows it is
//! the first of `--data-dir`, `RMULE_DATA` and `%LOCALAPPDATA%\rmule`: the
//! local application data, not the roaming `%APPDATA%`, because part files
//! run to gigabytes and a roaming profile is copied whole at every sign-in
//! and sign-out. Windows reads neither `XDG_DATA_HOME` nor `HOME`: a shell
//! such as Git Bash sets `HOME`, and the data directory must not change with
//! the shell rmule was started from. An empty variable counts as unset
//! everywhere.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Which rule picked the data directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataDirSource {
    /// `--data-dir`.
    Flag,
    /// `RMULE_DATA`.
    RmuleData,
    /// `$XDG_DATA_HOME/rmule` (Unix).
    XdgDataHome,
    /// `$HOME/.local/share/rmule` (Unix).
    Home,
    /// `%LOCALAPPDATA%\rmule` (Windows).
    LocalAppData,
}

/// The data directory as resolved: where it is, and which rule picked it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataDir {
    /// The directory.
    pub path: PathBuf,
    /// The rule that picked it.
    pub source: DataDirSource,
}

/// The rules after the flag, in the order this platform tries them.
#[cfg(not(windows))]
const NATIVE_RULES: &[DataDirSource] = UNIX_RULES;
#[cfg(windows)]
const NATIVE_RULES: &[DataDirSource] = WINDOWS_RULES;

#[cfg(any(test, not(windows)))]
const UNIX_RULES: &[DataDirSource] = &[
    DataDirSource::RmuleData,
    DataDirSource::XdgDataHome,
    DataDirSource::Home,
];
#[cfg(any(test, windows))]
const WINDOWS_RULES: &[DataDirSource] = &[DataDirSource::RmuleData, DataDirSource::LocalAppData];

/// The data directory and the rule that picked it: `flag` first, then this
/// platform's variables in the order the module names. `env` reads a
/// variable; it is the process environment in a binary.
pub fn resolve_data_dir(
    flag: Option<&Path>,
    env: impl Fn(&str) -> Option<OsString>,
) -> Option<DataDir> {
    resolve_by(NATIVE_RULES, flag, env)
}

/// The operator's home directory, which no shared directory may be: `HOME`
/// on Unix, `USERPROFILE` on Windows, an empty variable counting as unset.
pub fn home_dir(env: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn resolve_by(
    rules: &[DataDirSource],
    flag: Option<&Path>,
    env: impl Fn(&str) -> Option<OsString>,
) -> Option<DataDir> {
    if let Some(dir) = flag {
        return Some(DataDir {
            path: dir.to_path_buf(),
            source: DataDirSource::Flag,
        });
    }
    rules.iter().find_map(|&source| {
        let (name, below) = match source {
            DataDirSource::Flag => return None,
            DataDirSource::RmuleData => ("RMULE_DATA", None),
            DataDirSource::XdgDataHome => ("XDG_DATA_HOME", Some("rmule")),
            DataDirSource::Home => ("HOME", Some(".local/share/rmule")),
            DataDirSource::LocalAppData => ("LOCALAPPDATA", Some("rmule")),
        };
        let base = PathBuf::from(env(name).filter(|value| !value.is_empty())?);
        let path = match below {
            Some(below) => base.join(below),
            None => base,
        };
        Some(DataDir { path, source })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            vars.iter()
                .find(|(var, _)| *var == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    fn picked(rules: &[DataDirSource], vars: &[(&str, &str)]) -> Option<(PathBuf, DataDirSource)> {
        resolve_by(rules, None, from(vars)).map(|dir| (dir.path, dir.source))
    }

    const EVERY_VARIABLE: &[(&str, &str)] = &[
        ("RMULE_DATA", "/rmule-data"),
        ("XDG_DATA_HOME", "/xdg"),
        ("HOME", "/home/u"),
        ("LOCALAPPDATA", r"C:\Users\u\AppData\Local"),
    ];

    #[test]
    fn the_flag_beats_every_variable() {
        let flag = Path::new("/flag");
        for rules in [UNIX_RULES, WINDOWS_RULES] {
            assert_eq!(
                resolve_by(rules, Some(flag), from(EVERY_VARIABLE)),
                Some(DataDir {
                    path: flag.to_path_buf(),
                    source: DataDirSource::Flag
                })
            );
        }
    }

    #[test]
    fn unix_tries_rmule_data_then_xdg_then_home() {
        assert_eq!(
            picked(UNIX_RULES, EVERY_VARIABLE),
            Some(("/rmule-data".into(), DataDirSource::RmuleData))
        );
        assert_eq!(
            picked(UNIX_RULES, &EVERY_VARIABLE[1..]),
            Some(("/xdg/rmule".into(), DataDirSource::XdgDataHome))
        );
        assert_eq!(
            picked(UNIX_RULES, &EVERY_VARIABLE[2..]),
            Some((
                PathBuf::from("/home/u").join(".local/share/rmule"),
                DataDirSource::Home
            ))
        );
        assert_eq!(picked(UNIX_RULES, &EVERY_VARIABLE[3..]), None);
    }

    #[test]
    fn windows_tries_rmule_data_then_local_app_data_and_never_home() {
        assert_eq!(
            picked(WINDOWS_RULES, EVERY_VARIABLE),
            Some(("/rmule-data".into(), DataDirSource::RmuleData))
        );
        assert_eq!(
            picked(WINDOWS_RULES, &EVERY_VARIABLE[1..]),
            Some((
                PathBuf::from(r"C:\Users\u\AppData\Local").join("rmule"),
                DataDirSource::LocalAppData
            ))
        );
        assert_eq!(picked(WINDOWS_RULES, &EVERY_VARIABLE[1..3]), None);
    }

    #[test]
    fn an_empty_variable_counts_as_unset() {
        let vars = [
            ("RMULE_DATA", ""),
            ("XDG_DATA_HOME", "/xdg"),
            ("LOCALAPPDATA", ""),
        ];
        assert_eq!(
            picked(UNIX_RULES, &vars),
            Some(("/xdg/rmule".into(), DataDirSource::XdgDataHome))
        );
        assert_eq!(picked(WINDOWS_RULES, &vars), None);
        assert_eq!(home_dir(from(&[("HOME", ""), ("USERPROFILE", "")])), None);
    }

    #[test]
    fn the_home_is_read_from_this_platforms_variable() {
        let vars = [("HOME", "/home/u"), ("USERPROFILE", r"C:\Users\u")];
        let expected = if cfg!(windows) {
            r"C:\Users\u"
        } else {
            "/home/u"
        };
        assert_eq!(home_dir(from(&vars)), Some(PathBuf::from(expected)));
    }
}
