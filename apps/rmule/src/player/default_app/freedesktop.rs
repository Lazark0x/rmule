//! The freedesktop **Default App** (ADR-0114, "The Default App"), read from
//! the files the specs name rather than asked of a process: the extension's
//! MIME type from shared-mime-info's `globs2` files, then the app the MIME
//! Applications spec's `mimeapps.list` files name for that type, in the
//! spec's order. Nothing is started to ask, so a test hands the lookup
//! directories of its own. Only `*.<extension>` globs name an extension's
//! type, and a type's parent types are not walked.

use std::collections::HashSet;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Where the freedesktop files lie, each list most important first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dirs {
    /// `$XDG_CONFIG_HOME`, then each of `$XDG_CONFIG_DIRS`.
    pub config: Vec<PathBuf>,
    /// `$XDG_DATA_HOME`, then each of `$XDG_DATA_DIRS`.
    pub data: Vec<PathBuf>,
    /// `$XDG_CURRENT_DESKTOP`'s names, lowercased, for the desktop-specific
    /// `mimeapps.list` files.
    pub desktops: Vec<String>,
}

impl Dirs {
    /// The directories this process's environment names.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_vars(|name| std::env::var_os(name))
    }

    /// The directories the variables `var` reads name, with the Base
    /// Directory spec's defaults: a home directory unset, empty or relative
    /// falls back under `$HOME`, an unset or empty list to the spec's list,
    /// and a relative entry is dropped.
    pub(super) fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Self {
        let home = var("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_absolute());
        let own = |name: &str, under_home: &str| {
            var(name)
                .map(PathBuf::from)
                .filter(|dir| dir.is_absolute())
                .or_else(|| home.as_ref().map(|home| home.join(under_home)))
        };
        let listed = |name: &str, default: &str| {
            let list = var(name)
                .filter(|list| !list.is_empty())
                .unwrap_or_else(|| default.into());
            std::env::split_paths(&list)
                .filter(|dir| dir.is_absolute())
                .collect::<Vec<_>>()
        };
        let desktops = var("XDG_CURRENT_DESKTOP")
            .map(|names| {
                names
                    .to_string_lossy()
                    .split(':')
                    .filter(|name| !name.is_empty())
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        Self {
            config: own("XDG_CONFIG_HOME", ".config")
                .into_iter()
                .chain(listed("XDG_CONFIG_DIRS", "/etc/xdg"))
                .collect(),
            data: own("XDG_DATA_HOME", ".local/share")
                .into_iter()
                .chain(listed("XDG_DATA_DIRS", "/usr/local/share:/usr/share"))
                .collect(),
            desktops,
        }
    }
}

/// The desktop entry of the app that opens files with `extension`, `None`
/// when no type has the extension or no installed app opens the type.
///
/// # Errors
/// A file the lookup reads that is there but cannot be read.
pub fn lookup(dirs: &Dirs, extension: &str) -> io::Result<Option<PathBuf>> {
    match mime_type(dirs, extension)? {
        Some(mime) => app_for(dirs, &mime),
        None => Ok(None),
    }
}

/// The MIME type the `globs2` files give `*.<extension>`: the heaviest glob,
/// the first read among equals, the user's files read first.
fn mime_type(dirs: &Dirs, extension: &str) -> io::Result<Option<String>> {
    let folded = extension.to_lowercase();
    let mut heaviest: Option<(u32, String)> = None;
    for dir in &dirs.data {
        let Some(text) = read(&dir.join("mime").join("globs2"))? else {
            continue;
        };
        for (weight, mime) in globs(&text, extension, &folded) {
            if heaviest.as_ref().is_none_or(|(most, _)| weight > *most) {
                heaviest = Some((weight, mime.to_string()));
            }
        }
    }
    Ok(heaviest.map(|(_, mime)| mime))
}

/// The weight and MIME type of each `weight:type:glob[:flags]` line of a
/// `globs2` text whose glob is `*.<extension>`: compared case folded, or as
/// written when the flags hold `cs`.
fn globs<'a>(
    text: &'a str,
    extension: &'a str,
    folded: &'a str,
) -> impl Iterator<Item = (u32, &'a str)> + 'a {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(move |line| {
            let mut fields = line.split(':');
            let weight = fields.next()?.parse().ok()?;
            let mime = fields.next()?;
            let suffix = fields.next()?.strip_prefix("*.")?;
            let case_sensitive = fields
                .next()
                .is_some_and(|flags| flags.split(',').any(|flag| flag == "cs"));
            let matched = if case_sensitive {
                suffix == extension
            } else {
                suffix.to_lowercase() == folded
            };
            matched.then_some((weight, mime))
        })
}

/// The desktop entry of the app the lists name for `mime`: the first
/// installed one under *Default Applications*, else under *Added
/// Associations*, else in a data directory's `mimeinfo.cache`, past any one
/// a list names under *Removed Associations*.
fn app_for(dirs: &Dirs, mime: &str) -> io::Result<Option<PathBuf>> {
    let mut lists = Vec::new();
    for path in mimeapps_lists(dirs) {
        lists.extend(read(&path)?);
    }
    let mut caches = Vec::new();
    for dir in &dirs.data {
        caches.extend(read(&dir.join("applications").join("mimeinfo.cache"))?);
    }
    let removed: HashSet<&str> = lists
        .iter()
        .flat_map(|text| entries(text, "Removed Associations", mime))
        .collect();
    let defaults = lists
        .iter()
        .flat_map(|text| entries(text, "Default Applications", mime));
    let associated = lists
        .iter()
        .flat_map(|text| entries(text, "Added Associations", mime))
        .chain(
            caches
                .iter()
                .flat_map(|text| entries(text, "MIME Cache", mime)),
        )
        .filter(|id| !removed.contains(id));
    Ok(defaults
        .chain(associated)
        .find_map(|id| installed(dirs, id)))
}

/// The `mimeapps.list` files in the spec's order: each config directory,
/// then each data directory's `applications`, and in each the
/// desktop-specific lists before the plain one.
fn mimeapps_lists(dirs: &Dirs) -> Vec<PathBuf> {
    let applications = dirs.data.iter().map(|dir| dir.join("applications"));
    dirs.config
        .iter()
        .cloned()
        .chain(applications)
        .flat_map(|dir| {
            dirs.desktops
                .iter()
                .map(|desktop| dir.join(format!("{desktop}-mimeapps.list")))
                .chain(std::iter::once(dir.join("mimeapps.list")))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The desktop file IDs a desktop-entry-style `text` lists for `mime` in its
/// `[group]`, in their order.
fn entries<'a>(text: &'a str, group: &'a str, mime: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    let mut current = "";
    text.lines()
        .filter_map(move |line| {
            let line = line.trim();
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            {
                current = name;
                return None;
            }
            let (key, ids) = line.split_once('=')?;
            (current == group && key.trim() == mime).then_some(ids)
        })
        .flat_map(|ids| ids.split(';'))
        .map(str::trim)
        .filter(|id| !id.is_empty())
}

/// The desktop file the desktop file ID `id` names, in the first data directory
/// that holds it: under `applications` as named, or with one `-` read as a
/// subdirectory, as the spec maps `kde-foo.desktop` to `kde/foo.desktop`. An
/// ID is a file name, so one holding a `/` names nothing.
fn installed(dirs: &Dirs, id: &str) -> Option<PathBuf> {
    if !id.ends_with(".desktop") || id.contains('/') {
        return None;
    }
    let names: Vec<PathBuf> = std::iter::once(PathBuf::from(id))
        .chain(
            id.match_indices('-')
                .map(|(at, _)| Path::new(&id[..at]).join(&id[at + 1..])),
        )
        .collect();
    dirs.data.iter().find_map(|dir| {
        let applications = dir.join("applications");
        names
            .iter()
            .map(|name| applications.join(name))
            .find(|path| path.is_file())
    })
}

/// `path`'s text, `None` when it is not there.
fn read(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
