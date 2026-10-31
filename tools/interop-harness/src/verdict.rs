//! One typed verdict and its one writer.
//!
//! Every flow ends in a [`Verdict`], and [`write`] is the only way one reaches
//! a run dir: a `<flow>-verdict.toml` whose top-level `verdict` is one of the
//! words below. The Run Record, the exit status and a person reading the file
//! all read the same word, so a run cannot say two things at once.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Serialize, Serializer};

/// What a run's evidence came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The counterparty did the thing and every claim the run owes held.
    Pass,
    /// The topology stood up and the target exchange did not fire, or a
    /// required leg was not driven: the honest partial.
    Observed,
    /// A claim fell, or the topology never stood up.
    Fail,
    /// The flow's gate refused to run it.
    Skipped,
    /// Nothing was judged.
    NotRun,
    /// The run stood up and the exchange it reads was never drawn.
    NotDrawn,
    /// A control the reading depends on did not hold.
    Blocked,
    /// Kad's TCP check read open and its UDP check stayed short.
    TcpOpen,
    /// A run against the public network; it promotes nothing (ADR-0045).
    Smoke,
}

impl Verdict {
    const ALL: [Self; 9] = [
        Self::Pass,
        Self::Observed,
        Self::Fail,
        Self::Skipped,
        Self::NotRun,
        Self::NotDrawn,
        Self::Blocked,
        Self::TcpOpen,
        Self::Smoke,
    ];

    /// The word a verdict file holds.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Observed => "OBSERVED",
            Self::Fail => "FAIL",
            Self::Skipped => "SKIPPED",
            Self::NotRun => "NOT-RUN",
            Self::NotDrawn => "NOT-DRAWN",
            Self::Blocked => "BLOCKED",
            Self::TcpOpen => "TCP_OPEN",
            Self::Smoke => "SMOKE",
        }
    }

    /// The verdict `word` names, or `None` for a word outside the list.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verdict| verdict.word() == word)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.word())
    }
}

impl Serialize for Verdict {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.word())
    }
}

/// The file `flow`'s verdict lands in under `dir`.
#[must_use]
pub fn path(dir: &Path, flow: &str) -> PathBuf {
    dir.join(format!("{flow}-verdict.toml"))
}

/// Write `body` as `flow`'s verdict file under `dir`, and return its path.
///
/// # Errors
/// If `body` does not serialize to a TOML table holding a known `verdict`, or
/// the file cannot be written.
pub fn write(dir: &Path, flow: &str, body: &impl Serialize) -> Result<PathBuf> {
    let text =
        toml::to_string_pretty(body).with_context(|| format!("serialize {flow}'s verdict"))?;
    write_rendered(dir, flow, &text)
}

/// Write `flow`'s verdict file from TOML text a scorer renders by hand, for the
/// comments it carries; the text meets the same checks as a typed body.
///
/// # Errors
/// If `text` is not TOML holding a known `verdict`, or the file cannot be
/// written.
pub fn write_rendered(dir: &Path, flow: &str, text: &str) -> Result<PathBuf> {
    let table: toml::Table = text
        .parse()
        .with_context(|| format!("{flow}'s verdict is not TOML"))?;
    let Some(word) = table.get("verdict").and_then(toml::Value::as_str) else {
        bail!("{flow}'s verdict holds no `verdict` word");
    };
    if Verdict::from_word(word).is_none() {
        bail!("{flow}'s verdict reads `{word}`, which is no verdict");
    }
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = path(dir, flow);
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Every verdict file under `dir`, in no set order. `None` stands for a file
/// that is unreadable or holds no known word: it proves nothing, and it must
/// not vanish from the count either.
#[must_use]
pub fn found_under(dir: &Path) -> Vec<Option<Verdict>> {
    let mut found = Vec::new();
    collect(dir, &mut found);
    found
}

fn collect(dir: &Path, found: &mut Vec<Option<Verdict>>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, found);
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("-verdict.toml"))
        {
            found.push(read(&path));
        }
    }
}

fn read(path: &Path) -> Option<Verdict> {
    let table: toml::Table = fs::read_to_string(path).ok()?.parse().ok()?;
    Verdict::from_word(table.get("verdict")?.as_str()?)
}

#[cfg(test)]
mod tests {
    use super::{Verdict, found_under, write, write_rendered};

    #[derive(serde::Serialize)]
    struct Body {
        verdict: &'static str,
    }

    /// The writer stops at what the Run Record could not read back: a foreign
    /// word, no word, and text that is not TOML (a repeated key among them).
    #[test]
    fn the_writer_refuses_what_could_not_be_read_back() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write(dir.path(), "a", &Body { verdict: "GREEN" }).is_err());
        assert!(write_rendered(dir.path(), "a", "claims = 3\n").is_err());
        assert!(write_rendered(dir.path(), "a", "verdict = \"PASS\"\nx = 1\nx = 2\n").is_err());
        assert!(found_under(dir.path()).is_empty());
        write(dir.path(), "a", &Body { verdict: "NOT-RUN" }).unwrap();
        assert_eq!(found_under(dir.path()), [Some(Verdict::NotRun)]);
    }
}
