//! The **Driver Row**: the flat TOML a bench driver writes for a harness flow
//! to parse back into claims.
//!
//! This binary carries no serialiser and a row is a handful of scalars, so the
//! rows are rendered by hand — and their spelling is a read contract with
//! `tools/interop-harness`, whose `DriverRow` reader turns them back into typed
//! facts. Counterparty text reaches these rows (nicknames, close reasons, log
//! lines), so every string value is escaped: a stray quote would make the run
//! dir unreadable to the flow that has to judge it.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};

/// A driver row under construction: TOML key/value lines in the order they were
/// added.
pub(crate) struct Row {
    out: String,
}

impl Row {
    /// Open a row with a comment header naming what wrote it.
    pub(crate) fn new(header: &str) -> Self {
        let mut out = String::new();
        for line in header.lines() {
            let _ = writeln!(out, "# {line}");
        }
        Self { out }
    }

    /// A string value, escaped.
    pub(crate) fn str(&mut self, key: &str, value: &str) -> &mut Self {
        let _ = writeln!(self.out, "{key} = \"{}\"", escape(value));
        self
    }

    /// A boolean value.
    pub(crate) fn bool(&mut self, key: &str, value: bool) -> &mut Self {
        let _ = writeln!(self.out, "{key} = {value}");
        self
    }

    /// An integer value.
    pub(crate) fn int(&mut self, key: &str, value: i64) -> &mut Self {
        let _ = writeln!(self.out, "{key} = {value}");
        self
    }

    /// An array of strings, one line, escaped.
    pub(crate) fn list(&mut self, key: &str, values: &[String]) -> &mut Self {
        let rendered = values
            .iter()
            .map(|value| format!("\"{}\"", escape(value)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(self.out, "{key} = [{rendered}]");
        self
    }

    /// The rendered row.
    pub(crate) fn finish(self) -> String {
        self.out
    }
}

/// Print the row and write it, creating the parent directory.
///
/// # Errors
/// If the file cannot be written.
pub(crate) fn write_row(path: &Path, row: Row) -> Result<()> {
    let text = row.finish();
    print!("{text}");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, &text).with_context(|| format!("write {}", path.display()))
}

/// Escape a TOML basic-string value.
fn escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c if (c as u32) < 0x20 => vec!['?'],
            c => vec![c],
        })
        .collect()
}
