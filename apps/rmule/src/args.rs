//! The command line of `rmule` (ADR-0076 §Arguments): what an invocation asks
//! for, read before anything touches the data directory. The rule that
//! resolves that directory is core's, re-exported here.
//!
//! This module holds codes only — which option, which failure, which rule
//! picked the directory. Every sentence the operator reads about them, the
//! usage and `--version` included, is written in [`crate::words::front_door`].

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::run_log::Level;

/// What an invocation asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invocation {
    /// Print the usage and exit.
    Help(RunArgs),
    /// Print the build's version and exit.
    Version,
    /// Run the app.
    Run(RunArgs),
}

/// The options that shape a run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// `--data-dir`: beats every environment rule.
    pub data_dir: Option<PathBuf>,
    /// `--log-level`: beats the stored *Full run log* preference.
    pub log_level: Option<Level>,
}

/// An option that takes a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueOption {
    /// `--data-dir`.
    DataDir,
    /// `--log-level`.
    LogLevel,
}

/// Why a command line was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgsError {
    /// An argument that is no option of `rmule`, as given.
    Unknown(OsString),
    /// An option given without its value, or with an empty one.
    MissingValue(ValueOption),
    /// A `--log-level` that names no level, as given.
    UnknownLevel(OsString),
    /// An option given twice.
    Repeated(ValueOption),
}

/// Read the arguments after the program name.
///
/// # Errors
///
/// The first argument that is not a valid option or value.
pub fn parse<I>(args: I) -> Result<Invocation, ArgsError>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut args = args.into_iter().map(Into::into);
    let mut run = RunArgs::default();
    let (mut help, mut version) = (false, false);
    while let Some(arg) = args.next() {
        let (name, inline) = split_inline(&arg);
        match name.to_str() {
            Some("-h" | "--help") if inline.is_none() => help = true,
            Some("-V" | "--version") if inline.is_none() => version = true,
            Some("--data-dir") => {
                let value = take_value(inline, &mut args, ValueOption::DataDir)?;
                if run.data_dir.replace(PathBuf::from(value)).is_some() {
                    return Err(ArgsError::Repeated(ValueOption::DataDir));
                }
            }
            Some("--log-level") => {
                let value = take_value(inline, &mut args, ValueOption::LogLevel)?;
                let level = match value.to_str() {
                    Some("lean") => Level::Lean,
                    Some("detailed") => Level::Full,
                    _ => return Err(ArgsError::UnknownLevel(value)),
                };
                if run.log_level.replace(level).is_some() {
                    return Err(ArgsError::Repeated(ValueOption::LogLevel));
                }
            }
            _ => return Err(ArgsError::Unknown(arg.clone())),
        }
    }
    Ok(if help {
        Invocation::Help(run)
    } else if version {
        Invocation::Version
    } else {
        Invocation::Run(run)
    })
}

/// `--name=value` split at its first `=` byte; any other argument whole. On
/// Unix an argument is bytes, so the value may be any bytes, as the
/// two-argument form's is.
#[cfg(unix)]
fn split_inline(arg: &OsStr) -> (&OsStr, Option<OsString>) {
    use std::os::unix::ffi::OsStrExt;
    let bytes = arg.as_bytes();
    match bytes.iter().position(|byte| *byte == b'=') {
        Some(at) if bytes.starts_with(b"--") => (
            OsStr::from_bytes(&bytes[..at]),
            Some(OsStr::from_bytes(&bytes[at + 1..]).to_owned()),
        ),
        _ => (arg, None),
    }
}

/// `--name=value` split at its first `=`; any other argument whole. An
/// argument here is not a byte string, so an inline value must be UTF-8; the
/// two-argument form (`--data-dir <path>`) takes any path, and `--help` says
/// so.
#[cfg(not(unix))]
fn split_inline(arg: &OsStr) -> (&OsStr, Option<OsString>) {
    match arg.to_str().and_then(|text| text.split_once('=')) {
        Some((name, value)) if name.starts_with("--") => (OsStr::new(name), Some(value.into())),
        _ => (arg, None),
    }
}

/// The value of `option`: given inline, or the next argument.
fn take_value(
    inline: Option<OsString>,
    rest: &mut impl Iterator<Item = OsString>,
    option: ValueOption,
) -> Result<OsString, ArgsError> {
    inline
        .or_else(|| rest.next())
        .filter(|value| !value.is_empty())
        .ok_or(ArgsError::MissingValue(option))
}

/// The data directory's rule is core's, so `rmule` and `rmule-cli` open
/// the same store: `--data-dir`, then the platform's variables.
pub use rmule_core::{DataDir, DataDirSource, resolve_data_dir};

/// The build this binary is: its package version, and the commit, the
/// commit's UTC date and the dirty mark the build script captured — empty
/// when it could not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Build {
    /// The package version.
    pub version: &'static str,
    /// The commit, 12 hex digits; empty outside a git checkout.
    pub commit: &'static str,
    /// The commit's date, `YYYY-MM-DD` UTC; empty outside a git checkout.
    pub committed: &'static str,
    /// Whether the sources that build `rmule` differed from the commit, so
    /// the binary is not the commit.
    pub dirty: bool,
}

/// This binary's build.
pub const BUILD: Build = Build {
    version: env!("CARGO_PKG_VERSION"),
    commit: env!("RMULE_BUILD_COMMIT"),
    committed: env!("RMULE_BUILD_COMMITTED"),
    dirty: matches!(env!("RMULE_BUILD_DIRTY").as_bytes(), b"1"),
};

/// Which of the run's standard streams is not a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingTerminal {
    /// Input is not a terminal.
    Input,
    /// Output is not a terminal.
    Output,
    /// Neither is.
    Both,
}

impl MissingTerminal {
    /// Which stream fails to be a terminal, from whether input and output
    /// are; `None` when both are.
    #[must_use]
    pub const fn from_streams(input_is_terminal: bool, output_is_terminal: bool) -> Option<Self> {
        match (input_is_terminal, output_is_terminal) {
            (true, true) => None,
            (false, true) => Some(Self::Input),
            (true, false) => Some(Self::Output),
            (false, false) => Some(Self::Both),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Invocation, ArgsError> {
        parse(args.iter().copied())
    }

    #[test]
    fn both_value_forms_and_the_level_words_parse() {
        assert_eq!(
            parsed(&["--data-dir", "/d", "--log-level=detailed"]),
            Ok(Invocation::Run(RunArgs {
                data_dir: Some("/d".into()),
                log_level: Some(Level::Full),
            }))
        );
        assert_eq!(
            parsed(&["--data-dir=/a=b", "--log-level", "lean"]),
            Ok(Invocation::Run(RunArgs {
                data_dir: Some("/a=b".into()),
                log_level: Some(Level::Lean),
            }))
        );
    }

    /// A path is bytes on Unix: the inline form takes one that is not UTF-8,
    /// exactly as the two-argument form does.
    #[cfg(unix)]
    #[test]
    fn an_inline_data_dir_takes_a_path_that_is_not_utf8() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let path = OsStr::from_bytes(b"/scratch/\xff\xfe=x").to_owned();
        assert!(path.to_str().is_none());
        let mut inline = b"--data-dir=".to_vec();
        inline.extend_from_slice(path.as_bytes());
        let expected = Ok(Invocation::Run(RunArgs {
            data_dir: Some(PathBuf::from(&path)),
            log_level: None,
        }));
        assert_eq!(parse([OsString::from_vec(inline)]), expected);
        assert_eq!(
            parse([OsString::from("--data-dir"), path.clone()]),
            expected
        );
    }

    #[test]
    fn help_wins_over_version_and_keeps_the_run_options() {
        assert_eq!(
            parsed(&["-V", "--data-dir", "/d", "--help"]),
            Ok(Invocation::Help(RunArgs {
                data_dir: Some("/d".into()),
                log_level: None,
            }))
        );
    }

    #[test]
    fn refusals_name_what_was_wrong() {
        assert_eq!(parsed(&["-x"]), Err(ArgsError::Unknown("-x".into())));
        assert_eq!(
            parsed(&["--help=yes"]),
            Err(ArgsError::Unknown("--help=yes".into()))
        );
        assert_eq!(
            parsed(&["--data-dir"]),
            Err(ArgsError::MissingValue(ValueOption::DataDir))
        );
        assert_eq!(
            parsed(&["--data-dir="]),
            Err(ArgsError::MissingValue(ValueOption::DataDir))
        );
        assert_eq!(
            parsed(&["--log-level", "full"]),
            Err(ArgsError::UnknownLevel("full".into()))
        );
        assert_eq!(
            parsed(&["--log-level=lean", "--log-level=lean"]),
            Err(ArgsError::Repeated(ValueOption::LogLevel))
        );
    }
}
