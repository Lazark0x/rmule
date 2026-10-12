//! What `rmule` prints before it takes the terminal (ADR-0076 §Arguments):
//! the version line, the usage, `--help`, and every sentence a run ends with
//! before it starts. Written from the codes in [`crate::args`].

use std::fmt::Write as _;

use rmule_core::run_log::{CAP_BYTES, FILE_NAME, PREDECESSOR_NAME};

use crate::args::{ArgsError, Build, DataDir, DataDirSource, MissingTerminal, ValueOption};

/// `rmule <version> (<commit>, committed <date>)`, the commit marked
/// `-dirty` when the binary is not the commit — the one version line, shown
/// by `--version`, `--help` and the help overlay.
#[must_use]
pub fn version_line(build: Build) -> String {
    let commit = match (build.commit, build.dirty) {
        ("", _) => "commit unknown".to_owned(),
        (commit, false) => commit.to_owned(),
        (commit, true) => format!("{commit}-dirty"),
    };
    let committed = if build.committed.is_empty() {
        "commit date unknown".to_owned()
    } else {
        format!("committed {}", build.committed)
    };
    format!("rmule {} ({commit}, {committed})", build.version)
}

/// The two shapes of an invocation.
pub const USAGE: &str =
    "Usage: rmule [--data-dir <path>] [--log-level lean|detailed]\n       rmule --help | --version";

/// The pointer a refusal ends with.
const MORE: &str = "Run rmule --help for the options, where the data lives, and the environment.";

/// A refused command line: the sentence, then the usage.
#[must_use]
pub fn args_error(error: &ArgsError) -> String {
    let sentence = match error {
        ArgsError::Unknown(arg) => format!(
            "rmule: \"{}\" is not an option of rmule; nothing was started.",
            arg.to_string_lossy()
        ),
        ArgsError::MissingValue(ValueOption::DataDir) => {
            "rmule: --data-dir needs a directory path; nothing was started.".to_owned()
        }
        ArgsError::MissingValue(ValueOption::LogLevel) => {
            "rmule: --log-level needs a level, lean or detailed; nothing was started.".to_owned()
        }
        ArgsError::UnknownLevel(level) => format!(
            "rmule: \"{}\" is not a Run Log level (use lean or detailed); nothing was started.",
            level.to_string_lossy()
        ),
        ArgsError::Repeated(option) => format!(
            "rmule: {} is given twice; nothing was started.",
            option_name(*option)
        ),
    };
    format!("{sentence}\n\n{USAGE}\n\n{MORE}")
}

const fn option_name(option: ValueOption) -> &'static str {
    match option {
        ValueOption::DataDir => "--data-dir",
        ValueOption::LogLevel => "--log-level",
    }
}

/// A run with no terminal to draw on.
#[must_use]
pub const fn no_terminal(missing: MissingTerminal) -> &'static str {
    match missing {
        MissingTerminal::Input => {
            "rmule needs a terminal, and its input is not one; nothing was started."
        }
        MissingTerminal::Output => {
            "rmule needs a terminal, and its output is not one; nothing was started."
        }
        MissingTerminal::Both => {
            "rmule needs a terminal, and neither its input nor its output is one; nothing was started."
        }
    }
}

/// A run that stopped on an OS error outside the core — the runtime could
/// not start, or the terminal would not open or restore.
#[must_use]
pub fn run_failed(kind: std::io::ErrorKind, os_code: Option<i32>) -> String {
    format!(
        "rmule stopped: the terminal or its runtime failed ({}).",
        super::os::refusal_words(kind, os_code)
    )
}

/// Which rule picked the data directory, as `--help` and the Settings tab
/// both say it.
#[must_use]
pub const fn source_words(source: DataDirSource) -> &'static str {
    match source {
        DataDirSource::Flag => "from --data-dir",
        DataDirSource::RmuleData => "from RMULE_DATA",
        DataDirSource::XdgDataHome => "from XDG_DATA_HOME",
        DataDirSource::Home => "from HOME",
        DataDirSource::LocalAppData => "from LOCALAPPDATA",
    }
}

/// What `--help` adds under `--data-dir` where an argument is not a byte
/// string, so `--data-dir=<path>` cannot carry every path.
#[cfg(not(unix))]
const INLINE_PATH: &str = "
                       --data-dir=<path> takes a UTF-8 path only; give any
                       other path as --data-dir <path>.";
#[cfg(unix)]
const INLINE_PATH: &str = "";

/// Where the data directory would be, when no rule names one.
#[cfg(not(windows))]
pub const NO_DATA_DIR: &str = "none: give --data-dir, or set RMULE_DATA or HOME";
/// Where the data directory would be, when no rule names one.
#[cfg(windows)]
pub const NO_DATA_DIR: &str = "none: give --data-dir, or set RMULE_DATA or LOCALAPPDATA";

/// What `--help` says `--data-dir` beats: this platform's variables.
#[cfg(not(windows))]
const FLAG_BEATS: &str = "RMULE_DATA, XDG_DATA_HOME and HOME";
#[cfg(windows)]
const FLAG_BEATS: &str = "RMULE_DATA and LOCALAPPDATA";

/// `--help`'s rule for the data directory and the variables it reads, as
/// this platform resolves it.
#[cfg(not(windows))]
const DATA_DIR_RULE: &str = "  The data directory is the first of: --data-dir, $RMULE_DATA,
  $XDG_DATA_HOME/rmule, $HOME/.local/share/rmule. An empty variable counts as
  unset.

Environment:
  RMULE_DATA      the data directory, when --data-dir is not given
  XDG_DATA_HOME   the data directory is $XDG_DATA_HOME/rmule, when neither
                  --data-dir nor RMULE_DATA is given
  HOME            the data directory is $HOME/.local/share/rmule, when none of
                  the above is given
";
#[cfg(windows)]
const DATA_DIR_RULE: &str = "  The data directory is the first of: --data-dir, %RMULE_DATA%,
  %LOCALAPPDATA%\\rmule. An empty variable counts as unset.

Environment:
  RMULE_DATA      the data directory, when --data-dir is not given
  LOCALAPPDATA    the data directory is %LOCALAPPDATA%\\rmule, when neither
                  --data-dir nor RMULE_DATA is given
";

/// `--help`: the version, the usage, the options, where this invocation's
/// data and Run Log are, and every environment variable `rmule` reads.
#[must_use]
pub fn help(build: Build, data_dir: Option<&DataDir>) -> String {
    let mut text = format!(
        "{} — an eD2k and Kad file-sharing client in the terminal.\n\n{USAGE}\n",
        version_line(build)
    );
    let _ = write!(
        text,
        "
Options:
  --data-dir <path>    Keep the data in <path>; it is created on the first run.
                       Beats {FLAG_BEATS}.{INLINE_PATH}
  --log-level <level>  How much the Run Log holds this run:
                         lean      reachability evidence and event codes
                         detailed  lean, plus peer addresses, file names, paths
                                   and hashes
                       Beats the Settings choice \"Full run log\" for this run
                       and is not stored. Without it, that choice decides; it is
                       lean until changed.
  -h, --help           Print this help and exit.
  -V, --version        Print the version, the commit and its date, and exit;
                       -dirty on the commit means the binary was built from
                       uncommitted changes.
",
    );
    text.push_str("\nWhere things live:\n");
    match data_dir {
        Some(DataDir { path: dir, source }) => {
            let _ = writeln!(
                text,
                "  Data directory  {} ({})",
                dir.display(),
                source_words(*source)
            );
            let _ = writeln!(
                text,
                "  Run Log         {} (moved aside to {PREDECESSOR_NAME} at {} MiB)",
                dir.join(FILE_NAME).display(),
                CAP_BYTES / (1024 * 1024)
            );
        }
        None => {
            let _ = writeln!(text, "  Data directory  {NO_DATA_DIR}");
            text.push_str("  Run Log         none without a data directory\n");
        }
    }
    text.push_str(DATA_DIR_RULE);
    text.push_str(
        "  RMULE_LOG       the filter on what the Run Log writes, in tracing-subscriber's
                  EnvFilter syntax (default info); it does not choose lean or
                  detailed
  RMULE_THEME     the colours: dark, light or 256; beats COLORTERM, and a theme
                  chosen in Settings beats it
  COLORTERM       truecolor or 24bit selects the full-colour theme; otherwise
                  the 256-colour one

rmule draws on the terminal it is started from: its input and output must both
be a terminal, or it exits without starting.
",
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILT: Build = Build {
        version: "1.2.3",
        commit: "0123456789ab",
        committed: "2026-09-30",
        dirty: false,
    };

    #[test]
    fn a_fact_the_build_could_not_capture_is_said_unknown() {
        assert_eq!(
            version_line(BUILT),
            "rmule 1.2.3 (0123456789ab, committed 2026-09-30)"
        );
        assert_eq!(
            version_line(Build {
                dirty: true,
                ..BUILT
            }),
            "rmule 1.2.3 (0123456789ab-dirty, committed 2026-09-30)"
        );
        let bare = Build {
            commit: "",
            committed: "",
            dirty: false,
            ..BUILT
        };
        assert_eq!(
            version_line(bare),
            "rmule 1.2.3 (commit unknown, commit date unknown)"
        );
    }
}
