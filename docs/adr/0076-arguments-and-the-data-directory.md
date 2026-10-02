# rmule parses its own arguments and resolves the data directory once, before anything touches it

## Context

Every run of `rmule` (ADR-0069) touches a data directory: the store and the Run Log
(ADR-0075) live there. A run that writes into it before it knows what it was asked —
for `--help`, a mistyped option or a piped stdout — leaves state behind. Unix and Windows
name a per-user data directory differently, and Git Bash sets `HOME` on Windows.

## Decision

`rmule` reads its command line before anything touches the data directory: no directory
is created, no Run Log installed and no store opened until the arguments have parsed and
the run has a terminal.

- **Options:** `--help` (`-h`), `--version` (`-V`), `--data-dir <path>` and
  `--log-level lean|detailed`, as `--opt value` or `--opt=value`. Anything else — an
  unknown argument, a missing or empty value, an unknown level, a repeated option — is a
  usage error: one sentence and the usage on stderr, exit code 2. `--help` and
  `--version` win and exit 0.
- `--opt=value` splits at the first `=` byte, so on Unix an inline `--data-dir` takes a
  non-UTF-8 path exactly as the two-argument form does. Elsewhere an inline value must be
  UTF-8, and `--help` says so and names the two-argument form.
- **The parser is rmule's own.** `--help`, `--version` and every exit sentence are
  operator-facing text written in `words/` from a code; a library parser would render text
  the app does not own.
- **Data directory, resolved once** and used by both the store and the Run Log:
  - Unix: `--data-dir`, then `RMULE_DATA`, then `$XDG_DATA_HOME/rmule`, then
    `$HOME/.local/share/rmule`.
  - Windows: `--data-dir`, then `RMULE_DATA`, then `%LOCALAPPDATA%\rmule`.
    `XDG_DATA_HOME` and `HOME` are not read.
  - `rmule-cli` resolves the same order, `RMULE_DATA` included.
- **Which rule picked the directory is a code.** The resolver returns the path with its
  source, and `--help`'s *Where things live* and the Settings note both word that code. A
  run whose directory resolved but whose core could not attach still shows the path and
  source; only a run with no directory shows a dash, with a note saying what would give
  one.
- `--help` prints the usage, the options, the data directory and Run Log for this
  invocation with the rule that picked them, and every environment variable the binary
  reads on its platform (`RMULE_DATA`, the platform's data-home variables, `RMULE_LOG`,
  `RMULE_THEME`, `COLORTERM`).
- **Run Log level:** `--log-level` wins over the stored *Full run log* preference for the
  run and is never stored; `detailed` is the operator's word for full. `RMULE_LOG` stays the
  `tracing` filter and chooses no level.
- **No terminal, no run.** When stdin or stdout is not a terminal, `rmule` says so on
  stderr and exits 1, after the arguments and before the Run Log and the core, so a piped
  run writes nothing into the data directory.
- **Builds are told apart.** A build script records the commit (12 hex digits of `HEAD`),
  the commit's UTC date, and whether the sources that build `rmule` had uncommitted
  changes to tracked files (the app's sources, build script and manifest, each linked
  crate's, the workspace manifest, the lockfile and the toolchain file; untracked files,
  docs, tests and tools do not count). `--version` prints
  `rmule <version> (<commit>, committed <date>)`, the commit marked `-dirty` when
  applicable; outside a git checkout it reads `commit unknown, commit date unknown`. The
  same line opens `--help` and the help overlay (`?`), and the same facts as codes open
  every Run Log as its `run_start` record.

## Consequences

- `--help`, a usage error and a run without a terminal write nothing into the data
  directory.
- A report names the exact build and where its data lives.

## Considered options

- **An argument-parsing library.** Rejected: it renders help and errors in words the app
  does not own.
