//! Numbered lines into the real Run Log, for the two claims no running core
//! draws on demand: what a `kill -9` costs a flood of lines, and that a build
//! which aborts on panic still writes the panic's record.
//!
//! `run_log_probe <data dir> <lines> [panic-at-line]`. The last number printed
//! on stdout is a line the log was handed; the log's own file says what
//! reached the disk. The hook is `rmule-cli`'s order: the record first.

use std::io::Write as _;
use std::path::PathBuf;

use rmule_core::run_log::{self, DrainAtExit, Level, Record, RunLog};

/// Lines between two progress prints.
const PRINT_EVERY: u64 = 1000;

fn main() {
    let mut args = std::env::args().skip(1);
    let data_dir = PathBuf::from(args.next().expect("a data dir"));
    let lines: u64 = args.next().expect("a line count").parse().expect("lines");
    let panic_at: Option<u64> = args.next().map(|at| at.parse().expect("panic line"));

    let log = RunLog::open(&data_dir, Level::Full).expect("open the Run Log");
    let level = log.level();
    let _failures = log.install().expect("install the Run Log");
    let _drain = DrainAtExit;
    std::panic::set_hook(Box::new(move |info| {
        run_log::panic_record(info, &level);
    }));

    let mut stdout = std::io::stdout();
    for line in 1..=lines {
        run_log::write(&Record::new("probe.line").count("n", line), Level::Full);
        if line % PRINT_EVERY == 0 {
            writeln!(stdout, "handed n={line}").expect("stdout");
            stdout.flush().expect("stdout");
        }
        assert!(panic_at != Some(line), "the probe panics at line {line}");
    }
}
