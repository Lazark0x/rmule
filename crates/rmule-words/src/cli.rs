//! The words only `rmule-cli` speaks: its exit codes, its lines for a one-shot
//! `add`, and what its commands print.

use super::units::{count, human_size};

/// `--help`'s last section: what a script reads from the exit code.
pub const EXIT_CODES: &str = "\
Exit codes:
  0  done
  1  anything else: the store, the disk, an internal fault
  2  the command line or the link could not be read
  3  the engine refused the download: no download directory, a name taken
  4  the download failed or was cancelled
  5  nothing to reach: no server and no source, or no connection
  6  --timeout ran out
  7  stopped by a signal";

/// The download a one-shot run names before the core has queued it.
pub const NOT_YET_QUEUED: &str = "(not yet queued)";

/// `add` given a link of another kind.
pub const NOT_A_FILE_LINK: &str = "the link is not an eD2k file link";

/// `add` with nothing to ask.
pub const NO_SERVER_NO_SOURCE: &str = "no server configured and the link names no source; run \
                                       `rmule-cli server add <host:port>`";

/// The event stream ended under a running `add`.
pub const ENGINE_ENDED: &str = "the engine stopped before the download completed";

/// `add --timeout` ran out.
#[must_use]
pub fn timed_out(seconds: u64) -> String {
    format!(
        "stopped after {}: the download has not completed; the part file stays for the next run",
        count(seconds, "second", "seconds")
    )
}

/// A one-shot download named by its id.
#[must_use]
pub fn download_label(id: u64) -> String {
    format!("id={id}")
}

/// `add` with no server, going by the link alone.
#[must_use]
pub fn starting_from_link(sources: usize) -> String {
    format!(
        "no server configured; starting from the {} the link names",
        count(sources as u64, "source", "sources")
    )
}

/// The core took the download.
#[must_use]
pub fn queued(id: u64) -> String {
    format!("queued id={id}")
}

/// A download that ended without its file.
#[must_use]
pub fn download_failed(label: &str, why: &str) -> String {
    format!("download {label} failed: {why}")
}

/// A download cancelled under the run.
#[must_use]
pub fn download_cancelled(label: &str) -> String {
    format!("download {label} cancelled")
}

/// `add`'s progress, on stderr: a lookup answered.
#[must_use]
pub fn sources_found(total: usize, usable: usize) -> String {
    format!(
        "found {}, {usable} to dial",
        count(total as u64, "source", "sources")
    )
}

/// `add`'s progress, on stderr: a part proved, with the whole file's bytes
/// when the run knows them.
#[must_use]
pub fn part_verified(parts_done: u64, parts: Option<usize>, size: u64) -> String {
    match parts {
        Some(parts) => format!(
            "{parts_done} of {parts} parts verified, of {}",
            human_size(size)
        ),
        None => format!(
            "{} verified, of {}",
            count(parts_done, "part", "parts"),
            human_size(size)
        ),
    }
}

/// The fields a link carried that no client reads; `None` when there were
/// none.
#[must_use]
pub fn skipped_fields(fields: &[String]) -> Option<String> {
    let quoted: Vec<String> = fields.iter().map(|name| format!("`{name}`")).collect();
    match quoted.as_slice() {
        [] => None,
        [one] => Some(format!(
            "ignored the field {one} the link carried, which no client reads"
        )),
        many => Some(format!(
            "ignored the fields {} the link carried, which no client reads",
            many.join(", ")
        )),
    }
}

/// `server add`'s line.
#[must_use]
pub fn server_added(host: &str, port: u16) -> String {
    format!("added {host}:{port}")
}

/// `server add` given something that names no server.
#[must_use]
pub fn unreadable_endpoint(text: &str) -> String {
    format!("'{text}' is not a server address: give it as host:port")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_source_and_one_second_are_singular() {
        assert!(starting_from_link(1).contains("the 1 source the link"));
        assert!(starting_from_link(2).contains("the 2 sources the link"));
        assert!(timed_out(1).contains("after 1 second:"));
    }

    #[test]
    fn progress_names_the_parts_once_the_run_knows_them() {
        assert_eq!(
            part_verified(3, Some(8), 1024),
            "3 of 8 parts verified, of 1.0 KB"
        );
        assert_eq!(part_verified(1, None, 512), "1 part verified, of 512 B");
    }
}
