//! A panic's line in the Run Log (ADR-0118): what a front end's panic hook
//! calls first, so the record and every line queued ahead of it are on disk
//! whatever the panic costs next.

use std::panic::PanicHookInfo;

use super::level::LevelHandle;
use super::record::Record;

/// Write `info` to the Run Log and drain it. Bounded, and safe on any thread,
/// the log's own writer included: the drain gives up rather than wait for
/// itself.
pub fn panic_record(info: &PanicHookInfo<'_>, level: &LevelHandle) {
    let thread = std::thread::current();
    let (file, line) = info
        .location()
        .map_or(("unknown", 0), |site| (site.file(), site.line()));
    let record = record_of(
        thread.name().unwrap_or("unnamed"),
        file,
        line,
        message(info),
    );
    super::write(&record, level.get());
    super::drain();
}

/// The text a `panic!` carries: a literal or a formatted string are the two
/// payloads the macros make.
fn message<'a>(info: &'a PanicHookInfo<'_>) -> Option<&'a str> {
    let payload = info.payload();
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
}

fn record_of(thread: &str, file: &str, line: u32, message: Option<&str>) -> Record {
    let record = Record::new("panic").panic_site(thread, file, line);
    match message {
        Some(message) => record.panic_message(message),
        None => record,
    }
}

/// The two levels' lines of one panic, for a test beside the rule.
#[cfg(test)]
pub(super) fn lines(message: &str) -> (String, String) {
    use super::level::Level;
    let record = record_of("tokio-runtime-worker", "src/x.rs", 7, Some(message));
    (record.render(Level::Lean), record.render(Level::Full))
}
