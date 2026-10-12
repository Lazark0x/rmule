//! The operating system's refusals, in the operator's words: an I/O error
//! kind, and the OS's error number as data when it gave one — never the
//! standard library's or the OS's own sentence.

use std::io::ErrorKind;

/// What an OS refusal of this kind means for the operator.
///
/// Every kind the standard library names today has its own sentence.
/// `ErrorKind` is `#[non_exhaustive]`, so the compiler demands one arm for a
/// kind a later toolchain adds; it says only that the system refused.
#[must_use]
pub const fn kind_words(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::NotFound => "it is not there",
        ErrorKind::PermissionDenied => "permission denied",
        ErrorKind::AddrInUse => "another program holds the port",
        ErrorKind::AddrNotAvailable => "this machine does not hold that address",
        ErrorKind::ConnectionRefused => "the other side refused the connection",
        ErrorKind::ConnectionReset => "the other side reset the connection",
        ErrorKind::ConnectionAborted => "the connection was aborted",
        ErrorKind::BrokenPipe => "the connection closed while writing",
        ErrorKind::NotConnected => "there is no connection",
        ErrorKind::TimedOut => "it did not answer in time",
        ErrorKind::HostUnreachable => "the host cannot be reached",
        ErrorKind::NetworkUnreachable => "the network cannot be reached",
        ErrorKind::NetworkDown => "the network is down",
        ErrorKind::StorageFull => "the disk is full",
        ErrorKind::QuotaExceeded => "the disk quota is used up",
        ErrorKind::ReadOnlyFilesystem => "the disk is read-only",
        ErrorKind::IsADirectory => "it is a folder, not a file",
        ErrorKind::NotADirectory => "it is a file, not a folder",
        ErrorKind::DirectoryNotEmpty => "the folder is not empty",
        ErrorKind::AlreadyExists => "it already exists",
        ErrorKind::OutOfMemory => "the system is out of memory",
        ErrorKind::Unsupported => "the system does not support it",
        ErrorKind::InvalidInput => "the system rejected what was asked",
        ErrorKind::InvalidData => "what was read is not valid",
        ErrorKind::Interrupted => "the system interrupted it",
        ErrorKind::WouldBlock => "the system was not ready",
        ErrorKind::UnexpectedEof => "it ended early",
        ErrorKind::WriteZero => "the system wrote nothing",
        ErrorKind::StaleNetworkFileHandle => "the network file went stale",
        ErrorKind::NotSeekable => "the file cannot be read from a chosen place",
        ErrorKind::FileTooLarge => "the file is too large",
        ErrorKind::ResourceBusy => "another program is using it",
        ErrorKind::ExecutableFileBusy => "the program file is in use",
        ErrorKind::Deadlock => "the system found a deadlock",
        ErrorKind::CrossesDevices => "it cannot move between disks",
        ErrorKind::TooManyLinks => "it has too many links",
        ErrorKind::InvalidFilename => "the file name is not valid",
        ErrorKind::ArgumentListTooLong => "the argument list is too long",
        ErrorKind::Other => "the system refused for a reason it did not name",
        _ => "the system refused",
    }
}

/// An OS refusal with its error number, when the OS gave one: "permission
/// denied (system error 13)".
#[must_use]
pub fn refusal_words(kind: ErrorKind, os_code: Option<i32>) -> String {
    match os_code {
        Some(code) => format!("{} (system error {code})", kind_words(kind)),
        None => kind_words(kind).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Causes that once shared a sentence each say their own.
    #[test]
    fn kinds_that_were_folded_into_one_sentence_read_apart() {
        let folded: [&[ErrorKind]; 4] = [
            &[
                ErrorKind::ConnectionReset,
                ErrorKind::ConnectionAborted,
                ErrorKind::BrokenPipe,
            ],
            &[
                ErrorKind::HostUnreachable,
                ErrorKind::NetworkUnreachable,
                ErrorKind::NetworkDown,
            ],
            &[ErrorKind::StorageFull, ErrorKind::QuotaExceeded],
            &[ErrorKind::Interrupted, ErrorKind::WouldBlock],
        ];
        for group in folded {
            let mut sentences: Vec<&str> = group.iter().map(|kind| kind_words(*kind)).collect();
            sentences.sort_unstable();
            sentences.dedup();
            assert_eq!(sentences.len(), group.len(), "{group:?} share a sentence");
        }
    }
}
