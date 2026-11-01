//! The Durable Store's words, where a store failure or a value Core Settings
//! refused reaches the operator: never core's own message, which is for the
//! Run Log.

use super::Sentence;

/// Why the store would not open, and what to keep: the file is the only link
/// from each part file to its download, so no sentence may read as leave to
/// delete it.
#[must_use]
pub fn open_refusal(refusal: rmule_core::OpenRefusal) -> String {
    use rmule_core::OpenRefusal;
    match refusal {
        OpenRefusal::Busy => "another rmule is running on this data directory".to_string(),
        OpenRefusal::Newer { found, current } => format!(
            "rmule.redb is store version {found}, and this build reads up to {current}: \
             run the newer rmule, and keep the file"
        ),
        OpenRefusal::TooOld { found } => format!(
            "rmule.redb is store version {found}, older than this build can upgrade: \
             keep the file and open it with an older rmule first"
        ),
        OpenRefusal::Damaged => "rmule.redb is damaged: keep it, and any rmule.redb.v file \
             beside it, since they hold your downloads"
            .to_string(),
        OpenRefusal::Disk { os_code } => format!(
            "the disk refused rmule.redb{}: free some space or check the permissions, \
             then start rmule again",
            os_code_clause(os_code)
        ),
        OpenRefusal::NotCopied { os_code } => format!(
            "rmule.redb needs an upgrade, and the copy kept before one could not be made{}: \
             free some space, then start rmule again; the file is as it was",
            os_code_clause(os_code)
        ),
    }
}

fn os_code_clause(os_code: Option<i32>) -> String {
    os_code.map_or_else(String::new, |code| format!(" (system code {code})"))
}

/// The server just reached could not be kept for the next start.
pub const LAST_SERVER_NOT_SAVED: Sentence = Sentence::fixed(
    "could not remember this server: connect at start may dial another (see the run log)",
);

/// A Settings edit the store would not keep.
pub const NOT_SAVED: Sentence =
    Sentence::fixed("could not save the setting: writing to the data directory failed (see the run log)");

/// A Settings edit Core Settings refused for its value: nothing was written,
/// and the sentence says what the key takes, for a download dir the share
/// guards refuse, why it may not be shared, and for a Temp Directory, why it was
/// not taken.
#[must_use]
pub fn setting_refused(refusal: &rmule_core::SettingRefusal) -> Sentence {
    use rmule_core::SettingRefusal as R;
    Sentence::fixed(match refusal {
        R::PortZero => "not saved: a port must be from 1 to 65535",
        R::DeadServerRetriesZero => "not saved: the dead server limit must be at least 1",
        R::DownloadDirNotAbsolute => "not saved: the download dir must be an absolute path",
        R::DownloadDirNotUtf8 => "not saved: the download dir path must be valid UTF-8",
        R::DownloadDirNotADirectory => "not saved: the download dir names a file, not a directory",
        R::DownloadDirRefused(guard) => {
            return Sentence::owned(format!(
                "not saved: everything under the download dir is shared, and {}",
                super::scan::download_dir_refusal(guard)
            ));
        }
        R::TempDirRefused(guard) => {
            return Sentence::owned(format!(
                "not saved as the Temp Directory: {}",
                super::scan::temp_dir_refusal(guard)
            ));
        }
        R::NicknameUnfit => "not saved: the nickname must not be blank or hold control characters",
        R::UrlBlank => "not saved: the mirror URL must not be blank",
        R::CoreKey => "not saved: that key is one of core's own (see the run log)",
    })
}
