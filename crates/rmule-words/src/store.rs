//! The Durable Store's words, where a store failure or a value Core Settings
//! refused reaches the operator: never core's own message, which is for the
//! Run Log.

use std::io::ErrorKind;
use std::path::Path;

use super::Sentence;
use super::os::refusal_words;

/// Why the store in `data_dir` would not open, and what to keep: the file is
/// the only link from each part file to its download, so no sentence may read
/// as leave to delete it. The path is named: with `RMULE_DATA` or `$HOME` in
/// play the operator may not know which directory was meant.
#[must_use]
pub fn open_refusal(refusal: rmule_core::OpenRefusal, data_dir: &Path) -> String {
    use rmule_core::OpenRefusal;
    let dir = data_dir.display();
    let file = data_dir.join(rmule_core::DURABLE_STORE_FILE);
    let file = file.display();
    match refusal {
        OpenRefusal::Busy => format!("another rmule is running on the data directory {dir}"),
        OpenRefusal::Newer { found, current } => format!(
            "{file} is store version {found}, and this build reads up to {current}: \
             run the newer rmule, and keep the file"
        ),
        OpenRefusal::TooOld { found, floor } => format!(
            "{file} is store version {found}, and this build upgrades only from {floor}: \
             keep the file and open it once with rmule 0.2.0, which upgrades it"
        ),
        OpenRefusal::Damaged => format!(
            "{file} is damaged: keep it, and any rmule.redb.v file beside it, since they hold \
             your downloads"
        ),
        OpenRefusal::Disk {
            kind: ErrorKind::NotADirectory,
            ..
        } => format!("the data directory {dir} cannot be used: a file stands in its path"),
        OpenRefusal::Disk { kind, os_code } => format!(
            "the data directory {dir} cannot be used: {}",
            refusal_words(kind, os_code)
        ),
        OpenRefusal::NotCopied { os_code } => format!(
            "{file} needs an upgrade, and the copy kept before one could not be made{}: \
             free some space, then start rmule again; the file is as it was",
            os_code_clause(os_code)
        ),
    }
}

fn os_code_clause(os_code: Option<i32>) -> String {
    os_code.map_or_else(String::new, |code| format!(" (system error {code})"))
}

/// The tab now up could not be kept for the next start.
pub const LAST_TAB_NOT_SAVED: Sentence =
    Sentence::fixed("could not remember this tab: the next start may open on another");

/// The server just reached could not be kept for the next start.
pub const LAST_SERVER_NOT_SAVED: Sentence = Sentence::fixed(
    "could not remember this server: connect at start may dial another (see the run log)",
);

/// A Settings edit the store would not keep.
pub const NOT_SAVED: Sentence = Sentence::fixed(
    "could not save the setting: writing to the data directory failed (see the run log)",
);

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
