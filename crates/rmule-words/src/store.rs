//! The Durable Store's words, where a store failure or a value Core Settings
//! refused reaches the operator: never core's own message, which is for the
//! Run Log.

use super::Sentence;

/// A Settings edit on a run with no config store.
pub const NO_CONFIG_STORE: Sentence = Sentence::fixed("no config store (UI-only run)");

/// The server just reached could not be kept for the next start.
pub const LAST_SERVER_NOT_SAVED: Sentence = Sentence::fixed(
    "could not remember this server: connect at start may dial another (see the run log)",
);

/// A Settings edit the store would not keep.
pub const NOT_SAVED: Sentence =
    Sentence::fixed("could not save the setting: the store refused (see the run log)");

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
