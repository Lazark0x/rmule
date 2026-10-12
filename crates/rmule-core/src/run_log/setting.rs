//! The Run Log's record of a value Core Settings refused: the refusal's code,
//! and for a download directory the guard it failed, never the message a
//! front end words.

use crate::SettingRefusal;

use super::codes;
use super::record::Record;

impl SettingRefusal {
    /// The Run Log's record of this refusal.
    #[must_use]
    pub fn record(&self) -> Record {
        codes::setting_refusal(Record::new("setting.refused"), self)
    }
}
