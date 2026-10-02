//! Wire-faithful eD2k text: strings that keep the bytes a counterparty sent,
//! because server banners and file names are routinely not valid UTF-8.

use std::fmt;
use std::str::Utf8Error;

/// Wire-faithful eD2k text value.
///
/// Server-emitted strings are not guaranteed UTF-8 — legacy banners and
/// descriptions are routinely Windows-1252 or mojibake. `Ed2kText` preserves
/// the original bytes losslessly so packet round trips stay byte-exact while
/// strict UTF-8 callers can opt in via [`try_as_str`](Self::try_as_str).
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ed2kText {
    bytes: Vec<u8>,
}

impl Ed2kText {
    /// Text rmule itself authored, which is UTF-8 by construction.
    #[must_use]
    pub fn from_utf8(text: impl Into<String>) -> Self {
        Self {
            bytes: text.into().into_bytes(),
        }
    }

    /// Text as a counterparty sent it — any bytes, no validation, no
    /// substitution.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// The bytes, unchanged — what re-encoding writes back, so a round trip
    /// stays byte-exact.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The text as `&str` when it happens to be valid UTF-8.
    ///
    /// # Errors
    /// The `Utf8Error` from the failed conversion — a caller that needs a
    /// string for display should use [`Self::to_display_string`] instead.
    pub fn try_as_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.bytes)
    }

    /// A lossy UTF-8 rendering for display: invalid sequences become U+FFFD.
    /// Never send this back to the wire — it is not the original bytes.
    #[must_use]
    pub fn to_display_string(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// Take the bytes, consuming the value.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Display for Ed2kText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.bytes))
    }
}

/// The text in quotes, never the byte vector: valid UTF-8 escaped as `str`'s
/// `Debug` escapes it (control characters, quotes, backslashes), and every
/// byte that is not part of a valid sequence written as `\xNN`. Two values
/// that differ only in invalid bytes therefore still print differently.
impl fmt::Debug for Ed2kText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write as _;
        f.write_char('"')?;
        for chunk in self.bytes.utf8_chunks() {
            for c in chunk.valid().chars() {
                // A lone quote is escaped by `char`'s form but not `str`'s;
                // inside a quoted string the `str` rule is the right one.
                if c == '\'' {
                    f.write_char(c)?;
                } else {
                    write!(f, "{}", c.escape_debug())?;
                }
            }
            for byte in chunk.invalid() {
                write!(f, "\\x{byte:02X}")?;
            }
        }
        f.write_char('"')
    }
}

#[cfg(test)]
mod tests {
    use super::Ed2kText;

    #[test]
    fn debug_prints_the_text_escaping_invalid_bytes_and_controls() {
        let text = Ed2kText::from_bytes(b"caf\xE9 \"x\"\n'ok'\\".to_vec());
        assert_eq!(format!("{text:?}"), r#""caf\xE9 \"x\"\n'ok'\\""#);
    }

    #[test]
    fn debug_of_valid_text_matches_str_debug() {
        let text = Ed2kText::from_utf8("Сервер — ok\t");
        assert_eq!(format!("{text:?}"), format!("{:?}", "Сервер — ok\t"));
    }
}
