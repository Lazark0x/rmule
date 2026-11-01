//! The one reading of a session event for tools: what happened and the fields
//! that say so. A tool's line and the row a capture's `events.toml` keeps are
//! both rendered from it, so a new event states its facts once. Each format's
//! names are its own and stay put when a variant is renamed; harness parsers
//! read the line, and archived captures read the row.

use std::fmt;

use crate::FileHash;

/// One value of an [`EventRow`], by how a format writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowValue {
    /// A number or a flag: the same in either format.
    Plain(String),
    /// Text: bare on a line, a quoted string in a capture.
    Text(String),
    /// An opcode: hexadecimal on a line, decimal in a capture.
    Opcode(u8),
}

/// Which formats carry a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    Both,
    Line,
    Capture,
}

/// A session event as tools read it. [`fmt::Display`] is its line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    line_prefix: Option<&'static str>,
    line_name: &'static str,
    capture_type: &'static str,
    fields: Vec<(Reach, &'static str, RowValue)>,
}

impl EventRow {
    /// A row with no fields yet, by its name on a line and its capture `type`.
    #[must_use]
    pub const fn new(line_name: &'static str, capture_type: &'static str) -> Self {
        Self {
            line_prefix: None,
            line_name,
            capture_type,
            fields: Vec::new(),
        }
    }

    /// Put `prefix` ahead of the name on a line.
    #[must_use]
    pub fn under(mut self, prefix: &'static str) -> Self {
        self.line_prefix = Some(prefix);
        self
    }

    /// The label a capture's row carries as its `type`.
    #[must_use]
    pub const fn capture_type(&self) -> &'static str {
        self.capture_type
    }

    /// The fields a capture's row carries, in order.
    pub fn capture_fields(&self) -> impl Iterator<Item = (&'static str, &RowValue)> {
        self.fields
            .iter()
            .filter(|(reach, ..)| *reach != Reach::Line)
            .map(|(_, key, value)| (*key, value))
    }

    fn field(mut self, reach: Reach, key: &'static str, value: RowValue) -> Self {
        self.fields.push((reach, key, value));
        self
    }

    /// A number or flag both formats carry.
    #[must_use]
    pub fn plain(self, key: &'static str, value: impl fmt::Display) -> Self {
        self.field(Reach::Both, key, RowValue::Plain(value.to_string()))
    }

    /// Text both formats carry.
    #[must_use]
    pub fn text(self, key: &'static str, value: impl fmt::Display) -> Self {
        self.field(Reach::Both, key, RowValue::Text(value.to_string()))
    }

    /// An opcode both formats carry, each in its own notation.
    #[must_use]
    pub fn opcode(self, key: &'static str, opcode: u8) -> Self {
        self.field(Reach::Both, key, RowValue::Opcode(opcode))
    }

    /// The file an event is about, as both formats name it.
    #[must_use]
    pub fn file(self, file_hash: FileHash) -> Self {
        self.text("file_hash", file_hash.to_hex_upper())
    }

    /// A field only the line carries.
    #[must_use]
    pub fn line_only(self, key: &'static str, value: impl fmt::Display) -> Self {
        self.field(Reach::Line, key, RowValue::Plain(value.to_string()))
    }

    /// A bare word on the line, with no key.
    #[must_use]
    pub fn line_word(self, value: impl fmt::Display) -> Self {
        self.line_only("", value)
    }

    /// A number or flag only the capture carries.
    #[must_use]
    pub fn capture_plain(self, key: &'static str, value: impl fmt::Display) -> Self {
        self.field(Reach::Capture, key, RowValue::Plain(value.to_string()))
    }

    /// Text only the capture carries.
    #[must_use]
    pub fn capture_text(self, key: &'static str, value: impl fmt::Display) -> Self {
        self.field(Reach::Capture, key, RowValue::Text(value.to_string()))
    }
}

impl fmt::Display for EventRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(prefix) = self.line_prefix {
            write!(f, "{prefix} ")?;
        }
        f.write_str(self.line_name)?;
        for (reach, key, value) in &self.fields {
            if *reach == Reach::Capture {
                continue;
            }
            match value {
                RowValue::Plain(value) | RowValue::Text(value) if key.is_empty() => {
                    write!(f, " {value}")?;
                }
                RowValue::Plain(value) | RowValue::Text(value) => write!(f, " {key}={value}")?,
                RowValue::Opcode(opcode) => write!(f, " {key}=0x{opcode:02X}")?,
            }
        }
        Ok(())
    }
}
