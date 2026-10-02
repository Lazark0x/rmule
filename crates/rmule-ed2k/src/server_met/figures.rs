//! A server.met row's figures: what the server last reported about
//! itself and when rmule's predecessor last heard it — the ping, the user and
//! file counts, the soft and hard file limits, the version, and the time of
//! the last answer. aMule writes them on every save (`CServerList::SaveServerMet`,
//! `ServerList.cpp:776-789`) and reads them back in `CServer::AddTagFromFile`
//! (`Server.cpp:182-270`).

use rmule_primitives::{Ed2kText, Tag, TagName, TagValue};

/// `ST_PING` — the last measured round trip, in milliseconds.
const TAG_PING: u8 = 0x0C;
/// `ST_SOFTFILES` — the server's soft file limit.
const TAG_SOFTFILES: u8 = 0x88;
/// `ST_HARDFILES` — the server's hard file limit.
const TAG_HARDFILES: u8 = 0x89;
/// `ST_LASTPING` — when the server last answered, Unix seconds.
const TAG_LASTPING: u8 = 0x90;
/// `ST_VERSION` — the server's version, a string or a packed `hi16.lo16`.
const TAG_VERSION: u8 = 0x91;

/// The figures one server.met row carried. Every field is `None` when its tag
/// was absent; a zero is kept as the zero the file wrote, and the caller
/// decides what a never-answered row's zeros mean (aMule writes `0` for a
/// server it never pinged, with an `ST_LASTPING` of `0`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerMetFigures {
    /// `ST_PING`, milliseconds.
    pub ping_ms: Option<u32>,
    /// The `"users"` tag (named by text, not by id).
    pub users: Option<u32>,
    /// The `"files"` tag (named by text, not by id).
    pub files: Option<u32>,
    /// `ST_SOFTFILES`.
    pub soft_files: Option<u32>,
    /// `ST_HARDFILES`.
    pub hard_files: Option<u32>,
    /// `ST_LASTPING`, Unix seconds, as written. aMule rejects a value in the
    /// future on load (`Server.cpp:196-200`); the reader has no clock, so
    /// that check is the caller's.
    pub last_ping: Option<u32>,
    /// `ST_VERSION`: the first string form wins (aMule writes it twice), and
    /// an integer form reads `hi16.lo16`, as aMule renders it.
    pub version: Option<String>,
}

impl ServerMetFigures {
    /// A row that carried no figure at all.
    pub const NONE: Self = Self {
        ping_ms: None,
        users: None,
        files: None,
        soft_files: None,
        hard_files: None,
        last_ping: None,
        version: None,
    };

    /// Fold one tag of a row into the figures; a tag that is not a figure is
    /// left alone.
    pub(super) fn read(&mut self, tag: &Tag) {
        let value = tag.value();
        match (tag.name().id(), tag.name().text_value()) {
            (Some(TAG_PING), _) => self.ping_ms = integer(value),
            (Some(TAG_SOFTFILES), _) => self.soft_files = integer(value),
            (Some(TAG_HARDFILES), _) => self.hard_files = integer(value),
            (Some(TAG_LASTPING), _) => self.last_ping = integer(value),
            (Some(TAG_VERSION), _) => match value {
                TagValue::String(text) if self.version.is_none() => {
                    self.version = Some(text.to_display_string());
                }
                TagValue::String(_) => {}
                other => {
                    if let Some(packed) = integer(other) {
                        self.version = Some(format!("{}.{}", packed >> 16, packed & 0xFFFF));
                    }
                }
            },
            (None, Some("users")) => self.users = integer(value),
            (None, Some("files")) => self.files = integer(value),
            _ => {}
        }
    }
}

impl ServerMetFigures {
    /// The tags these figures write, each only when present — the reader's
    /// inverse, so a decode → encode → decode keeps them.
    pub(super) fn tags(&self) -> Vec<Tag> {
        let id = |id: u8, value: Option<u32>| {
            value.map(|value| Tag::new(TagName::compact_id(id), TagValue::U32(value)))
        };
        let named = |name: &str, value: Option<u32>| {
            value.and_then(|value| {
                TagName::text(name)
                    .ok()
                    .map(|name| Tag::new(name, TagValue::U32(value)))
            })
        };
        [
            named("users", self.users),
            named("files", self.files),
            id(TAG_PING, self.ping_ms),
            id(TAG_LASTPING, self.last_ping),
            id(TAG_SOFTFILES, self.soft_files),
            id(TAG_HARDFILES, self.hard_files),
            self.version.as_ref().map(|version| {
                Tag::new(
                    TagName::compact_id(TAG_VERSION),
                    TagValue::String(Ed2kText::from_utf8(version)),
                )
            }),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// An integer tag of any width that fits 32 bits, as aMule's `GetInt` reads it.
fn integer(value: &TagValue) -> Option<u32> {
    match value {
        TagValue::U8(v) => Some(u32::from(*v)),
        TagValue::U16(v) => Some(u32::from(*v)),
        TagValue::U32(v) => Some(*v),
        TagValue::U64(v) => u32::try_from(*v).ok(),
        TagValue::String(_) | TagValue::Hash(_) => None,
    }
}
