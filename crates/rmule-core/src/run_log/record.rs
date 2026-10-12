//! A line of the Run Log: an event code and typed fields.
//!
//! A field enters a [`Record`] only through the method that names what the
//! value is, and [`Kind::class`] is the one place that decides which level
//! admits it. A record is never formatted whole: [`Record::render`] drops the
//! fields the level does not admit. Search text, search result names and File
//! History paths have no method, so no level can hold them.

use std::fmt::{Display, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::path::Path;

use rmule_primitives::{
    ClientId, FileHash, Ipv4Endpoint, Ipv6Endpoint, PartHash, PeerEndpoint, ServerEndpoint,
    UserHash,
};

use super::level::Level;

/// What a field's value is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An address of ours.
    OwnAddress,
    /// The host and port of an eD2k server.
    ServerEndpoint,
    /// An ID a server gave us.
    OwnId,
    /// A port.
    Port,
    /// A number of things, an index, a rank, a duration in whole seconds.
    Count,
    /// A code from a closed vocabulary.
    Code,
    /// A protocol flags word as it was sent, bit for bit.
    FlagWord,
    /// The address of a peer, or an ID that stands for one.
    PeerAddress,
    /// The client name and version a peer announced.
    PeerSoftware,
    /// A file's name.
    FileName,
    /// The size of a named file.
    FileSize,
    /// A file hash or a part hash.
    Hash,
    /// A peer's user hash or Kad ID.
    PeerIdentity,
    /// A directory or file path.
    Path,
    /// A URL.
    Url,
}

impl Kind {
    /// The lowest level that admits a value of this kind.
    #[must_use]
    pub const fn class(self) -> Level {
        match self {
            Kind::OwnAddress
            | Kind::ServerEndpoint
            | Kind::OwnId
            | Kind::Port
            | Kind::Count
            | Kind::Code
            | Kind::FlagWord => Level::Lean,
            Kind::PeerAddress
            | Kind::PeerSoftware
            | Kind::FileName
            | Kind::FileSize
            | Kind::Hash
            | Kind::PeerIdentity
            | Kind::Path
            | Kind::Url => Level::Full,
        }
    }

    /// Whether the value may hold spaces or quotes, so it is written quoted
    /// and escaped to stay on one line.
    const fn quoted(self) -> bool {
        match self {
            Kind::PeerSoftware | Kind::FileName | Kind::Path | Kind::Url => true,
            Kind::OwnAddress
            | Kind::ServerEndpoint
            | Kind::OwnId
            | Kind::Port
            | Kind::Count
            | Kind::Code
            | Kind::FlagWord
            | Kind::PeerAddress
            | Kind::FileSize
            | Kind::Hash
            | Kind::PeerIdentity => false,
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// An address type a record may hold as an address, rather than as text.
pub trait Address: sealed::Sealed + Display {}

macro_rules! addresses {
    ($($ty:ty),* $(,)?) => {
        $(impl sealed::Sealed for $ty {} impl Address for $ty {})*
    };
}
addresses!(
    PeerEndpoint,
    Ipv4Endpoint,
    Ipv6Endpoint,
    SocketAddrV4,
    IpAddr,
    Ipv4Addr,
    Ipv6Addr
);

/// A number a record may hold as a count.
pub trait Number: Copy {
    /// The number as a signed 64-bit value, saturating.
    fn value(self) -> i64;
}

macro_rules! numbers {
    ($($ty:ty),* $(,)?) => {
        $(impl Number for $ty {
            fn value(self) -> i64 {
                i64::try_from(self).unwrap_or(i64::MAX)
            }
        })*
    };
}
numbers!(u8, u16, u32, u64, u128, usize, i32, i64);

/// An event code and the typed fields that came with it.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    code: &'static str,
    fields: Vec<(Kind, &'static str, String)>,
}

impl Record {
    /// A record of the event `code`, holding no fields yet.
    #[must_use]
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            fields: Vec::new(),
        }
    }

    fn field(mut self, kind: Kind, name: &'static str, value: String) -> Self {
        self.fields.push((kind, name, value));
        self
    }

    /// A code from a closed vocabulary: a reason, a state, a verdict.
    #[must_use]
    pub fn code(self, name: &'static str, code: &'static str) -> Self {
        self.field(Kind::Code, name, code.to_string())
    }

    /// A yes or a no.
    #[must_use]
    pub fn flag(self, name: &'static str, on: bool) -> Self {
        self.code(name, if on { "yes" } else { "no" })
    }

    /// The kind of an OS error, and its number when it gave one.
    #[must_use]
    pub fn os_error(self, kind: std::io::ErrorKind, os_code: Option<i32>) -> Self {
        self.os_error_named("error", kind, os_code)
    }

    /// [`os_error`](Self::os_error) under `name`, for a record whose `error`
    /// key is already taken.
    #[must_use]
    pub fn os_error_named(
        self,
        name: &'static str,
        kind: std::io::ErrorKind,
        os_code: Option<i32>,
    ) -> Self {
        let record = self.field(Kind::Code, name, super::codes::io_error(kind).to_owned());
        match os_code {
            Some(number) => record.count("os_code", number),
            None => record.code("os_code", "none"),
        }
    }

    /// A number of things, an index, a rank, seconds.
    #[must_use]
    pub fn count(self, name: &'static str, value: impl Number) -> Self {
        self.field(Kind::Count, name, value.value().to_string())
    }

    /// A flags word as the server sent it, in hex, so what a sentence says of
    /// its bits can be checked against the bits.
    #[must_use]
    pub fn flag_word(self, name: &'static str, word: u32) -> Self {
        self.field(Kind::FlagWord, name, format!("0x{word:08X}"))
    }

    /// A port.
    #[must_use]
    pub fn port(self, name: &'static str, port: u16) -> Self {
        self.field(Kind::Port, name, port.to_string())
    }

    /// An address of ours.
    #[must_use]
    pub fn own_address(self, name: &'static str, address: &impl Address) -> Self {
        self.field(Kind::OwnAddress, name, address.to_string())
    }

    /// The server we are talking to.
    #[must_use]
    pub fn server_endpoint(self, name: &'static str, server: &ServerEndpoint) -> Self {
        self.field(
            Kind::ServerEndpoint,
            name,
            format!("{}:{}", server.host(), server.port()),
        )
    }

    /// The address a server is reached at.
    #[must_use]
    pub fn server_address(self, name: &'static str, address: &impl Address) -> Self {
        self.field(Kind::ServerEndpoint, name, address.to_string())
    }

    /// The ID a server gave us.
    #[must_use]
    pub fn own_id(self, name: &'static str, id: ClientId) -> Self {
        self.field(Kind::OwnId, name, id.as_u32().to_string())
    }

    /// A peer's address.
    #[must_use]
    pub fn peer_address(self, name: &'static str, address: &impl Address) -> Self {
        self.field(Kind::PeerAddress, name, address.to_string())
    }

    /// A peer's ID, which for a High ID is its address.
    #[must_use]
    pub fn peer_id(self, name: &'static str, id: ClientId) -> Self {
        self.field(Kind::PeerAddress, name, id.as_u32().to_string())
    }

    /// The client software a peer announced.
    #[must_use]
    pub fn peer_software(self, name: &'static str, label: &str) -> Self {
        self.field(Kind::PeerSoftware, name, label.to_string())
    }

    /// A file's name.
    #[must_use]
    pub fn file_name(self, name: &'static str, file_name: &str) -> Self {
        self.field(Kind::FileName, name, file_name.to_string())
    }

    /// The size of a named file.
    #[must_use]
    pub fn file_size(self, name: &'static str, bytes: u64) -> Self {
        self.field(Kind::FileSize, name, bytes.to_string())
    }

    /// A file's hash.
    #[must_use]
    pub fn file_hash(self, name: &'static str, hash: &FileHash) -> Self {
        self.field(Kind::Hash, name, hash.to_hex_upper())
    }

    /// A part's hash.
    #[must_use]
    pub fn part_hash(self, name: &'static str, hash: &PartHash) -> Self {
        self.field(Kind::Hash, name, hash.to_hex_upper())
    }

    /// A peer's user hash.
    #[must_use]
    pub fn user_hash(self, name: &'static str, hash: &UserHash) -> Self {
        self.field(Kind::PeerIdentity, name, hash.to_hex_upper())
    }

    /// A peer's Kad ID.
    #[must_use]
    pub fn kad_id(self, name: &'static str, id: &crate::KadId) -> Self {
        self.field(
            Kind::PeerIdentity,
            name,
            data_encoding::HEXUPPER.encode(id.as_bytes()),
        )
    }

    /// A directory or file path.
    #[must_use]
    pub fn path(self, name: &'static str, path: &Path) -> Self {
        self.field(Kind::Path, name, path.display().to_string())
    }

    /// A URL.
    #[must_use]
    pub fn url(self, name: &'static str, url: &str) -> Self {
        self.field(Kind::Url, name, url.to_string())
    }

    /// The line `level` admits: the code, then every field its class allows.
    #[must_use]
    pub fn render(&self, level: Level) -> String {
        let mut line = self.code.to_string();
        for (kind, name, value) in &self.fields {
            if kind.class() > level {
                continue;
            }
            let _ = if kind.quoted() {
                write!(line, " {name}=\"{}\"", value.escape_debug())
            } else {
                write!(line, " {name}={value}")
            };
        }
        line
    }
}
