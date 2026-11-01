//! The headers of every table's columns. A column's stored key is another
//! thing (`table_sort::keys`): this word may be translated, that one may not.

/// A row's name.
pub const NAME: &str = "Name";
/// A file's name.
pub const FILE: &str = "File";
/// A size in bytes.
pub const SIZE: &str = "Size";
/// How much of a download is done.
pub const DONE: &str = "Done";
/// A download's chunk map.
pub const PROGRESS: &str = "Progress";
/// A rate.
pub const SPEED: &str = "Speed";
/// The time a download has left.
pub const ETA: &str = "ETA";
/// A download's sources, short for its narrow column.
pub const SRC: &str = "Src";
/// A row's status.
pub const STATUS: &str = "Status";
/// A result's sources.
pub const SOURCES: &str = "Sources";
/// A result's file type.
pub const TYPE: &str = "Type";
/// One source of a download.
pub const SOURCE: &str = "Source";
/// What a peer calls its client.
pub const SOFTWARE: &str = "Software";
/// Where a source stands.
pub const PHASE: &str = "Phase";
/// A server's address.
pub const ADDRESS: &str = "Address";
/// A server's port.
pub const PORT: &str = "Port";
/// A server's description.
pub const DESC: &str = "Desc";
/// A server's measured round trip.
pub const PING: &str = "Ping";
/// A server's users.
pub const USERS: &str = "Users";
/// A server's files.
pub const FILES: &str = "Files";
/// How long ago a server answered.
pub const AGE: &str = "Age";
/// A server's priority.
pub const PRIO: &str = "Prio";
/// A server's failed tries.
pub const FAIL: &str = "Fail";
/// Whether a server is pinned.
pub const STATIC: &str = "Static";
/// Where a shared file or an upload peer stands.
pub const STATE: &str = "State";
/// How many peers a file is uploading to.
pub const UPLOADING: &str = "Uploading";
/// How many requests a file drew.
pub const REQUESTS: &str = "Requests";
/// How many of them it accepted.
pub const ACCEPTED: &str = "Accepted";
/// How much of it went out.
pub const TRANSFERRED: &str = "Transferred";
/// An upload peer.
pub const PEER: &str = "Peer";
