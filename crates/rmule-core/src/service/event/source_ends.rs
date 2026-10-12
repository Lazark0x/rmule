//! Why a source's road ended short: a dial that ended before the peer's
//! hello, a reask reply the download could not take, and a source let go to
//! make room. Each is a code the front end words; none names an address but
//! [`PurgedSource`], which says which source went.

/// Why a download's dial to a source ended before the peer's hello
/// ([`DownloadEvent::DialEnded`](super::DownloadEvent::DialEnded)). Such a
/// worker holds no part to release, so this is the only trace it leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialEnd {
    /// Refused before any socket: our policy requires obfuscation and no
    /// record or hello ever stated the peer's crypt stance, so it is met as a
    /// peer that cannot obfuscate (ADR-0049's outbound rule).
    CryptStanceUnknown,
    /// Refused before any socket: our policy requires obfuscation and the
    /// peer stated it cannot.
    CryptUnsupported,
    /// Refused before any socket: the peer requires obfuscation and ours is
    /// off.
    CryptRequiredByPeer,
    /// Refused before any socket: a side requires obfuscation and the peer's
    /// User Hash, the obfuscation key, is not known.
    CryptKeyUnknown,
    /// Never dialed: the IP filter blocks its address.
    IpFiltered,
    /// Never dialed: the peer is banned.
    Banned,
    /// The peer's host refused the connection.
    ConnectionRefused,
    /// No answer inside the connect timeout.
    TimedOut,
    /// The connection was reset before the hello.
    Reset,
    /// Another OS error ended the dial.
    Os {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
    },
    /// The peer closed the connection before its hello.
    ClosedBeforeHello,
    /// No hello arrived inside the startup deadline.
    NoHelloInTime,
    /// The peer sent what the session could not accept before its hello.
    ProtocolViolation,
    /// rmule closed the connection before the hello (the run stopping).
    ClosedLocally,
}

/// Why a reask reply reached a download and changed nothing
/// ([`DownloadEvent::ReaskReplyIgnored`](super::DownloadEvent::ReaskReplyIgnored)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoredReaskReply {
    /// Shorter than the two-byte header.
    Runt,
    /// Not `0x91`, `0x92` or `0x93`.
    UnexpectedOpcode,
    /// No pooled source holds the endpoint it came from.
    NoPooledSource,
    /// Its body did not read as the reply shape both ends' UDP versions
    /// call for.
    Misframed,
    /// Its part status counts other than the file's parts: aMule's
    /// `ProcessFileStatus` throws on it and drops the whole answer, rank
    /// unread (stock 2.3.3 `DownloadClient.cpp:416-424`).
    PartCountMismatch,
}

/// Why a download let a source go to make room as the file neared its source
/// limit ([`DownloadEvent::SourcePurged`](super::DownloadEvent::SourcePurged)):
/// aMule's three purges in `CPartFile::Process` (stock 2.3.3
/// `PartFile.cpp:1406-1456`), one source at a time on one clock per file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourcePurgeReason {
    /// A Low ID that no road reaches: we cannot be called back for it and it
    /// names no coordinator (aMule `DS_LOWTOLOWIP`).
    LowToLow,
    /// It holds no part we lack (aMule `DS_NONEEDEDPARTS`).
    NoNeededParts,
    /// Its queue stayed full (aMule `IsRemoteQueueFull`).
    QueueFull,
}

/// The source a download let go
/// ([`DownloadEvent::SourcePurged`](super::DownloadEvent::SourcePurged)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgedSource {
    /// The endpoint it stood queued at.
    Endpoint(rmule_primitives::PeerEndpoint),
    /// A Low ID never reached, by the id and the server that assigned it —
    /// `None` when it was the server we are logged into.
    LowId {
        /// Its server-assigned Low ID.
        low_id: rmule_primitives::ClientId,
        /// The server that assigned it, when not ours.
        server: Option<rmule_primitives::Ipv4Endpoint>,
    },
}
