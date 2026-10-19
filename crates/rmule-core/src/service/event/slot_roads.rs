//! How an upload slot reaches the peer it is granted to, and why a
//! **Dial-Back Grant** ended unsent (ADR-0057): the vocabulary that lets the
//! operator tell a grant on a link the peer held from one rmule dialed back.

use super::DialEnd;

/// The road an upload slot took to its peer
/// ([`ServeEvent::UploadSlotGranted`](super::ServeEvent::UploadSlotGranted)).
/// Declared in rank order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantRoad {
    /// On the link the peer held: at its own ask, or at its promotion while
    /// linked (aMule `UploadQueue.cpp:211-217`).
    Linked,
    /// On the link rmule dialed to the waiter it promoted with no link up,
    /// after the hellos (aMule `BaseClient.cpp:1707-1716`).
    DialedBack,
    /// On the link the waiter came back on while rmule held its slot for a
    /// dial-back (aMule `ClientTCPSocket.cpp:328`, `:417`).
    CameBack,
    /// At its ask on the link it came back on, after the **Next-Connection
    /// Mark** a Low ID earns (aMule `UploadQueue.cpp:410-425`).
    NextConnection,
}

/// Why a **Dial-Back Grant** ended without reaching its waiter
/// ([`ServeEvent::UploadDialBackFailed`](super::ServeEvent::UploadDialBackFailed)).
/// The waiter loses its place with it, as aMule deletes a client whose
/// upload connect failed (`BaseClient.cpp:1333-1337`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialBackEnd {
    /// The dial ended before the waiter's hello.
    Dial(DialEnd),
    /// The client that answered at the waiter's endpoint named another User
    /// Hash.
    AnotherClient,
    /// No link of the waiter came up within the purge window
    /// (`MAX_PURGEQUEUETIME`).
    Lapsed,
}
