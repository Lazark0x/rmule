//! How an upload slot reaches the peer it is granted to, why a **Dial-Back
//! Grant** ended unsent (ADR-0057), and why a slot holder's block request
//! ended its slot (ADR-0031): the vocabulary that lets the operator tell a
//! grant on a link the peer held from one rmule dialed back, and read why a
//! peer lost its slot.

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

/// Why a slot holder's block request ended its slot before anything of it was
/// read ([`ServeEvent::BlockAskRefused`](super::ServeEvent::BlockAskRefused),
/// ADR-0031). aMule throws on each and only takes the client out of its upload
/// queue (`UploadClient.cpp:211-231`, `:270-281`). Declared in rank order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockAskFault {
    /// A range ends past the file's end (`UploadClient.cpp:211-213`).
    PastEnd,
    /// A range is longer than three blocks, `3 × EMBLOCKSIZE`
    /// (`UploadClient.cpp:221-224`).
    TooLong,
    /// A range of a Partial Share falls outside its **Verified Range**
    /// (ADR-0113; aMule `UploadClient.cpp:227-231`).
    Unverified,
}
