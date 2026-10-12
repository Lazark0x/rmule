//! The steps of one server login between its session edges (ADR-0075, Run
//! Log): what rmule claimed about itself, what the server did with the claim,
//! and where the login stopped. A step is evidence, not an edge: no level moves
//! with it, and every field is rmule's own or the server's, never a peer's.

use std::net::Ipv6Addr;
use std::time::Duration;

use rmule_primitives::{AddressFamily, ClientId};

use rmule_ed2k::ServerGrants;

use crate::address_learning::AssignedAddress;
pub use crate::reachability::Ipv6Probe;

/// One step of a login to a server, carried by
/// [`CoreEvent::ServerLogin`](super::CoreEvent::ServerLogin).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginStep {
    /// The **Login Mapping Wait** ended: the listener's port-mapping row
    /// settled, or the wait's bound passed first and the login leaves while
    /// the gateway may still be granting the port the server's check dials.
    /// Only with a mapping runtime running.
    MappingWait {
        /// The listen port the login advertises.
        port: u16,
        /// Whether the row settled inside the bound.
        settled: bool,
    },
    /// How the link to the server is about to be opened — plain or
    /// obfuscated, and why plain (ADR-0042). Stated before every dial, so a
    /// fallback after a failed obfuscated attempt is a second one.
    LinkChosen {
        /// The link.
        link: LoginLink,
    },
    /// The TCP dial to the server did not come up, or an obfuscated one did
    /// and its crypt handshake did not complete; a plain fallback or a
    /// [`ServerConnectFailure::Unreachable`](super::ServerConnectFailure::Unreachable)
    /// follows.
    DialFailed {
        /// Why.
        cause: DialFailure,
    },
    /// The link is up and the login has left, claiming these.
    LoginSent {
        /// What the login said about rmule.
        claim: LoginClaim,
    },
    /// The server ended the link before it answered the login; a
    /// [`ServerConnectFailure::ClosedBeforeAnswer`](super::ServerConnectFailure::ClosedBeforeAnswer)
    /// follows.
    ClosedBeforeAnswer {
        /// How the link ended.
        cause: LoginCloseCause,
    },
    /// The link is up and the login's answer is awaited: the server's High-ID
    /// port test may dial the listener plain until it lands (the **Awaited
    /// Testers**' server window).
    PortTestAwaited,
    /// A connection from the awaited server's address was accepted inside
    /// the window.
    PortTestArrived {
        /// How the listener admitted it.
        admission: PortTestAdmission,
    },
    /// A connection from the awaited server ended: a **Test Connection**,
    /// served nothing, or one admitted as an ordinary peer, inside the window
    /// or late.
    PortTestEnded {
        /// How.
        end: PortTestEnd,
    },
    /// A connection from the server came after its window closed (the
    /// **Awaited Testers** remember a closed window for a bounded time).
    PortTestLate {
        /// How long after the window closed it came.
        late_by: Duration,
        /// What the listener did with it.
        admission: PortTestLateAdmission,
    },
    /// The login was answered or ended, and the port test's window with it.
    PortTestWindowClosed {
        /// Whether a connection from the server arrived inside it.
        arrived: bool,
    },
    /// The server assigned an id at login.
    Answered {
        /// What it assigned.
        assignment: IdAssignment,
    },
    /// The connected server assigned an id again mid-session.
    Reassigned {
        /// What it assigned.
        assignment: IdAssignment,
    },
    /// The connected server stated a verdict on the IPv6 address the login
    /// advertised.
    Ipv6Probe {
        /// What it stated.
        verdict: Ipv6Probe,
    },
    /// A High ID landed while Kad's TCP verdict read firewalled, and Kad was
    /// asked to check again: the server has just reached the listener Kad
    /// advertises.
    KadRecheck,
}

/// What one `OP_IDCHANGE` assigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdAssignment {
    /// The id: High (the address the server reached) or Low.
    pub client_id: ClientId,
    /// Our public IPv4 as this answer establishes it, or the server's own
    /// address refused as ours.
    pub address: AssignedAddress,
    /// What the server granted, each `SRV_TCPFLG_*` bit by name.
    pub grants: ServerGrants,
}

/// How the listener admitted a connection from the awaited server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortTestAdmission {
    /// A plain dial under `ObfuscationPolicy::Required`, admitted as a
    /// **Test Connection**: answered its hello and served nothing.
    TestConnection,
    /// Admitted as an ordinary peer: the crypt policy admits its opener, so
    /// nothing tells the test apart from a peer.
    Peer,
}

/// What the listener did with a connection from the server that came after
/// its window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortTestLateAdmission {
    /// A plain dial under `ObfuscationPolicy::Required`, refused: no test is
    /// awaited from it any more.
    Refused,
    /// Admitted as an ordinary peer: its opener meets the crypt policy.
    Peer,
}

/// How a connection from the awaited server ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortTestEnd {
    /// The tester closed it.
    TesterClosed,
    /// It asked to be served, and was closed.
    AskedToBeServed,
    /// It outlived a test's bound, and was closed.
    Lapsed,
    /// The IP filter refused it before its hello.
    IpFiltered,
    /// A ban on its address refused it before its hello.
    Banned,
    /// Admitted as an ordinary peer, its peer connection ended — the one end
    /// known of a test the crypt policy cannot tell from a peer.
    PeerConnectionEnded {
        /// Who closed the peer connection.
        closed_by: PortTestClosedBy,
    },
}

/// Who closed a port test's peer connection: its own close reason, read where
/// the accept router ends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortTestClosedBy {
    /// rmule closed it: a serve decision, a teardown, or core letting the
    /// connection go.
    Us,
    /// The server closed it, cleanly or by vanishing.
    Peer,
    /// The server sent what the peer session could not continue past.
    ProtocolViolation,
    /// The socket failed.
    Io {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
    },
    /// No hello came inside the startup deadline.
    Timeout,
    /// The connection's driver stopped without naming a close.
    DriverEnded,
    /// A close the peer session names and this vocabulary does not yet: its
    /// stable label ([`rmule_peer::PeerCloseReason::label`]).
    Unlisted {
        /// The peer session's label for it.
        label: &'static str,
    },
}

impl From<&rmule_peer::PeerCloseReason> for PortTestClosedBy {
    fn from(reason: &rmule_peer::PeerCloseReason) -> Self {
        use rmule_peer::PeerCloseReason as R;
        match reason {
            R::Local => Self::Us,
            R::PeerClosed => Self::Peer,
            R::ProtocolViolation => Self::ProtocolViolation,
            R::Io(kind) => Self::Io { kind: *kind },
            R::ConnectTimeout | R::HelloTimeout => Self::Timeout,
            // `PeerCloseReason` is non-exhaustive: a variant it gains keeps
            // its own stable label rather than borrowing another's.
            other => Self::Unlisted {
                label: other.label(),
            },
        }
    }
}

/// What a login said about rmule: every value is rmule's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginClaim {
    /// The family of the link the login went out on; `None` when the
    /// connection did not name the address it reached.
    pub family: Option<AddressFamily>,
    /// The TCP listen port the login advertises.
    pub tcp_port: u16,
    /// The client-UDP port the login advertises; `None` when it carries no
    /// UDP ports.
    pub client_udp_port: Option<u16>,
    /// The Kad UDP port the login advertises; `None` when it carries none or
    /// names none (no Kad node running).
    pub kad_udp_port: Option<u16>,
    /// The IPv6 address the login advertises, when the Advertised Endpoints
    /// chooser settled one.
    pub advertised_ipv6: Option<Ipv6Addr>,
}

/// How a login's link to the server is opened (ADR-0042): aMule's dial gate
/// (`ServerSocket.cpp:786-795`) read against our policy and what the server
/// has said of itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginLink {
    /// The server's own port, plain.
    Plain {
        /// Why not obfuscated.
        why: PlainLinkReason,
    },
    /// The server's obfuscation TCP port, with the server form of the crypt
    /// handshake before the login.
    Obfuscated {
        /// The port dialed.
        port: u16,
    },
}

/// Why a login's link is plain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainLinkReason {
    /// Our policy does not initiate obfuscation: it is off, or `Supported`.
    PolicyDoesNotInitiate,
    /// Our policy initiates, but the server has not said it takes obfuscation
    /// over TCP: no obfuscation TCP port is known for it, or neither its UDP
    /// nor its TCP flags carry `TCPOBFUSCATION`.
    ServerNotKnownToObfuscate,
    /// The obfuscated attempt failed and the policy is `Requested`, which
    /// falls back to plain where `Required` does not.
    ObfuscatedAttemptFailed,
}

/// Why a dial to a server did not come up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialFailure {
    /// No answer inside the connect timeout.
    TimedOut,
    /// The OS refused it.
    Os {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
        /// The OS's error number, when there is one.
        os_code: Option<i32>,
    },
    /// The connection's driver ended before the dial settled.
    DriverEnded,
    /// The obfuscated link came up, but the server form of the crypt
    /// handshake did not complete (ADR-0042).
    CryptHandshake {
        /// How it failed: the socket's error, `TimedOut` for a server that
        /// said nothing within the connect timeout, `InvalidData` for an
        /// answer that did not decrypt to the sync magic.
        kind: std::io::ErrorKind,
    },
}

/// How a link ended before its login was answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginCloseCause {
    /// rmule closed it.
    Local,
    /// The server closed the socket without a word.
    ServerClosed,
    /// The server sent what the login session could not accept.
    ProtocolViolation,
    /// The socket failed.
    Io {
        /// The kind of the OS error.
        kind: std::io::ErrorKind,
    },
    /// The dial's own timeout.
    ConnectTimeout,
    /// The login's own deadline.
    LoginTimeout,
    /// The server refused the login.
    Refused,
    /// A close the eD2k session names and this vocabulary does not yet: its
    /// stable label ([`rmule_ed2k::CloseReason::label`]).
    Unlisted {
        /// The eD2k session's label for it.
        label: &'static str,
    },
}

impl From<&rmule_ed2k::CloseReason> for LoginCloseCause {
    fn from(reason: &rmule_ed2k::CloseReason) -> Self {
        use rmule_ed2k::CloseReason as R;
        match reason {
            R::Local => Self::Local,
            R::ServerClosed => Self::ServerClosed,
            R::ProtocolViolation(_) => Self::ProtocolViolation,
            R::Io(kind) => Self::Io { kind: *kind },
            R::ConnectTimeout => Self::ConnectTimeout,
            R::LoginTimeout => Self::LoginTimeout,
            R::LoginRejected => Self::Refused,
            // `CloseReason` is non-exhaustive: a variant it gains keeps its
            // own stable label rather than borrowing another's.
            other => Self::Unlisted {
                label: other.label(),
            },
        }
    }
}
