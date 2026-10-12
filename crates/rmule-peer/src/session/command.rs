//! What a driver asks of a peer session, and the fan-out that applies it.
//!
//! [`PeerCommand`] is the whole inbound vocabulary — both capabilities'
//! asks on one connection (ADR-0031), grouped like [`PeerEvent`]. Each
//! group's submodule defines its commands and hands every one that touches
//! session state to the leg that owns that state, framing directly only the
//! asks that are nothing but one packet on the wire. Either path rejects what
//! the current state forbids.

mod connection;
mod requester;
mod server;
mod side;

pub use self::connection::ConnectionCommand;
pub use self::requester::RequesterCommand;
pub use self::server::ServerCommand;
pub use self::side::SideCommand;

use rmule_primitives::SessionOutput;

use super::{PeerCloseReason, PeerEvent, PeerSession, State};

/// One effect drained from a [`PeerSession`]: the shared [`SessionOutput`]
/// spine over the peer event and close-reason vocabularies (ADR-0044).
pub type PeerOutput = SessionOutput<PeerEvent, PeerCloseReason>;

/// Everything a driver can ask of a session — both capabilities on one
/// connection (ADR-0031), grouped by the side of the conversation each
/// serves. A command the current state forbids is answered with
/// `CommandRejected`, never a panic and never silence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerCommand {
    /// The link itself: close it, or correct the IPv6 our hello named.
    Connection(ConnectionCommand),
    /// Our pull from the peer: the Requester Capability (ADR-0025).
    Requester(RequesterCommand),
    /// Our answers to the peer's pull: the Server Capability (ADR-0031).
    Server(ServerCommand),
    /// Frames core's node-wide services send over the link.
    Side(SideCommand),
}

impl PeerSession {
    /// Apply one command, or reject it with the reason the state gives.
    /// Every group lands on its own submodule; nothing is handled here.
    pub fn handle_command(&mut self, command: PeerCommand) {
        if matches!(self.state, State::Closed) {
            return;
        }
        match command {
            PeerCommand::Connection(command) => self.apply_connection(command),
            PeerCommand::Requester(command) => self.apply_requester(command),
            PeerCommand::Server(command) => self.apply_server(command),
            PeerCommand::Side(command) => self.apply_side(command),
        }
    }
}
