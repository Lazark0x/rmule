//! What holds a **Peer Link** besides its downloads (ADR-0107 invariant 9):
//! its serve side while it serves, once the peer has asked it anything over
//! the link (ADR-0031), and the buddy slot while the link is the held buddy
//! link (ADR-0061). A link its last rider leaves with neither holding it
//! closes then, so a rider's Queued Hang-Up sends the FIN well inside the
//! uploader's 40 s silent-link close (ADR-0116, `ClientTCPSocket.cpp:201-229`).

use rmule_primitives::PeerEndpoint;

use crate::buddy_link::SharedBuddySlot;

/// The serve side's and the buddy slot's hold on one link.
pub(in crate::adapters) struct ServeHold {
    remote: PeerEndpoint,
    buddy: SharedBuddySlot,
    serving: bool,
    pulled: bool,
}

impl ServeHold {
    /// The hold on the link at `remote` as its serve side attaches: serving,
    /// asked nothing yet.
    pub(in crate::adapters) const fn new(remote: PeerEndpoint, buddy: SharedBuddySlot) -> Self {
        Self {
            remote,
            buddy,
            serving: true,
            pulled: false,
        }
    }

    /// Whether the serve side still takes the link's requests.
    pub(in crate::adapters) const fn serving(&self) -> bool {
        self.serving
    }

    /// The serve side let the link go.
    pub(in crate::adapters) fn serve_ended(&mut self) {
        self.serving = false;
    }

    /// The peer asked the serve side something over the link: its pull is
    /// the peer's to end, so the serve side holds the link from now on.
    pub(in crate::adapters) fn pulled(&mut self) {
        self.pulled = true;
    }

    /// Whether the link stays up with no download holding it.
    pub(in crate::adapters) fn holds(&self) -> bool {
        (self.serving && self.pulled) || self.buddy.holds_link(self.remote)
    }
}
