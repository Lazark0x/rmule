//! The **Link Riders** (ADR-0107 invariant 8): the downloads of one Peer
//! Link — the one riding it, aMule's one `m_reqfile`, and the ones waiting in
//! arrival order, aMule's A4AF list — and who takes the link next.

use std::collections::VecDeque;

use rmule_peer::{PeerCommand, PeerIdentity};
use tokio::sync::oneshot;

use super::{DownloadHalf, LinkJoin, Seat};
use crate::service::DialEnd;

/// The downloads of one link: the one riding it and the ones waiting, in
/// arrival order (ADR-0107 invariant 8).
#[derive(Default)]
pub(in crate::adapters) struct Riders {
    rider: Option<DownloadHalf>,
    /// The rider's worker let the link go: its commands are done, but what
    /// the session still reports of them — a file request's report among
    /// them — reaches it until another download takes the link.
    departed: bool,
    waiting: VecDeque<Waiter>,
}

/// A download waiting on the link, answered at its turn.
struct Waiter {
    half: DownloadHalf,
    seated: oneshot::Sender<Seat>,
}

impl Riders {
    /// Riders whose first rider is `half`: the download that dialed the link.
    pub(in crate::adapters) fn seated(half: DownloadHalf) -> Self {
        Self {
            rider: Some(half),
            departed: false,
            waiting: VecDeque::new(),
        }
    }

    /// Take `join`: seat it when nobody rides a link that knows its peer,
    /// else line it up and tell it so. Before the hello — no `identity` yet
    /// — every join waits.
    pub(in crate::adapters) fn take(&mut self, join: LinkJoin, identity: Option<&PeerIdentity>) {
        let LinkJoin {
            half,
            waiting,
            seated,
        } = join;
        let waiter = Waiter { half, seated };
        match identity {
            Some(identity) if !self.is_ridden() => {
                self.seat(waiter, identity);
            }
            _ => {
                if waiting.send(()).is_ok() {
                    self.waiting.push_back(waiter);
                }
            }
        }
    }

    /// The rider's worker let the link go: the oldest waiter still running
    /// takes it once the link knows its peer. Answers whether the link is
    /// left with nobody riding it, so an unasked grant still standing is
    /// nobody's and goes back (ADR-0056 item 3).
    pub(in crate::adapters) fn rider_left(&mut self, identity: Option<&PeerIdentity>) -> bool {
        self.departed = true;
        if let Some(identity) = identity {
            self.seat_next(identity);
        }
        !self.is_ridden()
    }

    /// The hello came: a link nobody rides any more seats its oldest waiter.
    pub(in crate::adapters) fn identified(&mut self, identity: &PeerIdentity) {
        if !self.is_ridden() {
            self.seat_next(identity);
        }
    }

    /// The Dial in Flight closed before its hello: every waiter is retired
    /// with `cause`, as the dialing download is.
    pub(in crate::adapters) fn dial_ended(&mut self, cause: DialEnd) {
        for waiter in self.waiting.drain(..) {
            let _ = waiter.seated.send(Seat::DialEnded(cause));
        }
    }

    fn seat_next(&mut self, identity: &PeerIdentity) {
        while let Some(waiter) = self.waiting.pop_front() {
            if self.seat(waiter, identity) {
                break;
            }
        }
    }

    fn seat(&mut self, waiter: Waiter, identity: &PeerIdentity) -> bool {
        if waiter
            .seated
            .send(Seat::Riding(Box::new(identity.clone())))
            .is_ok()
        {
            self.rider = Some(waiter.half);
            self.departed = false;
            true
        } else {
            false
        }
    }

    /// Whether a download rides the link now.
    pub(in crate::adapters) fn is_ridden(&self) -> bool {
        self.rider.is_some() && !self.departed
    }

    /// The download the link's requester events go to: the rider, or the
    /// last one while nobody took its place.
    pub(in crate::adapters) fn rider(&self) -> Option<&DownloadHalf> {
        self.rider.as_ref()
    }

    /// Whether no download holds the link any more: none rides it and none
    /// still running waits on it.
    pub(in crate::adapters) fn is_empty(&mut self) -> bool {
        self.waiting.retain(|waiter| !waiter.seated.is_closed());
        !self.is_ridden() && self.waiting.is_empty()
    }

    /// The rider's next command; `None` once its worker let the link go.
    /// Never resolves while nobody rides.
    pub(in crate::adapters) async fn next_command(&mut self) -> Option<PeerCommand> {
        match self.rider.as_mut() {
            Some(rider) if !self.departed => rider.peer_cmd_rx.recv().await,
            _ => std::future::pending().await,
        }
    }
}
