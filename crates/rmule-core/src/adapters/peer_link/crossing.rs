//! A peer's hello meeting a dial of rmule's to the same peer (ADR-0107
//! invariant 7). The far end keeps one socket per client, and the client asks
//! on whichever link it keeps only from `DS_CONNECTING`
//! (`BaseClient.cpp:1692-1698`): answer the hello on the link it is about to
//! replace, and it has asked there, asks nothing on the one it keeps
//! (`ClientList.cpp:400-403`) and drops the grant on it
//! (`ClientTCPSocket.cpp:640-645`). Close that link instead and it is a dead
//! source (`BaseClient.cpp:1340-1346`). So while a dial's hello is out the
//! peer's hello is held: unanswered, unfiled, and unheard of by the serve
//! side, until the far end shows which link it kept.
//!
//! An answer on the dial does not show that: a client with no address yet
//! refuses the attach and a second client with no file answers
//! (`ClientList.cpp:388-397`), with the real one waiting on the held link.
//! What shows it is that link's close: the attach deletes it ahead of the
//! answer. So a dial answered with a hello held on it goes back on the
//! yielding list and tells its rider and its grant nothing; the close lets it
//! go on, and the [`CLOSE_BOUND`] passing makes it yield to the held link,
//! answered then, as a dial yields before its hello.
//!
//! The session reads the hello, and this decides, in one step under the book's
//! lock: a dial claims its hello under the same lock, so no hello of ours can
//! go out behind an answer. It cannot wait for the accept road's triage, which
//! starts with the serve loop, after the server's port test was answered.
//!
//! Only a link from the address the dial went to can be that peer's own: a
//! hello from anywhere else is a claim no socket backs, and meets no dial
//! (ADR-0107, "What a link proves to take a dial").

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule_peer::{HelloGate, PeerIdentity};
use rmule_primitives::{PeerEndpoint, UserHash};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use super::{Book, Filing, FoundLink, LinkJoin, LinkName, Moving, SharedPeerLinks};

/// How long a hello is held when rmule's User Hash is the lower of the two.
/// It stays well inside the peer's 40 s clock on the link it is waiting on
/// (`ClientTCPSocket.cpp:201-229`), with the answer's trip to spare.
const HOLD_AS_THE_LOWER_HASH: Duration = Duration::from_secs(20);

/// How long it is held otherwise. Two rmules crossing each hold the other's
/// hello, and only the bound settles that: the higher hash gives its dial up
/// first, answering the lower's, whose own dial is so answered in time.
const HOLD_AS_THE_HIGHER_HASH: Duration = Duration::from_secs(10);

/// How long past the dial's answer the held link may stay open before the far
/// end has refused the attach. The attach closes that link ahead of the answer
/// (`ClientList.cpp:400-403`, `ClientTCPSocket.cpp:391`), so this is no aMule
/// timer: it only outlasts a FIN retransmitted on a live path. Read short, it
/// loses a client that kept the dial; read long, it delays a first contact.
pub(super) const CLOSE_BOUND: Duration = Duration::from_secs(3);

/// A dial whose hello is out and not answered yet.
pub(super) struct UnansweredDial {
    answered: watch::Sender<bool>,
    give_up: oneshot::Sender<()>,
    /// A hello has been held on the dial, whether or not it still is.
    crossed: bool,
}

impl UnansweredDial {
    /// The dial's hello claimed: the entry for the book, and where the dial
    /// hears it was given up.
    pub(super) fn new() -> (Self, oneshot::Receiver<()>) {
        let (give_up, given_up) = oneshot::channel();
        let (answered, _) = watch::channel(false);
        (
            Self {
                answered,
                give_up,
                crossed: false,
            },
            given_up,
        )
    }

    /// The far end answered: every hello held on the dial learns it, and
    /// starts the [`CLOSE_BOUND`].
    pub(super) fn answered(&self) {
        self.answered.send_replace(true);
    }

    /// Whether a peer's hello is held on the dial.
    pub(super) fn holds_a_hello(&self) -> bool {
        self.answered.receiver_count() > 0
    }

    /// Whether a peer's hello was ever held on the dial.
    pub(super) const fn crossed(&self) -> bool {
        self.crossed
    }
}

/// The gate of a dial's session: its link's first words wait while a hello is
/// held on the dial, for the far end that took it over owes them an answer's
/// wait ([`AnswerHeard::Kept`]).
pub(in crate::adapters) struct DialGate {
    links: SharedPeerLinks,
    filing: u64,
}

impl std::fmt::Debug for DialGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialGate").finish_non_exhaustive()
    }
}

impl DialGate {
    pub(super) fn gate(links: SharedPeerLinks, filing: u64) -> Arc<dyn HelloGate> {
        Arc::new(Self { links, filing })
    }
}

impl HelloGate for DialGate {
    fn may_answer(&self, _: PeerEndpoint, _: &PeerIdentity) -> bool {
        true
    }

    fn may_open_dial(&self) -> bool {
        self.links.book.lock().map_or(true, |book| {
            book.unanswered
                .get(&self.filing)
                .is_none_or(|dial| !dial.crossed)
        })
    }
}

/// What the far end's answer on a dial came to.
pub(in crate::adapters) enum AnswerHeard {
    /// Nothing crossed the dial: it goes on.
    Stands,
    /// The far end closed its own link, a hello held on the dial: the dial
    /// goes on, and owes the client it took over the answer to that hello.
    /// `OP_HELLO` on a socket does not end a client's wait for the answer to
    /// its own (`BaseClient.cpp:466`, `:744`), and aMule drops a link that
    /// speaks before that comes (`ClientTCPSocket.cpp:1298-1302`).
    Kept,
    /// The far end stayed on its own link: the dial gives way to it.
    GaveWay(FoundLink),
}

/// An accepted link, answered and filed under its names.
pub(in crate::adapters) struct AcceptedLink {
    pub(in crate::adapters) filing: Filing,
    pub(in crate::adapters) joins: mpsc::UnboundedReceiver<LinkJoin>,
    pub(in crate::adapters) moving: Moving,
}

/// What a peer's hello met among rmule's dials.
pub(in crate::adapters) enum Meeting {
    /// Nothing crosses it: the link is filed and its hello may be answered.
    Clear(AcceptedLink),
    /// A dial's hello is out unanswered: hold this one until it settles.
    Crossed(CrossedDial),
}

/// How a dial a hello was held on settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::adapters) enum DialSettled {
    /// The far end answered it, which alone says nothing of which link it
    /// kept.
    Answered,
    /// It ended unanswered: the far end is on its own link.
    Ended,
}

/// The dial a held hello waits on. Dropped with the dial waiting for its
/// verdict and nothing having overtaken it, the dial goes on.
pub(in crate::adapters) struct CrossedDial {
    links: SharedPeerLinks,
    filing: u64,
    answered: watch::Receiver<bool>,
    ends: Instant,
}

impl CrossedDial {
    /// When the hello must stop being held, for this dial and any it meets
    /// after: the peer's clock on the link runs from its hello, however many
    /// dials stand in the way.
    pub(in crate::adapters) const fn ends(&self) -> Instant {
        self.ends
    }

    /// How long past the dial's answer it may stay held.
    pub(in crate::adapters) const fn close_bound(&self) -> Duration {
        CLOSE_BOUND
    }

    /// Resolves when the dial is answered or ends.
    pub(in crate::adapters) async fn settled(&mut self) -> DialSettled {
        match self.answered.wait_for(|answered| *answered).await {
            Ok(_) => DialSettled::Answered,
            Err(_) => DialSettled::Ended,
        }
    }

    /// The bound passed with the hello held: the far end read nothing on the
    /// dial and stays on its own link, so the dial is given up.
    pub(in crate::adapters) fn give_up(&self) {
        let Ok(mut book) = self.links.book.lock() else {
            return;
        };
        if let Some(dial) = book.unanswered.remove(&self.filing) {
            let _ = dial.give_up.send(());
        }
    }
}

impl Drop for CrossedDial {
    fn drop(&mut self) {
        if let Ok(mut book) = self.links.book.lock() {
            book.yielding.remove(&self.filing);
        }
    }
}

impl SharedPeerLinks {
    /// The hello of a link the peer opened from `remote`, proving `names`,
    /// meets rmule's dials, `own` being rmule's User Hash when known: held
    /// when one to that address has its hello out unanswered under a name,
    /// else the link is filed, in the one step, and such a dial whose hello
    /// has not gone out yields to it.
    pub(in crate::adapters) fn meet(
        &self,
        remote: PeerEndpoint,
        names: Vec<LinkName>,
        own: Option<UserHash>,
    ) -> Meeting {
        let peer = names.iter().find_map(|name| match name {
            LinkName::User(hash) => Some(*hash),
            _ => None,
        });
        self.meet_until(remote, names, Instant::now() + held_for(own, peer))
    }

    /// The hello held on `earlier`, which let it go, meets rmule's dials
    /// again: a dial it meets now holds it only until `earlier` would have.
    pub(in crate::adapters) fn meet_again(
        &self,
        remote: PeerEndpoint,
        names: Vec<LinkName>,
        earlier: &CrossedDial,
    ) -> Meeting {
        self.meet_until(remote, names, earlier.ends)
    }

    fn meet_until(&self, remote: PeerEndpoint, names: Vec<LinkName>, ends: Instant) -> Meeting {
        let mut book = self.book.lock().expect("peer links lock");
        if let Some((filing, answered)) = book.crossing(remote, &names) {
            return Meeting::Crossed(CrossedDial {
                links: self.clone(),
                filing,
                answered,
                ends,
            });
        }
        let (filing, joins, moving) = self.file_in(&mut book, remote, names);
        Meeting::Clear(AcceptedLink {
            filing,
            joins,
            moving,
        })
    }

    /// What the hello read on the link from `remote` met, as its session's
    /// gate left it; `None` for a link with no gate of these Peer Links.
    pub(in crate::adapters) fn take_met(&self, remote: PeerEndpoint) -> Option<Meeting> {
        let mut book = self.book.lock().ok()?;
        book.met.remove(&remote)
    }
}

impl Book {
    /// The dial to `remote`'s address with its hello out unanswered that one
    /// of `names` is filed under, and where a hello held on it hears it
    /// settle.
    fn crossing(
        &mut self,
        remote: PeerEndpoint,
        names: &[LinkName],
    ) -> Option<(u64, watch::Receiver<bool>)> {
        let filing = names.iter().find_map(|name| {
            let held = self.links.get(name)?;
            (held.remote.ip() == remote.ip() && self.unanswered.contains_key(&held.filing))
                .then_some(held.filing)
        })?;
        let dial = self.unanswered.get_mut(&filing)?;
        dial.crossed = true;
        Some((filing, dial.answered.subscribe()))
    }
}

fn held_for(own: Option<UserHash>, peer: Option<UserHash>) -> Duration {
    match (own, peer) {
        (Some(own), Some(peer)) if own.as_bytes() > peer.as_bytes() => HOLD_AS_THE_HIGHER_HASH,
        _ => HOLD_AS_THE_LOWER_HASH,
    }
}

/// The gate an accepted link's session asks as it reads the peer's hello
/// ([`HelloGate`]): it meets rmule's dials there and then, and leaves what it
/// met for the link's triage. Owned by the session, so a link that ends before
/// its triage takes nothing with it.
pub(in crate::adapters) struct MetHello {
    links: SharedPeerLinks,
    own: UserHash,
    remote: Mutex<Option<PeerEndpoint>>,
}

impl std::fmt::Debug for MetHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetHello").finish_non_exhaustive()
    }
}

impl MetHello {
    /// The gate of one accepted link of the node whose User Hash is `own`.
    pub(in crate::adapters) fn gate(links: SharedPeerLinks, own: UserHash) -> Arc<dyn HelloGate> {
        Arc::new(Self {
            links,
            own,
            remote: Mutex::new(None),
        })
    }
}

impl HelloGate for MetHello {
    fn may_answer(&self, peer: PeerEndpoint, identity: &PeerIdentity) -> bool {
        let names = LinkName::proven(peer, identity, None);
        let meeting = self.links.meet(peer, names, Some(self.own));
        let answer = matches!(meeting, Meeting::Clear(_));
        if let Ok(mut remote) = self.remote.lock() {
            *remote = Some(peer);
        }
        // Dropped outside the lock, as below.
        let earlier = self
            .links
            .book
            .lock()
            .ok()
            .and_then(|mut book| book.met.insert(peer, meeting));
        drop(earlier);
        answer
    }
}

impl Drop for MetHello {
    fn drop(&mut self) {
        let remote = self.remote.get_mut().ok().and_then(|remote| remote.take());
        if let Some(remote) = remote {
            // Dropped outside the lock: a filing gives its names up under it.
            let left = self.links.take_met(remote);
            drop(left);
        }
    }
}
