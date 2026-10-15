//! The **Peer Links** (ADR-0107, "One peer, one link"): every live,
//! identified link to a peer — accepted, dialed or adopted — filed under each
//! name it proves, and the downloads that ride it one at a time.
//!
//! aMule holds one client per peer, found by address and port, then by
//! `(low_id, server)`, then by user hash (`FindMatchingClient`,
//! `ClientList.cpp:253-347`), and asks it for every file over the socket it
//! holds (`BaseClient.cpp:1489-1496`): one requested file at a time, the
//! others waiting on its A4AF list (`DownloadClient.cpp:496-507`). A second
//! socket from the same address and port makes it drop the first
//! (`ClientList.cpp:400-403`), and whatever the first carried ends. So a
//! download looks the peer up under every name its source has before it
//! dials or asks for a callback, and rides — or waits on — the link it finds.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use rmule_peer::{ConnectionCommand, PeerCommand, PeerEvent, PeerIdentity};
use rmule_primitives::{ClientId, Ipv4Endpoint, PeerEndpoint, UserHash};
use tokio::sync::{mpsc, oneshot};

use super::peer_transfer::{PeerWorkerCommand, PeerWorkerEvent};
use crate::server_list::SharedServerListStore;
use crate::service::LinkTurn;

/// One name a Peer Link is filed under: an **Ask Name** the link proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum LinkName {
    /// Where a dial would reach the peer: the link's own address with the
    /// hello's listen port.
    Endpoint(PeerEndpoint),
    /// A Low ID and the server that assigned it, where a callback reaches
    /// the peer.
    Callback {
        /// The server the peer is logged in to.
        server: Ipv4Endpoint,
        /// The id that server gave it.
        low_id: ClientId,
    },
    /// The User Hash the peer's hello named.
    User(UserHash),
}

impl LinkName {
    /// Every name the link from `remote` proves for the peer `identity`
    /// reads: its dial endpoint, its User Hash, and — for a Low ID with a
    /// server — its callback. An IPv4 claim on an IPv6 link is not one: the
    /// peer is a source at its socket's address (ADR-0107 invariant 10).
    pub(crate) fn of(remote: PeerEndpoint, identity: &PeerIdentity) -> Vec<Self> {
        let mut names = vec![
            Self::Endpoint(remote.with_port(identity.tcp_port())),
            Self::User(identity.user_hash()),
        ];
        let low_id = identity.client_id();
        if low_id.is_low_id()
            && low_id.as_u32() != 0
            && let Some(server) = identity.connected_server()
        {
            names.push(Self::Callback { server, low_id });
        }
        names
    }
}

/// The Peer Links, each under every name it proves. One cell shared by the
/// accept road and every dial (ADR-0048 "Identity ownership"), with the
/// server list a Low ID's server is checked against before it becomes a name.
#[derive(Clone, Default)]
pub(crate) struct SharedPeerLinks {
    book: Arc<Mutex<Book>>,
    servers: Option<SharedServerListStore>,
}

#[derive(Default)]
struct Book {
    filed: u64,
    links: HashMap<LinkName, Filed>,
}

#[derive(Clone)]
struct Filed {
    filing: u64,
    remote: PeerEndpoint,
    join_tx: mpsc::Sender<LinkJoin>,
}

/// A download's ask to ride a link: seated at once when nobody rides it,
/// told it waits otherwise, and answered with the peer's identity at its
/// turn.
pub(super) struct LinkJoin {
    half: DownloadHalf,
    waiting: oneshot::Sender<()>,
    seated: oneshot::Sender<PeerIdentity>,
}

/// A download's half of a link: where the link's events reach it and where
/// its commands come from.
pub(super) struct DownloadHalf {
    /// The link's requester events and its close, to the worker.
    pub(super) requester_tx: mpsc::Sender<PeerEvent>,
    /// The identity revisions and source asks the download keeps.
    pub(super) worker_evt_tx: mpsc::Sender<PeerWorkerEvent>,
    /// The worker's commands, framed onto the link; closed when it is done.
    pub(super) peer_cmd_rx: mpsc::Receiver<PeerCommand>,
}

/// A link a download found under one of its source's names, not yet joined.
pub(crate) struct FoundLink {
    /// The link's remote end.
    pub(crate) remote: PeerEndpoint,
    join_tx: mpsc::Sender<LinkJoin>,
}

/// A link a download took its turn on: the peer as the link knows it, and
/// the download's two ends of the link.
pub(crate) struct JoinedLink {
    pub(crate) identity: PeerIdentity,
    pub(crate) peer_cmd_tx: mpsc::Sender<PeerCommand>,
    pub(crate) requester_rx: mpsc::Receiver<PeerEvent>,
}

/// How a download's ask to ride a link ended.
pub(crate) enum Turn {
    /// The download rides the link now.
    Seated(Box<JoinedLink>),
    /// The link ended before the download's turn: it dials as before.
    LinkEnded,
    /// The download's run let the worker go while it waited.
    Stopped,
}

impl SharedPeerLinks {
    /// Peer Links that check a changed Low ID's server against `servers`.
    pub(crate) fn knowing(servers: SharedServerListStore) -> Self {
        Self {
            book: Arc::default(),
            servers: Some(servers),
        }
    }

    /// What a link answers an `OP_CHANGE_CLIENT_ID` offer of `client_id` on
    /// `server`: aMule takes a Low ID only for a server in its list, at the
    /// port it lists, and a High ID with the server when it knows it
    /// (`ClientTCPSocket.cpp:773-787`). `None` leaves the peer as it was.
    pub(crate) fn take_client_id(
        &self,
        client_id: ClientId,
        server: Ipv4Addr,
    ) -> Option<ConnectionCommand> {
        let known = self.known_server(server);
        (client_id.is_high_id() || known.is_some()).then_some(ConnectionCommand::TakeClientId {
            client_id,
            server: known,
        })
    }

    /// The server the list holds at `ip`, with the port it lists. A
    /// DNS-named row is no address a peer can name.
    fn known_server(&self, ip: Ipv4Addr) -> Option<Ipv4Endpoint> {
        let servers = self.servers.as_ref()?.servers().ok()?;
        servers.into_iter().find_map(|server| {
            let at = server.endpoint.host().parse::<Ipv4Addr>().ok()?;
            (at == ip).then(|| Ipv4Endpoint::new(at, server.endpoint.port()))
        })
    }

    /// File a link from `remote` under `names` for as long as the returned
    /// filing lives. A link filed later under one of the names takes that
    /// name: aMule keeps a client on its newest socket.
    pub(super) fn file(
        &self,
        remote: PeerEndpoint,
        names: Vec<LinkName>,
    ) -> (Filing, mpsc::Receiver<LinkJoin>) {
        let (join_tx, join_rx) = mpsc::channel(4);
        let mut book = self.book.lock().expect("peer links lock");
        book.filed += 1;
        let filing = book.filed;
        let filed = Filed {
            filing,
            remote,
            join_tx,
        };
        for name in &names {
            book.links.insert(*name, filed.clone());
        }
        let filing = Filing {
            links: self.clone(),
            filed,
            names,
        };
        (filing, join_rx)
    }

    /// The link filed under the first of `names` that names one.
    pub(crate) fn find(&self, names: &[LinkName]) -> Option<FoundLink> {
        let book = self.book.lock().expect("peer links lock");
        names.iter().find_map(|name| {
            book.links.get(name).map(|filed| FoundLink {
                remote: filed.remote,
                join_tx: filed.join_tx.clone(),
            })
        })
    }
}

impl FoundLink {
    /// Ask to ride the link, reporting to `worker_evt_tx`, and wait for the
    /// turn: at once when nobody rides it, after the downloads ahead of it
    /// otherwise. While it waits it says so once, and a `Shutdown` — or the
    /// run dropping the worker — on `commands` gives the place up.
    pub(crate) async fn take_turn(
        self,
        worker_evt_tx: &mpsc::Sender<PeerWorkerEvent>,
        commands: &mut mpsc::Receiver<PeerWorkerCommand>,
    ) -> Turn {
        let (peer_cmd_tx, peer_cmd_rx) = mpsc::channel(16);
        let (requester_tx, requester_rx) = mpsc::channel(64);
        let (waiting, told_waiting) = oneshot::channel();
        let (seated, turn) = oneshot::channel();
        let half = DownloadHalf {
            requester_tx,
            worker_evt_tx: worker_evt_tx.clone(),
            peer_cmd_rx,
        };
        let join = LinkJoin {
            half,
            waiting,
            seated,
        };
        if self.join_tx.send(join).await.is_err() {
            return Turn::LinkEnded;
        }
        let mut told_waiting = Some(told_waiting);
        let mut turn = turn;
        loop {
            tokio::select! {
                identity = &mut turn => {
                    let Ok(identity) = identity else { return Turn::LinkEnded };
                    let _ = worker_evt_tx
                        .send(PeerWorkerEvent::LinkShared { turn: LinkTurn::Riding })
                        .await;
                    return Turn::Seated(Box::new(JoinedLink {
                        identity,
                        peer_cmd_tx,
                        requester_rx,
                    }));
                }
                told = recv_once(&mut told_waiting) => {
                    if told.is_ok() {
                        let _ = worker_evt_tx
                            .send(PeerWorkerEvent::LinkShared { turn: LinkTurn::Waiting })
                            .await;
                    }
                }
                command = commands.recv() => match command {
                    None | Some(PeerWorkerCommand::Shutdown { .. }) => return Turn::Stopped,
                    // Nothing else is asked of a worker that has not
                    // connected: the brain waits for its `Connected`.
                    Some(_) => {}
                },
            }
        }
    }
}

/// The next join a filed link takes; never resolves once the link holds no
/// name any more.
pub(super) async fn recv_join(joins: &mut Option<mpsc::Receiver<LinkJoin>>) -> Option<LinkJoin> {
    match joins {
        Some(joins) => joins.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_once(rx: &mut Option<oneshot::Receiver<()>>) -> Result<(), ()> {
    match rx.as_mut() {
        Some(inner) => {
            let told = inner.await.map_err(|_| ());
            *rx = None;
            told
        }
        None => std::future::pending().await,
    }
}

/// One link's place in the book, given up when the link ends — name by name,
/// unless a newer link took the name since.
pub(super) struct Filing {
    links: SharedPeerLinks,
    filed: Filed,
    names: Vec<LinkName>,
}

impl Filing {
    /// File the link under `names` instead of what it was filed under: the
    /// peer's identity moved (a Low ID it changed to).
    pub(super) fn refile(&mut self, names: Vec<LinkName>) {
        if names == self.names {
            return;
        }
        if let Ok(mut book) = self.links.book.lock() {
            release(&mut book, self.filed.filing, &self.names);
            for name in &names {
                book.links.insert(*name, self.filed.clone());
            }
        }
        self.names = names;
    }
}

impl Drop for Filing {
    fn drop(&mut self) {
        if let Ok(mut book) = self.links.book.lock() {
            release(&mut book, self.filed.filing, &self.names);
        }
    }
}

fn release(book: &mut Book, filing: u64, names: &[LinkName]) {
    for name in names {
        if book
            .links
            .get(name)
            .is_some_and(|filed| filed.filing == filing)
        {
            book.links.remove(name);
        }
    }
}

/// The downloads of one link: the one riding it and the ones waiting, in
/// arrival order (ADR-0107 invariant 8).
#[derive(Default)]
pub(super) struct Riders {
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
    seated: oneshot::Sender<PeerIdentity>,
}

impl Riders {
    /// Riders whose first rider is `half`: the download that dialed the link.
    pub(super) fn seated(half: DownloadHalf) -> Self {
        Self {
            rider: Some(half),
            departed: false,
            waiting: VecDeque::new(),
        }
    }

    /// Take `join`: seat it when nobody rides, else line it up and tell it
    /// so.
    pub(super) fn take(&mut self, join: LinkJoin, identity: &PeerIdentity) {
        let LinkJoin {
            half,
            waiting,
            seated,
        } = join;
        let waiter = Waiter { half, seated };
        if !self.is_ridden() {
            self.seat(waiter, identity);
        } else if waiting.send(()).is_ok() {
            self.waiting.push_back(waiter);
        }
    }

    /// The rider's worker let the link go: the oldest waiter still running
    /// takes it. Before the hello — no `identity` yet — nobody can be
    /// waiting.
    pub(super) fn rider_left(&mut self, identity: Option<&PeerIdentity>) {
        self.departed = true;
        let Some(identity) = identity else { return };
        while let Some(waiter) = self.waiting.pop_front() {
            if self.seat(waiter, identity) {
                break;
            }
        }
    }

    fn seat(&mut self, waiter: Waiter, identity: &PeerIdentity) -> bool {
        if waiter.seated.send(identity.clone()).is_ok() {
            self.rider = Some(waiter.half);
            self.departed = false;
            true
        } else {
            false
        }
    }

    fn is_ridden(&self) -> bool {
        self.rider.is_some() && !self.departed
    }

    /// The download the link's requester events go to: the rider, or the
    /// last one while nobody took its place.
    pub(super) fn rider(&self) -> Option<&DownloadHalf> {
        self.rider.as_ref()
    }

    /// Whether no download holds the link any more: none rides it and none
    /// still running waits on it.
    pub(super) fn is_empty(&mut self) -> bool {
        self.waiting.retain(|waiter| !waiter.seated.is_closed());
        !self.is_ridden() && self.waiting.is_empty()
    }

    /// The rider's next command; `None` once its worker let the link go.
    /// Never resolves while nobody rides.
    pub(super) async fn next_command(&mut self) -> Option<PeerCommand> {
        match self.rider.as_mut() {
            Some(rider) if !self.departed => rider.peer_cmd_rx.recv().await,
            _ => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests;
