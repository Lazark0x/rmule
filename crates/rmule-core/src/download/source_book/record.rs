//! One source's record in the **Source Book**: its one stage, the endpoints it
//! answers to, and the record-tier attachments that live and die with it
//! (ADR-0090). A record holds no clock and no channel; the book alone moves it
//! between stages. A worker that identified holds the peer's **Peer Identity**
//! in its Worker stage, so what the hello stated ends with that worker
//! (ADR-0049).

use rmule_peer::{PartBitmap, PeerIdentity};
use rmule_primitives::{Ipv4Endpoint, PeerCrypt, PeerEndpoint};

use super::road::PendingRoad;
use super::standing::Standing;
use crate::download::source_ask_clock::AskFacts;
use crate::download::state::LowIdCandidate;

/// A record's name inside one book, minted in sighting order, so a lower id is
/// the older record — the order the merge rule's "newer" reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct RecordId(pub(super) u64);

/// The pooled lane a record waits in, in the order a fill drains them: a
/// dialable source first, then a Low ID on the server we are logged into,
/// then a Low ID whose own server must relay its callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lane {
    /// Dialed at its first endpoint.
    HighId,
    /// A Low-ID candidate in our server's namespace, or a Kad row's, which is
    /// in none.
    LowIdConnected,
    /// A Low-ID candidate another server assigned (ADR-0051).
    LowIdGlobal,
}

impl Lane {
    /// The Low-ID lane `candidate`'s namespace puts it in while we are logged
    /// into `ours`.
    pub(super) fn of(candidate: &LowIdCandidate, ours: Option<Ipv4Endpoint>) -> Self {
        if candidate.from_kad || candidate.on_server(ours) {
            Self::LowIdConnected
        } else {
            Self::LowIdGlobal
        }
    }
}

/// Which road put a worker on a record's endpoint — what its end costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialRoad {
    /// A High-ID endpoint, either dual-stack half included.
    HighId,
    /// A Low-ID candidate's IPv6 half (rung 0, ADR-0087).
    Rung0,
    /// A called-back Low-ID peer that dialed in and was adopted (ADR-0039).
    Callback,
}

/// A worker on one endpoint of the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Live {
    /// The road that put it there.
    pub(crate) road: DialRoad,
    /// The endpoint its channel is keyed by.
    pub(crate) endpoint: PeerEndpoint,
}

/// What a connected worker's peer told it, current with every revision and
/// gone with the worker: an earlier connection's word never stands in for it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Heard {
    /// The identity the peer's session keeps once the hello is read: its own
    /// statement of its hash, its crypt stance, its UDP contact and its buddy.
    pub(super) identity: Option<Box<PeerIdentity>>,
    /// Whether the peer answered the worker's probe. Until it does, the
    /// record's Advertised Parts are an earlier connection's or a merged-in
    /// record's, and the worker is handed nothing (ADR-0112 §3).
    pub(super) answered: bool,
}

/// A record's one stage — its one owner (ADR-0090 invariant 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    /// Waiting in a lane for a free slot.
    Pooled(Lane),
    /// A worker that has not completed its handshake.
    Dialing(Live),
    /// A connected worker, with what its peer told it on this connection.
    Worker(Live, Heard),
    /// A callback or punch in flight toward a Low-ID candidate, with its road
    /// and the deadlines that govern it.
    CallbackPending(PendingRoad),
    /// Holding its queue standing at this endpoint, no worker: the
    /// **Remote-Queued Pool**.
    RemoteQueued(PeerEndpoint),
}

impl Stage {
    /// The merge rule's rank: Worker > Dialing > CallbackPending >
    /// RemoteQueued > Pooled.
    pub(super) const fn rank(&self) -> u8 {
        match self {
            Self::Worker(..) => 4,
            Self::Dialing(_) => 3,
            Self::CallbackPending(_) => 2,
            Self::RemoteQueued(_) => 1,
            Self::Pooled(_) => 0,
        }
    }

    /// The worker the stage holds, when it holds one.
    pub(super) const fn live(&self) -> Option<Live> {
        match self {
            Self::Dialing(live) | Self::Worker(live, _) => Some(*live),
            Self::Pooled(_) | Self::CallbackPending(_) | Self::RemoteQueued(_) => None,
        }
    }

    /// The identity the stage's worker holds, once its peer identified.
    pub(super) fn identity(&self) -> Option<&PeerIdentity> {
        match self {
            Self::Worker(_, heard) => heard.identity.as_deref(),
            _ => None,
        }
    }

    /// Whether the stage holds one of the download's worker slots.
    pub(super) const fn holds_slot(&self) -> bool {
        matches!(
            self,
            Self::Dialing(_) | Self::Worker(..) | Self::CallbackPending(_)
        )
    }
}

/// The crypt side a peer's own identity states — its stance under its hash,
/// which outranks any record's at a later dial (ADR-0049).
pub(super) fn stated_crypt(identity: &PeerIdentity) -> PeerCrypt {
    PeerCrypt::new(identity.crypt_stance(), Some(identity.user_hash()))
}

/// One source.
#[derive(Clone, Debug)]
pub(super) struct Record {
    pub(super) stage: Stage,
    /// The endpoints the record answers to, at most two: `[0]` the one it is
    /// pooled, dialed, worked or queued at, `[1]` the same peer's other half
    /// — or, for a Low-ID candidate, its IPv6 half.
    pub(super) endpoints: Vec<PeerEndpoint>,
    /// The Low-ID Candidate Record, whose key is the record's `CallbackKey`
    /// alias.
    pub(super) candidate: Option<LowIdCandidate>,
    /// The queue standing a worker of it earned (ADR-0057).
    pub(super) standing: Option<Standing>,
    /// The endpoint it was restored at from a **Source Seed** (ADR-0109).
    pub(super) seed: Option<PeerEndpoint>,
    /// What the download's source asks stamped on this peer (ADR-0108).
    pub(super) asks: AskFacts,
    /// The parts its source last advertised, over the file's real parts:
    /// its **Advertised Parts** (ADR-0112). Written only through the book,
    /// which keeps **Part Frequency** with it.
    pub(super) advertised: Option<PartBitmap>,
}

impl Record {
    /// A record in `stage` with nothing attached yet.
    pub(super) fn new(stage: Stage) -> Self {
        Self {
            stage,
            endpoints: Vec::new(),
            candidate: None,
            standing: None,
            seed: None,
            asks: AskFacts::default(),
            advertised: None,
        }
    }

    /// The worker on `endpoint`, if the record's live worker is there.
    pub(super) fn live_at(&self, endpoint: PeerEndpoint) -> Option<Live> {
        self.stage.live().filter(|live| live.endpoint == endpoint)
    }

    /// The record's endpoint other than `endpoint`.
    pub(super) fn other_than(&self, endpoint: PeerEndpoint) -> Option<PeerEndpoint> {
        self.endpoints.iter().copied().find(|&e| e != endpoint)
    }
}
