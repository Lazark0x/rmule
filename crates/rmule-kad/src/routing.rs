//! Deterministic, in-memory k-bucket routing table.
//!
//! Contacts are bucketed by the leading-zero count of their XOR distance to
//! the table's own ID under the capture-proven ordering (ADR-0043).
//! Buckets cap at [`KadRoutingTable::K`]; a full bucket admits a newcomer only
//! by replacing a [`Failed`](KadContactState::Failed) contact, so long-lived
//! contacts win — the classic Kademlia insertion bias, which also bounds what
//! an adversary can displace by flooding. Per-bucket last-activity stamps are
//! refresh *bookkeeping* only; scheduling refresh lookups is requester work.
//! Each entry also carries its aging (`aging`, aMule's per-contact expiry),
//! which the small-timer pass reads to pick a bucket's oldest due contact.
//!
//! No RNG, no clock reads: mutation order and the injected [`KadInstant`]s
//! fully determine the state, which is what the mesh-sim tier relies on.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::udp_key::KadUdpKey;
use crate::{KadId, KadInstant, KadNodeEndpoint};

mod aging;
mod answer;
mod caps;

use aging::ContactAging;
pub(crate) use answer::KadAnswerRefusal;
use caps::AdmissionTally;
pub use caps::KadAdmissionCap;

/// Where a contact sits in the lookup lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadContactState {
    /// Known but never probed — usable as a walk candidate, unproven as a
    /// live node.
    Unqueried,
    /// Probed, with the answer still outstanding.
    Pending,
    /// Answered a probe: validated-live.
    Responded,
    /// Stayed silent past its deadline. Still held, but first in line to be
    /// evicted when its bucket needs room.
    Failed,
}

/// A known Kad node: its identity, endpoints, protocol version, and lifecycle
/// state.
///
/// The TCP port and Kad version ride along because the wire contact row
/// (`[id][ip][udp][tcp][version]`, capture-proven in the routing and
/// node-message fixtures) carries them, and answering bootstrap/lookup
/// requests must re-serialize them.
///
/// `verified` is the **Verified Contact** flag (ADR-0064, `CONTEXT.md`): the
/// contact's IP has been proven not spoofed — by a hello carrying a valid
/// receiver key, by the `0x22` three-way handshake, or by arriving pre-verified
/// from a bootstrap file. It is a distinct axis from
/// [`state`](KadContactState) (liveness): only verified contacts are served in
/// routing answers or seed own lookup walks. Verification persists once set —
/// an ordinary hello update never clears it (only a key-proven endpoint move
/// does, aMule `CContact::SetIPAddress`).
///
/// `udp_key` is the contact's learned [`KadUdpKey`] — the sender verify key its
/// datagrams carried, bound to *our* public IP at learn time (aMule
/// `CContact::m_udpKey`). It guards updates against entry hijacking
/// ([`KadRoutingUpdate::RejectedKeyMismatch`]) and keys our obfuscated
/// datagrams back to the contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadContact {
    id: KadId,
    endpoint: KadNodeEndpoint,
    tcp_port: u16,
    version: u8,
    state: KadContactState,
    verified: bool,
    udp_key: KadUdpKey,
}

impl KadContact {
    /// A freshly discovered, not-yet-queried, **unverified** contact.
    #[must_use]
    pub const fn new(id: KadId, endpoint: KadNodeEndpoint, tcp_port: u16, version: u8) -> Self {
        Self::with_state(id, endpoint, tcp_port, version, KadContactState::Unqueried)
    }

    /// A contact in an explicit lifecycle `state`, **unverified** — the wire and
    /// hello intake paths (hearsay rows, responded senders) all enter unverified;
    /// verification is a separate transition ([`into_verified`](Self::into_verified)).
    #[must_use]
    pub const fn with_state(
        id: KadId,
        endpoint: KadNodeEndpoint,
        tcp_port: u16,
        version: u8,
        state: KadContactState,
    ) -> Self {
        Self {
            id,
            endpoint,
            tcp_port,
            version,
            state,
            verified: false,
            udp_key: KadUdpKey::EMPTY,
        }
    }

    /// The contact's Kad ID — its position in the keyspace, and what every
    /// distance is measured from.
    #[must_use]
    pub const fn id(&self) -> KadId {
        self.id
    }

    /// Its Kad UDP endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> KadNodeEndpoint {
        self.endpoint
    }

    /// Its eD2k TCP port — carried for a peer handoff, never dialed from here.
    #[must_use]
    pub const fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    /// Its Kad protocol version, which decides which exchanges it can take
    /// part in.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Where it sits in the probe lifecycle.
    #[must_use]
    pub const fn state(&self) -> KadContactState {
        self.state
    }

    /// Whether this contact's IP is proven not spoofed — the **Verified
    /// Contact** flag that [`select_closest_servable`](KadRoutingTable::select_closest_servable)
    /// gates on.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// The same contact in a different lifecycle state; verification is
    /// preserved (liveness and identity are independent axes).
    #[must_use]
    pub const fn in_state(self, state: KadContactState) -> Self {
        Self { state, ..self }
    }

    /// The same contact marked IP-verified — the routing-table `VerifyContact`
    /// transition (aMule `RoutingZone.cpp#L870`) and the bootstrap-file
    /// pre-verified seam (the nodes.dat verified bit, ADR-0066).
    #[must_use]
    pub const fn into_verified(self) -> Self {
        Self {
            verified: true,
            ..self
        }
    }

    /// The contact's learned UDP verify key — [`KadUdpKey::EMPTY`] until a
    /// crypt datagram from it carried a sender key.
    #[must_use]
    pub const fn udp_key(&self) -> KadUdpKey {
        self.udp_key
    }

    /// The same contact carrying `udp_key` — set by the intake paths from the
    /// datagram's crypt trailer (bound to our public IP at receipt) and by the
    /// nodes.dat reader from the persisted pair.
    #[must_use]
    pub const fn with_udp_key(self, udp_key: KadUdpKey) -> Self {
        Self { udp_key, ..self }
    }
}

/// The outcome of offering a contact to the routing table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadRoutingUpdate {
    /// New contact stored in a bucket with room.
    Added,
    /// New contact stored by evicting a [`Failed`](KadContactState::Failed)
    /// contact from its full bucket.
    AddedEvictingFailed {
        /// The failed contact that made room.
        evicted: KadId,
    },
    /// A contact with this ID already existed and was replaced in place.
    Updated,
    /// The bucket is full of non-failed contacts; the newcomer is dropped
    /// (long-lived contacts win).
    RejectedBucketFull,
    /// The contact carries the table's own ID; a node never routes to itself.
    RejectedSelf,
    /// A **verified** contact already holds this ID at a *different* endpoint
    /// and the claimant presented no matching key; the newcomer is an
    /// anti-hijack reject (aMule `RoutingZone.cpp#L897`): a proven contact is
    /// never displaced by an unproven claimant of its ID. (A claimant that
    /// *does* present the entry's key is the genuine node and may move it —
    /// the move clears `verified`, aMule `CContact::SetIPAddress`.)
    RejectedHijack {
        /// The ID the claimant tried to take over.
        id: KadId,
    },
    /// The stored contact carries a UDP key valid at our current public IP and
    /// the claimant failed to present it — aMule's "tried to update contact
    /// entry but failed to provide the proper sender key … denying update"
    /// (`RoutingZone.cpp#L442`). Nothing about the entry changes, not even its
    /// liveness stamp.
    RejectedKeyMismatch {
        /// The ID whose entry stands unchanged.
        id: KadId,
    },
    /// Storing the contact at its IP would break an admission cap (ADR-0064,
    /// aMule `CheckGlobalIPLimits` and the bin's /24 rule): a newcomer is
    /// dropped, and a known contact moving to a new IP keeps its old entry
    /// unchanged (aMule `ChangeContactIPAddress`).
    RejectedAdmissionCap {
        /// The cap that refused it.
        cap: KadAdmissionCap,
    },
}

/// One stored contact with its aging — the routing-table record. Aging lives
/// here, not on [`KadContact`], because a contact is also a wire row and a
/// command payload, where no table history exists.
#[derive(Clone, Copy, Debug)]
struct RoutingEntry {
    contact: KadContact,
    aging: ContactAging,
}

impl RoutingEntry {
    const fn fresh(now: KadInstant, contact: KadContact) -> Self {
        Self {
            contact,
            aging: ContactAging::fresh(now),
        }
    }
}

/// One k-bucket: at most [`KadRoutingTable::K`] contacts, oldest first —
/// admission order, except that an answering contact moves to the back
/// (aMule's `CRoutingBin` list with `PushToBottom`) — stamped with the instant
/// of its last accepted mutation.
#[derive(Clone, Debug, Default)]
struct KadBucket {
    contacts: Vec<RoutingEntry>,
    last_activity: Option<KadInstant>,
}

impl KadBucket {
    /// The IP of every contact the bucket holds — what its /24 cap counts.
    fn ips(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.contacts
            .iter()
            .map(|entry| entry.contact.endpoint().ip())
    }
}

/// A k-bucket Kad routing table keyed by the owning node's [`KadId`].
///
/// Iteration order (bucket index, then insertion order within the bucket) is
/// deterministic, so simulation traces and bookkeeping are reproducible.
#[derive(Clone, Debug)]
pub struct KadRoutingTable {
    own_id: KadId,
    buckets: Vec<KadBucket>,
    /// The instant of the last received Kad datagram — aMule's
    /// `CPrefs::m_lastContact`, stamped at the ADR-0064 entry gate. `None` until
    /// the node has ever heard from the network. Read by
    /// [`has_had_contact`](Self::has_had_contact), the network-joined predicate.
    last_contact: Option<KadInstant>,
    /// This node's public IP — the address every stored [`KadUdpKey`] is
    /// evaluated at (aMule reads `theApp->GetPublicIP()` inside
    /// `RoutingZone::Add`'s key gate). `None` until the verify-key state is
    /// armed, which leaves the key gate silent — the pre-key posture.
    own_public_ip: Option<Ipv4Addr>,
    /// The table-wide per-IP and per-/24 counts the admission caps read
    /// (ADR-0064), kept in step with every stored contact's IP.
    admission: AdmissionTally,
}

impl KadRoutingTable {
    /// Contacts per bucket. eMule's routing bins hold 10 contacts (aMule
    /// `CRoutingBin`, link-only reference in
    /// `docs/reference/notes/kad-packet-framing.md`).
    pub const K: usize = 10;

    /// One bucket per possible leading-zero count of a 128-bit distance.
    pub const BUCKET_COUNT: usize = 128;

    /// How long a received Kad datagram keeps the node "connected" — aMule's
    /// `KADEMLIADISCONNECTDELAY` (20 min,
    /// [kad/Constants.h#L43](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/include/protocol/kad/Constants.h#L43)).
    /// Past it with no further contact, `HasHadContact` — and so the node — goes
    /// disconnected (ADR-0067).
    pub const HAD_CONTACT_WINDOW: Duration = Duration::from_secs(20 * 60);

    /// An empty table for a node of this ID.
    #[must_use]
    pub fn new(own_id: KadId) -> Self {
        Self {
            own_id,
            buckets: vec![KadBucket::default(); Self::BUCKET_COUNT],
            last_contact: None,
            own_public_ip: None,
            admission: AdmissionTally::default(),
        }
    }

    /// Arm (or move) the public IP the stored contacts' UDP keys are evaluated
    /// at. Keys learned under a previous IP silently retire — their
    /// [`KadUdpKey::key_value`] collapses to `0` at the new address, exactly
    /// aMule's behavior when its public IP changes.
    pub fn set_own_public_ip(&mut self, ip: Ipv4Addr) {
        self.own_public_ip = Some(ip);
    }

    /// Stamp the last-contact instant — the node just received a well-formed Kad
    /// datagram (aMule's `SetLastContact()`, called at the ADR-0064 entry gate
    /// for *any* accepted datagram, not only ones that add a contact).
    /// Monotonic: an out-of-order older stamp never rewinds the window.
    pub fn note_contact(&mut self, now: KadInstant) {
        self.last_contact = Some(match self.last_contact {
            Some(previous) => previous.max(now),
            None => now,
        });
    }

    /// aMule's `HasHadContact`: whether a Kad datagram was received within the
    /// last [`HAD_CONTACT_WINDOW`](Self::HAD_CONTACT_WINDOW). This is the
    /// network-joined predicate (`CKademlia::IsConnected` = `m_running ∧
    /// HasHadContact`); it gates the bootstrap dial loop and the ed2k→Kad
    /// handoff (ADR-0067). Strict, like aMule's `now - last < DELAY`: exactly on
    /// the boundary the node is already disconnected.
    #[must_use]
    pub fn has_had_contact(&self, now: KadInstant) -> bool {
        self.last_contact
            .is_some_and(|at| now < at + Self::HAD_CONTACT_WINDOW)
    }

    /// This node's own Kad ID — the origin every bucket distance is measured
    /// from.
    #[must_use]
    pub const fn own_id(&self) -> KadId {
        self.own_id
    }

    /// The bucket a contact ID belongs to, or `None` for the own ID itself.
    fn bucket_index(&self, id: KadId) -> Option<usize> {
        let zeros = self.own_id.distance(&id).leading_zeros();
        // 128 leading zeros means zero distance: the own ID.
        usize::try_from(zeros)
            .ok()
            .filter(|&z| z < Self::BUCKET_COUNT)
    }

    /// Offer a contact: update in place if the ID is known, add it if its
    /// bucket has room, replace the bucket's first `Failed` contact if not,
    /// and reject it otherwise. `now` stamps the bucket's refresh bookkeeping
    /// on every accepted mutation.
    ///
    /// Updates run aMule's anti-hijack gates in aMule's order
    /// (`RoutingZone.cpp#L442`):
    ///
    /// 1. **Key gate** — a stored key valid at our public IP must be matched by
    ///    the claimant, or the whole update is denied
    ///    ([`RejectedKeyMismatch`](KadRoutingUpdate::RejectedKeyMismatch)).
    /// 2. **Endpoint move** — past the key gate, a claimant *with* the entry's
    ///    valid key is the genuine node: it may move the entry, and the move
    ///    clears `verified` (aMule `CContact::SetIPAddress`) until a
    ///    verification path re-proves the new address. A keyless claimant
    ///    never moves a **verified** entry
    ///    ([`RejectedHijack`](KadRoutingUpdate::RejectedHijack)) — rmule's
    ///    documented strengthening of aMule's `IsAcceptableContact` filter
    ///    (`RoutingZone.cpp#L897`) for entries the key gate cannot judge.
    /// 3. **Admission caps** — a move to a new IP must keep the table within
    ///    one contact per IP and ten per /24, and the bucket within two per
    ///    /24 ([`RejectedAdmissionCap`](KadRoutingUpdate::RejectedAdmissionCap),
    ///    aMule `ChangeContactIPAddress`).
    ///
    /// A newcomer passes the same caps before it takes a free slot or a
    /// `Failed` contact's (aMule `CRoutingBin::AddContact`, ADR-0064).
    pub fn upsert(&mut self, now: KadInstant, contact: KadContact) -> KadRoutingUpdate {
        let Some(index) = self.bucket_index(contact.id()) else {
            return KadRoutingUpdate::RejectedSelf;
        };
        let my_ip = self.own_public_ip;
        let bucket = &mut self.buckets[index];
        let admission = &mut self.admission;
        let arriving_ip = contact.endpoint().ip();

        let update = if let Some(position) = bucket
            .contacts
            .iter()
            .position(|entry| entry.contact.id() == contact.id())
        {
            let existing = bucket.contacts[position].contact;
            let stored_key = my_ip.map_or(0, |ip| existing.udp_key().key_value(ip));
            let presented_key = my_ip.map_or(0, |ip| contact.udp_key().key_value(ip));
            if stored_key != 0 && stored_key != presented_key {
                return KadRoutingUpdate::RejectedKeyMismatch { id: contact.id() };
            }
            let moved = existing.endpoint() != contact.endpoint();
            // Past the key gate, a nonzero stored key means the claimant
            // presented it — key-proven identity.
            let key_proven = stored_key != 0;
            if moved && existing.verified() && !key_proven {
                return KadRoutingUpdate::RejectedHijack { id: contact.id() };
            }
            let left_ip = existing.endpoint().ip();
            if left_ip != arriving_ip {
                if let Some(cap) = admission.refusal(arriving_ip, bucket.ips(), Some(left_ip)) {
                    return KadRoutingUpdate::RejectedAdmissionCap { cap };
                }
                admission.uncount(left_ip);
                admission.count(arriving_ip);
            }
            // Without an armed public IP the key gate cannot judge; keep a
            // stored key rather than let a plaintext update wipe it. Armed,
            // aMule overwrites unconditionally (the gate already vouched).
            let mut next = if my_ip.is_none() && contact.udp_key().is_empty() {
                contact.with_udp_key(existing.udp_key())
            } else {
                contact
            };
            // Verification persists across in-place updates; an endpoint move
            // clears it (the new address is unproven) unless the incoming
            // contact carries its own proof.
            if !moved && existing.verified() {
                next = next.into_verified();
            }
            bucket.contacts[position].contact = next;
            KadRoutingUpdate::Updated
        } else if bucket.contacts.len() < Self::K {
            if let Some(cap) = admission.refusal(arriving_ip, bucket.ips(), None) {
                return KadRoutingUpdate::RejectedAdmissionCap { cap };
            }
            bucket.contacts.push(RoutingEntry::fresh(now, contact));
            admission.count(arriving_ip);
            KadRoutingUpdate::Added
        } else if let Some(position) = bucket
            .contacts
            .iter()
            .position(|entry| entry.contact.state() == KadContactState::Failed)
        {
            let failed = bucket.contacts[position].contact;
            let failed_ip = failed.endpoint().ip();
            if let Some(cap) = admission.refusal(arriving_ip, bucket.ips(), Some(failed_ip)) {
                return KadRoutingUpdate::RejectedAdmissionCap { cap };
            }
            bucket.contacts[position] = RoutingEntry::fresh(now, contact);
            admission.uncount(failed_ip);
            admission.count(arriving_ip);
            KadRoutingUpdate::AddedEvictingFailed {
                evicted: failed.id(),
            }
        } else {
            return KadRoutingUpdate::RejectedBucketFull;
        };

        bucket.last_activity = Some(now);
        update
    }

    /// Mark a contact IP-verified — aMule's `VerifyContact(id, ip)`
    /// ([RoutingZone.cpp#L870](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingZone.cpp#L870)):
    /// the ID must name a stored contact **and** `observed_ip` must match its
    /// endpoint IP (an ACK from the wrong IP proves nothing). Returns whether the
    /// contact is now verified; idempotent, and never adds a contact.
    pub fn verify_contact(&mut self, id: KadId, observed_ip: Ipv4Addr) -> bool {
        let Some(index) = self.bucket_index(id) else {
            return false;
        };
        match self.buckets[index]
            .contacts
            .iter_mut()
            .map(|entry| &mut entry.contact)
            .find(|c| c.id() == id)
        {
            Some(contact) if contact.endpoint().ip() == observed_ip => {
                *contact = contact.into_verified();
                true
            }
            _ => false,
        }
    }

    /// Remove a contact, reporting whether it existed.
    pub fn evict(&mut self, id: KadId) -> bool {
        let Some(index) = self.bucket_index(id) else {
            return false;
        };
        let bucket = &mut self.buckets[index];
        let Some(position) = bucket
            .contacts
            .iter()
            .position(|entry| entry.contact.id() == id)
        else {
            return false;
        };
        let evicted = bucket.contacts.remove(position);
        self.admission.uncount(evicted.contact.endpoint().ip());
        true
    }

    /// The contact with this ID, if the table holds it.
    #[must_use]
    pub fn get(&self, id: KadId) -> Option<&KadContact> {
        let index = self.bucket_index(id)?;
        self.buckets[index]
            .contacts
            .iter()
            .map(|entry| &entry.contact)
            .find(|c| c.id() == id)
    }

    /// How many contacts the table holds across every bucket.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.contacts.len()).sum()
    }

    /// Whether the table holds no contacts — a node in this state can seed no
    /// walk and must bootstrap first.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.contacts.is_empty())
    }

    /// All contacts, bucket order then insertion order — deterministic.
    pub fn contacts(&self) -> impl Iterator<Item = &KadContact> {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter().map(|entry| &entry.contact))
    }

    /// The contact whose [`KadId`] is XOR-closest to `target`, or `None` if the
    /// table is empty. Ordering is the capture-proven Kad distance (ADR-0043).
    #[must_use]
    pub fn select_nearest(&self, target: KadId) -> Option<&KadContact> {
        self.contacts()
            .min_by_key(|contact| contact.id().distance(&target))
    }

    /// The servable answer set — aMule's `GetClosestTo`
    /// ([RoutingBin.cpp#L195](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/routing/RoutingBin.cpp#L195)):
    /// up to `count` **IP-verified** [`Responded`](KadContactState::Responded)
    /// contacts, closest to `target` first — the answer set for `KADEMLIA2_REQ`
    /// and the seed set for own lookup walks. Unverified contacts are never
    /// served to other nodes and never seed our walks (ADR-0064).
    ///
    /// **Zero-servable-cliff invariant** (ADR-0064 two-stage activation):
    /// gating never empties a non-empty servable set. Online IP verification
    /// is key-coupled — live under the armed verify-key state, where a keyed
    /// join verifies its responders on their first answer — but a degenerate
    /// all-plaintext topology (the deterministic mesh, legacy-only peers)
    /// would never verify anything, and
    /// a strict gate there would silently unjoin the node (aMule in the same
    /// topology serves silence). So until *some* contact is verified (a
    /// bootstrap file, an empty-table bootstrap answer, or a keyed exchange),
    /// the Responded set is served as the documented interim. The moment any
    /// contact verifies, the interim disengages and unverified contacts stop
    /// being served.
    #[must_use]
    pub fn select_closest_servable(&self, target: KadId, count: usize) -> Vec<&KadContact> {
        let responded: Vec<&KadContact> = self
            .contacts()
            .filter(|c| c.state() == KadContactState::Responded)
            .collect();
        let mut pool: Vec<&KadContact> = if responded.iter().any(|c| c.verified()) {
            responded.into_iter().filter(|c| c.verified()).collect()
        } else {
            responded
        };
        // Distinct IDs have distinct XOR distances, so the key is unique and
        // the order is deterministic.
        pool.sort_by_key(|c| c.id().distance(&target));
        pool.truncate(count);
        pool
    }

    /// The touched bucket with the oldest activity stamp: the next refresh
    /// candidate. Bookkeeping only — refresh lookups are requester work.
    #[must_use]
    pub fn stalest_bucket(&self) -> Option<(usize, KadInstant)> {
        self.buckets
            .iter()
            .enumerate()
            .filter_map(|(index, bucket)| bucket.last_activity.map(|at| (index, at)))
            .min_by_key(|&(index, at)| (at, index))
    }
}
