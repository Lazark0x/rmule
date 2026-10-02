//! What rmule knows about **itself** on the wire: its own user hash and its
//! external IPv4 — the two self-facts every UDP crypt surface keys on, and the
//! only two aMule reads at datagram-send time (`thePrefs::GetUserHash()`,
//! `theApp->GetPublicIP()`).
//!
//! Only the user hash is *held* here. The address is a **projection** of the
//! [`AddressLearning`](crate::address_learning) store (ADR-0084): this cell
//! learns nothing about addresses and decides nothing about them, it reads the
//! one store that does. Before ADR-0084 the server session wrote an IPv4 here
//! directly and every other observation — the Kad `0x58`, a mapping grant, a
//! local interface — had nowhere to go; now the session emits an
//! **Address Observation** like every other source and this cell reads the
//! verdict.
//!
//! The two facts still ride one shared cell because they arrive *after* the
//! sockets bind, from different sources and at different moments:
//!
//! - the **user hash** is fixed at build time: `CoreBuilder::build` writes
//!   the store's (or a tool's named) hash here once, before the actor spawns,
//!   and no command carries one — [`ClientCredentials`](crate::ClientCredentials)
//!   holds only the nickname, port and version (ADR-0048 "Identity ownership");
//! - the **address** arrives with the connected server's `OP_IDCHANGE`
//!   (`ServerAssignedFacts::public_ip`, ADR-0047) — or, once the other feeders
//!   land, from any tier of the ladder.
//!
//! Consumers read, never write: the server-UDP crypt-ping arm gates on
//! `public_ip_known` (ADR-0046, aMule's `GetPublicIP() > 0` precondition)
//! and the peer-UDP crypt layer keys outbound datagrams on both
//! (`MD5(target_hash ‖ our_public_ip ‖ MAGICVALUE_UDP ‖ random_key)`) while
//! decrypting inbound ones on our user hash alone. A `Stale` verdict still
//! answers here on purpose: a server *disconnect* must not blank a key
//! mid-reask. A Low-ID re-assignment is the opposite case — the server
//! contradicting itself — and the store withdraws the address outright, so
//! the send gate disarms exactly as it did before.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rmule_primitives::{AddressFamily, ClientId, Ipv4Endpoint, UserHash};

use crate::address_learning::SharedAddressLearning;

/// The live eD2k session as a *self-fact*: which server we are logged in to
/// and the id it assigned us (ADR-0032 — the login is the only source of
/// either).
///
/// Both halves answer a question no other cell can. The id says whether we are
/// **Low-ID** — eMule's `CServerConnect::IsLowID()`, aMule's
/// `theApp->IsFirewalled()` half — and the server says whether a peer that
/// names a server in its hello is on *ours*. A node with no live session holds
/// `None` here, which reads as Low-ID and as "nobody shares our server": the
/// same posture the references take with `clientid == 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectedSession {
    /// The server, in the form a peer's hello encodes — `None` when its host
    /// is not an IPv4 literal, in which case no peer can be *proven* to share
    /// it (neither can we prove it of ourselves).
    pub(crate) server: Option<Ipv4Endpoint>,
    /// The id the server assigned us at login.
    pub(crate) client_id: ClientId,
}

/// The shared self-facts cell (see the module docs). Cheap to clone; every
/// clone reads the one set of facts, so a fact raised after a socket bound is
/// visible to the layers that bound before it.
#[derive(Clone, Default)]
pub(crate) struct SharedOwnIdentity(Arc<OwnIdentityCell>);

#[derive(Default)]
struct OwnIdentityCell {
    /// Our own eD2k user hash, fixed by the builder; `None` only on an
    /// adapter-level test cell.
    user_hash: std::sync::Mutex<Option<UserHash>>,
    /// The live session's [`ConnectedSession`], or `None` between sessions.
    /// Written by establishment when the login is accepted, re-written by the
    /// session task on a mid-session re-assignment and cleared by it as it
    /// ends, so it names a session that exists. A `watch` because the Kad pump
    /// must hear the High-ID half move rather than find out on a tick
    /// (the **Reach Generation**).
    connected_session: tokio::sync::watch::Sender<Option<ConnectedSession>>,
    /// The **Address Learning** store this cell projects its address from.
    addresses: SharedAddressLearning,
    /// The **Awaited Testers** (ADR-0046 "Test Connections"): establishment
    /// writes the server half — the login's other self-fact — and the Kad
    /// pump the helper half.
    awaited_testers: crate::awaited_testers::SharedAwaitedTesters,
}

impl SharedOwnIdentity {
    /// Who may dial the listener plain under `Required` right now.
    pub(crate) fn awaited_testers(&self) -> &crate::awaited_testers::SharedAwaitedTesters {
        &self.0.awaited_testers
    }

    /// The **Address Learning** store behind the projection — where the server
    /// session, the Kad pump and the port mapper put their observations.
    pub(crate) fn addresses(&self) -> &SharedAddressLearning {
        &self.0.addresses
    }

    /// Fix `user_hash` as ours (ADR-0048 "Identity ownership").
    /// `CoreBuilder::build` is the one production writer, once, before the
    /// actor spawns — a node has one identity (ADR-0032), as aMule's user
    /// hash is read once from `preferences.dat` and never set again
    /// (`Preferences.cpp:925-953`). No command carries a hash, so nothing can
    /// ask to change it.
    pub(crate) fn set_user_hash(&self, user_hash: UserHash) {
        *self.0.user_hash.lock().expect("own user-hash mutex") = Some(user_hash);
    }

    /// Our own user hash, or `None` on an adapter-level test cell no builder
    /// fixed.
    pub(crate) fn user_hash(&self) -> Option<UserHash> {
        *self.0.user_hash.lock().expect("own user-hash mutex")
    }

    /// Publish the live session's self-facts, or clear them as it ends.
    pub(crate) fn set_connected_session(&self, session: Option<ConnectedSession>) {
        self.0.connected_session.send_replace(session);
    }

    /// The live session's server re-assigned our id mid-session (a second
    /// `OP_IDCHANGE`): the id half follows it, as aMule's
    /// `CServerConnect::IsLowID()` reads the current id rather than the
    /// login's. No live session, nothing to re-assign.
    pub(crate) fn reassign_client_id(&self, client_id: ClientId) {
        self.0
            .connected_session
            .send_if_modified(|session| match session {
                Some(live) if live.client_id != client_id => {
                    live.client_id = client_id;
                    true
                }
                _ => false,
            });
    }

    /// The live session's self-facts, or `None` between sessions.
    pub(crate) fn connected_session(&self) -> Option<ConnectedSession> {
        *self.0.connected_session.borrow()
    }

    /// Subscribe to every write of the live session — the Server High ID
    /// family of the **Reach Generation** (ADR-0060 "Self Reach"):
    /// a login, a re-assignment, a server move, the session's end.
    pub(crate) fn subscribe_session(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<ConnectedSession>> {
        self.0.connected_session.subscribe()
    }

    /// Our external IPv4 as **Address Learning** currently judges it, fresh or
    /// stale, or `None` when no tier has ever held one.
    pub(crate) fn public_ip(&self) -> Option<Ipv4Addr> {
        match self.0.addresses.address(AddressFamily::V4) {
            Some(IpAddr::V4(ip)) => Some(ip),
            // The IPv4 ladder cannot hold an IPv6 value.
            Some(IpAddr::V6(_)) | None => None,
        }
    }

    /// Our external IPv6, the same projection one family over — the sender
    /// address a datagram we send *from* the v6 half of a Family Pair carries,
    /// and therefore the one the recipient will key its decrypt on (ADR-0087's
    /// 35-byte layout).
    ///
    /// Deliberately the store's stale-tolerant verdict rather than the
    /// **Advertised IPv6** cell: that one is gated for *advertising* (the pair
    /// bound, the verdict fresh, no server probe against it), and a key is not
    /// an advert. Naming an address we no longer hold is a lie; keying on one
    /// we held a minute ago is at worst a datagram the peer reads as
    /// plaintext, which is the same outcome as not obfuscating at all.
    pub(crate) fn public_ipv6(&self) -> Option<std::net::Ipv6Addr> {
        match self.0.addresses.address(AddressFamily::V6) {
            Some(IpAddr::V6(ip)) => Some(ip),
            // The IPv6 ladder cannot hold an IPv4 value.
            Some(IpAddr::V4(_)) | None => None,
        }
    }

    /// aMule's `theApp->GetPublicIP() != 0` precondition, the gate both UDP
    /// crypt surfaces share.
    pub(crate) fn public_ip_known(&self) -> bool {
        self.public_ip().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_learning::AddressObservation;

    #[test]
    fn a_lowid_relogin_withdraws_the_public_ip_but_a_disconnect_leaves_it() {
        // Two cases the old boolean cell could not tell apart, and they must
        // not behave the same (ADR-0084). A Low-ID re-assignment is the server
        // contradicting itself — we hold no public address — so the crypt
        // surfaces must fall back to plaintext rather than key on a value no
        // peer can reproduce. A disconnect says nothing about the address, so
        // the last-known one stays readable and a reconnect never blanks the
        // key mid-reask.
        let own = SharedOwnIdentity::default();
        own.addresses()
            .observe(AddressObservation::server_high_id(Ipv4Addr::new(
                203, 0, 113, 9,
            )));
        assert!(own.public_ip_known());

        own.addresses().end_server_session();
        assert_eq!(
            own.public_ip(),
            Some(Ipv4Addr::new(203, 0, 113, 9)),
            "a disconnect leaves the last-known address readable"
        );

        own.addresses().observe_server_assigned(
            rmule_primitives::ClientId::from_u32(0),
            None,
            None,
        );
        assert!(!own.public_ip_known());
        assert_eq!(own.public_ip(), None);
    }
}
