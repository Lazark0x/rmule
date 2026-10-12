//! The hello context a connection presents: our identity, the **Presented
//! Client ID** **Self Reach** answers, and the live server session's server,
//! or none between sessions (ADR-0098, "Every hello names the live session").

use rmule_peer::PeerHandshakeContext;
use rmule_primitives::ClientIdentity;

use crate::address_learning::SocketRole;
use crate::reachability::SharedSelfReach;

/// The hello context every dial presents at the moment it dials: our
/// `identity`, the Presented Client ID
/// ([`SharedSelfReach::presented_client_id`], aMule's `GetID` written per
/// hello: `BaseClient.cpp:1026`), and the live session's server — none
/// between sessions. aMule and eMule write the connected server's
/// address and port into every hello, zeros when not connected
/// (`CUpDownClient::SendHelloTypePacket`: aMule `BaseClient.cpp:1164-1171`,
/// eMuleAI `BaseClient.cpp:2212-2218`) — never a server a download was once
/// started on.
///
/// The TCP port is [`presented_tcp_port`]'s for the one `identity` names.
pub(crate) fn live_peer_handshake_context(
    identity: &ClientIdentity,
    reach: &SharedSelfReach,
) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            identity.user_hash(),
            identity.nickname().clone(),
            reach.presented_tcp_port(identity.tcp_port()),
            identity.protocol_version(),
        ),
        client_id: reach.presented_client_id(),
        ed2k_client_id: reach.ed2k_client_id(),
        public_ip: reach.public_ip(),
        connected_server: reach.session().and_then(|session| session.server),
    }
}

/// The TCP port we present now for the Core Settings' `configured` one. A
/// `0` is "the OS's choice": the port the eD2k listener holds bound at this
/// read, so a download or a Kad dial begun before the listener bound names
/// the one it holds now, and `0` while none is up, since there is nothing to
/// reach. A surface that outlives a listener keeps the configured port and
/// reads it through here at each use.
///
/// One owner answers every port-`0` question — this, the credentials a login
/// names and where the listener binds ([`listen_tcp_port`]): **Address
/// Learning**'s record of the TCP role's bind.
pub(crate) fn presented_tcp_port(
    configured: u16,
    own: &crate::own_identity::SharedOwnIdentity,
) -> u16 {
    match (configured, own.addresses().bind(SocketRole::Tcp)) {
        (0, Some((_, bound))) => bound,
        (port, _) => port,
    }
}

/// Where the eD2k listener binds for the Core Settings' `configured` port: a
/// `0` takes the port the listener first bound in this process, so one that
/// stopped and starts again binds the port every hello, login and Kad node
/// already presented, and `0` again before any bind (the OS's choice).
pub(crate) fn listen_tcp_port(
    configured: u16,
    own: &crate::own_identity::SharedOwnIdentity,
) -> u16 {
    match configured {
        0 => own.addresses().held_port(SocketRole::Tcp).unwrap_or(0),
        port => port,
    }
}

/// Where a long-lived surface reads the hello it presents: the listener's
/// accept pump and its tunnel and callback admissions, the firewalled
/// front's buddy dial and the Kad TCP dial-back. It is read at each
/// connection, never kept as a copy, so a hello names the Presented Client
/// ID as Self Reach answers it then — a mid-session `OP_IDCHANGE`, a login, a
/// logout or a Kad verdict move shows in the next hello — and the live
/// session's server, or none between sessions: the owner every download dial
/// reads too.
#[derive(Clone)]
pub(crate) enum HelloSource {
    /// Our identity, under Self Reach's answers at each read.
    Live {
        identity: ClientIdentity,
        reach: SharedSelfReach,
    },
    /// One fixed context, for a test that drives an admission directly.
    #[cfg(test)]
    Fixed(PeerHandshakeContext),
}

impl HelloSource {
    /// The hello `identity` presents under `reach`'s answers.
    pub(crate) const fn live(identity: ClientIdentity, reach: SharedSelfReach) -> Self {
        Self::Live { identity, reach }
    }

    /// The hello to present now.
    pub(crate) fn now(&self) -> PeerHandshakeContext {
        match self {
            Self::Live { identity, reach } => live_peer_handshake_context(identity, reach),
            #[cfg(test)]
            Self::Fixed(ctx) => ctx.clone(),
        }
    }
}

impl std::fmt::Debug for HelloSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HelloSource").field(&self.now()).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_net::family::FamilyBinds;
    use rmule_peer::{Hello, HelloAdvert, PeerHelloBody};
    use rmule_primitives::{AddressFamily, ClientId, Ed2kText, Ipv4Endpoint, UserHash};

    use super::*;
    use crate::address_learning::AddressObservation;
    use crate::natt::front::SharedNattFront;
    use crate::own_identity::{ConnectedSession, SharedOwnIdentity};
    use crate::reachability::{KadRunLease, SharedKadVerdicts, TcpReachability};
    use crate::{KadId, KadReachLevel};

    /// Our address as the Kad self-check confirms it.
    const OURS: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 9);
    const SERVER: Ipv4Endpoint = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661);
    const LOW: ClientId = ClientId::from_u32(0x0000_2A57);

    fn identity(tcp_port: u16) -> ClientIdentity {
        ClientIdentity::new(
            UserHash::from_bytes([7; 16]),
            Ed2kText::from_utf8("rmule"),
            tcp_port,
            0x3C,
        )
    }

    /// Self Reach as the actor weaves it, over a published Kad level.
    struct Node {
        reach: SharedSelfReach,
        kad: SharedKadVerdicts,
        own: SharedOwnIdentity,
    }

    impl Node {
        fn new() -> Self {
            let kad = SharedKadVerdicts::default();
            let own = SharedOwnIdentity::default();
            let reach = SharedSelfReach::new(
                KadReachLevel::published(kad.clone()),
                own.clone(),
                SharedNattFront::default(),
            );
            Self { reach, kad, own }
        }

        /// A Kad node starts and hears its first counterparty.
        fn kad_joins(&self) -> KadRunLease {
            let lease = self.reach.lease_kad(KadId::from_bytes([3; 16]));
            self.kad.writer().set_joined();
            lease
        }

        /// The self-check confirms our address: two observers agree.
        fn kad_confirms_address(&self) {
            for observer in [Ipv4Addr::new(80, 1, 1, 1), Ipv4Addr::new(81, 2, 2, 2)] {
                self.own
                    .addresses()
                    .observe(AddressObservation::kad_observed_address(observer, OURS));
            }
        }

        fn login(&self, client_id: ClientId) {
            self.own.set_connected_session(Some(ConnectedSession {
                server: Some(SERVER),
                client_id,
            }));
        }

        /// The hello a peer reads off the wire, built from this node's
        /// hello source now.
        fn hello(&self) -> PeerHelloBody {
            let ctx = HelloSource::live(identity(4662), self.reach.clone()).now();
            let hello = Hello::new(PeerHelloBody::from_handshake_context(
                &ctx,
                &HelloAdvert::default(),
            ));
            Hello::decode_packet(&hello.encode_packet())
                .expect("a hello we just built decodes")
                .into_body()
        }
    }

    fn high_id(address: Ipv4Addr) -> ClientId {
        ClientId::from_u32(u32::from_le_bytes(address.octets()))
    }

    /// aMule's `GetID` arm 1 (`amule.cpp:2046-2048`): an open Kad node names
    /// its own address — even while its server holds it at a Low ID, since
    /// aMule trusts Kad above eD2k — and still names the session's server.
    #[test]
    fn an_open_kad_node_names_its_address_over_a_server_low_id() {
        let node = Node::new();
        let _kad = node.kad_joins();
        node.kad_confirms_address();
        node.kad.set_tcp(TcpReachability::Open);
        assert_eq!(node.hello().client_id, high_id(OURS), "serverless");

        node.login(LOW);
        let hello = node.hello();
        assert_eq!(hello.client_id, high_id(OURS), "not the server's Low ID");
        assert_eq!(hello.connected_server, SERVER);
    }

    /// The eD2k ID is the session's id alone (`GetED2KID`, `amule.cpp:2039`):
    /// an open Kad node presents its address, but the context still carries
    /// the server's Low ID, and `0` while no session is up — the fact the
    /// Secure User Identification challenge IP keys on.
    #[test]
    fn the_context_carries_the_ed2k_id_apart_from_the_presented_one() {
        let node = Node::new();
        let _kad = node.kad_joins();
        node.kad_confirms_address();
        node.kad.set_tcp(TcpReachability::Open);
        let ctx = HelloSource::live(identity(4662), node.reach.clone()).now();
        assert_eq!(ctx.client_id, high_id(OURS));
        assert_eq!(ctx.ed2k_client_id, ClientId::from_u32(0), "no session");
        assert_eq!(
            ctx.public_ip,
            Some(OURS),
            "Address Learning's confirmed one"
        );

        node.login(LOW);
        let ctx = HelloSource::live(identity(4662), node.reach.clone()).now();
        assert_eq!(ctx.client_id, high_id(OURS), "presented: Kad");
        assert_eq!(ctx.ed2k_client_id, LOW, "eD2k: the server's");
    }

    /// Arm 2: off an open Kad, the session's id — the one it assigned last.
    #[test]
    fn a_firewalled_kad_node_on_a_server_names_the_servers_id() {
        let node = Node::new();
        let _kad = node.kad_joins();
        node.login(LOW);
        assert_eq!(node.hello().client_id, LOW);

        let reassigned = ClientId::from_u32(0x0000_3B68);
        node.own.reassign_client_id(reassigned);
        assert_eq!(
            node.hello().client_id,
            reassigned,
            "a mid-session OP_IDCHANGE"
        );
    }

    /// Arm 3 (`amule.cpp:2051-2053`): a serverless, firewalled Kad node names
    /// `1`, which a peer reads as a Low ID — not `0`, which aMule reads as
    /// "use the address I see" (`BaseClient.cpp:678`), so as a High ID.
    #[test]
    fn a_serverless_firewalled_kad_node_names_one() {
        let node = Node::new();
        let _kad = node.kad_joins();
        node.kad_confirms_address();
        let hello = node.hello();
        assert_eq!(hello.client_id, ClientId::from_u32(1));
        assert!(hello.client_id.is_low_id());
        assert_eq!(
            hello.connected_server,
            Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)
        );
    }

    /// Arm 4: neither a session nor a joined Kad names `0` — a node that runs
    /// Kad but has heard nobody yet is not connected (`IsConnected` is
    /// `HasHadContact`), as aMule presents it.
    #[test]
    fn neither_a_session_nor_a_joined_kad_names_zero() {
        let node = Node::new();
        assert_eq!(node.hello().client_id, ClientId::from_u32(0), "nothing");

        let _kad = node.reach.lease_kad(KadId::from_bytes([3; 16]));
        assert_eq!(
            node.hello().client_id,
            ClientId::from_u32(0),
            "Kad running, nobody heard"
        );
    }

    /// Every move of a family the owner reads shows in the next hello, with
    /// no copy anywhere to refresh: a login and a logout under a firewalled
    /// Kad, the Kad TCP verdict opening and falling back, and the node's
    /// stop.
    #[test]
    fn the_next_hello_follows_every_move_of_the_facts_it_reads() {
        let node = Node::new();
        let kad = node.kad_joins();
        node.kad_confirms_address();
        assert_eq!(
            node.hello().client_id,
            ClientId::from_u32(1),
            "Kad firewalled"
        );

        node.login(LOW);
        assert_eq!(node.hello().client_id, LOW, "logged in");
        node.own.set_connected_session(None);
        assert_eq!(node.hello().client_id, ClientId::from_u32(1), "logged out");

        node.kad.set_tcp(TcpReachability::Open);
        assert_eq!(node.hello().client_id, high_id(OURS), "Kad TCP opened");
        node.kad.set_tcp(TcpReachability::Firewalled);
        assert_eq!(node.hello().client_id, ClientId::from_u32(1), "and closed");

        drop(kad);
        assert_eq!(node.hello().client_id, ClientId::from_u32(0), "Kad stopped");
    }

    /// An injected port of `0` follows the listener: nothing to name before
    /// it binds, its bound port while it holds it, nothing again once it
    /// stops. A port the settings name is presented as it is.
    #[test]
    fn a_port_of_zero_is_the_port_the_listener_holds_bound_at_each_hello() {
        let node = Node::new();
        let port = |identity: &ClientIdentity| {
            live_peer_handshake_context(identity, &node.reach)
                .identity
                .tcp_port()
        };
        assert_eq!(port(&identity(0)), 0, "no listener: nothing to name");

        let v4 = FamilyBinds {
            bound: vec![AddressFamily::V4],
            refused: Vec::new(),
        };
        node.own
            .addresses()
            .record_bind(SocketRole::Tcp, &v4, 51_234);
        assert_eq!(port(&identity(0)), 51_234);
        assert_eq!(port(&identity(4662)), 4662, "a set port is the settings'");

        node.own.addresses().forget_bind(SocketRole::Tcp);
        assert_eq!(port(&identity(0)), 0);
    }
}
