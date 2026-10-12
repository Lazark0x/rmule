//! A server's **Aux Ports** (ADR-0080): the relation between the port rmule
//! dials a server on and the *standard* port the server calls its own.
//!
//! aMule keeps two ports per server — `port`, the one it connects to, and
//! `realport`, the "official" one it lists, advertises and keys its list on
//! (`Server.h:69-73`). They differ after an *aux-port login*, where the
//! server's `OP_IDCHANGE` names its standard port (`ServerSocket.cpp:289-311`),
//! and after a server.met row carrying `ST_AUXPORTSLIST`, whose header port
//! is the standard one and whose list starts with the port to dial
//! (`Server.cpp:222-231`). The list is the row's own fact and is written back
//! only while the two differ (`ServerList.cpp:763-765`).

use rmule_primitives::ServerEndpoint;

/// The standard port of a row dialed on another port, and the ports it can be
/// dialed on.
///
/// Present on a [`ManagedServer`](super::ManagedServer) only while the two
/// differ, which is aMule's own condition for writing the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAuxPorts {
    /// The server's standard port: what its server.met row lists, what its
    /// UDP port derives from, and what a downloaded list names it by.
    pub standard_port: u16,
    /// The ports it takes aux-port logins on, the one dialed first. Never
    /// empty.
    pub ports: Vec<u16>,
}

impl ServerAuxPorts {
    /// What a server.met row says: its header port is the standard one, and
    /// `ports` is its `ST_AUXPORTSLIST`. `None` for an empty list, which some
    /// server.mets carry (`Server.cpp:226`).
    #[must_use]
    pub fn from_met(standard_port: u16, ports: &[u16]) -> Option<Self> {
        let ports: Vec<u16> = ports.iter().copied().filter(|port| *port != 0).collect();
        (!ports.is_empty() && ports.iter().any(|port| *port != standard_port)).then_some(Self {
            standard_port,
            ports,
        })
    }

    /// What an aux-port login's ID answer adds to a row dialed on `dialed`
    /// when the server named `standard`: the list keeps an existing value and
    /// otherwise starts as the dialed port (`ServerSocket.cpp:341-343`).
    /// `None` when the answer names no port, or the dialed one — nothing
    /// differs, so there is nothing to keep.
    #[must_use]
    pub(crate) fn from_login(existing: Option<&Self>, dialed: u16, standard: u16) -> Option<Self> {
        if standard == 0 || standard == dialed {
            return None;
        }
        Some(Self {
            standard_port: standard,
            ports: existing
                .map(|aux| aux.ports.clone())
                .filter(|ports| !ports.is_empty())
                .unwrap_or_else(|| vec![dialed]),
        })
    }
}

/// The endpoint a downloaded server.met names this row by: `endpoint`'s host
/// at the standard port.
pub(super) fn standard_endpoint(
    endpoint: &ServerEndpoint,
    aux: Option<&ServerAuxPorts>,
) -> ServerEndpoint {
    match aux {
        Some(aux) => ServerEndpoint::new(endpoint.host(), aux.standard_port)
            .unwrap_or_else(|_| endpoint.clone()),
        None => endpoint.clone(),
    }
}

#[cfg(test)]
mod tests {
    use rmule_ed2k::{ServerAssignedFacts, ServerPriority};
    use rmule_primitives::{ClientId, Ed2kText};

    use super::*;
    use crate::server_list::{ManagedServer, ServerListStore, ServerMerge, test_facts};
    use crate::store::app_config::DurableAppConfig;

    fn endpoint(host: &str, port: u16) -> ServerEndpoint {
        ServerEndpoint::new(host, port).expect("valid endpoint")
    }

    fn store() -> DurableAppConfig {
        DurableAppConfig::new(rmule_testkit::memory_store())
    }

    fn named(host: &str, port: u16, name: &str) -> ManagedServer {
        let mut row = ManagedServer::listed(endpoint(host, port));
        row.name = Ed2kText::from_utf8(name);
        row
    }

    /// An aux-port login re-ports the row it dialed: the server's standard
    /// port becomes its list identity and the dialed port stays in the aux
    /// list, so a downloaded row naming the standard port finds it rather
    /// than adding a second one.
    #[test]
    fn an_aux_port_login_re_ports_the_row_and_a_downloaded_row_finds_it() {
        let store = store();
        let dialed = endpoint("203.0.113.9", 4232);
        store
            .merge_server(named("203.0.113.9", 4232, "Aux"))
            .unwrap();

        assert!(store.set_server_standard_port(&dialed, 4661).unwrap());
        let row = store.servers().unwrap().remove(0);
        assert_eq!(
            row.endpoint, dialed,
            "the row is still dialed on the aux port"
        );
        assert_eq!(row.standard_endpoint(), endpoint("203.0.113.9", 4661));
        assert_eq!(
            row.aux_ports,
            Some(ServerAuxPorts {
                standard_port: 4661,
                ports: vec![4232]
            })
        );

        let downloaded = named("203.0.113.9", 4661, "Renamed");
        assert_eq!(
            store.merge_server(downloaded).unwrap(),
            ServerMerge::Updated
        );
        let rows = store.servers().unwrap();
        assert_eq!(rows.len(), 1, "no second row for one server");
        assert_eq!(rows[0].name.to_display_string(), "Renamed");
        assert_eq!(rows[0].endpoint, dialed);
    }

    /// An existing aux list survives a later login; a login naming no port or
    /// the dialed one changes nothing; an unlisted endpoint reports so.
    #[test]
    fn a_login_keeps_the_list_it_has_and_ignores_a_port_that_differs_from_nothing() {
        let store = store();
        let dialed = endpoint("203.0.113.9", 4232);
        store
            .merge_server(ManagedServer::listed(dialed.clone()))
            .unwrap();

        assert!(store.set_server_standard_port(&dialed, 0).unwrap());
        assert!(store.set_server_standard_port(&dialed, 4232).unwrap());
        assert_eq!(store.servers().unwrap()[0].aux_ports, None);

        store.set_server_standard_port(&dialed, 4661).unwrap();
        store.set_server_standard_port(&dialed, 4662).unwrap();
        let aux = store.servers().unwrap()[0].aux_ports.clone().unwrap();
        assert_eq!((aux.standard_port, aux.ports), (4662, vec![4232]));

        assert!(
            !store
                .set_server_standard_port(&endpoint("198.51.100.1", 4661), 4662)
                .unwrap()
        );
    }

    /// The standard endpoint may already be listed as a row of its own (a
    /// downloaded list, an operator's add): learning it absorbs that row into
    /// the dialed one, which keeps the key the session runs on and gains the
    /// name, priority and pin the listed row held.
    #[test]
    fn a_standard_endpoint_already_listed_is_absorbed_not_duplicated() {
        let store = store();
        let mut listed = named("203.0.113.9", 4661, "Listed");
        listed.priority = ServerPriority::High;
        listed.is_static = true;
        store.merge_server(listed).unwrap();
        let dialed = endpoint("203.0.113.9", 4232);
        store
            .merge_server(ManagedServer::listed(dialed.clone()))
            .unwrap();

        store.set_server_standard_port(&dialed, 4661).unwrap();

        let rows = store.servers().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.endpoint, dialed);
        assert_eq!(row.name.to_display_string(), "Listed");
        assert_eq!(row.priority, ServerPriority::High);
        assert!(row.is_static);
        assert_eq!(
            row.aux_ports.as_ref().map(|aux| aux.standard_port),
            Some(4661)
        );
    }

    /// The login path: the ID answer's standard port reaches the row through
    /// the facts seam, and a short answer without one leaves the row alone.
    #[test]
    fn the_id_answers_standard_port_reaches_the_row() {
        let dialed = endpoint("203.0.113.9", 4232);
        let (facts, _) = test_facts(std::slice::from_ref(&dialed));
        let answer = |standard_tcp_port| ServerAssignedFacts {
            public_ip: None,
            standard_tcp_port,
            obfuscation_tcp_port: None,
        };

        let id = ClientId::from_u32(0x0100_0001);
        facts.granted(&dialed, id, None, &answer(None));
        assert_eq!(facts.listed().unwrap()[0].aux_ports, None);

        facts.granted(&dialed, id, None, &answer(Some(4661)));
        assert_eq!(
            facts.listed().unwrap()[0].standard_endpoint(),
            endpoint("203.0.113.9", 4661)
        );
    }

    /// Lugdunum fills the standard-port slot with the assigned id (captured:
    /// id 936, slot 936); that is not an aux port and must not rename the row.
    #[test]
    fn a_standard_port_slot_that_echoes_the_assigned_id_is_not_a_port() {
        let dialed = endpoint("203.0.113.9", 4661);
        let (facts, _) = test_facts(std::slice::from_ref(&dialed));
        facts.granted(
            &dialed,
            ClientId::from_u32(936),
            None,
            &ServerAssignedFacts {
                public_ip: None,
                standard_tcp_port: Some(936),
                obfuscation_tcp_port: None,
            },
        );
        assert_eq!(facts.listed().unwrap()[0].aux_ports, None);
    }

    /// An empty `ST_AUXPORTSLIST`, which some server.mets carry, is no aux
    /// ports at all, and a list naming only the standard port adds nothing.
    #[test]
    fn an_empty_list_or_one_naming_only_the_standard_port_is_no_aux_ports() {
        assert_eq!(ServerAuxPorts::from_met(4661, &[]), None);
        assert_eq!(ServerAuxPorts::from_met(4661, &[0]), None);
        assert_eq!(ServerAuxPorts::from_met(4661, &[4661]), None);
    }
}
