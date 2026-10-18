//! The Run Log's record of the server list and of the server connection: the
//! login steps a reachability diagnosis reads. The server endpoint is lean.

use crate::{ServerConnectionEvent, ServerListEvent};

use crate::run_log::codes;
use crate::run_log::record::Record;

impl ServerListEvent {
    /// The Run Log's record of this server list event.
    #[must_use]
    pub fn record(&self) -> Record {
        use ServerListEvent as L;
        match self {
            L::ServerAdded { server } => {
                Record::new("server_list.added").server_endpoint("server", server)
            }
            L::ServerUpdated { server } => {
                Record::new("server_list.updated").server_endpoint("server", server)
            }
            L::ServerRemoved { server } => {
                Record::new("server_list.removed").server_endpoint("server", server)
            }
            L::ReservedServerDropped { server } => {
                Record::new("server_list.reserved_dropped").server_endpoint("server", server)
            }
            L::ServerPriorityChanged { server, priority } => {
                Record::new("server_list.priority_changed")
                    .server_endpoint("server", server)
                    .code("priority", codes::server_priority(*priority))
            }
            L::ServerStaticChanged { server, is_static } => {
                Record::new("server_list.static_changed")
                    .server_endpoint("server", server)
                    .flag("static", *is_static)
            }
            L::ServerListUpdateStarted { url } => {
                Record::new("server_list.update_started").url("url", url)
            }
            L::ServerListUpdated {
                added,
                updated,
                total,
            } => Record::new("server_list.update_finished")
                .count("added", *added)
                .count("updated", *updated)
                .count("total", *total),
            L::ServerListUpdateFailed { reason } => {
                codes::list_update_failure(Record::new("server_list.update_failed"), *reason)
            }
        }
    }
}

impl ServerConnectionEvent {
    /// The Run Log's record of this server connection event.
    #[must_use]
    pub fn record(&self) -> Record {
        use ServerConnectionEvent as C;
        match self {
            C::Connecting { server, leaving } => {
                let record = Record::new("server.connecting").server_endpoint("server", server);
                match leaving {
                    Some(previous) => record.server_endpoint("leaving", previous),
                    None => record,
                }
            }
            C::Connected { server, client_id } => Record::new("server.connected")
                .server_endpoint("server", server)
                .own_id("client_id", *client_id),
            C::ConnectFailed { server, reason } => Record::new("server.connect_failed")
                .server_endpoint("server", server)
                .code("reason", codes::connect_failure(*reason)),
            C::Disconnected { server } => {
                Record::new("server.disconnected").server_endpoint("server", server)
            }
            C::Reconnecting {
                server,
                attempt,
                bound,
                next_in,
                steady,
                ..
            } => {
                let record = Record::new("server.reconnecting")
                    .server_endpoint("server", server)
                    .count("attempt", *attempt);
                let record = match bound {
                    Some(bound) => record.count("bound", *bound),
                    None => record.code("bound", "none"),
                };
                record
                    .count("next_in_secs", next_in.as_secs())
                    .flag("steady", *steady)
            }
            C::ReconnectEnded { server, reason } => codes::reconnect_end(
                Record::new("server.reconnect_ended").server_endpoint("server", server),
                reason,
            ),
        }
    }
}
