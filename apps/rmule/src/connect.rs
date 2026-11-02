//! The **connect at start** (ADR-0095, "Connecting is the operator's act"):
//! nothing in rmule dials a server but the operator's connect, so a start
//! that connects on its own repeats the last one they made. On by default, as
//! aMule's `Autoconnect` is (`Preferences.cpp:1160`, acted on at
//! `amule.cpp:1310`), and a stored off stays off. A first run has made no
//! connect to repeat, so it dials nothing and says nothing.
//!
//! When on, the app sends the same `ConnectToServer` Networks' `c` key sends,
//! through the same establishment (listen, map, then log in), to the server
//! the operator last connected to. That one server, once: aMule's autoconnect
//! walks the list (`ConnectToAnyServer`, `ServerConnect.cpp:55-70`), and each
//! step of that walk dials a server the operator never picked. An
//! unreachable server's `ConnectFailed` is shown like any other.

use rmule_primitives::ServerEndpoint;

use crate::words::Sentence;
use crate::words::server::LAST_SERVER_UNLISTED;

/// What a start does about connecting.
#[derive(Clone, Debug)]
pub enum AtStart {
    /// The preference is off, or no connect was ever made: nothing is dialed,
    /// and nothing is said.
    Nothing,
    /// The operator's connect — the `ConnectToServer` the `c` key sends — to
    /// the server they last connected to.
    Connect(ServerEndpoint),
    /// The preference is on but the server is gone from the list; the status
    /// bar says why.
    CannotConnect(Sentence),
}

/// Decide the start's connect from the preference, the server last connected
/// to, and the servers listed now.
#[must_use]
pub fn at_start(
    connect_at_start: bool,
    last_server: Option<&ServerEndpoint>,
    listed: &[ServerEndpoint],
) -> AtStart {
    if !connect_at_start {
        return AtStart::Nothing;
    }
    let Some(server) = last_server else {
        return AtStart::Nothing;
    };
    if !listed.contains(server) {
        return AtStart::CannotConnect(LAST_SERVER_UNLISTED);
    }
    AtStart::Connect(server.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(port: u16) -> ServerEndpoint {
        ServerEndpoint::new("192.0.2.7", port).expect("endpoint")
    }

    #[test]
    fn off_a_start_dials_nothing() {
        let last = server(4661);
        assert!(matches!(
            at_start(false, Some(&last), std::slice::from_ref(&last)),
            AtStart::Nothing
        ));
    }

    #[test]
    fn on_a_start_connects_to_the_server_last_connected_to() {
        let last = server(4661);
        let AtStart::Connect(to) = at_start(true, Some(&last), &[server(4242), last.clone()])
        else {
            panic!("the operator's connect, to the last server");
        };
        assert_eq!(to, last);
    }

    /// The default is on, and a first run has no connect to repeat.
    #[test]
    fn a_first_run_dials_nothing_and_says_nothing() {
        assert!(matches!(
            at_start(true, None, &[server(4661)]),
            AtStart::Nothing
        ));
    }

    #[test]
    fn on_with_the_server_gone_it_says_why_and_dials_nothing() {
        assert!(matches!(
            at_start(true, Some(&server(4661)), &[server(4242)]),
            AtStart::CannotConnect(why) if why == LAST_SERVER_UNLISTED
        ));
    }
}
