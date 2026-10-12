//! The **Server Policy**: the operator's two server-list preferences core
//! acts on (ADR-0052, "dead servers are marked, never removed"), and how a
//! row's health follows from its failure tally under them.
//!
//! The policy is part of **Core Settings** (ADR-0069): the actor starts
//! under it, so nothing core does before its first command runs under a
//! default the operator changed, and a change through the settings handle is
//! taken up live.

use super::ManagedServer;

/// aMule's `/eMule/DeadServerRetry` default (`Preferences.cpp:1187`): the
/// failure tally at which a server is dead.
pub const DEFAULT_DEAD_AFTER: u32 = 3;

/// What core does with a server by what reaching it has shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    /// The **Dead Server Limit**: a server whose consecutive failure tally
    /// is at or above it is dead. Never below 1, so a server that has not
    /// failed is never dead.
    pub dead_after: u32,
    /// The **Announce Policy** (ADR-0099): withhold the share set from a
    /// server that grants related search. Off by default — rmule announces
    /// its shares, as aMule does.
    pub withhold_from_related_search: bool,
}

impl Default for ServerPolicy {
    fn default() -> Self {
        Self {
            dead_after: DEFAULT_DEAD_AFTER,
            withhold_from_related_search: false,
        }
    }
}

impl ServerPolicy {
    /// The limit as a stored preference spells it: a whole number of at
    /// least 1; anything else is the default, as an unset one is.
    #[must_use]
    pub fn parse_dead_after(text: Option<&str>) -> u32 {
        text.and_then(|text| text.trim().parse::<u32>().ok())
            .filter(|limit| *limit >= 1)
            .unwrap_or(DEFAULT_DEAD_AFTER)
    }

    /// Whether `server` is dead under this policy.
    #[must_use]
    pub fn is_dead(&self, server: &ManagedServer) -> bool {
        server.fail_count >= self.dead_after.max(1)
    }

    /// `server`'s health under this policy.
    #[must_use]
    pub fn health(&self, server: &ManagedServer) -> ServerHealth {
        if self.is_dead(server) {
            ServerHealth::Dead
        } else if server.fail_count > 0 {
            ServerHealth::Failing
        } else if server.figures.is_some() || server.grants.is_some() {
            ServerHealth::Answered
        } else {
            ServerHealth::Unproven
        }
    }
}

/// How reaching a server has gone, as the surfaced row carries it. Ordered
/// by [`rank`](Self::rank), which is what a table sorts it by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServerHealth {
    /// No failure since its last answer, and it has answered.
    Answered,
    /// No failure, and no answer either: never reached yet.
    Unproven,
    /// Failures below the **Dead Server Limit**.
    Failing,
    /// Failures at or above the limit: a **Dead Server**.
    Dead,
}

impl ServerHealth {
    /// Best first: answered, unproven, failing, dead.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Answered => 0,
            Self::Unproven => 1,
            Self::Failing => 2,
            Self::Dead => 3,
        }
    }
}

/// When a **Dead Server** died, as the surfaced row carries it (ADR-0052,
/// "Dead since when"): a run-time fact, never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeadSince {
    /// Its health turned dead this long ago, as of the snapshot.
    For(std::time::Duration),
    /// It was already dead when this run first read the list.
    BeforeThisRun,
}

#[cfg(test)]
mod tests {
    use rmule_primitives::ServerEndpoint;

    use super::*;

    fn failed(fail_count: u32) -> ManagedServer {
        ManagedServer {
            fail_count,
            ..ManagedServer::listed(ServerEndpoint::new("192.0.2.61", 4661).unwrap())
        }
    }

    /// The tally alone decides: below the limit a server is failing, at it
    /// and past it dead, and a limit of zero reads as one, never as "every
    /// server is dead".
    #[test]
    fn a_server_is_dead_from_the_limit_on() {
        let policy = ServerPolicy {
            dead_after: 3,
            ..ServerPolicy::default()
        };
        assert_eq!(policy.health(&failed(0)), ServerHealth::Unproven);
        assert_eq!(policy.health(&failed(2)), ServerHealth::Failing);
        assert_eq!(policy.health(&failed(3)), ServerHealth::Dead);
        assert_eq!(policy.health(&failed(9)), ServerHealth::Dead);
        let zero = ServerPolicy {
            dead_after: 0,
            ..ServerPolicy::default()
        };
        assert_eq!(zero.health(&failed(0)), ServerHealth::Unproven);
        assert_eq!(zero.health(&failed(1)), ServerHealth::Dead);
    }

    #[test]
    fn a_stored_limit_below_one_or_unreadable_is_the_default() {
        assert_eq!(ServerPolicy::parse_dead_after(Some("5")), 5);
        assert_eq!(
            ServerPolicy::parse_dead_after(Some("0")),
            DEFAULT_DEAD_AFTER
        );
        assert_eq!(
            ServerPolicy::parse_dead_after(Some("many")),
            DEFAULT_DEAD_AFTER
        );
        assert_eq!(ServerPolicy::parse_dead_after(None), DEFAULT_DEAD_AFTER);
    }
}
