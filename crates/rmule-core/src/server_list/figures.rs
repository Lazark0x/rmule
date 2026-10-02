//! A server's **Figures**: what it last told us about itself — its
//! ping, user and file counts, soft and hard file limits and version — and
//! when. They live on the Managed Server List's durable row, as aMule keeps
//! them in `server.met` (`CServerList::SaveServerMet`, `ServerList.cpp:776-789`),
//! so a restart shows them at once, with their age, rather than blanks until
//! the Status Ping Sweep comes round again.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmule_ed2k::{ServerMetFigures, ServerUdpFlags};

/// What a server last reported, and when it last answered. The time is wall
/// time, because it must mean the same thing after a restart; every figure is
/// `None` until an answer carried it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerFigures {
    /// When the server last answered, in seconds since the Unix epoch (aMule's
    /// `ST_LASTPING`): a status ping's `0x97`, the connected server's
    /// `OP_SERVERSTATUS`, or the import's own last-ping time.
    pub answered_at: u64,
    /// The last measured round trip to its UDP port.
    pub ping: Option<Duration>,
    /// Users it last reported online.
    pub users: Option<u32>,
    /// Files it last reported indexed.
    pub files: Option<u32>,
    /// Its soft file limit (`0x97`, aMule `ST_SOFTFILES`).
    pub soft_files: Option<u32>,
    /// Its hard file limit (`0x97`, aMule `ST_HARDFILES`).
    pub hard_files: Option<u32>,
    /// Its version as it named it (`0xA3`, aMule `ST_VERSION`).
    pub version: Option<String>,
    /// The UDP flags word of its last challenge-matched `0x97` (the ones it
    /// named; `None` until an answer carried them). Unknown bits are kept.
    pub udp_flags: Option<ServerUdpFlags>,
}

impl ServerFigures {
    /// Figures answered at `at` and carrying nothing yet.
    #[must_use]
    pub const fn answered(at: u64) -> Self {
        Self {
            answered_at: at,
            ping: None,
            users: None,
            files: None,
            soft_files: None,
            hard_files: None,
            version: None,
            udp_flags: None,
        }
    }

    /// How long ago the server last answered, as of `now`; zero for a time
    /// ahead of `now` (a clock stepped back).
    #[must_use]
    pub fn age(&self, now: SystemTime) -> Duration {
        now.duration_since(UNIX_EPOCH + Duration::from_secs(self.answered_at))
            .unwrap_or_default()
    }

    /// The figures a server.met row carried, dated by its own last-ping time.
    /// `None` when the row names no last answer, or one of `0`, or
    /// one after `now` — aMule's load rejects a future time too
    /// (`Server.cpp:196-200`): a figure with no time behind it cannot say how
    /// old it is, and aMule writes zeros for a server it never pinged.
    #[must_use]
    pub fn from_met(met: &ServerMetFigures, now: SystemTime) -> Option<Self> {
        let at = u64::from(met.last_ping.filter(|at| *at > 0)?);
        if at > unix_seconds(now) {
            return None;
        }
        Some(Self {
            answered_at: at,
            ping: met.ping_ms.map(|ms| Duration::from_millis(u64::from(ms))),
            users: met.users,
            files: met.files,
            soft_files: met.soft_files,
            hard_files: met.hard_files,
            version: met.version.clone(),
            udp_flags: None,
        })
    }
}

/// `now` as whole seconds since the Unix epoch.
#[must_use]
pub fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn met(last_ping: Option<u32>) -> ServerMetFigures {
        ServerMetFigures {
            last_ping,
            users: Some(9),
            ..ServerMetFigures::NONE
        }
    }

    /// An import keeps figures only with a real time behind them, and dates
    /// them by it.
    #[test]
    fn an_imported_rows_figures_are_dated_by_its_last_ping_or_dropped() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let kept = ServerFigures::from_met(&met(Some(6_400)), now).expect("dated figures");
        assert_eq!(kept.users, Some(9));
        assert_eq!(kept.age(now), Duration::from_secs(3_600));
        assert_eq!(
            ServerFigures::from_met(&met(Some(0)), now),
            None,
            "never pinged"
        );
        assert_eq!(ServerFigures::from_met(&met(None), now), None, "no time");
        assert_eq!(
            ServerFigures::from_met(&met(Some(20_000)), now),
            None,
            "future"
        );
    }
}
