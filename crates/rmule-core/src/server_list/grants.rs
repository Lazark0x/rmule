//! A server's **Grants Report**: what it last said it grants a client at
//! login — the raw `SRV_TCPFLG_*` word of its `OP_IDCHANGE` — and when
//! (ADR-0080, "What a server grants is durable"). Kept on the durable row so
//! the operator can judge a server before connecting to it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmule_ed2k::{ServerGrants, ServerTcpFlags};

/// The TCP grants a server last reported, and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerGrantsReport {
    /// The word as the server sent it. Unknown bits are kept: the word is the
    /// stored key, and a front end words each flag it names.
    pub tcp_flags: ServerTcpFlags,
    /// When the login (or a later `OP_IDCHANGE`) reported it, in seconds since
    /// the Unix epoch.
    pub reported_at: u64,
}

impl ServerGrantsReport {
    /// The word projected onto what each consumer gates on.
    #[must_use]
    pub fn grants(&self) -> ServerGrants {
        ServerGrants::from(self.tcp_flags)
    }

    /// How long ago the server reported it, as of `now`; zero for a time
    /// ahead of `now` (a clock stepped back).
    #[must_use]
    pub fn age(&self, now: SystemTime) -> Duration {
        now.duration_since(UNIX_EPOCH + Duration::from_secs(self.reported_at))
            .unwrap_or_default()
    }
}
