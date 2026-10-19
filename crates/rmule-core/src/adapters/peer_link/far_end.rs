//! What a link rmule dialed shows of its far end (ADR-0107 invariant 7, "A
//! link rmule dialed, already dead at the far end"): whether its session has
//! ended, and when anything last crossed it either way. The link's driver
//! notes both as it reads and sends; the serve side reads them before it lets
//! the client's own link go for the dial, since the far end keeps one socket
//! per client (`ClientList.cpp:400-403`) and one that dropped the dial holds
//! only its own link.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rmule_net::peer::{Connection as PeerConnection, PeerNetError};
use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent};
use rmule_primitives::PeerEndpoint;

use crate::service::DeadDialSign;

/// aMule's socket timeout, `CONNECTION_TIMEOUT` (40 s, `Constants.h:34`,
/// `EMSocket.cpp:61`): a socket nothing was sent or received on for longer
/// is closed (`ClientTCPSocket.cpp:201-229`), its timer restarting at every
/// packet either way (`:1886-1895`, `:2059-2080`).
const FAR_END_SOCKET_TIMEOUT: Duration = Duration::from_secs(40);

/// The far end of one link rmule dialed, as its driver saw it (see the module
/// docs). Clones share one reading.
#[derive(Clone, Debug)]
pub struct FarEnd(Arc<Reading>);

#[derive(Debug)]
struct Reading {
    /// When the reading started: the link came up.
    since: Instant,
    /// When something last crossed the link, as milliseconds after `since`.
    crossed_ms: AtomicU64,
    /// The link's session ended.
    ended: AtomicBool,
}

impl Default for FarEnd {
    fn default() -> Self {
        Self::new()
    }
}

impl FarEnd {
    /// The far end of a link that just came up: something crossed it now.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Reading {
            since: Instant::now(),
            crossed_ms: AtomicU64::new(0),
            ended: AtomicBool::new(false),
        }))
    }

    /// Something crossed the link: rmule read a packet off it, or framed one
    /// onto it.
    pub fn crossed(&self) {
        let elapsed = u64::try_from(self.0.since.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.0.crossed_ms.fetch_max(elapsed, Ordering::Release);
    }

    /// The link's session ended: a reset or a FIN was read on it, or rmule
    /// closed it.
    pub fn ended(&self) {
        self.0.ended.store(true, Ordering::Release);
    }

    /// Note one event read off the link: its close ends the link, anything
    /// else crossed it.
    pub fn read(&self, event: &PeerEvent) {
        if matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. })
        ) {
            self.ended();
        } else {
            self.crossed();
        }
    }

    /// Whether the link is a **Dead Dial** at `now`, and what shows it: its
    /// session ended, or nothing crossed it either way for longer than
    /// aMule's socket timeout. `None` while the far end may still hold it.
    #[must_use]
    pub fn dead_at(&self, now: Instant) -> Option<DeadDialSign> {
        if self.0.ended.load(Ordering::Acquire) {
            return Some(DeadDialSign::Ended);
        }
        let crossed =
            self.0.since + Duration::from_millis(self.0.crossed_ms.load(Ordering::Acquire));
        (now.saturating_duration_since(crossed) > FAR_END_SOCKET_TIMEOUT)
            .then_some(DeadDialSign::Silent)
    }
}

/// A link's connection as its router drives it: on a link rmule dialed,
/// every packet framed onto it or read off it is noted on its [`FarEnd`], and
/// its close ends it.
pub(in crate::adapters) struct LinkConnection {
    conn: PeerConnection,
    far_end: Option<FarEnd>,
}

impl LinkConnection {
    /// Drive `conn`, noting on `far_end` when rmule dialed it.
    pub(in crate::adapters) const fn new(conn: PeerConnection, far_end: Option<FarEnd>) -> Self {
        Self { conn, far_end }
    }

    /// The link's remote end.
    pub(in crate::adapters) const fn peer_endpoint(&self) -> PeerEndpoint {
        self.conn.peer_endpoint()
    }

    /// Frame `command` onto the link.
    pub(in crate::adapters) async fn send(&self, command: PeerCommand) -> Result<(), PeerNetError> {
        self.conn.send(command).await?;
        if let Some(far_end) = &self.far_end {
            far_end.crossed();
        }
        Ok(())
    }

    /// The next event read off the link; `None` once its driver is gone.
    pub(in crate::adapters) async fn next_event(&mut self) -> Option<PeerEvent> {
        let event = self.conn.next_event().await;
        if let Some(far_end) = &self.far_end {
            match &event {
                Some(event) => far_end.read(event),
                None => far_end.ended(),
            }
        }
        event
    }

    /// Shut the link down; its far end reads ended from now.
    pub(in crate::adapters) async fn shutdown(self) -> Result<(), PeerNetError> {
        if let Some(far_end) = &self.far_end {
            far_end.ended();
        }
        self.conn.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::FarEnd;
    use crate::service::DeadDialSign;

    #[test]
    fn a_dialed_link_is_dead_once_ended_or_silent_past_amules_timeout() {
        let far_end = FarEnd::new();
        let now = Instant::now();
        assert_eq!(far_end.dead_at(now + Duration::from_secs(39)), None);
        assert_eq!(
            far_end.dead_at(now + Duration::from_secs(41)),
            Some(DeadDialSign::Silent),
            "nothing crossed it for longer than aMule keeps a silent socket"
        );
        far_end.ended();
        assert_eq!(far_end.dead_at(now), Some(DeadDialSign::Ended));
    }
}
