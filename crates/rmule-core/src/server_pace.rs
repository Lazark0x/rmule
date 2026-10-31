//! The **Server Pace** (ADR-0051): the one owner of how often rmule's UDP
//! source asks reach servers, and the source gates every road reads.
//!
//! [`UdpRounds`] is aMule's `SendNextUDPPacket` walk (stock 2.3.3
//! `DownloadQueue.cpp:868-958`), sans-I/O: time and the world come in as
//! arguments, one step gives at most one datagram's worth of asks. A round
//! visits each swept server once, at most [`MAX_REQUESTS_PER_SERVER`] files to
//! one server. The file walk carries over from one server to the next and
//! wraps once every file was asked, so a queue past one server's share reaches
//! the following servers instead of starving. The clock runs from the end of a
//! round to the start of the next, as `m_lastudpsearchtime` does.
//!
//! The state is one snapshot of the swept list and one of the file queue: its
//! memory is bounded by the two, and it never outlives the round.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rmule_ed2k::ServerUdpFlags;
use rmule_primitives::{FileHash, ServerEndpoint, SourceLookupTarget, is_large_file};
use tokio::time::Instant;

/// aMule's `MAX_FILES_PER_UDP_PACKET` (stock 2.3.3 `DownloadQueue.cpp:72`):
/// keeps a datagram under 512 bytes.
const FILES_PER_DATAGRAM: usize = 31;

/// aMule's `MAX_REQUESTS_PER_SERVER` (stock 2.3.3 `DownloadQueue.cpp:73`):
/// the files one server hears in one round.
pub(crate) const MAX_REQUESTS_PER_SERVER: usize = 35;

/// A file holding this many sources is left out of a UDP round: aMule's
/// `thePrefs::GetMaxSourcePerFileUDP` at its default limit (stock 2.3.3
/// `DownloadQueue.cpp:914`, `Preferences.h:274`).
pub(crate) const UDP_SOURCE_GATE: u32 = 100;

/// A file holding this many sources is left out of a Kad ask: aMule's
/// `CPartFile::GetMaxSourcePerFileUDP` (stock 2.3.3 `PartFile.cpp:1512`,
/// `:3992`, `MAX_SOURCES_FILE_UDP`).
pub(crate) const KAD_SOURCE_GATE: u32 = 50;

/// A file holding this many sources is not asked of its server again: aMule's
/// `GetMaxSourcePerFileSoft` at its default limit (stock 2.3.3
/// `PartFile.cpp:1547`, `Preferences.h:270`).
pub(crate) const TCP_SOURCE_GATE: u32 = 270;

/// aMule's `SERVERREASKTIME` (stock 2.3.3 `Constants.h:36`): how long a run
/// waits before asking its session for the file's sources again.
pub(crate) const TCP_REASK: Duration = Duration::from_secs(800);

/// How soon a run past its re-ask looks again while its file sits at the
/// gate; aMule looks on every pass of `CPartFile::Process`.
const TCP_REASK_LOOK: Duration = Duration::from_secs(60);

/// How many sources a run holds, published by the run and read by the roads
/// that gate on it. One word per run, so a reader takes no lock of the run's.
#[derive(Clone, Debug, Default)]
pub(crate) struct SourceCount(Arc<AtomicU32>);

impl SourceCount {
    /// The run holds `sources` now.
    pub(crate) fn publish(&self, sources: u32) {
        self.0.store(sources, Ordering::Relaxed);
    }

    /// Whether the file holds fewer sources than `gate`.
    pub(crate) fn under(&self, gate: u32) -> bool {
        self.0.load(Ordering::Relaxed) < gate
    }
}

/// One run's periodic TCP re-ask (ADR-0097): 800 s after its last ask, while
/// the file is under the gate and a session is up. The clock is the run's, so
/// it dies with the run: a Resume or a re-add asks at once, as aMule's
/// `m_lastsearchtime` is zeroed at Resume and new for a new file (stock 2.3.3
/// `PartFile.cpp:2472`). With no session it waits, as a new session is an ask
/// of its own.
#[derive(Debug, Default)]
pub(crate) struct TcpReask {
    next_look: Option<Instant>,
}

impl TcpReask {
    /// The run asked at `now`.
    pub(crate) fn asked(&mut self, now: Instant) {
        self.next_look = Some(now + TCP_REASK);
    }

    /// When to look next; `None` while nothing is owed.
    pub(crate) const fn next_look(&self) -> Option<Instant> {
        self.next_look
    }

    /// The look at `now`: whether to ask, and when to look otherwise.
    pub(crate) fn look(&mut self, now: Instant, session_up: bool, sources: &SourceCount) -> bool {
        if !session_up {
            self.next_look = None;
            return false;
        }
        if self.next_look.is_some_and(|look| now < look) {
            return false;
        }
        let ask = sources.under(TCP_SOURCE_GATE);
        if !ask {
            self.next_look = Some(now + TCP_REASK_LOOK);
        }
        ask
    }
}

/// One datagram's worth of asks to `server`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UdpAsk {
    pub(crate) server: ServerEndpoint,
    pub(crate) flags: ServerUdpFlags,
    pub(crate) targets: Vec<SourceLookupTarget>,
}

/// The server a round is on and what it heard so far.
#[derive(Debug)]
struct Visit {
    server: ServerEndpoint,
    requests: usize,
}

impl Visit {
    /// How many files the next datagram may carry: aMule's
    /// `GetMaxFilesPerUDPServerPacket` (stock 2.3.3 `DownloadQueue.cpp:1281-1298`).
    fn allowed(&self, flags: ServerUdpFlags) -> usize {
        let left = MAX_REQUESTS_PER_SERVER.saturating_sub(self.requests);
        if flags.supports_ext_get_sources() {
            left.min(FILES_PER_DATAGRAM)
        } else {
            left.min(1)
        }
    }
}

/// A round in progress: the servers it has yet to reach, the one it is on,
/// and the files of the current pass of the queue.
#[derive(Debug)]
struct Walk {
    servers: VecDeque<ServerEndpoint>,
    visit: Option<Visit>,
    files: VecDeque<FileHash>,
}

fn queue_of(files: &[SourceLookupTarget]) -> VecDeque<FileHash> {
    files.iter().map(|target| target.file_hash()).collect()
}

/// The UDP round clock and the walk of the round in progress. One per Core:
/// a run's Pause, Resume, Cancel or re-add and a server change leave it
/// standing, a process restart starts it over (ADR-0051).
#[derive(Debug)]
pub(crate) struct UdpRounds {
    spacing: Duration,
    tick: Duration,
    /// When the last round ended; `None` until one has.
    ended: Option<Instant>,
    /// When the last datagram left; one per `tick` across every server.
    sent: Option<Instant>,
    walk: Option<Walk>,
}

impl UdpRounds {
    /// `spacing` from the end of one round to the start of the next, one
    /// datagram per `tick`.
    pub(crate) const fn new(spacing: Duration, tick: Duration) -> Self {
        Self {
            spacing,
            tick,
            ended: None,
            sent: None,
            walk: None,
        }
    }

    /// The asks of the next datagram at `now`, if one is due. `swept` is the
    /// swept list now and `files` the files under the gate now; `flags` reads
    /// a server's UDP flags. With no session nothing moves: a round in
    /// progress waits where it stands and no round starts (aMule's
    /// `SendNextUDPPacket` returns before touching its walk,
    /// `DownloadQueue.cpp:870`). A round needs a server and a file to start,
    /// so an empty list spends no clock.
    pub(crate) fn next_ask(
        &mut self,
        now: Instant,
        session_up: bool,
        swept: &[ServerEndpoint],
        files: &[SourceLookupTarget],
        flags: impl Fn(&ServerEndpoint) -> ServerUdpFlags,
    ) -> Option<UdpAsk> {
        if !session_up || self.sent.is_some_and(|sent| now < sent + self.tick) {
            return None;
        }
        if self.walk.is_none() {
            let due = self.ended.is_none_or(|ended| now >= ended + self.spacing);
            if !due || swept.is_empty() || files.is_empty() {
                return None;
            }
            self.walk = Some(Walk {
                servers: swept.iter().cloned().collect(),
                visit: None,
                files: queue_of(files),
            });
        }
        let walk = self.walk.as_mut()?;
        loop {
            // A server that left the swept list since the round started,
            // the one we logged into included, is passed over.
            let visit = walk
                .visit
                .as_ref()
                .filter(|visit| swept.contains(&visit.server));
            let allowed = visit.map_or(0, |visit| visit.allowed(flags(&visit.server)));
            if allowed == 0 {
                let Some(server) = walk.servers.pop_front() else {
                    self.walk = None;
                    self.ended = Some(now);
                    return None;
                };
                walk.visit = Some(Visit {
                    server,
                    requests: 0,
                });
                continue;
            }
            let server = walk.visit.as_ref()?.server.clone();
            let flags = flags(&server);
            let mut targets = Vec::with_capacity(allowed);
            while targets.len() < allowed {
                let Some(file_hash) = walk.files.pop_front() else {
                    break;
                };
                // A file gone or gated since this pass began is passed over,
                // a large file toward a server without large-file UDP too
                // ("UDP Request for sources on a large file ignored").
                targets.extend(files.iter().find(|target| {
                    target.file_hash() == file_hash
                        && (!is_large_file(target.file_size()) || flags.supports_large_files())
                }));
            }
            if walk.files.is_empty() {
                // Every file was asked: the next pass starts on the next server.
                walk.files = queue_of(files);
                walk.visit = None;
            } else if let Some(visit) = walk.visit.as_mut() {
                visit.requests += targets.len();
            }
            if !targets.is_empty() {
                self.sent = Some(now);
                return Some(UdpAsk {
                    server,
                    flags,
                    targets,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
