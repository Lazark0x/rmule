//! The **Awaited Testers** (ADR-0046 "Test Connections"): the
//! addresses a reachability test of ours is awaited from right now, which the
//! peer listener admits plain under `ObfuscationPolicy::Required`.
//!
//! aMule's `AwaitingTestFromIP || IsKadFirewallCheckIP`
//! (`EncryptedStreamSocket.cpp:388-390`), as two halves with one writer each:
//! - **the awaited server** — the server a login answer is awaited from,
//!   written by session establishment from the moment the dial is up until
//!   the login is answered or fails (aMule `CS_WAITFORLOGIN`,
//!   `ServerConnect.cpp:668-680`). Its High-ID port test dials in inside that
//!   window, before the login is answered.
//! - **the asked Kad helpers** — each contact a TCP firewall check was asked
//!   of, until its window lapses (aMule `AddKadFirewallRequest`,
//!   `ClientList.cpp:1307-1331`, 180 s), written by the Kad pump from the
//!   node's `ReachabilityCheckAsked`, dropped when a recheck starts (the node
//!   drops its windows then) and when the node stops.
//!
//! A mirrored level, not a query — the File-Known Predicate's shape: the accept pump reads it
//! synchronously per plain dial and never awaits the actor, the session or the Kad pump.
//!
//! The server's window also carries where its port test is reported (ADR-0075, Run Log): the
//! establishment reports the window opening and closing, the accept pump a connection from the
//! server arriving inside it, and the serve runtime how a test from it ended. A closed window is
//! remembered for [`LATE_TEST_MEMORY`], so a test that comes after it is reported as late rather
//! than lost among strangers — a server's and a Kad helper's alike, the helper's on the event bus
//! the core installs here, since it names no server to report through.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmule_net::peer::AwaitedTesters;
use rmule_primitives::ServerEndpoint;
use tokio::sync::mpsc::WeakSender;

use crate::server_list::ServerFacts;
use crate::service::{CoreEvent, LoginStep, PortTestLateAdmission};

/// The server a login answer is awaited from.
struct ServerWindow {
    /// The address its port test dials from.
    ip: IpAddr,
    /// The generation of the establishment that opened the window.
    generation: u64,
    /// Where the window's steps are reported.
    reporter: AwaitedServer,
    /// Whether a connection from `ip` arrived inside the window.
    arrived: bool,
}

/// How long a closed window is remembered, so a connection from its tester
/// after it is still known for a late test. A server tests while it answers
/// the login and a Kad helper as soon as it is asked, so a real test is late
/// by moments; the bound only keeps the memory from naming a tester for
/// good.
pub(crate) const LATE_TEST_MEMORY: Duration = Duration::from_secs(60);

/// A server window that closed, kept for [`LATE_TEST_MEMORY`].
struct ClosedWindow {
    /// The address its port test dials from.
    ip: IpAddr,
    /// Where a late test's steps are reported.
    reporter: AwaitedServer,
    /// When the window closed.
    closed_at: Instant,
}

/// The awaited server, as the port test's steps name it.
#[derive(Clone)]
pub(crate) struct AwaitedServer {
    endpoint: ServerEndpoint,
    facts: ServerFacts,
}

impl AwaitedServer {
    /// Report `step` of the login to this server.
    pub(crate) async fn report(&self, step: LoginStep) {
        self.facts.login_step(&self.endpoint, step).await;
    }
}

/// A Kad helper whose check window closed a moment ago, as its late test is
/// reported: the helper, how late, and where the event goes.
pub(crate) struct LateKadHelper {
    helper: Ipv4Addr,
    late_by: Duration,
    events: Option<WeakSender<CoreEvent>>,
}

impl LateKadHelper {
    /// Report the late test and what became of it.
    pub(crate) async fn report(self, admission: PortTestLateAdmission) {
        let Some(events) = self.events.as_ref().and_then(WeakSender::upgrade) else {
            return;
        };
        let _ = events
            .send(CoreEvent::KadHelperTestLate {
                helper: self.helper,
                late_by: self.late_by,
                admission,
            })
            .await;
    }
}

#[derive(Default)]
struct Awaited {
    /// The server a login answer is awaited from.
    server: Option<ServerWindow>,
    /// The last server window that closed.
    closed: Option<ClosedWindow>,
    /// Generations handed out, so an establishment only ever clears its own.
    generation: u64,
    /// Each asked Kad helper and the instant its window lapses; a lapsed one
    /// stays until the next ask moves it to `kad_closed`.
    kad: Vec<(Ipv4Addr, Instant)>,
    /// Each Kad helper whose window closed within [`LATE_TEST_MEMORY`], and
    /// when it closed.
    kad_closed: Vec<(Ipv4Addr, Instant)>,
    /// Where a late Kad helper test is reported; `None` until the core
    /// installs its bus, and on an adapter-level test cell. Weak, so this
    /// cell never holds the event channel open.
    events: Option<WeakSender<CoreEvent>>,
}

impl Awaited {
    /// Move every helper window closed by `now` — `closing_at` for one still
    /// open, its lapse for one already lapsed — into the memory, and forget
    /// what the memory has held long enough.
    fn close_kad_windows(&mut self, now: Instant, all: bool) {
        let mut open = Vec::with_capacity(self.kad.len());
        for (helper, until) in self.kad.drain(..) {
            if now < until && !all {
                open.push((helper, until));
            } else {
                tracing::debug!(%helper, "awaited testers: Kad helper left — its window closed");
                self.kad_closed.push((helper, until.min(now)));
            }
        }
        self.kad = open;
        self.kad_closed
            .retain(|(_, closed_at)| now.saturating_duration_since(*closed_at) < LATE_TEST_MEMORY);
    }
}

/// The cell itself — held by the session self-facts ([`SharedOwnIdentity`](crate::own_identity::SharedOwnIdentity)),
/// so establishment, the Kad pump and the serve adapter reach the one set.
/// A plain `std::sync::Mutex`: no section crosses an `.await`.
#[derive(Clone, Default)]
pub(crate) struct SharedAwaitedTesters(Arc<Mutex<Awaited>>);

/// The awaited server's term: dropping it ends the window, however the login
/// ended — answered, refused, timed out or its task gone.
pub(crate) struct AwaitingLogin {
    cell: SharedAwaitedTesters,
    generation: u64,
}

impl AwaitingLogin {
    /// End the window: whether a connection from the server arrived in it.
    pub(crate) fn close(self) -> bool {
        self.cell
            .lock()
            .server
            .as_ref()
            .is_some_and(|window| window.generation == self.generation && window.arrived)
    }
}

impl Drop for AwaitingLogin {
    fn drop(&mut self) {
        let mut awaited = self.cell.lock();
        if awaited
            .server
            .as_ref()
            .is_some_and(|window| window.generation == self.generation)
            && let Some(window) = awaited.server.take()
        {
            tracing::debug!(server = %window.ip, "awaited testers: server left — its login was answered or ended");
            awaited.closed = Some(ClosedWindow {
                ip: window.ip,
                reporter: window.reporter,
                closed_at: Instant::now(),
            });
        }
    }
}

impl SharedAwaitedTesters {
    fn lock(&self) -> std::sync::MutexGuard<'_, Awaited> {
        self.0.lock().expect("awaited-testers mutex")
    }

    /// A login to `endpoint`, reached at `server`, is sent and its answer
    /// awaited: the server's port test may dial plain until the returned term
    /// is closed or dropped, and its steps are reported through `facts`.
    pub(crate) fn awaiting_login_from(
        &self,
        server: IpAddr,
        endpoint: ServerEndpoint,
        facts: ServerFacts,
    ) -> AwaitingLogin {
        let mut awaited = self.lock();
        awaited.generation += 1;
        let generation = awaited.generation;
        awaited.server = Some(ServerWindow {
            ip: server,
            generation,
            reporter: AwaitedServer { endpoint, facts },
            arrived: false,
        });
        tracing::debug!(%server, "awaited testers: server entered — a login answer is awaited");
        AwaitingLogin {
            cell: self.clone(),
            generation,
        }
    }

    /// A connection from `ip` was accepted: when it is the awaited server's,
    /// the window records the arrival and names the server to report to.
    pub(crate) fn server_test_arrived(&self, ip: IpAddr) -> Option<AwaitedServer> {
        let mut awaited = self.lock();
        let window = awaited.server.as_mut().filter(|window| window.ip == ip)?;
        window.arrived = true;
        Some(window.reporter.clone())
    }

    /// A connection from `ip` came at `now`, outside every open window: when
    /// `ip` is the server whose window closed within [`LATE_TEST_MEMORY`], the
    /// server to report its late test to, and how long after the close it
    /// came.
    pub(crate) fn late_server_test(
        &self,
        ip: IpAddr,
        now: Instant,
    ) -> Option<(AwaitedServer, Duration)> {
        let awaited = self.lock();
        let closed = awaited.closed.as_ref().filter(|closed| closed.ip == ip)?;
        let late_by = now.saturating_duration_since(closed.closed_at);
        (late_by < LATE_TEST_MEMORY).then(|| (closed.reporter.clone(), late_by))
    }

    /// Where a late Kad helper test is reported: the core's event bus.
    pub(crate) fn install_events(&self, events: WeakSender<CoreEvent>) {
        self.lock().events = Some(events);
    }

    /// A connection from `ip` came at `now` while no check window of it is
    /// open: when `ip` is a Kad helper whose window closed within
    /// [`LATE_TEST_MEMORY`], its late test, with how long after the close it
    /// came.
    pub(crate) fn late_kad_test(&self, ip: IpAddr, now: Instant) -> Option<LateKadHelper> {
        let IpAddr::V4(helper) = ip else {
            return None;
        };
        let awaited = self.lock();
        let windows = awaited.kad.iter().filter(|(asked, _)| *asked == helper);
        if windows.clone().any(|(_, until)| now < *until) {
            return None;
        }
        let late_by = windows
            .chain(
                awaited
                    .kad_closed
                    .iter()
                    .filter(|(asked, _)| *asked == helper),
            )
            .map(|(_, closed_at)| now.saturating_duration_since(*closed_at))
            .min()?;
        (late_by < LATE_TEST_MEMORY).then(|| LateKadHelper {
            helper,
            late_by,
            events: awaited.events.clone(),
        })
    }

    /// A TCP firewall check was asked of `helper`; its connect-back may dial
    /// plain until `lapses`.
    pub(crate) fn kad_check_asked(&self, helper: Ipv4Addr, lapses: Instant) {
        let mut awaited = self.lock();
        let now = Instant::now();
        awaited.close_kad_windows(now, false);
        awaited.kad.push((helper, lapses));
        tracing::debug!(
            %helper,
            window_secs = lapses.saturating_duration_since(now).as_secs(),
            awaited = awaited.kad.len(),
            "awaited testers: Kad helper entered — a TCP check was asked of it"
        );
    }

    /// Every asked helper's window is gone: a recheck started, or the Kad
    /// node stopped — `why` says which, for the Run Log. Each is remembered
    /// as closed now, so a connect-back after it is known late.
    pub(crate) fn kad_checks_dropped(&self, why: &'static str) {
        self.kad_checks_dropped_at(why, Instant::now());
    }

    fn kad_checks_dropped_at(&self, why: &'static str, now: Instant) {
        let mut awaited = self.lock();
        if !awaited.kad.is_empty() {
            tracing::debug!(
                dropped = awaited.kad.len(),
                why,
                "awaited testers: every Kad helper left"
            );
        }
        awaited.close_kad_windows(now, true);
    }

    /// Whether a plain dial from `ip` at `now` is a test we await — strict
    /// `<` on a helper's window, as the node's own guard.
    pub(crate) fn awaits_at(&self, ip: IpAddr, now: Instant) -> bool {
        let awaited = self.lock();
        awaited
            .server
            .as_ref()
            .is_some_and(|window| window.ip == ip)
            || match ip {
                IpAddr::V4(v4) => awaited
                    .kad
                    .iter()
                    .any(|(helper, until)| *helper == v4 && now < *until),
                IpAddr::V6(_) => false,
            }
    }
}

impl AwaitedTesters for SharedAwaitedTesters {
    fn awaits_test_from(&self, ip: IpAddr) -> bool {
        self.awaits_at(ip, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    const HELPER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const STRANGER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

    fn login_to(cell: &SharedAwaitedTesters, ip: IpAddr) -> AwaitingLogin {
        let endpoint = ServerEndpoint::new(ip.to_string(), 4661).expect("endpoint");
        cell.awaiting_login_from(ip, endpoint, ServerFacts::default())
    }

    #[test]
    fn the_window_closes_saying_whether_the_servers_test_arrived_in_it() {
        let cell = SharedAwaitedTesters::default();
        let unanswered = login_to(&cell, SERVER);
        assert!(
            cell.server_test_arrived(STRANGER).is_none(),
            "a stranger is not the awaited server"
        );
        assert!(!unanswered.close(), "no test from the server arrived");

        let answered = login_to(&cell, SERVER);
        assert!(cell.server_test_arrived(SERVER).is_some());
        assert!(answered.close(), "the server's test arrived");
        assert!(
            cell.server_test_arrived(SERVER).is_none(),
            "a closed window names no server"
        );
    }

    #[test]
    fn the_awaited_server_is_admitted_only_while_its_login_is_unanswered() {
        let cell = SharedAwaitedTesters::default();
        let now = Instant::now();
        assert!(
            !cell.awaits_at(SERVER, now),
            "nothing awaited before a login"
        );
        let term = login_to(&cell, SERVER);
        assert!(cell.awaits_at(SERVER, now));
        assert!(!cell.awaits_at(STRANGER, now));
        drop(term);
        assert!(!cell.awaits_at(SERVER, now), "the answer closes the window");
    }

    /// A switch to another server opens its window before the abandoned
    /// establishment's term drops; that late drop must not close the new one.
    #[test]
    fn a_stale_login_term_does_not_close_a_later_servers_window() {
        let cell = SharedAwaitedTesters::default();
        let first = login_to(&cell, STRANGER);
        let _second = login_to(&cell, SERVER);
        drop(first);
        assert!(cell.awaits_at(SERVER, Instant::now()));
        assert!(!cell.awaits_at(STRANGER, Instant::now()));
    }

    #[test]
    fn a_closed_windows_server_is_known_late_for_a_bounded_time_and_never_admitted() {
        let cell = SharedAwaitedTesters::default();
        assert!(cell.late_server_test(SERVER, Instant::now()).is_none());
        let term = login_to(&cell, SERVER);
        assert!(
            cell.late_server_test(SERVER, Instant::now()).is_none(),
            "not late while its window is open"
        );
        drop(term);
        let closed = Instant::now();
        assert!(!cell.awaits_at(SERVER, closed), "late is never admitted");
        let (_, late_by) = cell
            .late_server_test(SERVER, closed + Duration::from_millis(1_500))
            .expect("the server whose window just closed");
        assert!(late_by >= Duration::from_millis(1_500) && late_by < LATE_TEST_MEMORY);
        assert!(cell.late_server_test(STRANGER, closed).is_none());
        assert!(
            cell.late_server_test(SERVER, closed + LATE_TEST_MEMORY)
                .is_none(),
            "the memory is bounded"
        );
    }

    #[test]
    fn an_asked_kad_helper_is_admitted_until_its_window_lapses() {
        let cell = SharedAwaitedTesters::default();
        let asked = Instant::now();
        let lapses = asked + Duration::from_secs(180);
        cell.kad_check_asked(HELPER, lapses);
        assert!(cell.awaits_at(IpAddr::V4(HELPER), asked));
        assert!(cell.awaits_at(IpAddr::V4(HELPER), lapses - Duration::from_millis(1)));
        assert!(!cell.awaits_at(IpAddr::V4(HELPER), lapses), "strict <");
        assert!(!cell.awaits_at(STRANGER, asked));
    }

    #[test]
    fn a_recheck_or_a_stop_drops_every_helpers_window() {
        let cell = SharedAwaitedTesters::default();
        let now = Instant::now();
        cell.kad_check_asked(HELPER, now + Duration::from_secs(180));
        cell.kad_checks_dropped("a recheck started");
        assert!(!cell.awaits_at(IpAddr::V4(HELPER), now));
    }

    #[test]
    fn a_lapsed_helpers_window_is_known_late_for_a_bounded_time_and_never_admitted() {
        let cell = SharedAwaitedTesters::default();
        let asked = Instant::now();
        let lapses = asked + Duration::from_secs(180);
        cell.kad_check_asked(HELPER, lapses);
        assert!(
            cell.late_kad_test(IpAddr::V4(HELPER), asked).is_none(),
            "not late while its window is open"
        );
        let later = lapses + Duration::from_millis(2_500);
        assert!(
            !cell.awaits_at(IpAddr::V4(HELPER), later),
            "late is never admitted"
        );
        let late = cell
            .late_kad_test(IpAddr::V4(HELPER), later)
            .expect("the helper whose window just lapsed");
        assert_eq!(late.late_by, Duration::from_millis(2_500));
        assert!(cell.late_kad_test(STRANGER, later).is_none());
        assert!(
            cell.late_kad_test(IpAddr::V4(HELPER), lapses + LATE_TEST_MEMORY)
                .is_none(),
            "the memory is bounded"
        );
    }

    /// A recheck drops the windows early: a connect-back after it is late by
    /// the time since the drop, and a helper asked again is awaited, not late.
    #[test]
    fn a_dropped_helper_is_late_from_the_drop_until_it_is_asked_again() {
        let cell = SharedAwaitedTesters::default();
        let asked = Instant::now();
        cell.kad_check_asked(HELPER, asked + Duration::from_secs(180));
        let dropped = asked + Duration::from_secs(10);
        cell.kad_checks_dropped_at("a recheck started", dropped);
        let late = cell
            .late_kad_test(IpAddr::V4(HELPER), dropped + Duration::from_secs(4))
            .expect("the helper whose window was dropped");
        assert_eq!(late.late_by, Duration::from_secs(4));
        cell.kad_check_asked(HELPER, Instant::now() + Duration::from_secs(180));
        assert!(
            cell.late_kad_test(IpAddr::V4(HELPER), Instant::now())
                .is_none(),
            "an open window again"
        );
    }

    /// The late test reaches the installed bus with the helper, how late, and
    /// what became of it.
    #[tokio::test]
    async fn a_late_helper_test_is_reported_on_the_installed_bus() {
        let cell = SharedAwaitedTesters::default();
        let (events_tx, mut events) = tokio::sync::mpsc::channel(4);
        cell.install_events(events_tx.downgrade());
        let lapsed = Instant::now();
        cell.kad_check_asked(HELPER, lapsed);
        let late = cell
            .late_kad_test(IpAddr::V4(HELPER), lapsed + Duration::from_millis(700))
            .expect("late");
        late.report(PortTestLateAdmission::Refused).await;
        let Some(CoreEvent::KadHelperTestLate {
            helper,
            late_by,
            admission,
        }) = events.recv().await
        else {
            panic!("a late Kad helper test");
        };
        assert_eq!(helper, HELPER);
        assert_eq!(late_by, Duration::from_millis(700));
        assert_eq!(admission, PortTestLateAdmission::Refused);
    }
}
