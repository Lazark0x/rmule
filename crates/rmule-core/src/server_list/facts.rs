//! The write side of **what happened with a server** — the one seam every
//! surface that reaches one reports its round trip to, so the durable failure
//! tally, the surfaced measurement and the emitted edge can never disagree
//! about the same trip. Also the publish discipline they share: every mutation
//! reads its list back and publishes it in one critical section on the level
//! ([`mutate_and_publish`]), so the published level is always a list the store
//! actually held.

use rmule_ed2k::{ServerGrants, ServerTcpFlags};
use rmule_primitives::{ClientId, Ed2kText, ServerEndpoint};

use crate::CoreError;
use crate::diagnostics::DiagnosticsState;
use crate::service::{CoreEvent, LoginStep, ServerConnectFailure, ServerConnectionEvent};

use super::{ManagedServer, ServerFigures, ServerListStore, SharedServerListStore};

/// Mutate the managed server list, then read it back and republish the level
/// in one critical section (ADR-0080).
///
/// The store handle carries no lock (ADR-0083): each mutation is its own
/// durable transaction, and the read-back plus publish is atomic on the level
/// ([`DiagnosticsState::publish_servers_from`]). Two writers (the actor's CRUD
/// arms and the update task) can interleave without the level ever settling
/// on a stale read: the read that lands last publishes last, and every read
/// follows its own mutation's commit.
pub(crate) fn mutate_and_publish<T>(
    store: &SharedServerListStore,
    diagnostics: &DiagnosticsState,
    mutate: impl FnOnce(&dyn ServerListStore) -> Result<T, CoreError>,
) -> Result<T, CoreError> {
    let outcome = mutate(&**store)?;
    diagnostics.publish_servers_from(|| store.servers())?;
    Ok(outcome)
}

/// The write side of **what happened with a server** (ADR-0080 §Dynamic server
/// facts, widened by the session-switch amendment) — the one seam every
/// surface that reaches a server writes through, so the durable tally, the
/// surfaced measurement and the reported edge can never disagree about the
/// same round trip.
///
/// Four surfaces hold one: the status-ping sweep ([`silent`](Self::silent)),
/// the server-UDP engine's challenge gate ([`answered`](Self::answered)), the
/// connected session's welcome burst ([`reported`](Self::reported) +
/// [`identified`](Self::identified)), and the session's own lifecycle
/// ([`connecting`](Self::connecting) → [`connected`](Self::connected) /
/// [`connect_failed`](Self::connect_failed) → [`disconnected`](Self::disconnected)).
/// Each method is one store critical section that ends before any I/O — the
/// lock discipline the on-demand list update established.
///
/// The lifecycle half writes the level *and* emits the edge here rather than
/// in the actor, because a session is established from four places (the
/// operator's connect, a search, a download's source lookup, the serve
/// announce) and only one of them is an actor arm. Writing both from the one
/// seam is what keeps `connected_server` from ever disagreeing with the trail.
///
/// A store error is the caller's to log, not to act on: none of these writes
/// is load-bearing for the wire, and a sweep that cannot record a tally must
/// still ping.
#[derive(Clone, Default)]
pub(crate) struct ServerFacts {
    /// The list every write lands in. `None` is the unwired sink an
    /// [`SharedServerSession`](crate::server_session) falls back to before the
    /// actor installs its own trio: there is no list to move, so a write is a
    /// no-op and [`listed`](Self::listed) is empty — a throwaway store would
    /// only make that silence look like a fact somebody keeps.
    store: Option<SharedServerListStore>,
    diagnostics: DiagnosticsState,
    /// Where the lifecycle edges go. `None` for a facts seam with no actor
    /// behind it (the adapter unit tests), which reports its level and its
    /// tally and emits nothing.
    ///
    /// A **weak** sender, because this seam outlives no actor: two of its
    /// holders (the server-UDP engine and the status sweep) are tasks that run
    /// for as long as the process does, and a strong clone in either would keep
    /// the event channel open forever — [`Core::shutdown`](crate::Core::shutdown)
    /// drains until the last sender is gone. Once the actor is down there is
    /// nobody left to hear an edge, so failing to upgrade is exactly right.
    events: Option<tokio::sync::mpsc::WeakSender<CoreEvent>>,
}

impl ServerFacts {
    pub(crate) fn new(
        store: SharedServerListStore,
        diagnostics: DiagnosticsState,
        events: Option<tokio::sync::mpsc::WeakSender<CoreEvent>>,
    ) -> Self {
        Self {
            store: Some(store),
            diagnostics,
            events,
        }
    }

    /// A seam with no list behind it that reports its events to `events`.
    #[cfg(test)]
    pub(crate) fn reporting_to(events: &tokio::sync::mpsc::Sender<CoreEvent>) -> Self {
        Self {
            store: None,
            diagnostics: DiagnosticsState::new(),
            events: Some(events.downgrade()),
        }
    }

    /// Mutate the list and republish, or do nothing at all when this seam has
    /// no list behind it.
    fn write<T: Default>(
        &self,
        mutate: impl FnOnce(&dyn ServerListStore) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(T::default());
        };
        mutate_and_publish(store, &self.diagnostics, mutate)
    }

    /// The list as the store holds it right now — the sweep's per-tick walk
    /// source, so a server added since the last tick joins the sweep and a
    /// removed one leaves it.
    pub(crate) fn listed(&self) -> Result<Vec<ManagedServer>, CoreError> {
        self.store
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |store| store.servers())
    }

    /// A status ping to `endpoint` went unanswered, and a ping near it was
    /// answered, so the silence is the server's (ADR-0052, the offline guard):
    /// one more failure. aMule counts at send (`ServerList.cpp:351`); rmule
    /// counts at the verdict, so a network outage moves no tally.
    pub(crate) async fn silent(&self, endpoint: &ServerEndpoint) -> Result<(), CoreError> {
        self.count_a_failure(endpoint).await
    }

    /// `row`'s host name answered `address` (ADR-0052's amendment): a
    /// run-time fact beside the row, published with it and projected into the
    /// swept list at once.
    pub(crate) fn resolved(&self, row: &ServerEndpoint, address: super::ResolvedAddress) {
        self.diagnostics.record_resolved_address(row, address);
    }

    /// `row`'s resolved address while it may be reused without asking the
    /// name again (aMule's `DNS_SOLVE_TIME`).
    pub(crate) fn fresh_address(&self, row: &ServerEndpoint) -> Option<std::net::Ipv4Addr> {
        self.diagnostics.fresh_resolved_address(row)
    }

    /// The listed row a reply from `endpoint` is about: the row whose name
    /// resolved to it, else the address itself.
    pub(crate) fn row_at(
        &self,
        endpoint: rmule_primitives::Ipv4Endpoint,
    ) -> Option<ServerEndpoint> {
        self.diagnostics.listed_row_at(endpoint)
    }

    /// The listed server a datagram from `udp_src` comes from by the
    /// obfuscation UDP port its row saved, with that row's crypt facts and
    /// UDP flags (ADR-0052's amendment).
    pub(crate) fn saved_udp_crypt_at(
        &self,
        udp_src: rmule_primitives::Ipv4Endpoint,
    ) -> Option<(
        rmule_primitives::Ipv4Endpoint,
        super::ServerUdpCrypt,
        Option<rmule_ed2k::ServerUdpFlags>,
    )> {
        self.diagnostics.saved_udp_crypt_at(udp_src)
    }

    /// Whether the Status Ping Sweep hears servers at all: `false` once it
    /// dropped a silence no answer near it vouched for, `true` again at the
    /// next answer. A level, so the operator is told once, not per silence.
    pub(crate) fn heard_from_servers(&self, heard: bool) {
        self.diagnostics.set_status_sweep_unheard(!heard);
    }

    /// What the connected session `endpoint` was told of the share set
    /// (ADR-0099): a level, so the operator reads it off the row it names.
    pub(crate) fn shares_told(
        &self,
        endpoint: &ServerEndpoint,
        shares: crate::diagnostics::SharesToServer,
    ) {
        self.diagnostics.set_share_announcement(endpoint, shares);
    }

    /// The policy servers are judged under now (ADR-0052).
    pub(crate) fn policy(&self) -> super::ServerPolicy {
        self.diagnostics.server_policy()
    }

    /// aMule's `AddFailedCount`: one more consecutive failure to reach
    /// `endpoint`. Shared by the sweep's silent ping and the failed
    /// TCP connect, because aMule keeps **one** `m_failedcount` per server and
    /// both `CServerList::ServerStats` and `CServerConnect::ConnectionFailed`
    /// move it. An unlisted endpoint is left alone — the seam reports that as
    /// `false`, which nothing here has to act on.
    ///
    /// One step at the seam, not a list scan plus a write-back: the store owns
    /// the increment (`ServerListStore::count_server_failure`) because only it
    /// can read the row and write it in one transaction.
    async fn count_a_failure(&self, endpoint: &ServerEndpoint) -> Result<(), CoreError> {
        self.write(|store| {
            store.count_server_failure(endpoint)?;
            Ok(())
        })
    }

    /// aMule's `ResetFailedCount`: `endpoint` was reached, so the consecutive
    /// tally is over. Shared by the answered ping and the accepted login.
    async fn absolve(&self, endpoint: &ServerEndpoint) -> Result<(), CoreError> {
        self.write(|store| {
            store.set_server_fail_count(endpoint, 0)?;
            Ok(())
        })
    }

    /// `endpoint` answered a status ping in `ping` with `status` (aMule's
    /// `SetPing` / `SetUserCount` / `SetFileCount` / the limits /
    /// `SetLastPingedTime` / `ResetFailedCount` on a challenge-matched
    /// `0x97`). The figures are the row's, dated now; the reset is what
    /// makes the tally a *consecutive* one, and it revives a dead server.
    /// The answer's UDP crypt facts, learned while our public IPv4 was
    /// `key_ip`, replace what an earlier answer said — cleared by a body that
    /// carries none, as aMule zeroes them (`ServerUDPSocket.cpp:199-232`).
    pub(crate) async fn answered(
        &self,
        endpoint: &ServerEndpoint,
        ping: std::time::Duration,
        status: &rmule_ed2k::GlobServStatRes,
        key_ip: Option<std::net::Ipv4Addr>,
    ) -> Result<(), CoreError> {
        let crypt = super::ServerUdpCrypt::from_status(status, key_ip);
        self.write(|store| store.set_server_udp_crypt(endpoint, crypt))?;
        let now = super::unix_seconds(std::time::SystemTime::now());
        self.edit_figures(endpoint, |figures| {
            let figures = figures.get_or_insert_with(|| ServerFigures::answered(now));
            figures.answered_at = now;
            figures.ping = Some(ping);
            figures.users = Some(status.users());
            figures.files = Some(status.files());
            // The limits ride a longer body; an older server's shorter one
            // leaves what an earlier answer said.
            figures.soft_files = status.soft_files().or(figures.soft_files);
            figures.hard_files = status.hard_files().or(figures.hard_files);
            figures.udp_flags = status.udp_flags().or(figures.udp_flags);
        })?;
        self.absolve(endpoint).await
    }

    /// The connected server reported its own load in the login welcome burst
    /// (`OP_SERVERSTATUS`). Counts only — a TCP session measures no UDP ping,
    /// and reaching a server over TCP says nothing about the UDP port the
    /// failure tally is about, so neither the ping nor the tally moves. Nor
    /// does the time of the last answer, as in aMule, whose `ST_LASTPING` is
    /// the status ping's: figures that had none are dated now.
    pub(crate) fn reported(&self, endpoint: &ServerEndpoint, users: u32, files: u32) {
        let now = super::unix_seconds(std::time::SystemTime::now());
        let written = self.edit_figures(endpoint, |figures| {
            let figures = figures.get_or_insert_with(|| ServerFigures::answered(now));
            figures.users = Some(users);
            figures.files = Some(files);
        });
        if let Err(error) = written {
            tracing::warn!(%error, "server status report not recorded in the list");
        }
    }

    /// A server named its version in a tagged `0xA3` description reply
    /// (ADR-0068): kept with its figures, which it does not re-date —
    /// a description is not a status answer.
    pub(crate) fn described(&self, endpoint: &ServerEndpoint, version: String) {
        let written = self.edit_figures(endpoint, |figures| {
            if let Some(figures) = figures.as_mut() {
                figures.version = Some(version.clone());
            }
        });
        if let Err(error) = written {
            tracing::warn!(%error, "server version not recorded in the list");
        }
    }

    /// Change `endpoint`'s figures in one store transaction and republish.
    fn edit_figures(
        &self,
        endpoint: &ServerEndpoint,
        mut edit: impl FnMut(&mut Option<ServerFigures>),
    ) -> Result<(), CoreError> {
        self.write(|store| {
            store.edit_server_figures(endpoint, &mut edit)?;
            Ok(())
        })
    }

    /// The connected server named itself in the login welcome burst
    /// (`OP_SERVERIDENT`). Folded into the listed row through the one merge
    /// primitive, so a server's own name reaches the list exactly as a
    /// downloaded one does — and an absent tag changes nothing, matching
    /// aMule's per-field `SetListName` / `SetDescription` on that packet.
    ///
    /// A server that is not listed is left unlisted: aMule updates the row it
    /// finds and adds nothing on this packet.
    pub(crate) async fn identified(
        &self,
        endpoint: &ServerEndpoint,
        name: Option<Ed2kText>,
        description: Option<Ed2kText>,
    ) -> Result<(), CoreError> {
        if name.is_none() && description.is_none() {
            return Ok(());
        }
        self.write(|store| {
            let Some(mut fresh) = store
                .servers()?
                .into_iter()
                .find(|row| &row.endpoint == endpoint)
            else {
                return Ok(());
            };
            if let Some(name) = name {
                fresh.name = name;
            }
            if let Some(description) = description {
                fresh.description = description;
            }
            store.merge_server(fresh)?;
            Ok(())
        })
    }

    /// A dial to `endpoint` is starting. Reports the intent and
    /// nothing else: no level moves until the wire answers, so a consumer that
    /// only reads `connected_server` still sees the truth while this is in
    /// flight. `leaving` is the server whose session this connect just ended.
    pub(crate) async fn connecting(
        &self,
        endpoint: &ServerEndpoint,
        leaving: Option<ServerEndpoint>,
    ) {
        self.emit(ServerConnectionEvent::Connecting {
            server: endpoint.clone(),
            leaving,
        })
        .await;
    }

    /// The login to `endpoint` was accepted with `client_id` and `grants`: mark
    /// it as the connected server, with what it granted, and absolve its failure tally (aMule's
    /// `CServerConnect::ConnectionEstablished` → `ResetFailedCount`).
    ///
    /// The edge is emitted last, so a consumer reacting to it already sees
    /// both the marker and the cleared tally on the level.
    pub(crate) async fn connected(
        &self,
        endpoint: &ServerEndpoint,
        client_id: ClientId,
        grants: ServerGrants,
    ) -> Result<(), CoreError> {
        let absolved = self.absolve(endpoint).await;
        self.diagnostics
            .set_connected_server(Some((endpoint.clone(), grants)));
        self.emit(ServerConnectionEvent::Connected {
            server: endpoint.clone(),
            client_id,
        })
        .await;
        absolved
    }

    /// The connect to `endpoint` did not produce a session.
    ///
    /// Every failure to reach or log in is aMule's
    /// `CServerConnect::ConnectionFailed` → `AddFailedCount`: one more
    /// consecutive failure to reach this server, on the same tally an
    /// unanswered ping climbs — whether the dial or the login is what
    /// failed.
    /// [`ServerConnectFailure::LoginTimedOut`] counts the same: a server that
    /// accepts the socket and then never answers the login is unreachable in
    /// every way that matters to the tally. It is a separate *variant* because
    /// the two are distinguishable on the wire and a consumer acts differently
    /// on them, not because the tally treats them differently.
    /// [`ServerConnectFailure::Filtered`] leaves the tally alone — the dial
    /// never happened, so nothing was learned about whether the server is
    /// reachable; counting our own policy as the server's failure would make
    /// the number mean two things.
    pub(crate) async fn connect_failed(
        &self,
        endpoint: &ServerEndpoint,
        reason: ServerConnectFailure,
    ) -> Result<(), CoreError> {
        let counted = match reason {
            ServerConnectFailure::Unreachable
            | ServerConnectFailure::LoginRefused
            | ServerConnectFailure::ClosedBeforeAnswer
            | ServerConnectFailure::LoginTimedOut => self.count_a_failure(endpoint).await,
            ServerConnectFailure::Filtered => Ok(()),
        };
        self.emit(ServerConnectionEvent::ConnectFailed {
            server: endpoint.clone(),
            reason,
        })
        .await;
        counted
    }

    /// A mid-session `OP_IDCHANGE` re-projected the connected server's grants
    /// (ADR-0047): the level follows, so a menu gated on it never reads the
    /// login's stale answer, and the row keeps the new report.
    pub(crate) fn regranted(&self, endpoint: &ServerEndpoint, tcp_flags: Option<ServerTcpFlags>) {
        self.diagnostics
            .set_connected_server_grants(tcp_flags.map(ServerGrants::from).unwrap_or_default());
        self.granted(endpoint, tcp_flags);
    }

    /// `endpoint`'s `OP_IDCHANGE` named what it grants (ADR-0080, "What a
    /// server grants is durable"): the row keeps the word, dated now. A reply
    /// that carried no flags word grants nothing, and is kept as that.
    pub(crate) fn granted(&self, endpoint: &ServerEndpoint, tcp_flags: Option<ServerTcpFlags>) {
        let report = super::ServerGrantsReport {
            tcp_flags: tcp_flags.unwrap_or(ServerTcpFlags::from_bits(0)),
            reported_at: super::unix_seconds(std::time::SystemTime::now()),
        };
        if let Err(error) = self.write(|store| store.set_server_grants(endpoint, report)) {
            tracing::warn!(%error, "server grants not recorded in the list");
        }
    }

    /// The session with `endpoint` has ended — an operator switch, a server
    /// hang-up, or a link fault; the level does not distinguish them because
    /// the consumer's question is only whether a session exists.
    ///
    /// Called by the session task itself, after it has failed every parked
    /// request, so the marker never outlives the session it names.
    pub(crate) async fn disconnected(&self, endpoint: &ServerEndpoint) {
        self.diagnostics.set_connected_server(None);
        self.emit(ServerConnectionEvent::Disconnected {
            server: endpoint.clone(),
        })
        .await;
    }

    /// A step of the login to `endpoint` (ADR-0075, Run Log): reported, and
    /// no level moves.
    pub(crate) async fn login_step(&self, endpoint: &ServerEndpoint, step: LoginStep) {
        self.send(CoreEvent::ServerLogin {
            server: endpoint.clone(),
            step,
        })
        .await;
    }

    async fn emit(&self, event: ServerConnectionEvent) {
        self.send(CoreEvent::ServerConnection(event)).await;
    }

    async fn send(&self, event: CoreEvent) {
        let Some(events) = self
            .events
            .as_ref()
            .and_then(tokio::sync::mpsc::WeakSender::upgrade)
        else {
            return;
        };
        let _ = events.send(event).await;
    }
}

/// A facts seam over a list seeded with `servers`, plus the diagnostics level
/// it publishes into — the one harness every surface that writes through
/// [`ServerFacts`] is tested against (the sweep, the `0x97` gate, the session's
/// welcome burst), so all three are asserted on the same surfaced row.
#[cfg(test)]
pub(crate) fn test_facts(servers: &[ServerEndpoint]) -> (ServerFacts, DiagnosticsState) {
    let store = crate::DurableAppConfig::new(
        crate::open_durable_store_in_memory().expect("the in-memory store opens"),
    );
    for endpoint in servers {
        store
            .merge_server(ManagedServer::listed(endpoint.clone()))
            .expect("seed the list");
    }
    let diagnostics = DiagnosticsState::new();
    // The level starts as the store holds it, exactly as the actor seeds it
    // before taking its first command.
    diagnostics.set_servers(store.servers().expect("the seeded list reads back"));
    (
        ServerFacts::new(std::sync::Arc::new(store), diagnostics.clone(), None),
        diagnostics,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(host: &str, port: u16) -> ServerEndpoint {
        ServerEndpoint::new(host, port).expect("valid endpoint")
    }

    /// A `0x97` body carrying `users`, `files` and the two file limits.
    fn status(users: u32, files: u32) -> rmule_ed2k::GlobServStatRes {
        let mut datagram = vec![0xE3, rmule_ed2k::Opcode::GlobServStatRes.as_u8()];
        for word in [0, users, files, 3000, 4000, 5000] {
            datagram.extend_from_slice(&u32::to_le_bytes(word));
        }
        rmule_ed2k::GlobServStatRes::decode_udp(&datagram).expect("a valid status body")
    }

    /// Facts arrive from the wire about whatever answers; the list stays the
    /// operator's. An unlisted server's ping, load or name adds no row —
    /// aMule updates the row it finds on these packets and adds nothing.
    #[tokio::test]
    async fn facts_about_an_unlisted_server_add_no_row() {
        let listed = endpoint("1.2.3.4", 4661);
        let stranger = endpoint("9.9.9.9", 4661);
        let (facts, diagnostics) = test_facts(&[listed]);

        facts.silent(&stranger).await.unwrap();
        facts
            .answered(
                &stranger,
                std::time::Duration::from_millis(7),
                &status(1, 2),
                None,
            )
            .await
            .unwrap();
        facts
            .identified(&stranger, Some(Ed2kText::from_utf8("Stranger")), None)
            .await
            .unwrap();

        let servers = diagnostics.snapshot().servers;
        assert_eq!(servers.len(), 1, "no phantom row appeared");
        assert_eq!(servers[0].server.endpoint, endpoint("1.2.3.4", 4661));
        assert_eq!(servers[0].ping, None, "the stranger's ping is not ours");
    }

    /// An answer is kept on the durable row, dated, so the snapshot
    /// shows it with its age and a restart reads it back; the limits ride
    /// with the counts.
    #[tokio::test]
    async fn an_answer_is_kept_on_the_row_dated() {
        let listed = endpoint("1.2.3.4", 4661);
        let (facts, diagnostics) = test_facts(std::slice::from_ref(&listed));
        facts
            .answered(
                &listed,
                std::time::Duration::from_millis(42),
                &status(10, 20),
                None,
            )
            .await
            .unwrap();

        let row = &diagnostics.snapshot().servers[0];
        assert_eq!(
            (row.ping, row.users, row.files),
            (
                Some(std::time::Duration::from_millis(42)),
                Some(10),
                Some(20)
            )
        );
        assert!(
            row.age
                .is_some_and(|age| age < std::time::Duration::from_secs(5))
        );
        let kept = facts.listed().unwrap()[0].figures.clone().expect("kept");
        assert_eq!((kept.soft_files, kept.hard_files), (Some(4000), Some(5000)));
    }

    /// What a server grants is kept on its row with when it said so: the
    /// login's TCP word, raw, and the status answer's UDP flags beside the
    /// figures — so the operator can judge a server before connecting.
    #[tokio::test]
    async fn what_a_server_grants_is_kept_on_its_row() {
        let listed = endpoint("198.51.100.44", 4661);
        let (facts, diagnostics) = test_facts(std::slice::from_ref(&listed));
        let never = &diagnostics.snapshot().servers[0];
        assert_eq!((never.server.grants, never.grants_age), (None, None));

        facts.granted(&listed, Some(ServerTcpFlags::from_bits(0x0000_0559)));
        let mut datagram = vec![0xE3, rmule_ed2k::Opcode::GlobServStatRes.as_u8()];
        for word in [0, 12, 34, 3000, 4000, 5000, 0x0000_073B] {
            datagram.extend_from_slice(&u32::to_le_bytes(word));
        }
        let status = rmule_ed2k::GlobServStatRes::decode_udp(&datagram).unwrap();
        facts
            .answered(&listed, std::time::Duration::from_millis(30), &status, None)
            .await
            .unwrap();

        let row = &diagnostics.snapshot().servers[0];
        let report = row.server.grants.expect("the login's report is kept");
        assert_eq!(report.tcp_flags.bits(), 0x0000_0559);
        assert!(report.grants().related_search);
        assert!(row.grants_age.is_some());
        assert_eq!(
            row.server
                .figures
                .as_ref()
                .and_then(|figures| figures.udp_flags)
                .map(rmule_ed2k::ServerUdpFlags::bits),
            Some(0x0000_073B)
        );
    }
}
