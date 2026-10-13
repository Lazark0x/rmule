//! Session **establishment** and the server switch: the one dial + login path,
//! the operator's `connect_to_server` (ADR-0093, "Connecting is the operator's
//! act"). It ends the live session and reports the `Disconnected(old)` →
//! `Connecting(new)` → `Connected`/`ConnectFailed` trail; no activity dials,
//! each rides [`SharedServerSession::live_session`] or waits for one. The IP-filter gate refuses a filtered
//! (or filtered-after-resolve) server before any dial; each dial's link,
//! plain or obfuscated, is chosen by the Obfuscation Policy as it starts,
//! and a failed obfuscated attempt earns one plain one under `Requested`
//! (`link`). The login's products are projected into the peer handshake
//! context peers are dialed with.

use std::net::Ipv4Addr;

use rmule_ed2k::{Ed2kEvent, ServerGrants};
use rmule_net::ed2k::{ConnectOptions as Ed2kConnectOptions, Connection as Ed2kConnection};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    AddressFamily, ClientId, ClientIdentity, Ipv4Endpoint, PeerEndpoint, ServerEndpoint, UserHash,
};

use super::multiplexer::{ServerSession, SessionSinks};
use super::{ServerSessionHandle, SharedServerSession};
use crate::DownloadFailure;
use crate::address_learning::SocketRole;
use crate::ip_filter::SharedIpFilter;
use crate::own_identity::SharedOwnIdentity;
use crate::server_list::ServerFacts;
use crate::service::{
    DialFailure, IdAssignment, LoginClaim, LoginCloseCause, LoginLink, LoginStep,
    ServerConnectFailure,
};

/// Establish the session at `server` now — aMule's "connect to
/// the selected server", a standing link the operator asks for and the only
/// login rmule makes (ADR-0095, "Connecting is the operator's act"; the actor
/// binds the listener and waits for its mapping before calling this).
///
/// Under one slot lock, **a live session is ended before the new one is
/// dialed**, and waited for, so the trail is always `Disconnected(old)` →
/// `Connecting(new)` → `Connected`/`ConnectFailed`, and the connected marker is
/// never briefly the wrong server.
pub(crate) async fn connect_to_server(
    shared: &SharedServerSession,
    server: ServerEndpoint,
    identity: ClientIdentity,
    ip_filter: &SharedIpFilter,
) -> Result<ServerSessionHandle, DownloadFailure> {
    let mut slot = shared.slot().lock().await;
    let leaving = match slot.take() {
        Some(live) => {
            let left = live.server().clone();
            live.disconnect().await;
            // A session to the same server is re-made, not left.
            (left != server).then_some(left)
        }
        None => None,
    };
    establish_into(shared, &mut slot, server, identity, ip_filter, leaving).await
}

/// Dial, log in, spawn the session task and install it in the held `slot`,
/// then bump the **Session Generation** so every follower meets it.
async fn establish_into(
    shared: &SharedServerSession,
    slot: &mut Option<ServerSessionHandle>,
    server: ServerEndpoint,
    identity: ClientIdentity,
    ip_filter: &SharedIpFilter,
    leaving: Option<ServerEndpoint>,
) -> Result<ServerSessionHandle, DownloadFailure> {
    let own = shared.own_identity().clone();
    let facts = shared.server_facts().clone();
    // A filtered server is refused before the connect (aMule
    // `CServerSocket::OnHostnameResolved`, `ServerSocket.cpp:737`: "Server IP
    // is filtered. Not connecting."). aMule's check runs on the *resolved*
    // address — its DynIP names are exempt only at add time — so a DNS-named
    // server is resolved here first and every resolved IPv4 checked. The
    // connect layer re-resolves on its own; that drift is benign (aMule
    // re-resolves per connect too, and a range blocklist catches rotation
    // inside a blocked range). An unresolvable host skips the check and fails
    // in the connect on its own terms; the resolve is skipped entirely while
    // the server gate is off or the table holds no ranges, so the common
    // empty-filter path costs no extra DNS round trip.
    let resolved: Vec<Ipv4Addr> = match server.host().parse::<Ipv4Addr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            let gate_armed = ip_filter
                .read()
                .expect("ip filter lock")
                .has_server_blocks();
            if gate_armed {
                match tokio::net::lookup_host((server.host(), server.port())).await {
                    Ok(addrs) => addrs
                        .filter_map(|addr| match addr {
                            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                            std::net::SocketAddr::V6(_) => None,
                        })
                        .collect(),
                    Err(_) => Vec::new(),
                }
            } else {
                Vec::new()
            }
        }
    };
    let server_filtered = {
        let filter = ip_filter.read().expect("ip filter lock");
        resolved.iter().any(|ip| filter.is_filtered_server(*ip))
    };
    if server_filtered {
        tracing::warn!(
            host = %server.host(),
            port = server.port(),
            "server IP is filtered; not connecting"
        );
        report_connect_failure(&facts, &server, ServerConnectFailure::Filtered).await;
        return Err(DownloadFailure::ServerFiltered);
    }
    facts.connecting(&server, leaving).await;
    // ADR-0087 §4.1: the login advertises our Known IPv6 only when the
    // Advertised Endpoints chooser has settled one — and then both signals
    // ride, because a server may gate on either.
    let advertised_ipv6 = shared.ipv6_advert().get();
    // ADR-0091: the login's `0xF9` is a claim that we can be punched, so it
    // rides only when the socket a punch would land on is really there — an
    // IPv4 client-UDP bind *and* its send half, without which the keepalive
    // that makes the claim true could never leave.
    let punch = shared.server_punch().clone();
    // One bind, two wire fields (ADR-0057): the sockets are unified, so both
    // halves name the same port — but the Kad half stays 0 unless a node is
    // actually running, which is the advert cell's fact and not the bind's
    // (aMule's `Kademlia::IsRunning() ? kadPort : 0`). The client-UDP half is
    // read at use, see `effective_client_udp_port` (ADR-0084).
    let udp_ports = punch.client_udp().and_then(|_| {
        crate::natt::server_punch::udp_ports_advert(
            effective_client_udp_port(own.addresses(), SocketRole::Udp),
            shared
                .udp_ports_advert()
                .get()
                .map(|advert| advert.kad_udp())
                .filter(|port| *port != 0),
        )
    });
    let our_hash = identity.user_hash();
    // The policy is read at each dial (ADR-0046), so a fallback dial follows
    // a change made while the first one failed.
    let mut policy = shared.obfuscation().get();
    let mut link = LoginLink::choose(policy, facts.obfuscation_tcp_port(&server));
    let (conn, client_id, grants, resolved) = loop {
        facts
            .login_step(&server, LoginStep::LinkChosen { link })
            .await;
        let plan = LoginPlan {
            link,
            policy,
            advertised_ipv6,
            udp_ports,
        };
        let reason = match establish(
            server.clone(),
            identity.clone(),
            plan,
            shared.login_timeout(),
            &own,
            &facts,
        )
        .await
        {
            Ok(established) => break established,
            Err(reason) => reason,
        };
        policy = shared.obfuscation().get();
        match link.after_failure(policy, reason) {
            Some(fallback) => link = fallback,
            None => {
                report_connect_failure(&facts, &server, reason).await;
                return Err(DownloadFailure::ServerDisconnected);
            }
        }
    };
    let server_ip = resolved.map(|addr| addr.ip());
    let over_ipv6 = resolved.is_some_and(|addr| addr.is_ipv6());
    // One of ADR-0084's three poll moments. A session is exactly when the
    // host's routing may have changed under us — a laptop that moved networks,
    // a link that came back — and the interface set is both a tier of its own
    // and the corroboration filter's evidence, so a stale one would judge the
    // server's reflection against addresses this host no longer holds.
    shared.refresh_interfaces();
    let handle = ServerSession::spawn(
        conn,
        client_id,
        SessionSinks {
            own,
            server: server.clone(),
            server_ip,
            facts: facts.clone(),
            ipv6_probe: shared.ipv6_probe().clone(),
            over_ipv6,
            punch: punch.clone(),
            grants,
            reach: shared.reach(),
            dial_backs: shared.dial_backs().clone(),
            tcp_port: identity.tcp_port(),
        },
    );
    *slot = Some(handle.clone());
    // The login is the only source of either half (ADR-0032): the id says
    // whether we are Low-ID, the server says whose hello names *ours*. Both
    // are published the moment the session exists and cleared as it ends, so
    // a reader never judges itself by a session that is gone.
    // The standard port, as the hello writes it: an aux-port login has just
    // re-ported the row, and aMule reports the port it lists, not the one it
    // dialed.
    let standard = facts.standard_endpoint_of(&server);
    shared
        .own_identity()
        .set_connected_session(Some(crate::own_identity::ConnectedSession {
            // The address the login actually reached, as aMule's
            // `GetCurrentServer()->GetIP()` is the resolved one; a DNS-named
            // server does not read 0.0.0.0 in our hellos.
            server: match resolved {
                Some(std::net::SocketAddr::V4(addr)) => {
                    Some(Ipv4Endpoint::new(*addr.ip(), standard.port()))
                }
                _ => connected_server_endpoint(&standard),
            },
            client_id,
        }));
    // After the self-facts, so a follower woken by the generation reads the
    // session's id and server, not the gap before them.
    shared.session_established();
    // IPv4 only, and by type: the punch is IPv4, and a session over IPv6
    // says nothing about our IPv4 mapping — so there is nothing to keep alive
    // and the chooser is never told the server can introduce us.
    if udp_ports.is_some()
        && let Some(std::net::SocketAddr::V4(server_addr)) = resolved
    {
        // The server's own port, not the one dialed: an obfuscated link
        // reached its obfuscation port, and the keepalive goes to the main
        // port's UDP sibling.
        let server = Ipv4Endpoint::new(*server_addr.ip(), server.port());
        spawn_natt_keepalive(punch, handle.clone(), PeerEndpoint::V4(server), our_hash);
    }
    // Last, and only once the session task exists: a consumer that reacts to
    // `Connected` by sending an activity command finds a session waiting.
    if let Err(error) = facts.connected(&server, client_id, grants).await {
        tracing::warn!(%error, "connected server's failure tally not absolved");
    }
    Ok(handle)
}

/// Keep the server's view of our client-UDP port true (ADR-0091): one `0x9F`
/// at once — so the server has *observed* our mapping before anyone can ask
/// to punch us — then one every
/// [`SERVER_KEEPALIVE_INTERVAL`](crate::natt::server_punch::SERVER_KEEPALIVE_INTERVAL),
/// for as long as this session lives. It leaves by the **client-UDP** send
/// half and no other: the port it arrives from is the one the server hands
/// out, so it must be the port a punch will land on.
///
/// The cadence is owned here, by the session, because the session is its
/// lifetime: a keepalive that outlived its login would keep a mapping warm for
/// a server that has forgotten us, and one that started late would leave a
/// window in which the server introduces us at a port it only guessed.
fn spawn_natt_keepalive(
    punch: crate::natt::server_punch::SharedServerPunch,
    session: ServerSessionHandle,
    server: PeerEndpoint,
    our_hash: UserHash,
) {
    let Some(tx) = punch.client_udp().cloned() else {
        return;
    };
    if crate::natt::server_punch::keepalive_send(server, &our_hash).is_none() {
        // An IPv6 session, or a port with no room for + 4: nothing to keep
        // alive, so nothing to claim either.
        return;
    }
    punch.go_live(&session);
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(crate::natt::server_punch::SERVER_KEEPALIVE_INTERVAL);
        while session.is_alive() {
            ticks.tick().await;
            let Some(send) = crate::natt::server_punch::keepalive_send(server, &our_hash) else {
                break;
            };
            if tx.send(send).await.is_err() {
                break;
            }
        }
    });
}

async fn report_connect_failure(
    facts: &ServerFacts,
    server: &ServerEndpoint,
    reason: ServerConnectFailure,
) {
    if let Err(error) = facts.connect_failed(server, reason).await {
        tracing::warn!(%error, "failed connect not counted against the server");
    }
}

/// What one dial's login states and how its link is opened.
#[derive(Clone, Copy)]
struct LoginPlan {
    /// Plain, or obfuscated to the server's obfuscation port.
    link: LoginLink,
    /// Our policy at this dial: the crypt flags the login states, whichever
    /// the link.
    policy: Option<rmule_net::peer::ObfuscationPolicy>,
    /// Our Known IPv6, when the Advertised Endpoints chooser settled one.
    advertised_ipv6: Option<std::net::Ipv6Addr>,
    /// The `0xF9` ports, when a punch could land.
    udp_ports: Option<rmule_ed2k::UdpPortsAdvert>,
}

/// Connect and log in once, returning the live connection plus what the login
/// assigned: the `client_id`, the whole `OP_IDCHANGE` extension projection
/// (ADR-0047) whose `public_ip` the caller publishes as a self-fact, and
/// **whether the connection runs over IPv6** — the gate on `OP_SERVERIDENT`'s
/// reflection (ADR-0087 §4.3). The only I/O in this module; the loop and the
/// handle stay sans-I/O and fakeable.
///
/// `login_timeout` arms the **session's own** login deadline (ADR-0044: the
/// deadline is session state, `login_deadline_elapsed`, not a driver timer and
/// not a `tokio::time::timeout` wrapped round this loop). So a server that
/// accepts the socket and then says nothing closes itself with
/// `CloseReason::LoginTimeout`, which this loop reads back as the typed
/// [`ServerConnectFailure::LoginTimedOut`] — the one fact that tells a caller
/// "the link is up, the server is mute" apart from "the dial failed".
async fn establish(
    server: ServerEndpoint,
    identity: ClientIdentity,
    plan: LoginPlan,
    login_timeout: std::time::Duration,
    own: &SharedOwnIdentity,
    facts: &ServerFacts,
) -> Result<
    (
        Ed2kConnection,
        ClientId,
        ServerGrants,
        Option<std::net::SocketAddr>,
    ),
    ServerConnectFailure,
> {
    let LoginPlan {
        link,
        policy,
        advertised_ipv6,
        udp_ports,
    } = plan;
    let options = Ed2kConnectOptions {
        obfuscation: policy.map(|policy| rmule_net::peer::ObfuscationConfig { policy }),
        obfuscated_port: link.obfuscated_port(),
        advertised_ipv6,
        udp_ports,
        login_timeout,
        ..Ed2kConnectOptions::default()
    };
    let tcp_port = identity.tcp_port();
    let mut conn =
        match Ed2kConnection::connect_with_options(server.clone(), identity, options).await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::info!(
                    host = %server.host(),
                    port = server.port(),
                    %error,
                    "server connect failed before the login"
                );
                let cause = dial_failure(&error);
                facts
                    .login_step(&server, LoginStep::DialFailed { cause })
                    .await;
                return Err(ServerConnectFailure::Unreachable);
            }
        };
    let resolved = conn.resolved_addr();
    let claim = LoginClaim {
        family: resolved.map(|addr| match addr {
            std::net::SocketAddr::V4(_) => AddressFamily::V4,
            std::net::SocketAddr::V6(_) => AddressFamily::V6,
        }),
        tcp_port,
        client_udp_port: udp_ports.map(|ports| ports.client_udp),
        kad_udp_port: udp_ports
            .map(|ports| ports.kad_udp)
            .filter(|port| *port != 0),
        advertised_ipv6,
    };
    // ADR-0046 "Test Connections": the server's High-ID port test may dial
    // plain until this login is answered or ends.
    let awaiting = resolved.map(|addr| {
        own.awaited_testers()
            .awaiting_login_from(addr.ip(), server.clone(), facts.clone())
    });
    if awaiting.is_some() {
        facts.login_step(&server, LoginStep::PortTestAwaited).await;
    }
    let answer = await_answer(&mut conn, &server, claim, own, facts).await;
    if let Some(awaiting) = awaiting {
        let arrived = awaiting.close();
        facts
            .login_step(&server, LoginStep::PortTestWindowClosed { arrived })
            .await;
    }
    answer.map(|(client_id, grants)| (conn, client_id, grants, resolved))
}

/// Read the login's events until it is answered or ends: the id and grants
/// the answer assigned, or why it failed.
async fn await_answer(
    conn: &mut Ed2kConnection,
    server: &ServerEndpoint,
    claim: LoginClaim,
    own: &SharedOwnIdentity,
    facts: &ServerFacts,
) -> Result<(ClientId, ServerGrants), ServerConnectFailure> {
    let server_ip = conn.resolved_addr().map(|addr| addr.ip());
    while let Some(event) = conn.next_event().await {
        match event {
            Ed2kEvent::LoginRequested { .. } => {
                facts
                    .login_step(server, LoginStep::LoginSent { claim })
                    .await;
            }
            Ed2kEvent::LoginAccepted {
                client_id,
                tcp_flags,
                facts: assigned,
            } => {
                // The IDCHANGE consumption (ADR-0047, feeding ADR-0046): the
                // login establishes our public IP, which is both the
                // crypt-ping precondition and the sender IP the peer-UDP send
                // key mixes in. The projection takes it from the assigned id
                // when that is High and from the server's reported address
                // when it is Low, so a login only leaves the send paths
                // plaintext when neither source yields an address.
                let address = own.addresses().observe_server_assigned(
                    client_id,
                    assigned.public_ip,
                    server_ip,
                );
                let grants = tcp_flags.map(ServerGrants::from).unwrap_or_default();
                facts.granted(server, client_id, tcp_flags, &assigned);
                let assignment = IdAssignment {
                    client_id,
                    address,
                    grants,
                };
                facts
                    .login_step(server, LoginStep::Answered { assignment })
                    .await;
                return Ok((client_id, grants));
            }
            Ed2kEvent::Disconnected {
                reason: rmule_ed2k::CloseReason::LoginTimeout,
            } => return Err(ServerConnectFailure::LoginTimedOut),
            Ed2kEvent::LoginRejected => {
                tracing::info!(host = %server.host(), port = server.port(), "server refused the login");
                return Err(ServerConnectFailure::LoginRefused);
            }
            Ed2kEvent::Disconnected { reason } => {
                tracing::info!(
                    host = %server.host(),
                    port = server.port(),
                    ?reason,
                    "server closed the link before answering the login"
                );
                let cause = LoginCloseCause::from(&reason);
                facts
                    .login_step(server, LoginStep::ClosedBeforeAnswer { cause })
                    .await;
                return Err(ServerConnectFailure::ClosedBeforeAnswer);
            }
            _ => {}
        }
    }
    Err(ServerConnectFailure::ClosedBeforeAnswer)
}

/// Why a dial did not come up, as the login step names it.
fn dial_failure(error: &rmule_net::ed2k::Ed2kNetError) -> DialFailure {
    use rmule_net::driver::DriverError;
    match error {
        rmule_net::ed2k::Ed2kNetError::Driver(DriverError::ConnectTimeout) => DialFailure::TimedOut,
        rmule_net::ed2k::Ed2kNetError::Driver(DriverError::Io(error)) => DialFailure::Os {
            kind: error.kind(),
            os_code: error.raw_os_error(),
        },
        rmule_net::ed2k::Ed2kNetError::CryptHandshake(error) => {
            DialFailure::CryptHandshake { kind: error.kind() }
        }
        _ => DialFailure::DriverEnded,
    }
}

/// The [`PeerHandshakeContext`] a peer dial presents over one lone server
/// session — a tool's, outside any core: the hello as **Self Reach** answers
/// it with that session live and nothing else known (ADR-0098), so its
/// **Presented Client ID** comes from the one owner every core hello reads.
/// The identity keeps none of the server-only login tags (ADR-0047).
///
/// `connected_server` is `Some` only when the server host is an IPv4 literal;
/// a DNS host resolves to `None`, which `PeerHelloBody` encodes as `0.0.0.0:0`
/// on the wire. The eD2k connection layer does not hand back the socket
/// address it resolved, so the unresolved case is logged here.
pub fn build_peer_handshake_context(
    client_id: ClientId,
    server: &ServerEndpoint,
    identity: &ClientIdentity,
) -> PeerHandshakeContext {
    let connected_server = connected_server_endpoint(server);
    if connected_server.is_none() {
        tracing::warn!(
            host = %server.host(),
            port = server.port(),
            "connected-server host is not an IPv4 literal; peer hello will encode connected_server as 0.0.0.0:0",
        );
    }
    let own = SharedOwnIdentity::default();
    own.set_connected_session(Some(crate::own_identity::ConnectedSession {
        server: connected_server,
        client_id,
    }));
    let reach = crate::reachability::SharedSelfReach::new(
        crate::KadReachLevel::published(crate::reachability::SharedKadVerdicts::default()),
        own,
        crate::natt::front::SharedNattFront::default(),
    );
    super::hello::live_peer_handshake_context(identity, &reach)
}

/// The literal-vs-DNS connected-server decision, owned in one place — replaces
/// the per-call-site `ipv4_server_endpoint` copies the orchestrator and serve
/// adapters each carried.
fn connected_server_endpoint(server: &ServerEndpoint) -> Option<Ipv4Endpoint> {
    server
        .host()
        .parse::<Ipv4Addr>()
        .ok()
        .map(|ip| Ipv4Endpoint::new(ip, server.port()))
}

/// The port `role`'s **Family Pair** holds *in IPv4*, or `None` when it holds
/// none — the bound families, never the configured selection (ADR-0084).
///
/// The `0xF9` advert's gate, and the reason a **Half-Bound Pair** needs no
/// second latch on this surface: a client-UDP pair that came up
/// on `::` alone contributes no IPv4 port here, so the tag is omitted
/// outright — and its absence is exactly what ed2k-server reads as "not a
/// punch target" (`FAIL_TARGET_NO_UDP`, ADR-0091). A zero port would be the
/// wrong shape: the tag's *presence* is the capability flag.
fn bound_ipv4_port(
    addresses: &crate::address_learning::SharedAddressLearning,
    role: SocketRole,
) -> Option<u16> {
    addresses
        .bind(role)
        .filter(|(families, _)| families.contains(&AddressFamily::V4))
        .map(|(_, port)| port)
}

/// The login's `0xF9` client-UDP port, read at use exactly like the hello's
/// (ADR-0084): [`bound_ipv4_port`] still gates whether a
/// punch target exists at all, but the value on the wire is Address
/// Learning's chooser answer for `role` — the external port once one is
/// learned, the bound port while nothing is — so a grant that lands after
/// the bind reaches the very next login, not just the next hello. aMule
/// keeps no login counterpart to cite here (`CT_EMULE_UDPPORTS` rides only
/// the hello, via `thePrefs::GetEffectiveUDPPort()`, `BaseClient.cpp:1062`,
/// `Preferences.h:217`); this tag is ed2k-server's own NAT-T extension
/// (`rmule-net/src/ed2k/options.rs`), and it now follows the same
/// effective-port rule the hello already established
/// ([`SharedUdpPortsAdvert::get`](crate::adapters::SharedUdpPortsAdvert::get)).
fn effective_client_udp_port(
    addresses: &crate::address_learning::SharedAddressLearning,
    role: SocketRole,
) -> Option<u16> {
    bound_ipv4_port(addresses, role)
        .map(|bound| addresses.advertised_v4_port(role).unwrap_or(bound))
}

#[cfg(test)]
mod tests;
