//! The **Family Pair** (ADR-0085): two sockets per role and port — one bound
//! `0.0.0.0`, one bound `::` with `IPV6_V6ONLY` — behind one pump that merges
//! them and speaks [`PeerEndpoint`].
//!
//! Two explicit sockets rather than one dual-stack `::` bind: a single
//! dual-stack socket behaves differently per OS (`bindv6only`, Windows
//! defaults) and leaks `::ffff:` mapped addresses into every path, so a
//! capture could not record the true family. With `IPV6_V6ONLY` set, a mapped
//! address never reaches rmule at all.
//!
//! Per-family enable is configuration. A family whose bind fails is reported
//! and simply absent — never fatal; only a pair with no family at all is an
//! error. What that absence *costs* is role-specific and stated once, by
//! [`PairRole::forfeits`] — never inferred at a consumer.

mod consequence;

pub use consequence::{Consequence, HalfBound, PairRole};

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rmule_primitives::{AddressFamily, Ipv4Endpoint, Ipv6Endpoint, PeerEndpoint};
use socket2::{Domain, Protocol, Socket, Type};

/// Which **Address Families** a role binds. The default binds both: the sockets are
/// symmetric even where nothing speaks IPv6 yet (ADR-0085).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FamilySelection {
    /// Bind the `0.0.0.0` socket.
    pub v4: bool,
    /// Bind the `::` socket, `IPV6_V6ONLY`.
    pub v6: bool,
}

impl Default for FamilySelection {
    fn default() -> Self {
        Self { v4: true, v6: true }
    }
}

impl FamilySelection {
    /// IPv4 only — the classic surface, and what a loopback test binds.
    #[must_use]
    pub const fn v4_only() -> Self {
        Self {
            v4: true,
            v6: false,
        }
    }

    /// Whether `family` is selected.
    #[must_use]
    pub const fn includes(self, family: AddressFamily) -> bool {
        match family {
            AddressFamily::V4 => self.v4,
            AddressFamily::V6 => self.v6,
        }
    }
}

/// What a Family Pair's binds did: the families that came up, and the ones
/// that refused, with why. A refusal is a diagnostic, not a failure — an
/// operator on an IPv4-only host loses the `::` socket and nothing else.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FamilyBinds {
    /// The families actually bound.
    pub bound: Vec<AddressFamily>,
    /// The families whose bind was refused: the family, the OS's
    /// `ErrorKind`, and the reason rendered. The kind rides alongside the
    /// message (not folded into it) because a caller whose *every* family
    /// refused needs a real `ErrorKind` to report — matching on
    /// `io::Error::kind()` must see `AddrInUse`, not a synthesized `Other`
    /// that erased it.
    pub refused: Vec<(AddressFamily, io::ErrorKind, String)>,
}

impl FamilyBinds {
    /// Whether `family` is present on this pair.
    #[must_use]
    pub fn holds(&self, family: AddressFamily) -> bool {
        self.bound.contains(&family)
    }
}

/// How many consecutive UDP receive errors [`ReceiveErrorBudget`] tolerates
/// before its caller must end its pump (the hot-loop defect class
/// applied to the receive arm: a closed/failed source ends a task, it never
/// busy-spins).
///
/// A small double digit: large enough that a burst from the ICMP-unreachable
/// family — `ConnectionRefused`/`ConnectionReset`, exactly the "network is
/// lossy" noise every UDP consumer here already tolerates — never trips it
/// (Windows, the one platform that reports a long run of them on an
/// unconnected socket, has them switched off at the bind by
/// [`rmule_winsock`]); small enough that a genuinely
/// dead socket ends its pump within `RECEIVE_ERROR_BUDGET *
/// RECEIVE_ERROR_BACKOFF` — a few hundred milliseconds, well under the "well
/// under a second" bar, rather than spinning forever.
pub const RECEIVE_ERROR_BUDGET: u32 = 32;

/// The pause [`ReceiveErrorBudget::record_error`]'s caller sleeps after a
/// *tolerated* error, and only then: a receive error returns immediately (no
/// natural network delay backs it, unlike a real empty socket), so retrying
/// in a tight loop while still under budget would hot-spin exactly as hard as
/// the exhausted case must not. Once the budget is exhausted the caller ends
/// at once — there is nothing left to back off for.
pub const RECEIVE_ERROR_BACKOFF: Duration = Duration::from_millis(5);

/// What one [`ReceiveErrorBudget::record_error`] call tells its caller to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveErrorOutcome {
    /// Still under [`RECEIVE_ERROR_BUDGET`]: sleep [`RECEIVE_ERROR_BACKOFF`]
    /// and retry the receive.
    Tolerated,
    /// [`RECEIVE_ERROR_BUDGET`] consecutive errors with no successful receive
    /// between them: the socket is dead, not merely lossy. End the pump now,
    /// naming the last error's kind and how many errors ran in a row.
    Exhausted {
        /// The most recent receive error's kind.
        kind: io::ErrorKind,
        /// How many consecutive errors preceded this one (inclusive).
        consecutive: u32,
    },
}

/// A consecutive-error counter for one datagram pump's receive side, shared
/// by every site that must tell a lossy network (transient errors, tolerated
/// forever) from a dead socket (a run of them, which must end the pump) —
/// the Kad driver's transport arm, the client-UDP and server-UDP runtime
/// transports, and this module's own [`UdpFamilyPair::recv`].
///
/// One instance per pump, held across calls: a successful receive resets it,
/// so only *consecutive* failures count.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReceiveErrorBudget {
    consecutive: u32,
}

impl ReceiveErrorBudget {
    /// A fresh budget: no errors observed yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { consecutive: 0 }
    }

    /// Record a receive that produced a datagram (whatever its contents):
    /// whatever streak was building is over.
    pub fn record_success(&mut self) {
        self.consecutive = 0;
    }

    /// Record one receive error of `kind`. See [`ReceiveErrorOutcome`] for
    /// what the caller does with the result.
    #[must_use]
    pub fn record_error(&mut self, kind: io::ErrorKind) -> ReceiveErrorOutcome {
        self.consecutive += 1;
        if self.consecutive >= RECEIVE_ERROR_BUDGET {
            ReceiveErrorOutcome::Exhausted {
                kind,
                consecutive: self.consecutive,
            }
        } else {
            ReceiveErrorOutcome::Tolerated
        }
    }
}

/// A role's two datagram sockets behind one pump: [`Self::recv`] merges them
/// and names each datagram's true family, [`Self::send_to`] picks the socket
/// the destination's family needs.
pub struct UdpFamilyPair {
    v4: Option<tokio::net::UdpSocket>,
    v6: Option<tokio::net::UdpSocket>,
    port: u16,
    binds: FamilyBinds,
}

impl UdpFamilyPair {
    /// Bind `port` (0 = an OS-assigned ephemeral port) in every selected
    /// family. Both sockets land on the **same** port: an ephemeral bind
    /// resolves on the first family to come up and the second follows it, so
    /// one advertised port number stays true for both.
    ///
    /// # Errors
    /// Only when no selected family bound at all — a role with no socket
    /// cannot serve.
    pub async fn bind(port: u16, selection: FamilySelection) -> io::Result<Self> {
        let (v4, v6, resolved, binds) = bind_pair(port, selection, bind_udp)?;
        if binds.bound.is_empty() {
            return Err(refused_every_family(&binds));
        }
        Ok(Self {
            v4: v4.map(tokio::net::UdpSocket::from_std).transpose()?,
            v6: v6.map(tokio::net::UdpSocket::from_std).transpose()?,
            port: resolved,
            binds,
        })
    }

    /// Bind one literal address — a loopback socket, or an operator pinning
    /// one interface, where the address is the point and there is no second
    /// family to pair with.
    ///
    /// # Errors
    /// Whatever the bind returned.
    pub async fn bind_literal(addr: SocketAddr) -> io::Result<Self> {
        let family = match addr {
            SocketAddr::V4(_) => AddressFamily::V4,
            SocketAddr::V6(_) => AddressFamily::V6,
        };
        let (socket, port) = bind_udp(addr)?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        let (v4, v6) = match family {
            AddressFamily::V4 => (Some(socket), None),
            AddressFamily::V6 => (None, Some(socket)),
        };
        Ok(Self {
            v4,
            v6,
            port,
            binds: FamilyBinds {
                bound: vec![family],
                refused: Vec::new(),
            },
        })
    }

    /// The port both sockets share — the truth any advertisement derives from.
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.port
    }

    /// What the pair's binds did.
    #[must_use]
    pub const fn binds(&self) -> &FamilyBinds {
        &self.binds
    }

    /// Send one datagram to `peer` on its own family's socket. A family this
    /// pair never bound is an error, not a silent drop — the caller chose the
    /// destination.
    ///
    /// # Errors
    /// [`io::ErrorKind::Unsupported`] when the peer's family is absent, or
    /// whatever the send itself returned; a short write is an error.
    pub async fn send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<()> {
        let socket = self.socket(peer.family()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("this pair bound no {} socket", peer.family()),
            )
        })?;
        let sent = socket
            .send_to(datagram, SocketAddr::new(peer.ip(), peer.port()))
            .await?;
        if sent != datagram.len() {
            return Err(io::Error::other("short UDP datagram write"));
        }
        Ok(())
    }

    /// [`send_to`](Self::send_to) as a `poll`, for a caller whose own send is
    /// a `poll_*` rather than a future — the NAT-T uTP engine's `Transport`
    /// seam (ADR-0091), which hands rmule a `&mut Context` and no `await`.
    ///
    /// # Errors
    /// [`io::ErrorKind::Unsupported`] when the peer's family is absent, else
    /// whatever the send returned. A short write is the caller's to notice:
    /// this returns the byte count the socket accepted, as `poll_send_to` does.
    pub fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        peer: PeerEndpoint,
        datagram: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let Some(socket) = self.socket(peer.family()) else {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("this pair bound no {} socket", peer.family()),
            )));
        };
        socket.poll_send_to(cx, datagram, SocketAddr::new(peer.ip(), peer.port()))
    }

    /// [`send_to`](Self::send_to) without awaiting anything — the shape a
    /// caller with neither a future nor a `Context` needs (`quinn`'s
    /// `AsyncUdpSocket::try_send`, ADR-0091).
    ///
    /// # Errors
    /// [`io::ErrorKind::Unsupported`] when the peer's family is absent,
    /// [`io::ErrorKind::WouldBlock`] when the socket buffer is full, else
    /// whatever the send returned.
    pub fn try_send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
        let socket = self.socket(peer.family()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("this pair bound no {} socket", peer.family()),
            )
        })?;
        socket.try_send_to(datagram, SocketAddr::new(peer.ip(), peer.port()))
    }

    /// The next datagram from either socket, with the endpoint it truly came
    /// from. `scratch` is the caller's reused receive buffer — one pump owns
    /// the receive side, so the buffer need not be per-datagram.
    ///
    /// # Errors
    /// Whatever the underlying receive returned.
    pub async fn recv(&self, scratch: &mut [u8]) -> io::Result<(usize, PeerEndpoint)> {
        loop {
            // Select on readiness rather than on two receives: one buffer, one
            // pump, no per-datagram allocation, and no second scratch to keep
            // in step with the first.
            let socket = match (&self.v4, &self.v6) {
                (Some(v4), Some(v6)) => tokio::select! {
                    ready = v4.readable() => { ready?; v4 }
                    ready = v6.readable() => { ready?; v6 }
                },
                (Some(only), None) | (None, Some(only)) => {
                    only.readable().await?;
                    only
                }
                // `bind` refuses to build a pair with no socket.
                (None, None) => return Err(refused_every_family(&self.binds)),
            };
            match socket.try_recv_from(scratch) {
                Ok((len, from)) => return Ok((len, endpoint_of(from))),
                // A readiness race with the other arm: the datagram went to
                // whichever socket the select did not pick. Wait again.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }

    const fn socket(&self, family: AddressFamily) -> Option<&tokio::net::UdpSocket> {
        match family {
            AddressFamily::V4 => self.v4.as_ref(),
            AddressFamily::V6 => self.v6.as_ref(),
        }
    }
}

/// A socket address as the endpoint it names. The conversion lives here, at
/// the socket edge, and nowhere else (ADR-0085): a `PeerEndpoint` carries no
/// flow info or scope id because neither is a wire value.
#[must_use]
pub fn endpoint_of(addr: SocketAddr) -> PeerEndpoint {
    match addr {
        SocketAddr::V4(addr) => PeerEndpoint::V4(Ipv4Endpoint::new(*addr.ip(), addr.port())),
        SocketAddr::V6(addr) => PeerEndpoint::V6(Ipv6Endpoint::new(*addr.ip(), addr.port())),
    }
}

/// The wildcard address `family` binds, at `port`.
#[must_use]
pub const fn wildcard(family: AddressFamily, port: u16) -> SocketAddr {
    match family {
        AddressFamily::V4 => SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        AddressFamily::V6 => SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    }
}

/// How many ephemeral ports a pair tries before it settles for one family.
/// A collision needs another socket on the one `::` port the OS just handed
/// the `0.0.0.0` half, so a second roll almost always clears it; the bound
/// keeps a host whose IPv6 port space is somehow full from spinning.
const EPHEMERAL_PAIR_ATTEMPTS: usize = 8;

/// One family's bound socket, in each slot, plus the port they share.
type BoundPair<S> = (Option<S>, Option<S>, u16, FamilyBinds);

/// Bind every selected family on `port`, the second following the first's
/// resolved number.
///
/// With `port == 0` the number is the OS's pick for IPv4, and IPv6 may
/// already hold it; that collision (`AddrInUse` on the second half) says
/// nothing about the host's IPv6, so the whole pair is rebound on a fresh
/// ephemeral port, up to [`EPHEMERAL_PAIR_ATTEMPTS`] times, rather than
/// coming up half. Any other refusal — an absent family — is final at once.
/// Refusals are logged only for the attempt that is kept.
fn bind_pair<S>(
    port: u16,
    selection: FamilySelection,
    bind: impl Fn(SocketAddr) -> io::Result<(S, u16)>,
) -> io::Result<BoundPair<S>> {
    let mut attempt = 1;
    loop {
        let mut binds = FamilyBinds::default();
        let mut resolved = port;
        let v4 = try_bind(
            &mut binds,
            &mut resolved,
            selection.v4.then_some(AddressFamily::V4),
            &bind,
        )?;
        let v6 = try_bind(
            &mut binds,
            &mut resolved,
            selection.v6.then_some(AddressFamily::V6),
            &bind,
        )?;
        let collided = port == 0
            && v4.is_some()
            && binds.refused.iter().any(|(family, kind, _)| {
                *family == AddressFamily::V6 && *kind == io::ErrorKind::AddrInUse
            });
        if collided && attempt < EPHEMERAL_PAIR_ATTEMPTS {
            tracing::debug!(
                port = resolved,
                "ephemeral port taken on `::`; rebinding the pair"
            );
            attempt += 1;
            continue;
        }
        for (family, _, reason) in &binds.refused {
            tracing::warn!(%family, %reason, "address family absent: its bind was refused");
        }
        return Ok((v4, v6, resolved, binds));
    }
}

/// Bind one family's socket, recording the outcome. `resolved` carries an
/// ephemeral port forward so the second family lands on the first's number.
/// The `Err` return is reserved for a bound socket that could not be handed to
/// the runtime; a refused *bind* is recorded, never returned.
fn try_bind<S>(
    binds: &mut FamilyBinds,
    resolved: &mut u16,
    family: Option<AddressFamily>,
    bind: impl FnOnce(SocketAddr) -> io::Result<(S, u16)>,
) -> io::Result<Option<S>> {
    let Some(family) = family else {
        return Ok(None);
    };
    match bind(wildcard(family, *resolved)) {
        Ok((socket, port)) => {
            *resolved = port;
            binds.bound.push(family);
            Ok(Some(socket))
        }
        Err(error) => {
            binds
                .refused
                .push((family, error.kind(), error.to_string()));
            Ok(None)
        }
    }
}

/// Join every refused family's reason into one message, and pick a real
/// `ErrorKind` for it rather than the catch-all `Other` a naive join would
/// need (an `io::Error` carries exactly one kind, and the families can
/// disagree). The rule, when they do disagree: the IPv4 half's kind — Kad,
/// the reask surface and the NAT-T punch path are IPv4-first
/// (ADR-0085/0087), and an operator's port conflict (`AddrInUse`) is far and
/// away the common case, so naming the family that conflict almost always
/// lands on first is the more actionable answer than a coin flip. Falls back
/// to the first refused family's kind when there is no v4 entry at all (a
/// v6-only selection, or one where IPv6 alone was ever attempted), and to
/// `Other` when nothing was even attempted (every family deselected).
fn refused_every_family(binds: &FamilyBinds) -> io::Error {
    let reasons = binds
        .refused
        .iter()
        .map(|(family, _, reason)| format!("{family}: {reason}"))
        .collect::<Vec<_>>()
        .join("; ");
    io::Error::new(
        dominant_refusal_kind(&binds.refused),
        format!("no address family bound ({reasons})"),
    )
}

/// See [`refused_every_family`] for the rule this applies.
fn dominant_refusal_kind(refused: &[(AddressFamily, io::ErrorKind, String)]) -> io::ErrorKind {
    let mut kinds = refused.iter().map(|(_, kind, _)| *kind);
    let Some(first) = kinds.next() else {
        return io::ErrorKind::Other;
    };
    if kinds.all(|kind| kind == first) {
        return first;
    }
    refused
        .iter()
        .find(|(family, _, _)| *family == AddressFamily::V4)
        .map_or(first, |(_, kind, _)| *kind)
}

/// Bind one unconnected UDP socket, the way every one rmule receives on is
/// bound: [`open`]'s options, plus the Windows ICMP-reset switch
/// ([`rmule_winsock`]), so a datagram to a dead port never fails the next
/// receive.
pub(crate) fn bind_udp(addr: SocketAddr) -> io::Result<(std::net::UdpSocket, u16)> {
    let socket = open(addr, Type::DGRAM, Protocol::UDP)?;
    rmule_winsock::disable_udp_connection_reset(&socket)?;
    let port = bound_port(&socket)?;
    Ok((socket.into(), port))
}

/// Bind one family's TCP listener. The backlog matches tokio's own default.
fn bind_tcp(addr: SocketAddr) -> io::Result<(std::net::TcpListener, u16)> {
    let socket = open(addr, Type::STREAM, Protocol::TCP)?;
    socket.listen(1024)?;
    let port = bound_port(&socket)?;
    Ok((socket.into(), port))
}

/// The port the OS actually gave the socket — the same number the second
/// family then binds, so an ephemeral pair still shares one port.
fn bound_port(socket: &Socket) -> io::Result<u16> {
    socket
        .local_addr()?
        .as_socket()
        .map(|addr| addr.port())
        .ok_or_else(|| io::Error::other("bound socket has no IP address"))
}

/// Open, configure and bind one socket. `IPV6_V6ONLY` is set on every `::`
/// socket, so a mapped `::ffff:` address never reaches rmule.
///
/// A TCP listener sets `SO_REUSEADDR`, as std's and tokio's own
/// `TcpListener::bind` do on Unix and as aMule's listener does
/// (`ListenSocket.cpp:63`, `MULE_SOCKET_REUSEADDR` → `LibSocketAsio.cpp:1696`).
/// Without it the connections a previous run closed hold the port in
/// `TIME_WAIT` — 30 s on macOS — and a restart inside that loses the family.
/// On Linux and macOS alike it admits only that: a second listener on the same
/// address and port is still refused, so two rmules cannot share one port.
/// `SO_REUSEPORT` is what would let them, and is never set. UDP sets neither:
/// it has no `TIME_WAIT`, and on Linux `SO_REUSEADDR` on two UDP sockets lets
/// both bind.
///
/// Windows sets no address option, as std and tokio do there. Its
/// `SO_REUSEADDR` is the Unix `SO_REUSEPORT`: a second socket may bind the
/// port a live listener holds. A plain bind there is refused only by a live
/// socket, so a previous run's closed connections never hold the port, and
/// two rmules still cannot share one. `SO_EXCLUSIVEADDRUSE` is not set
/// either: it would refuse the restart while any connection of the previous
/// run stays open, which a peer that stops reading can keep up, and the
/// only bind it would add to the refused ones is a specific address from the
/// same user account, which can already read rmule's data directory.
fn open(addr: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, kind, Some(protocol))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    #[cfg(unix)]
    if kind == Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// A role's two TCP listeners behind one accept pump: [`Self::accept`] merges
/// them and names each dialer's true family.
pub struct TcpFamilyPair {
    v4: Option<tokio::net::TcpListener>,
    v6: Option<tokio::net::TcpListener>,
    port: u16,
    binds: FamilyBinds,
}

impl TcpFamilyPair {
    /// Bind `port` (0 = ephemeral, resolved once and shared) in every selected
    /// family and start listening.
    ///
    /// # Errors
    /// Only when no selected family bound at all.
    pub async fn bind(port: u16, selection: FamilySelection) -> io::Result<Self> {
        let (v4, v6, resolved, binds) = bind_pair(port, selection, bind_tcp)?;
        if binds.bound.is_empty() {
            return Err(refused_every_family(&binds));
        }
        Ok(Self {
            v4: v4.map(tokio::net::TcpListener::from_std).transpose()?,
            v6: v6.map(tokio::net::TcpListener::from_std).transpose()?,
            port: resolved,
            binds,
        })
    }

    /// Bind one literal address — a loopback listener, where the address is
    /// the point and there is no second family to pair with.
    ///
    /// # Errors
    /// Whatever the bind returned.
    pub async fn bind_literal(addr: SocketAddr) -> io::Result<Self> {
        let family = match addr {
            SocketAddr::V4(_) => AddressFamily::V4,
            SocketAddr::V6(_) => AddressFamily::V6,
        };
        let (listener, port) = bind_tcp(addr)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let (v4, v6) = match family {
            AddressFamily::V4 => (Some(listener), None),
            AddressFamily::V6 => (None, Some(listener)),
        };
        Ok(Self {
            v4,
            v6,
            port,
            binds: FamilyBinds {
                bound: vec![family],
                refused: Vec::new(),
            },
        })
    }

    /// The port both listeners share.
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.port
    }

    /// What the pair's binds did.
    #[must_use]
    pub const fn binds(&self) -> &FamilyBinds {
        &self.binds
    }

    /// Accept the next inbound connection from either listener, with the
    /// endpoint the dialer truly came from.
    ///
    /// # Errors
    /// Whatever the underlying accept returned.
    pub async fn accept(&self) -> io::Result<(tokio::net::TcpStream, PeerEndpoint)> {
        let (stream, from) = match (&self.v4, &self.v6) {
            (Some(v4), Some(v6)) => tokio::select! {
                accepted = v4.accept() => accepted?,
                accepted = v6.accept() => accepted?,
            },
            (Some(only), None) | (None, Some(only)) => only.accept().await?,
            (None, None) => return Err(refused_every_family(&self.binds)),
        };
        Ok((stream, endpoint_of(from)))
    }
}

#[cfg(test)]
mod tests;
