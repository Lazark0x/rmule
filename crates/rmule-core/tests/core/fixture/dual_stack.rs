//! A port held on one Address Family and proven free on the other's wildcard
//! — the setup every Half-Bound Pair leg stands on.
//!
//! Each such leg holds a port on one family so rmule's bind of that half is
//! refused, and needs the *other* family's wildcard on the same number free so
//! that half comes up. Holding a `:0` port and assuming the other side is free
//! does not hold under load: the kernel picks an ephemeral port per family, so
//! the number it hands a `[::1]:0` bind can already be held on `0.0.0.0` by a
//! sibling leg (and vice versa) — the pair then fails totally and the leg
//! lands on the arm it called unreachable.
//!
//! So the number comes off [`super::next_band_port`]'s cursor (a band no
//! kernel hands out for `:0`, never given to two legs of this binary), and is
//! kept only once the other wildcard has been bound and released on it. A
//! collision moves on to the next number, a bounded number of times.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};

/// How many numbers [`reserve_dual_stack_port`] tries before it names the
/// setup broken. A collision needs another process on the same band number,
/// so running out means something is holding the band wholesale.
pub const DUAL_STACK_RESERVE_ATTEMPTS: usize = 64;

/// A port held on one address, whose other-family wildcard was free when
/// reserved. Dropping it releases the hold.
pub struct HeldPort {
    pub port: u16,
    _held: Socket,
}

/// Hold a band port on `held_ip` (UDP or TCP by `kind`) whose other family's
/// wildcard is free — `0.0.0.0` for a v6 hold, `::` (`IPV6_V6ONLY`) for a v4
/// one. On a host that cannot bind the other family at all there is nothing
/// to prove, and the first number `held_ip` takes is kept.
pub fn reserve_dual_stack_port(held_ip: IpAddr, kind: Type) -> HeldPort {
    reserve_dual_stack_port_from(
        held_ip,
        kind,
        std::iter::from_fn(|| Some(super::next_band_port())),
    )
}

/// [`reserve_dual_stack_port`] over caller-chosen candidate numbers — the seam
/// a leg uses to hand it a number known to collide.
pub fn reserve_dual_stack_port_from(
    held_ip: IpAddr,
    kind: Type,
    candidates: impl IntoIterator<Item = u16>,
) -> HeldPort {
    let other = match held_ip {
        IpAddr::V4(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let host_binds_other = open(SocketAddr::new(other, 0), kind).is_ok();
    for port in candidates.into_iter().take(DUAL_STACK_RESERVE_ATTEMPTS) {
        let Ok(held) = open(SocketAddr::new(held_ip, port), kind) else {
            continue;
        };
        if !host_binds_other || open(SocketAddr::new(other, port), kind).is_ok() {
            return HeldPort { port, _held: held };
        }
    }
    panic!("no port held on {held_ip} with {other} free in {DUAL_STACK_RESERVE_ATTEMPTS} attempts");
}

/// Bind `addr` the way rmule's own Family Pair does (`rmule_net::family`):
/// `IPV6_V6ONLY` on every v6 socket, no address reuse — so a hold here refuses
/// rmule's bind exactly as another process would. A TCP hold also listens.
fn open(addr: SocketAddr, kind: Type) -> io::Result<Socket> {
    let (domain, protocol) = match (addr, kind == Type::STREAM) {
        (SocketAddr::V4(_), true) => (Domain::IPV4, Protocol::TCP),
        (SocketAddr::V4(_), false) => (Domain::IPV4, Protocol::UDP),
        (SocketAddr::V6(_), true) => (Domain::IPV6, Protocol::TCP),
        (SocketAddr::V6(_), false) => (Domain::IPV6, Protocol::UDP),
    };
    let socket = Socket::new(domain, kind, Some(protocol))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;
    if kind == Type::STREAM {
        socket.listen(1)?;
    }
    Ok(socket)
}

/// Whether this host can bind IPv6 at all — the wildcard and the loopback,
/// both. A host that cannot is not one whose Family Pair came up *half*: its
/// `::` socket was never there to refuse, so a leg that claims something
/// about IPv6 has nothing to measure on it.
pub fn host_binds_ipv6() -> bool {
    [Ipv6Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST]
        .into_iter()
        .all(|ip| open(SocketAddr::new(IpAddr::V6(ip), 0), Type::DGRAM).is_ok())
}

/// Skip `leg` on a host without IPv6, saying so: a leg that
/// returned silently there would pass without having asserted anything.
/// True when the leg must return.
pub fn skip_without_ipv6(leg: &str) -> bool {
    let skip = !host_binds_ipv6();
    if skip {
        eprintln!("skipped {leg}: this host cannot bind an IPv6 socket");
    }
    skip
}
