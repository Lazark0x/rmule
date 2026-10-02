//! How a server host becomes an address to dial: **A first, with one AAAA
//! fallback** (ADR-0087 §4.7).
//!
//! This is the one place in rmule that deliberately prefers IPv4, and the
//! reason is structural rather than stylistic: **a HighID *is* the client's
//! packed public IPv4**. A client that reaches a server over IPv6 with no
//! routable IPv4 is assigned a LowID unconditionally — no implementation can
//! avoid it — so preferring AAAA on a dual-stack server costs a HighID for
//! nothing. Peer transfers still prefer IPv6 (the Dial Chooser's rung 0); it is
//! only the *server* leg that stays on IPv4 while one works.
//!
//! "One AAAA" and not "every AAAA" is the same judgement from the other side: a
//! v6-only server must be reachable, but a dual-stack server whose IPv4 is down
//! is a degraded server, and walking a long AAAA list would spend the connect
//! budget proving it.
//!
//! An IP literal short-circuits the resolver entirely, which also removes a
//! real bug: the previous path built `format!("{host}:{port}")`, and a bare
//! IPv6 literal — exactly what a `server.met` `ST_IPV6` row or an
//! `ed2k://|server|[…]|` link produces — formats as `2001:db8::1:4661`, which
//! is a *different valid address*, not a parse failure.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;

/// The addresses to try for `host:port`, in the order to try them.
///
/// A literal yields exactly itself. A name yields every A record the resolver
/// returned, in its order, followed by **at most one** AAAA.
pub(crate) async fn server_candidates(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let mut v4 = Vec::new();
    let mut v6 = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        match addr {
            SocketAddr::V4(_) => v4.push(addr),
            SocketAddr::V6(_) if v6.is_none() => v6 = Some(addr),
            SocketAddr::V6(_) => {}
        }
    }
    v4.extend(v6);
    if v4.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "server host resolved to no addresses",
        ));
    }
    Ok(v4)
}

/// Dial `host:port`, trying the candidates in [`server_candidates`] order and
/// returning the stream plus **the address it actually reached**.
///
/// The address travels back because the session's family decides one wire rule:
/// `CT_MOD_YOUR_IP` in `OP_SERVERIDENT` is a statement about IPv6 connectivity,
/// and a reflection received over an IPv4 session says nothing about it. A
/// consumer that cannot tell the families apart would have to either trust it
/// always or never.
///
/// `timeout` bounds the **whole** attempt, not each candidate: a caller asked
/// for a connection within that budget, and spending it twice because a name
/// had two records would double the wait it configured.
pub(crate) async fn connect_server(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<(TcpStream, SocketAddr)> {
    tokio::time::timeout(timeout, async {
        let candidates = server_candidates(host, port).await?;
        let mut last = None;
        for addr in candidates {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok((stream, addr)),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "server host resolved to no addresses",
            )
        }))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server connect timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A literal is not resolved at all — and a bare IPv6 literal survives,
    /// which the old `format!("{host}:{port}")` path turned into a different
    /// address rather than an error.
    #[tokio::test]
    async fn a_literal_host_yields_exactly_itself_in_either_family() {
        assert_eq!(
            server_candidates("198.51.100.7", 4661).await.unwrap(),
            vec!["198.51.100.7:4661".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            server_candidates("2001:db8::1", 4661).await.unwrap(),
            vec!["[2001:db8::1]:4661".parse::<SocketAddr>().unwrap()]
        );
        // The trap, stated: `host:port` concatenation on a bare IPv6 literal
        // is not a parse failure — it is a *different address*, which is why
        // the literal must never be round-tripped through that string.
        let naive: IpAddr = format!("{}:{}", "2001:db8::1", 4661)
            .parse()
            .expect("the naive form is itself a valid address");
        assert_ne!(naive, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    /// `localhost` is the one name every host resolves without a network, and
    /// on a dual-stack host it carries both families — so it is the ordering
    /// assertion: every A first, at most one AAAA after them.
    #[tokio::test]
    async fn a_name_yields_every_a_record_first_and_at_most_one_aaaa() {
        let candidates = server_candidates("localhost", 4661).await.unwrap();
        assert!(!candidates.is_empty());
        let first_v6 = candidates.iter().position(SocketAddr::is_ipv6);
        if let Some(index) = first_v6 {
            assert!(
                candidates[..index].iter().all(SocketAddr::is_ipv4),
                "no AAAA may precede an A: {candidates:?}"
            );
            assert_eq!(
                candidates[index..].len(),
                1,
                "exactly one AAAA fallback, never a list: {candidates:?}"
            );
        }
    }
}
