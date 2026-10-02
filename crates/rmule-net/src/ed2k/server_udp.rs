//! UDP datagram socket for server-UDP global source discovery (ADR-0051).
//! Fire-and-forget datagrams to eD2k servers — no framing, no session
//! (unlike the TCP [`crate::ed2k::Connection`]); a reply returns to this socket's
//! source address, so no advertised UDP port is needed.
//!
//! Still a **Family Pair** (ADR-0085): an ephemeral port in both families, so
//! an IPv6-reachable server can be talked to the moment the dialect learns how,
//! and a reply's recorded source is its true one.

use std::net::SocketAddrV4;

use rmule_primitives::PeerEndpoint;

use crate::family::{FamilySelection, UdpFamilyPair};

/// Read ceiling per datagram. A server-UDP source answer is small (a 16-byte
/// hash + up to 255 sources × 6 bytes ≈ 1.5 KiB), well under this.
const RECV_BUF_LEN: usize = 4096;

/// A bound UDP Family Pair for talking to eD2k servers' UDP ports.
pub struct ServerUdpSocket {
    pair: UdpFamilyPair,
}

impl ServerUdpSocket {
    /// Bind an ephemeral local UDP port in both **Address Families**.
    ///
    /// # Errors
    /// Only when no family bound at all.
    pub async fn bind() -> std::io::Result<Self> {
        Self::bind_with(0, FamilySelection::default()).await
    }

    /// Bind `port` (`0` = an OS-assigned ephemeral port, the production
    /// default — nothing outside rmule ever addresses this socket, so nothing
    /// needs it fixed) in the selected families.
    ///
    /// # Errors
    /// Only when no selected family bound at all.
    pub async fn bind_with(port: u16, selection: FamilySelection) -> std::io::Result<Self> {
        Ok(Self {
            pair: UdpFamilyPair::bind(port, selection).await?,
        })
    }

    /// The bound port, shared by both families (for tests / diagnostics).
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.pair.local_port()
    }

    /// What this pair's binds did — which families came up, and why any
    /// other did not.
    #[must_use]
    pub const fn binds(&self) -> &crate::family::FamilyBinds {
        self.pair.binds()
    }

    /// Send one datagram to `addr` (fire-and-forget; a short write is an error).
    ///
    /// # Errors
    /// Whatever the send returned.
    pub async fn send_to(&self, addr: SocketAddrV4, datagram: &[u8]) -> std::io::Result<()> {
        self.pair
            .send_to(crate::family::endpoint_of(addr.into()), datagram)
            .await
    }

    /// Receive the next datagram and the endpoint it truly came from.
    ///
    /// # Errors
    /// Whatever the receive returned.
    pub async fn recv(&self) -> std::io::Result<(Vec<u8>, PeerEndpoint)> {
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, from) = self.pair.recv(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, from))
    }
}
