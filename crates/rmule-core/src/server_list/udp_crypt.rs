//! A server's **Server UDP Crypt** facts (ADR-0052, "a server's UDP crypt
//! facts are durable"): the obfuscation ports and `ServerUDPKey` its last
//! challenge-matched `0x97` carried, and the public IP the key was learned
//! under — aMule's `ST_UDPPORTOBFUSCATION`, `ST_TCPPORTOBFUSCATION`,
//! `ST_UDPKEY` and `ST_UDPKEYIP` (`ServerList.cpp:784-796`).

use std::net::Ipv4Addr;

use rmule_ed2k::{GlobServStatRes, ServerUdpFlags};

/// What a server's status answer said about keying UDP to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerUdpCrypt {
    /// The UDP port it takes obfuscated datagrams on.
    pub obfuscation_udp_port: u16,
    /// The TCP port it takes obfuscated connections on.
    pub obfuscation_tcp_port: u16,
    /// Its `ServerUDPKey`, derived by the server from the address it saw us
    /// at.
    pub udp_key: u32,
    /// Our public IPv4 when the key was learned; `None` when none was known.
    /// The key is good only while this is still ours (`Server.cpp:300-314`).
    pub key_ip: Option<Ipv4Addr>,
}

impl ServerUdpCrypt {
    /// The facts a status answer carries, learned while our public IPv4 was
    /// `key_ip`; `None` for a body shorter than 40 bytes, which carries none —
    /// aMule zeroes all four then (`ServerUDPSocket.cpp:199-232`).
    #[must_use]
    pub fn from_status(status: &GlobServStatRes, key_ip: Option<Ipv4Addr>) -> Option<Self> {
        Some(Self {
            obfuscation_udp_port: status.obfuscation_udp_port()?,
            obfuscation_tcp_port: status.obfuscation_tcp_port()?,
            udp_key: status.server_udp_key()?,
            key_ip,
        })
    }

    /// The `ServerUDPKey` to key UDP to the server with while our public
    /// IPv4 is `own` and the server's UDP flags are `udp_flags`: aMule's
    /// `GetServerKeyUDP() != 0 && SupportsObfuscationUDP()`
    /// (`ServerUDPSocket.cpp:71`, `Server.cpp:300-307`) — non-zero, UDP
    /// obfuscation advertised, and learned under the address we hold now,
    /// because the server derived it from the address it saw.
    #[must_use]
    pub(crate) fn key_under(
        &self,
        udp_flags: Option<ServerUdpFlags>,
        own: Option<Ipv4Addr>,
    ) -> Option<u32> {
        let learned_here = self.key_ip.is_some() && self.key_ip == own;
        let advertised = udp_flags.is_some_and(ServerUdpFlags::supports_udp_obfuscation);
        (self.udp_key != 0 && advertised && learned_here).then_some(self.udp_key)
    }
}

#[cfg(test)]
mod tests {
    use rmule_primitives::ServerEndpoint;

    use super::*;
    use crate::server_list::test_facts;

    /// A challenge-matched `0x97` body of `len` bytes after the header,
    /// carrying the obfuscation ports 4673/4674 and key `0xABCD_1234` when
    /// it reaches 40.
    fn status(len: usize) -> GlobServStatRes {
        let mut datagram = vec![0xE3, rmule_ed2k::Opcode::GlobServStatRes.as_u8()];
        for word in [0x55AA_0001_u32, 1, 2, 3, 4, 5, 0x17FB, 6] {
            datagram.extend_from_slice(&word.to_le_bytes());
        }
        datagram.extend_from_slice(&4673_u16.to_le_bytes());
        datagram.extend_from_slice(&4674_u16.to_le_bytes());
        datagram.extend_from_slice(&0xABCD_1234_u32.to_le_bytes());
        datagram.truncate(2 + len);
        GlobServStatRes::decode_udp(&datagram).expect("a valid status body")
    }

    /// Every status answer refreshes the row's crypt facts in the store: a
    /// 40-byte body writes them under the public IP of the moment, a shorter
    /// one clears them, as aMule zeroes them.
    #[tokio::test]
    async fn every_status_answer_refreshes_the_durable_crypt_facts() {
        let listed = ServerEndpoint::new("192.0.2.40", 4661).unwrap();
        let (facts, _) = test_facts(std::slice::from_ref(&listed));
        let ours = Some(Ipv4Addr::new(198, 51, 100, 7));
        let stored = || facts.listed().unwrap()[0].udp_crypt;

        let ping = std::time::Duration::from_millis(9);
        facts
            .answered(&listed, ping, &status(40), ours)
            .await
            .unwrap();
        assert_eq!(
            stored(),
            Some(ServerUdpCrypt {
                obfuscation_udp_port: 4673,
                obfuscation_tcp_port: 4674,
                udp_key: 0xABCD_1234,
                key_ip: ours,
            })
        );

        facts
            .answered(&listed, ping, &status(32), ours)
            .await
            .unwrap();
        assert_eq!(stored(), None);
    }
}
