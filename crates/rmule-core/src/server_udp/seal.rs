//! The **Server-UDP Seal** (ADR-0046, ADR-0051): the one gate every server
//! datagram leaves through, aMule's `CServerUDPSocket::SendPacket`
//! (`ServerUDPSocket.cpp:351-385`) cite-and-rewritten. A sender hands it a
//! server's standard endpoint and a plain eD2k frame; the seal alone decides
//! where the datagram goes and in what form, so no sender knows a port
//! offset or a key. The crypt-ping is the one raw datagram
//! (`ServerList.cpp:314`): it goes as given to standard port + 12.
//!
//! The seal also holds the crypt context the receive side opens with — the
//! obfuscation policy that arms the layer in both directions (aMule reads
//! one preference, `IsServerCryptLayerUDPEnabled`, for both) and our public
//! IPv4, which a `ServerUDPKey` is good under.

use std::net::Ipv4Addr;

use rmule_ed2k::ServerUdpFlags;
use rmule_primitives::{
    DatagramNonce, Ipv4Endpoint, ServerCryptDirection, encrypt_datagram_server,
};

use crate::adapters::{
    SERVER_UDP_OBFUSCATION_PORT_OFFSET, SERVER_UDP_PORT_OFFSET, ServerUdpTransport,
};
use crate::obfuscation_policy::SharedObfuscationPolicy;
use crate::own_identity::SharedOwnIdentity;
use crate::server_capabilities::SharedServerCapabilities;
use crate::server_list::{ServerFacts, ServerUdpCrypt};

/// The send side of the server-UDP socket: every server datagram rmule sends
/// goes through one, over the transport it owns. Cheap to clone when the
/// transport is (an `Arc` in production), so each sender holds its own.
#[derive(Clone)]
pub(crate) struct ServerUdpSeal<T> {
    transport: T,
    /// The one obfuscation policy: any set policy arms the server-UDP crypt
    /// layer (ADR-0046), read per datagram so a live change reaches the next.
    policy: SharedObfuscationPolicy,
    /// Our own public IPv4, which a `ServerUDPKey` keys UDP under only while
    /// it is still the address the key was learned under.
    own: SharedOwnIdentity,
    /// This run's `0x97` records, each carrying the server's crypt facts.
    capabilities: SharedServerCapabilities,
    /// The managed list, whose rows keep the crypt facts across runs.
    facts: ServerFacts,
    /// Per-datagram seal entropy ([`os_datagram_nonce`](crate::client_udp::os_datagram_nonce)
    /// in production).
    nonce: fn() -> DatagramNonce,
}

impl<T: ServerUdpTransport> ServerUdpSeal<T> {
    /// A seal sending over `transport`, armed by `policy`, keying under the
    /// public IPv4 `own` holds, reading each server's crypt facts from
    /// `capabilities` (this run) then `facts` (its row), drawing each seal's
    /// randomness from `nonce`.
    pub(crate) const fn new(
        transport: T,
        policy: SharedObfuscationPolicy,
        own: SharedOwnIdentity,
        capabilities: SharedServerCapabilities,
        facts: ServerFacts,
        nonce: fn() -> DatagramNonce,
    ) -> Self {
        Self {
            transport,
            policy,
            own,
            capabilities,
            facts,
            nonce,
        }
    }

    /// Send one eD2k `frame` to the server whose standard endpoint is
    /// `server`, by the seal rule (`ServerUDPSocket.cpp:366-374`): while the
    /// policy is set and the server's crypt facts offer a key — non-zero,
    /// UDP obfuscation advertised, learned under the public IPv4 we hold now
    /// ([`ServerUdpCrypt::key_under`]) — the frame is sealed under that
    /// `ServerUDPKey` and sent to the server's obfuscation UDP port;
    /// otherwise it goes plain to standard port + 4. Nothing goes out for a
    /// port too high to offset.
    pub(crate) async fn send(&self, server: Ipv4Endpoint, frame: Vec<u8>) {
        let (to, datagram) = match self.offered_key(server) {
            Some((key, obfuscation_port)) => (
                Ipv4Endpoint::new(server.ip, obfuscation_port),
                encrypt_datagram_server(
                    &frame,
                    key,
                    ServerCryptDirection::ToServer,
                    &(self.nonce)(),
                ),
            ),
            None => {
                let Some(to) = offset(server, SERVER_UDP_PORT_OFFSET) else {
                    return;
                };
                (to, frame)
            }
        };
        self.transport.send_to(to, datagram).await;
    }

    /// The `ServerUDPKey` to seal for `server` with and the obfuscation UDP
    /// port the sealed datagram goes to; `None` while the layer is disarmed,
    /// the facts offer no key, or they name no port (a row whose only facts
    /// are a `server.met` key).
    fn offered_key(&self, server: Ipv4Endpoint) -> Option<(u32, u16)> {
        if !self.policy.armed() {
            return None;
        }
        let (crypt, udp_flags) = self.crypt_facts(server)?;
        let key = crypt.key_under(udp_flags, self.own.public_ip())?;
        (crypt.obfuscation_udp_port != 0).then_some((key, crypt.obfuscation_udp_port))
    }

    /// `server`'s crypt facts and UDP flags: this run's record first, else
    /// the ones its row saved — the order the receive side finds a server by
    /// its obfuscation port in ([`obfuscation_source`](Self::obfuscation_source)).
    fn crypt_facts(
        &self,
        server: Ipv4Endpoint,
    ) -> Option<(ServerUdpCrypt, Option<ServerUdpFlags>)> {
        let heard = self
            .capabilities
            .lock()
            .expect("server capabilities store")
            .get(&server)
            .and_then(|caps| Some((caps.udp_crypt?, caps.udp_flags)));
        heard.or_else(|| self.facts.saved_udp_crypt_of(server))
    }

    /// Send a crypt-ping `datagram` raw to the server's standard port + 12
    /// (ADR-0046): the server keys its encrypted `0x97` on the challenge it
    /// carries, so it is never sealed.
    pub(crate) async fn send_crypt_ping(&self, server: Ipv4Endpoint, datagram: Vec<u8>) {
        if let Some(to) = offset(server, SERVER_UDP_OBFUSCATION_PORT_OFFSET) {
            self.transport.send_to(to, datagram).await;
        }
    }

    /// The transport, for a test to read what was sent.
    #[cfg(test)]
    pub(crate) const fn transport(&self) -> &T {
        &self.transport
    }

    /// Whether the server-UDP crypt layer is armed right now: any set
    /// obfuscation policy.
    pub(crate) fn armed(&self) -> bool {
        self.policy.armed()
    }

    /// Our public IPv4 as of now, the address a `ServerUDPKey` is recorded
    /// and honoured under.
    pub(crate) fn public_ip(&self) -> Option<Ipv4Addr> {
        self.own.public_ip()
    }

    /// The server whose obfuscation UDP port `udp_src` is, at its standard
    /// endpoint, with the `ServerUDPKey` the receive gate allows — aMule's
    /// `ServerKeyUDP != 0 && SupportsObfuscationUDP`, the key learned under
    /// the public IPv4 we hold now (`ServerUDPSocket.cpp:71`,
    /// `Server.cpp:300-307`). This run's record is consulted first; a server
    /// this run has not heard is found by the port its row saved (ADR-0052's
    /// durable UDP crypt amendment). A server whose port matches but whose
    /// key the gate withholds is still found, keyed `None`: its outstanding
    /// crypt-ping may key it instead.
    pub(crate) fn obfuscation_source(
        &self,
        udp_src: Ipv4Endpoint,
    ) -> Option<(Ipv4Endpoint, Option<u32>)> {
        let own = self.own.public_ip();
        let heard = {
            let store = self.capabilities.lock().expect("server capabilities store");
            store.iter().find_map(|(server, caps)| {
                let crypt = caps.udp_crypt?;
                (server.ip == udp_src.ip && crypt.obfuscation_udp_port == udp_src.port)
                    .then(|| (*server, crypt.key_under(caps.udp_flags, own)))
            })
        };
        heard.or_else(|| {
            let (server, crypt, udp_flags) = self.facts.saved_udp_crypt_at(udp_src)?;
            Some((server, crypt.key_under(udp_flags, own)))
        })
    }
}

/// `server`'s address on its standard port + `by`; `None` past `u16::MAX`.
fn offset(server: Ipv4Endpoint, by: u16) -> Option<Ipv4Endpoint> {
    Some(Ipv4Endpoint::new(server.ip, server.port.checked_add(by)?))
}
