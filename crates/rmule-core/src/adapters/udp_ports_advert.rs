//! The live `CT_EMULE_UDPPORTS` advert (ADR-0057/0047): the one atomic cell
//! every hello-emitting adapter reads, so a hello advertises a reask endpoint
//! only while a real client-UDP socket is bound.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use rmule_peer::UdpPortsAdvert;

use crate::address_learning::{SharedAddressLearning, SocketRole};

/// The live `CT_EMULE_UDPPORTS` advert (ADR-0057/0047): rmule's real bound
/// client-UDP + Kad ports packed into one atomic word, so every hello-emitting
/// adapter (serve accept + download dial) reads the same source of truth. `0`
/// (the default) means "no reask endpoint" — Honest Capability Advertisement,
/// since a node with no bound client-UDP socket cannot answer a peer-UDP reask.
/// `Core::builder` creates it, clones it into every hello-emitting adapter, and
/// the actor sets it to the bound client-UDP port only while the reask uploader
/// serves (cleared on `StopServing`) — the "empty while not serving" ownership
/// [`SharedDialedServeSink`](super::dialed_serve::SharedDialedServeSink) uses.
///
/// The word holds only *bound* ports. Which client-UDP port goes on the wire
/// is the Advertised Endpoints chooser's call (ADR-0084): behind a NAT the
/// reask endpoint peers can reach is the learned external port, and with
/// nothing learned it is the bound one. That choice is made at every
/// [`get`](Self::get) against Address Learning, the port's one owner — never
/// copied in when serving starts, where a grant or a Kad port learned later
/// would leave every hello naming the stale one.
#[derive(Clone, Default)]
pub(crate) struct SharedUdpPortsAdvert {
    word: Arc<AtomicU32>,
    /// The owner of our external UDP port (ADR-0084).
    addresses: SharedAddressLearning,
    /// Set once at the client-UDP bind when its **Family Pair** came up
    /// without IPv4. A reask reaches this node over IPv4 or not
    /// at all, so a port advertised from a `::`-only socket is a dead
    /// invitation — and the latch lives here, beside the word, because the
    /// serve activity that publishes the port knows only that it is serving.
    /// Never cleared: there is no re-bind (ADR-0057 amendment).
    no_ipv4: Arc<std::sync::atomic::AtomicBool>,
}

impl SharedUdpPortsAdvert {
    /// An empty advert whose client-UDP half projects through `addresses` —
    /// the session cell's own store, so the hello and the login read one
    /// owner.
    pub(crate) fn over(addresses: SharedAddressLearning) -> Self {
        Self {
            addresses,
            ..Self::default()
        }
    }

    /// Record that the client-UDP **Family Pair** holds no IPv4 socket, so
    /// the client-UDP half of this advert stays `0` however often serving
    /// starts. `0` is the wire's own "no reask endpoint" — the
    /// same value aMule writes for a Kad node that is not running — and when
    /// both halves are `0` the tag is omitted outright.
    pub(crate) fn withhold_client_udp(&self) {
        self.no_ipv4.store(true, Ordering::Relaxed);
        self.update(|advert| UdpPortsAdvert::new(0, advert.kad_udp()));
    }

    /// Publish the real **bound** client-UDP port, leaving the Kad half alone —
    /// unless [`withhold_client_udp`](Self::withhold_client_udp) latched,
    /// in which case the half stays `0`.
    ///
    /// The two halves have different lifetimes — serving starts and stops
    /// independently of Kad — so each is written on its own and the word carries
    /// whatever is true right now.
    pub(crate) fn set_serving(&self, client_udp_port: u16) {
        let port = if self.no_ipv4.load(Ordering::Relaxed) {
            0
        } else {
            client_udp_port
        };
        self.update(|advert| UdpPortsAdvert::new(port, advert.kad_udp()));
    }

    /// Publish the running Kad node's UDP port, leaving the client-UDP half
    /// alone — aMule's `Kademlia::IsRunning() ? kadPort : 0`.
    ///
    /// Since the sockets unified (ADR-0057) this is the *same* port as the
    /// client-UDP half, exactly as it is on an eMule-family client. The two
    /// wire fields remain because the wire has two, and they still answer
    /// different questions: the client-UDP half says "a reask reaches me
    /// here", the Kad half says "a Kad node is running here" — so the halves
    /// are written by their own lifetimes (serving starts and stops
    /// independently of Kad) and a stopped Kad node still leaves a served
    /// reask endpoint advertised.
    ///
    /// Two counterparty decisions read the Kad half together with the hello's
    /// Kad-version nibble — whether to hand us a Kad bootstrap hint
    /// (`GetKadPort() && GetKadVersion() > 1`) and which form of
    /// firewall-check ack to send — so a zero here silently removes rmule from
    /// both.
    pub(crate) fn set_kad(&self, kad_udp_port: u16) {
        self.update(|advert| UdpPortsAdvert::new(advert.client_udp(), kad_udp_port));
    }

    /// Clear the client-UDP half (`StopServing`): no reask endpoint advertised.
    /// A running Kad node's port stays, because it is still running.
    pub(crate) fn clear(&self) {
        self.update(|advert| UdpPortsAdvert::new(0, advert.kad_udp()));
    }

    /// Clear the Kad half (`retire_kad`): a pump that died on its
    /// own must stop advertising a Kad port nobody answers on any more —
    /// aMule's own `Kademlia::IsRunning() ? kadPort : 0`, read fresh on every
    /// hello rather than latched from the last time Kad started. The
    /// client-UDP half stays, because reask serving does not die with Kad.
    pub(crate) fn clear_kad(&self) {
        self.update(|advert| UdpPortsAdvert::new(advert.client_udp(), 0));
    }

    /// Rewrite the word from its current value, so one half's writer never
    /// clobbers the other's.
    fn update(&self, change: impl Fn(UdpPortsAdvert) -> UdpPortsAdvert) {
        let _ = self
            .word
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |word| {
                Some(change(UdpPortsAdvert::from_packed(word)).packed())
            });
    }

    /// The advert a hello should carry now, or `None` when nothing is bound:
    /// a served client-UDP half names the chooser's current external port
    /// (the bound one while nothing external is learned).
    pub(crate) fn get(&self) -> Option<UdpPortsAdvert> {
        match self.word.load(Ordering::Relaxed) {
            0 => None,
            word => {
                let bound = UdpPortsAdvert::from_packed(word);
                let client_udp = match bound.client_udp() {
                    0 => 0,
                    port => self
                        .addresses
                        .advertised_v4_port(SocketRole::Udp)
                        .unwrap_or(port),
                };
                Some(UdpPortsAdvert::new(client_udp, bound.kad_udp()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rmule_peer::{Hello, HelloAdvert, PeerHandshakeContext, PeerHelloBody};
    use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, TagValue, UserHash};

    use super::*;

    fn ctx() -> PeerHandshakeContext {
        PeerHandshakeContext {
            identity: ClientIdentity::new(
                UserHash::from_bytes([0x22; UserHash::BYTE_LEN]),
                Ed2kText::from_utf8("udp-ports-advert-test"),
                4662,
                60,
            ),
            client_id: ClientId::from_u32(0x10000001),
            connected_server: None,
        }
    }

    /// `retire_kad` clears the dead pump's port so a later hello
    /// never carries it — proven at the wire frame, since
    /// the tag packs both halves into one word and a half-clear could
    /// silently clobber the other. A restart (`EnableKad` calling `set_kad`
    /// again) republishes the Kad half exactly as before.
    #[test]
    fn a_cleared_kad_half_reads_zero_in_the_hello_after_a_pump_death() {
        let advert = SharedUdpPortsAdvert::default();
        advert.set_serving(4672);
        advert.set_kad(4672);

        advert.clear_kad();

        let body = PeerHelloBody::from_handshake_context(
            &ctx(),
            &HelloAdvert {
                udp_ports: advert.get(),
                ..HelloAdvert::default()
            },
        );
        let decoded = Hello::decode_packet(&Hello::new(body).encode_packet())
            .expect("a hello we just built decodes")
            .into_body();
        let word = decoded
            .tags
            .iter()
            .find_map(|t| match (t.name().id(), t.value()) {
                (Some(0xF9), TagValue::U32(word)) => Some(*word),
                _ => None,
            })
            .expect("CT_EMULE_UDPPORTS still rides: the client-UDP half is live");
        let ports = UdpPortsAdvert::from_packed(word);
        assert_eq!(
            ports.kad_udp(),
            0,
            "the dead Kad port must not survive the clear"
        );
        assert_eq!(
            ports.client_udp(),
            4672,
            "clearing Kad must not clobber the serving half"
        );

        // A later EnableKad (a restart) sets the Kad half again.
        advert.set_kad(4672);
        assert_eq!(advert.get().map(UdpPortsAdvert::kad_udp), Some(4672));
    }

    /// A client-UDP pair that came up without IPv4 advertises no reask port,
    /// however often the serve activity republishes one: a port
    /// reachable only over IPv6 is a reask endpoint no IPv4 peer can use, and
    /// the wire's own spelling for that is `0`.
    #[test]
    fn a_withheld_client_udp_half_stays_zero_across_every_republish() {
        let advert = SharedUdpPortsAdvert::default();
        advert.withhold_client_udp();

        advert.set_serving(4672);
        assert_eq!(advert.get(), None, "both halves zero: the tag is omitted");

        // A running Kad node would be the other half — but Kad is refused on
        // this pair, so the only way the word is non-zero is the bug.
        advert.set_kad(4672);
        advert.set_serving(4672);
        assert_eq!(
            advert.get().map(UdpPortsAdvert::client_udp),
            Some(0),
            "the client-UDP half stays 0 even beside a non-zero Kad half"
        );
    }

    /// The served client-UDP half names the owner's current external port at
    /// every hello: serving starts on the bound port, a mapping
    /// grant learned afterwards reaches the very next hello, and a grant that
    /// moves moves it again — no `StartServing` in between. Built through the
    /// session cell, so the hello's store is the one the port mapper writes.
    #[test]
    fn every_hello_names_the_owner_s_current_external_udp_port() {
        use std::net::Ipv4Addr;
        use std::time::Duration;

        use rmule_net::family::FamilyBinds;
        use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint};

        use crate::address_learning::AddressObservation;

        let session = crate::server_session::SharedServerSession::default();
        let addresses = session.own_identity().addresses().clone();
        let advert = session.udp_ports_advert();
        addresses.record_bind(
            SocketRole::Udp,
            &FamilyBinds {
                bound: vec![AddressFamily::V4],
                refused: Vec::new(),
            },
            4672,
        );
        advert.set_serving(4672);
        let hello_client_udp = || advert.get().map(UdpPortsAdvert::client_udp);
        assert_eq!(
            hello_client_udp(),
            Some(4672),
            "nothing learned: the bound port"
        );

        let ours = Ipv4Addr::new(203, 0, 113, 50);
        let grant = |port| {
            AddressObservation::mapping_grant(
                SocketRole::Udp,
                PeerEndpoint::V4(Ipv4Endpoint::new(ours, port)),
                Duration::from_secs(3600),
            )
        };
        addresses.observe(grant(24672));
        assert_eq!(
            hello_client_udp(),
            Some(24672),
            "a later grant reaches the next hello"
        );

        addresses.observe(grant(34672));
        assert_eq!(
            hello_client_udp(),
            Some(34672),
            "and follows it when it moves"
        );
    }
}
