//! The **client-UDP socket front** and its protocol-byte demux (ADR-0057):
//! the single bound UDP port carries everything counterparties send to rmule's
//! advertised UDP endpoint — the peer-UDP reask surface, the NAT-T transport
//! frames **and the Kad node** — and this front demuxes each datagram on its
//! leading protocol byte to the concern that owns it. It is the sibling of the
//! server-UDP engine (ADR-0051, `server_udp`), over a deliberately **disjoint**
//! accepted set.
//!
//! One socket is the eMule-family shape, and the reason is not tidiness: the
//! mapping a serving buddy observes when we recruit it over Kad has to be the
//! mapping a NAT-T punch reaches, and a second Kad bind made those two
//! different holes in the same router. Unified, a Kad `0x58`/`0x61`
//! observation, the ed2k server's `0x9F` observation and a port-mapping grant
//! are all votes on **one External Endpoint** (ADR-0084's single UDP role).
//!
//! After the ADR-0046 dual-path receive transform ([`PeerUdpCrypt`]),
//! aMule's `CClientUDPSocket::OnPacketReceived` demuxes on the first byte:
//! `0xC5` `OP_EMULEPROT` → the peer-UDP engine; `0xE4` → the Kad engine; `0xE5`
//! → zlib-inflate → the Kad engine; anything else (a server-UDP `0xE3`, junk)
//! is dropped. The accepted set is disjoint from the server-UDP socket's
//! `0xE3`-only set, so the two sockets reject each other's traffic. Frame =
//! `[protocol][opcode][payload]`, no length prefix, minimum two bytes.
//!
//! The front routes `OP_REASKFILEPING` (`0x90`) to the serve activity's reply
//! matrix (ADR-0057 uploader side) and the reask reply quartet
//! `0x91`/`0x92`/`0x93` to the downloader's Remote-Queued Pool (ADR-0057
//! downloader side). The remaining arms are the named plug-in seams the
//! ADR calls out:
//!
//! - `0x94` (`OP_REASKCALLBACKUDP`) — the open-node reask relay: verified and
//!   framed to `OP_REASKCALLBACKTCP` (`0x9A`) over the buddy's TCP link (ADR-0061).
//! - `0x95` (`OP_DIRECTCALLBACKREQ`) — emitted by the route chooser; the
//!   firewalled-node consume (rate-limit + Reachability gate + dial-back) lives
//!   in [`crate::firewalled`] (ADR-0061). Wiring that consume to this front is
//!   the firewalled-node front's own work.
//! - `0xB2` (`OP_UDPRESERVEDPROT2`) plus the `0xC5` `0xA1`/`0xAA` NAT-T
//!   signalling — the **NAT-T Front**'s inbox (`crate::natt::front`, ADR-0091):
//!   one deep, never-awaited queue carrying the transport frames and the two
//!   signalling opcodes the front acts on. The standalone `0xA0` is named and
//!   dropped — acting on a relayed rendezvous needs a recruited buddy to gate
//!   its carrier against, which is the acting path's own inlet.
//! - `0xE4`/`0xE5` Kad — and **every leading byte no protocol claims**, once
//!   the peer-UDP key has missed: an obfuscated Kad datagram opens with the
//!   sender's random marker byte, so only the node's own key families can tell
//!   it from noise. Both go to the running node's inlet
//!   ([`SharedKadInlet`]), which is empty while no node runs.
//!
//! Per-datagram crypt ([`PeerUdpCrypt`], ADR-0046) is the plaintext-under-crypt
//! split the server-UDP front and the Kad node also run:
//! [`ClientUdpEngine::demux`] dual-path-decrypts an armed
//! datagram before the protocol demux, and [`encrypt_client_udp_send`]
//! send-gates an outbound one. It keys the **ed2k user-hash family**
//! (`MAGICVALUE_UDP`), this surface's own — distinct from the Kad NodeID /
//! verify-key families the Kad socket keys on. Off by default (the
//! `CoreConfig::peer_crypt` policy is unset), so nothing changes on the wire
//! until an operator — or the capture bench — arms it.
//!
//! # The family ruling, opcode by opcode (ADR-0087)
//!
//! This surface is a **Family Pair** (ADR-0085): one advertised port, two
//! sockets, and a datagram arrives carrying the family it truly came in. That
//! does not make every body here family-generic. ADR-0085's rule stands — *a
//! type is exactly as wide as its wire meaning* — so the decision is per
//! opcode, taken once, here at the driver, and never inside a consumer:
//!
//! | Opcode | Body | Family |
//! |---|---|---|
//! | `0x90` `OP_REASKFILEPING` | `<hash 16>[part status][complete sources]` | **both** |
//! | `0x91` `OP_REASKACK` | `[part status]<rank u16>` | **both** |
//! | `0x92` `OP_FILENOTFOUND` | empty | **both** |
//! | `0x93` `OP_QUEUEFULL` | empty | **both** |
//! | `0x94` `OP_REASKCALLBACKUDP` | `<buddyID 16><forwarded…>` | **IPv4 only** |
//! | `0x95` `OP_DIRECTCALLBACKREQ` | `<tcp port u16><userhash 16><connect opts u8>` | **both** |
//! | `0xA1` `OP_HOLEPUNCH` | empty | **both** |
//! | `0xAA` `OP_NATT_ENDPOINT_HINT` | `<target 16><buddyID 16><file 16><ipv4 4><port 2><opts 1>` | **IPv4 only** |
//! | `0xB2` NAT-T frame | uTP / QUIC / CAPS / KEY | **both** |
//! | `0xE4`/`0xE5` Kad | a Kad2 datagram | **IPv4 only** |
//!
//! The reask quartet packs **no address at all**: the sender is the datagram's
//! own source, and the answer goes back to it. ADR-0087 says so in as many
//! words — "reask `0x90`/`0x91` are byte-identical over IPv6; upload-side
//! sender attribution compares the full 128 bits" — so the quartet is
//! family-generic by construction, and the queue already attributes a reask by
//! the whole address. `0x95` is the same shape: the requester's address is the
//! datagram source, the dial-back target is that source, and its rate limit
//! already buckets by **Accounting Key** (per `/64`, ADR-0087).
//!
//! `0x94` is the exception, and not because of its own body — which names no
//! address either — but because of what the relay *becomes*. A verified `0x94`
//! is rewritten into `OP_REASKCALLBACKTCP` (`0x9A`) over the buddy's TCP link
//! with the requester's endpoint injected as `WriteUInt32(ip)` +
//! `WriteUInt16(port)`, so the firewalled client on the far end knows where to
//! answer. That field is 32 bits to the bone, and the firewalled client is not
//! ours to upgrade: a stock aMule reading a `0xFFFFFFFF` sentinel there would
//! UDP-answer the reask to `255.255.255.255` and read the forwarded tail
//! sixteen bytes out of alignment. ADR-0087's `HasEd2kWireForm` governs —
//! a native-IPv6 peer is *omitted* from a 32-bit wire field, never written as
//! something the reader will misread — and for a relay, omitting is dropping.
//! So an IPv6 `0x94` drops and is **counted**
//! ([`SessionCounters::unanswerable_family_datagrams_total`]), never truncated
//! and never relayed to the wrong address.
//!
//! `0xAA` is the table's second IPv4-only row, and not because of the address in
//! its body — that is the *target*'s, and IPv4 by the dialect — but because of
//! what believing it requires: `EndpointHint::is_from` compares the observed
//! source against the buddy's `Ipv4Endpoint`, so an IPv6 source cannot be
//! attributed at all. A hint rmule cannot attribute is one it must not punch
//! on, so it drops at the driver and is counted, exactly as an IPv6 `0x94` is.
//! `0xB2` and the empty `0xA1` name no address anywhere and pass in both
//! (ADR-0046's amendment states the `0xB2` half).
//!
//! Kad stays IPv4-only end to end (ADR-0087: "no Kad opcode, version or
//! contact format changes"), so the v6 half of this pair carries no Kad ever:
//! a declared `0xE4`/`0xE5` there is dropped and counted with the other two
//! IPv4-only rows, while an *unclaimed* byte on the v6 half is merely dropped
//! — noise is noise in either family, and counting it would make it read as a
//! dialect gap.
//!
//! [`SessionCounters::unanswerable_family_datagrams_total`]: crate::diagnostics::SessionCounters::unanswerable_family_datagrams_total

use std::sync::{Arc, Mutex};

use rmule_primitives::PeerEndpoint;
use tokio::sync::mpsc;

mod engine;
#[cfg(test)]
mod kad_traffic;
#[cfg(test)]
mod live;
mod peer_crypt;

pub(crate) use engine::{ClientUdpEngine, ClientUdpTransport};
pub(crate) use peer_crypt::{
    ClientUdpSend, PeerUdpCrypt, PeerUdpCryptTarget, crypt_stance_from_connect_options,
    direct_callback_connect_options, direct_callback_datagram, encrypt_client_udp_send,
    os_datagram_nonce,
};

/// One datagram received on the client-UDP socket, tagged with its UDP source
/// endpoint — the front's demuxed hand-off unit and the serve reply's
/// destination.
///
/// The endpoint carries the family the datagram truly arrived in (ADR-0085's
/// Family Pair binds `IPV6_V6ONLY`, so no `::ffff:` mapping ever reaches
/// here). The per-opcode family ruling is the module doc's table: the front
/// drops and counts what an opcode cannot express, so every consumer
/// downstream of it may trust the endpoint it is handed.
pub(crate) type ClientUdpDatagram = (PeerEndpoint, Vec<u8>);

/// The install slot the front hands Kad datagrams to (ADR-0057): the inbound
/// half of `rmule_net::kad`'s [`KadInlet`](rmule_net::kad::KadInlet).
///
/// Empty until `EnableKad` starts a node, and empty again once it stops,
/// because the socket outlives every Kad runtime that rides it — a node can be
/// started, stopped and started again on one bind. An empty slot is the honest
/// gate: with no node running there is nothing a Kad datagram could be handed
/// to, and the front trace-drops it without anyone having to ask whether Kad
/// is up. Filled with `try_send` and never awaited, the `natt` inbox's posture
/// and for the same reason.
///
/// A `std::sync::Mutex` because every use is a `try_send` that never crosses
/// an `.await` — the front must not be able to block on a Kad lock.
pub(crate) type SharedKadInlet = Arc<Mutex<Option<mpsc::Sender<rmule_net::kad::KadDatagram>>>>;

/// Shared fixtures for the submodules' tests: the crypt-armed identities,
/// target builders, and per-packet nonce both the front's receive tests and
/// the send-gate tests key on.
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_peer::ReaskFilePing;
    use rmule_primitives::{CryptStance, DatagramNonce, FileHash, UserHash};

    use super::{PeerUdpCrypt, PeerUdpCryptTarget};
    use crate::own_identity::SharedOwnIdentity;

    // --- Per-datagram crypt (ADR-0046): the ed2k user-hash family ---

    pub(crate) fn a_reask_ping(fill: u8) -> Vec<u8> {
        ReaskFilePing {
            file_hash: FileHash::from_bytes([fill; FileHash::BYTE_LEN]),
            part_status: None,
            complete_sources: None,
        }
        .encode_udp()
    }

    /// A fixed per-packet nonce so the crypt bytes are deterministic (the
    /// entropy seam a live send draws from the OS).
    pub(crate) fn a_nonce() -> DatagramNonce {
        DatagramNonce {
            marker_byte: 0x40,
            random_key: 0xBEEF,
            padding: vec![0xAA, 0xBB, 0xCC],
        }
    }

    /// Self-facts for a node with `hash` logged in at High-ID with `ip`.
    pub(crate) fn own(hash: UserHash, ip: [u8; 4]) -> SharedOwnIdentity {
        let own = SharedOwnIdentity::default();
        own.set_user_hash(hash);
        own.addresses()
            .observe(crate::address_learning::AddressObservation::server_high_id(
                Ipv4Addr::from(ip),
            ));
        own
    }

    /// Self-facts for a node holding a global-unicast IPv6 as well as its
    /// High-ID IPv4 — a dual-stack rmule, which is what the 35-byte key
    /// layout needs on the send side (ADR-0087).
    pub(crate) fn own_dual_stack(
        hash: UserHash,
        ip: [u8; 4],
        ipv6: std::net::Ipv6Addr,
    ) -> SharedOwnIdentity {
        let own = own(hash, ip);
        // The **local-interface corroboration filter** (ADR-0084): a
        // reflected IPv6 is adopted only when this host also holds it, so the
        // realistic posture is both — the host holds the address and the
        // outside world says it sees it.
        own.addresses().refresh_interfaces(&[ipv6.into()]);
        own.addresses()
            .observe(crate::address_learning::AddressObservation::server_reflection(ipv6.into()));
        own
    }

    /// An armed layer for a node that accepts obfuscation and asks for it —
    /// aMule's `IsClientCryptLayerRequested()` true, the bench posture.
    pub(crate) fn armed_requesting(hash: UserHash, ip: [u8; 4]) -> PeerUdpCrypt {
        PeerUdpCrypt::new(own(hash, ip), CryptStance::new(true, true, false))
    }

    /// [`armed_requesting`] for a dual-stack node: it can key a send in either
    /// family, so which layout it picks is decided by the destination alone.
    pub(crate) fn armed_requesting_dual_stack(
        hash: UserHash,
        ip: [u8; 4],
        ipv6: std::net::Ipv6Addr,
    ) -> PeerUdpCrypt {
        PeerUdpCrypt::new(
            own_dual_stack(hash, ip, ipv6),
            CryptStance::new(true, true, false),
        )
    }

    /// A target peer that advertised `SupportsCryptLayer` only.
    pub(crate) fn supporting_target(hash: UserHash) -> PeerUdpCryptTarget {
        PeerUdpCryptTarget::new(hash, CryptStance::new(true, false, false))
    }
}
