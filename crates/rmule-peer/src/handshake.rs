//! What this node brings to a peer hello: its own identity, client id and
//! connected server ([`PeerHandshakeContext`]), plus the Secure User
//! Identification key material a session advertises and signs with
//! (ADR-0041).
//!
//! Advertised capability is honest — a stance is claimed only when the node
//! can actually answer for it.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rmule_primitives::{
    CT_EMULE_SERVINGBUDDYIPV6, CT_MOD_IP_V6, CT_MOD_MISCOPTIONS, Capabilities, ClientId,
    ClientIdentity, CryptStance, Ed2kText, Ipv4Endpoint, SecureIdentKey, Tag, TagName, TagValue,
    ipv6_address_tag,
};

use crate::capability::{
    CT_EMULE_MISCOPTIONS1, CT_EMULE_MISCOPTIONS2, MiscOptions1, MiscOptions2, ModMiscOptions,
    UdpPortsAdvert,
};
use crate::hello::PeerHelloBody;
use crate::hello_tag::{CT_EMULE_VERSION, CT_MOD_VERSION, CT_NAME, CT_VERSION};
use crate::software::RMULE_MOD_VERSION;

/// The Secure User Identification material the application supplies for one peer
/// connection (ADR-0041): our long-lived keypair (shared across sessions via
/// `Arc`) plus a fresh per-connection challenge. The challenge is *injected*
/// here rather than drawn from a CSPRNG inside the sans-I/O session, so the
/// session stays deterministic for Correctness-Tier tests — the same discipline
/// that keeps I/O out of `rmule-peer`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureIdentConfig {
    /// Our keypair, shared across every connection.
    pub key: Arc<SecureIdentKey>,
    /// This connection's challenge, injected so the session draws no randomness of its own.
    pub challenge: u32,
}

/// The `CT_EMULE_VERSION` value rmule advertises:
/// `(compat_id << 24) | (major << 17) | (minor << 10) | (update << 7)`.
/// Registry-derived (ADR-0047) so the server-login surface and this one
/// can never drift apart; see `Capabilities::emule_version_word`.
const RMULE_MULE_VERSION: u32 = Capabilities::shipped(CryptStance::disabled()).emule_version_word();

/// What a hello advertises about this node *right now*, as opposed to the
/// static identity in [`PeerHandshakeContext`]: the capability stances and the
/// one address the Advertised Endpoints chooser has settled on.
///
/// Every field is Honest Capability Advertisement (ADR-0047) — a stance is
/// claimed only when the node can answer for it — with one deliberate
/// exception the IPv6 dialect requires: the `CT_MOD_MISCOPTIONS` **Static
/// Capability Claim** rides every hello unconditionally, because peers read an
/// absent bit as "no support" and would never offer an IPv6 source again. The
/// *fact* is [`ipv6`](Self::ipv6), which the chooser gates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HelloAdvert {
    /// Light the Secure User Identification nibble (ADR-0041) — `true` only
    /// when the session holds a keypair.
    pub secure_ident: bool,
    /// The protocol-obfuscation stance (`MiscOptions2`, ADR-0042), or `None`
    /// for a connection with no obfuscation policy.
    pub crypt: Option<MiscOptions2>,
    /// The real bound reask/Kad ports (`CT_EMULE_UDPPORTS`, ADR-0057), or
    /// `None` when no client-UDP socket serves.
    pub udp_ports: Option<UdpPortsAdvert>,
    /// Our Known IPv6 as the Advertised Endpoints chooser settled it
    /// (ADR-0084: Known *and* not probed-unreachable), or `None`. Written as
    /// `CT_MOD_IP_V6` — the tag peers read as "reachable over IPv6", never the
    /// claim bit.
    pub ipv6: Option<Ipv6Addr>,
    /// Our serving buddy, or `None` when we are not firewalled behind a held
    /// buddy link — emule-qt's one gate for all three buddy tags
    /// (`sendBuddyTags`, `UpDownClient.cpp:1197-1210`; aMule's
    /// `GetBuddy() && IsFirewalled()`, `BaseClient.cpp:1484`). See
    /// [`ServingBuddyAdvert`].
    pub serving_buddy: Option<ServingBuddyAdvert>,
    /// Light `MiscOptions2` bit 12, `SupportsDirectUDPCallback` — core's Self
    /// Reach answer at this hello: Kad TCP firewalled, Kad UDP verified open
    /// (aMule `BaseClient.cpp:1131-1132`).
    pub direct_udp_callback: bool,
}

/// `CT_EMULE_BUDDYIP` (`0xFC`): our buddy's IPv4, as a `uint32` whose
/// little-endian bytes are the address octets in wire order (aMule writes
/// `GetBuddy()->GetIP()`, `BaseClient.cpp:1486`).
pub const CT_EMULE_BUDDYIP: u8 = 0xFC;
/// `CT_EMULE_BUDDYUDP` (`0xFD`): our buddy's UDP port in the low 16 bits of a
/// `uint32`, the high 16 reserved (`BaseClient.cpp:1489-1493`).
pub const CT_EMULE_BUDDYUDP: u8 = 0xFD;

/// The buddy a firewalled node's hello names (ADR-0061): where a peer that
/// cannot dial us sends its `OP_REASKCALLBACKUDP` instead, and — the IPv6
/// dialect's addition (ADR-0087) — the buddy's IPv6.
///
/// One value for all three tags, so they share one gate by construction:
/// `CT_EMULE_BUDDYIP` + `CT_EMULE_BUDDYUDP` ride whenever the advert does,
/// `CT_EMULE_SERVINGBUDDYIPV6` only when it also knows an IPv6 (emule-qt's
/// `haveBuddyIPv6`, `UpDownClient.cpp:1209`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServingBuddyAdvert {
    /// The buddy's IPv4 and its UDP port: `CT_EMULE_BUDDYIP` + `CT_EMULE_BUDDYUDP`.
    pub buddy_udp: Ipv4Endpoint,
    /// The buddy's IPv6, `CT_EMULE_SERVINGBUDDYIPV6`, or `None`.
    pub ipv6: Option<Ipv6Addr>,
}

/// Bridge value built by the application layer from a live `Ed2kSession`
/// plus the static `ClientIdentity`. `rmule-peer` never reads from an
/// `Ed2kSession` directly — see `docs/adr/0081-crate-topology.md`
/// and `docs/adr/0047-honest-capability-advertisement.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHandshakeContext {
    /// Who we say we are: nickname, versions, and any extra tags.
    pub identity: ClientIdentity,
    /// The Client ID the hello presents, which tells a peer whether it can dial us back.
    pub client_id: ClientId,
    /// The eD2k ID the server session holds, or the Low ID `0` with none: aMule's
    /// `GetED2KID`, the one fact the Secure User Identification V2 challenge IP
    /// keys on (`BaseClient.cpp:2096-2104`), whatever `client_id` presents.
    pub ed2k_client_id: ClientId,
    /// Our public IPv4 as we know it, or `None`: aMule's `GetPublicIP(true)`,
    /// which a kind-10 Secure User Identification verification reads before
    /// the eD2k ID (`ClientCreditsList.cpp:405-413`).
    pub public_ip: Option<std::net::Ipv4Addr>,
    /// The server we are logged in to, or `None`, which a hello carries as the zero endpoint.
    pub connected_server: Option<Ipv4Endpoint>,
}

impl PeerHelloBody {
    /// Build the outbound hello body from the static handshake context and
    /// what this node advertises right now.
    #[must_use]
    pub fn from_handshake_context(ctx: &PeerHandshakeContext, advert: &HelloAdvert) -> Self {
        let HelloAdvert {
            secure_ident: advertise_secure_ident,
            crypt: crypt_advert,
            udp_ports,
            ipv6,
            serving_buddy,
            direct_udp_callback,
        } = *advert;
        let extras = ctx.identity.extra_tags();
        let mut tags = Vec::with_capacity(7 + extras.len());
        tags.push(Tag::new(
            TagName::length_prefixed_id(CT_NAME),
            TagValue::String(ctx.identity.nickname().clone()),
        ));
        tags.push(Tag::new(
            TagName::length_prefixed_id(CT_VERSION),
            TagValue::U32(ctx.identity.protocol_version()),
        ));
        // Honest Capability Advertisement (ADR-0047/0057): rmule's real bound
        // reask/Kad ports, emitted only when the shared client-UDP socket serves.
        // Placed before `MiscOptions1` to match aMule's contiguous eMule tag
        // block order (`0xF9` before `0xFA`, the captured layout).
        let udp_ports = udp_ports.filter(|ports| !ports.is_empty());
        if let Some(ports) = udp_ports {
            tags.push(ports.to_tag());
        }
        // ADR-0061's buddy contact, where aMule writes it: right after
        // `CT_EMULE_UDPPORTS` (`BaseClient.cpp:1484-1495`), both as forced
        // 32-bit integers.
        if let Some(buddy) = serving_buddy {
            tags.push(Tag::new(
                TagName::length_prefixed_id(CT_EMULE_BUDDYIP),
                TagValue::U32(u32::from_le_bytes(buddy.buddy_udp.ip.octets())),
            ));
            tags.push(Tag::new(
                TagName::length_prefixed_id(CT_EMULE_BUDDYUDP),
                TagValue::U32(u32::from(buddy.buddy_udp.port)),
            ));
        }
        // Honest Capability Advertisement (ADR-0047/0041): advertise the eMule
        // extended-protocol capabilities rmule implements. Secure User
        // Identification is lit only when the application supplied a keypair, so
        // a peer never asks us to sign a challenge we cannot answer. The peer-UDP
        // version nibble (aMule's 4) rides only alongside a live `CT_EMULE_UDPPORTS`
        // advert — a peer's `UDPReaskForDownload` gate keys on both (ADR-0057).
        let mut misc1 = MiscOptions1::rmule_advertised_with_secure_ident(advertise_secure_ident);
        if udp_ports.is_some() {
            misc1 = misc1.with_udp_version(
                Capabilities::shipped(CryptStance::disabled()).peer_udp_version(),
            );
        }
        tags.push(misc1.to_tag());
        // Honest Capability Advertisement (ADR-0054/0055): rmule implements
        // ExtMultiPacket (bit 5) and SourceExchange2 (bit 10), so those ride the
        // MiscOptions2 word independently of the crypt stance. Fold them onto
        // the protocol-obfuscation crypt advert (ADR-0042) when the connection
        // carries an obfuscation policy — `supports` is truthful, rmule accepts
        // obfuscated inbound — or onto an otherwise-empty word when
        // it does not: a hello with no crypt policy must still advertise the two
        // capabilities it implements. The tag rides whenever any bit is set; an
        // all-zero word is still omitted.
        let mut misc2 = crypt_advert
            .unwrap_or(MiscOptions2::from_bits(0))
            .with_multipacket_ext()
            .with_source_exchange2()
            .with_direct_udp_callback(direct_udp_callback);
        // The Kad version nibble rides the same live signal as the Kad port
        // beside it (aMule's `Kademlia::IsRunning() ? kadPort : 0`): a hello sent
        // while no Kad node runs claims nothing. Under-advertising it is not a
        // safe default — aMule reads `<= 1` as "cannot participate in Kad2" and
        // never hands us a bootstrap hint, and it reads `< 7` as "ack a
        // firewall-check connect-back over legacy UDP `0x59`", so the
        // ADR-0058 `OP_KAD_FWTCPCHECK_ACK` path would never be taken.
        if udp_ports.is_some_and(|ports| ports.kad_udp() != 0) {
            misc2 = misc2
                .with_kad_version(Capabilities::shipped(CryptStance::disabled()).kad_version());
        }
        if !misc2.is_empty() {
            tags.push(misc2.to_tag());
        }
        // See RMULE_MULE_VERSION: without 0xFB an eMule peer never treats us
        // as an extended client and never initiates SUI.
        tags.push(Tag::new(
            TagName::length_prefixed_id(CT_EMULE_VERSION),
            TagValue::U32(RMULE_MULE_VERSION),
        ));
        // The IPv6 dialect's mod block (ADR-0087), appended after the eMule
        // block a stock aMule reads: the Static Capability Claim on every
        // hello, then the address tag only while the chooser reports one.
        tags.push(ModMiscOptions::rmule_claim().to_tag());
        if let Some(address) = ipv6 {
            tags.push(ipv6_address_tag(CT_MOD_IP_V6, address));
        }
        if let Some(address) = serving_buddy.and_then(|buddy| buddy.ipv6) {
            tags.push(ipv6_address_tag(CT_EMULE_SERVINGBUDDYIPV6, address));
        }
        // How one rmule knows another (ADR-0047): the mod
        // name, last in the block as aMule's own builds write it
        // (`BaseClient.cpp:1615-1619`). Readers show it and act on nothing in
        // it — and eMuleAI stops scoring the mod tag above as a nameless
        // "ghost mod".
        tags.push(Tag::new(
            TagName::length_prefixed_id(CT_MOD_VERSION),
            TagValue::String(Ed2kText::from_utf8(RMULE_MOD_VERSION)),
        ));
        tags.extend(
            extras
                .iter()
                .filter(|t| !is_canonical_hello_tag(t))
                .cloned(),
        );

        Self {
            user_hash: ctx.identity.user_hash(),
            client_id: ctx.client_id,
            tcp_port: ctx.identity.tcp_port(),
            tags,
            connected_server: ctx
                .connected_server
                .unwrap_or_else(|| Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}

fn is_canonical_hello_tag(tag: &Tag) -> bool {
    matches!(
        tag.name().id(),
        Some(
            CT_NAME
                | CT_VERSION
                | CT_EMULE_BUDDYIP
                | CT_EMULE_BUDDYUDP
                | CT_EMULE_MISCOPTIONS1
                | CT_EMULE_MISCOPTIONS2
                | CT_EMULE_VERSION
                | CT_MOD_MISCOPTIONS
                | CT_MOD_IP_V6
                | CT_EMULE_SERVINGBUDDYIPV6
                | CT_MOD_VERSION
        )
    )
}
