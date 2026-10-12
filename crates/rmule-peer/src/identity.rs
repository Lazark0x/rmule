//! The typed projection of a decoded peer hello: the name, version, ports and
//! capability stances a peer claims about itself.
//!
//! Untyped tags survive byte-faithful, so a later capability read can promote
//! one without a fresh capture.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_primitives::{
    ClientId, CryptStance, Ed2kText, Ipv4Endpoint, Ipv6Endpoint, PeerSource, SourceSighting, Tag,
    TagValue, UserHash,
};

use crate::capability::{CT_EMULE_UDPPORTS, MiscOptions1, MiscOptions2, ModMiscOptions};
use crate::handshake::{CT_EMULE_BUDDYIP, CT_EMULE_BUDDYUDP, ServingBuddyAdvert};
use crate::hello::{PeerHelloBody, hello_int, hello_text};
use crate::hello_tag::{CT_NAME, CT_VERSION};
use crate::ipv6::PeerIpv6Tags;
use crate::peer_udp::crypt::PeerUdpCryptTarget;
use crate::session::SourceExchangeSupport;
use crate::software::ClientSoftware;

const CT_PORT: u8 = 0x0F;

/// Whether `tag` is a copy of `id` of the type its reader takes.
fn is_read_as(tag: &Tag, id: u8) -> bool {
    tag.name().id() == Some(id)
        && match (id, tag.value()) {
            (CT_NAME, TagValue::String(_)) => true,
            (CT_NAME, _) => false,
            (_, value) => matches!(value, TagValue::U8(_) | TagValue::U16(_) | TagValue::U32(_)),
        }
}

/// Typed projection of a decoded peer hello body, kept current by the session
/// that read it: an `OP_EMULEINFO` revises its software, reask contact and
/// source-exchange facts, an `OP_CHANGE_CLIENT_IP` its IPv6, an `OP_CHANGE_CLIENT_ID` its Client ID,
/// and nothing
/// else moves it. Untyped tags are preserved byte-faithful so a later
/// capability read can promote one without losing wire fidelity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    user_hash: UserHash,
    client_id: ClientId,
    tcp_port: u16,
    nickname: Option<Ed2kText>,
    protocol_version: Option<u32>,
    connected_server: Option<Ipv4Endpoint>,
    /// The server an `OP_CHANGE_CLIENT_ID` named, once one has: the packet
    /// carries an address and no port, and the claim it supersedes the hello's
    /// (`None` until the peer revises its ID).
    revised_server: Option<Ipv4Addr>,
    /// The peer's advertised **Kad** UDP port (`0` = none), the high half of
    /// `CT_EMULE_UDPPORTS` (ADR-0067).
    kad_udp_port: u16,
    /// The peer's advertised **client-UDP** port (`0` = none), the low half of
    /// `CT_EMULE_UDPPORTS` — the ADR-0057 source-reask concern (the counterpart
    /// of the Kad half above). The `OP_REASKFILEPING` (`0x90`) destination when
    /// this source is queued and hangs up (aMule `m_nUDPPort`).
    client_udp_port: u16,
    /// The peer's advertised Kad protocol version (`0` = not a Kad2 node), the
    /// low nibble of `CT_EMULE_MISCOPTIONS2`.
    kad_version: u8,
    /// The peer's advertised **peer-UDP protocol version**, the UDP-version
    /// nibble of `CT_EMULE_MISCOPTIONS1` (aMule `m_byUDPVer`). Gates the `0x90`
    /// reask body extras — version `> 3` carries our part-status bitfield, `> 2`
    /// our complete-source count.
    udp_version: u8,
    /// The peer's claimed **extended-requests version**, the nibble of
    /// `CT_EMULE_MISCOPTIONS1` bits [8..12) (aMule `m_byExtendedRequestsVer`).
    /// `0` claims no part status in its name asks and reasks.
    extended_requests_version: u8,
    /// The peer's advertised protocol-obfuscation stance, the crypt bits of
    /// `CT_EMULE_MISCOPTIONS2` (aMule `m_fSupportsCryptLayer` /
    /// `m_fRequestsCryptLayer` / `m_fRequiresCryptLayer`). Read by the per-datagram
    /// UDP crypt send-gate (ADR-0046) as well as the stream dial.
    crypt: CryptStance,
    /// The peer's **Static Capability Claim** (`CT_MOD_MISCOPTIONS`,
    /// ADR-0087), masked to the bits rmule models. `None` for every client
    /// outside the IPv6 dialect's mod family.
    mod_misc: Option<ModMiscOptions>,
    /// The dialect's address tags, each already past `IsUsableTagIdentity`
    /// (ADR-0087). The peer's own v6 here — not the claim bit above — is what
    /// makes it dialable in that family.
    ipv6_tags: PeerIpv6Tags,
    /// The peer's serving buddy (ADR-0061), from `CT_EMULE_BUDDYIP` +
    /// `CT_EMULE_BUDDYUDP` with `CT_EMULE_SERVINGBUDDYIPV6` beside them —
    /// the read side of the one [`ServingBuddyAdvert`] rmule's own hello
    /// writes.
    serving_buddy: Option<ServingBuddyAdvert>,
    /// Which client the peer runs, as its hello tells it.
    software: ClientSoftware,
    /// What the peer said about source exchange, as the session that read
    /// its hello judged it (ADR-0108). Unknown — never askable — until set.
    source_exchange: SourceExchangeSupport,
    unknown_tags: Vec<Tag>,
}

impl PeerIdentity {
    #[must_use]
    /// Read what a peer's hello says about it. Tags this crate does not model
    /// are kept rather than dropped, so a capture can still account for them.
    pub fn from_hello_body(body: &PeerHelloBody) -> Self {
        // Both references assign per tag, so a repeated tag's last copy of the
        // right type is the one read (`hello_int`).
        let nickname = hello_text(&body.tags, CT_NAME).cloned();
        let protocol_version = hello_int(&body.tags, CT_VERSION);
        let name_at = body.tags.iter().rposition(|tag| is_read_as(tag, CT_NAME));
        let version_at = body
            .tags
            .iter()
            .rposition(|tag| is_read_as(tag, CT_VERSION));
        // The extended-hello capability tags (`CT_EMULE_UDPPORTS`,
        // `CT_EMULE_MISCOPTIONS*`) are *read* below without being consumed, so
        // they still land here byte-faithful — the same read-not-strip
        // treatment MiscOptions1/2 already get in the session (ADR-0047). Only
        // the CT_NAME/CT_VERSION copies read are promoted out.
        let unknown_tags = body
            .tags
            .iter()
            .enumerate()
            .filter(|(at, _)| Some(*at) != name_at && Some(*at) != version_at)
            .map(|(_, tag)| tag.clone())
            .collect();

        let connected_server =
            if body.connected_server == Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0) {
                None
            } else {
                Some(body.connected_server)
            };

        Self {
            user_hash: body.user_hash,
            client_id: body.client_id,
            // `CT_PORT` overrides the fixed field in both references (aMule
            // `BaseClient.cpp:526`, eMule `:407`); only eDonkey-era clients send it.
            #[allow(clippy::cast_possible_truncation)] // both keep its low 16 bits
            tcp_port: hello_int(&body.tags, CT_PORT).map_or(body.tcp_port, |port| port as u16),
            nickname,
            protocol_version,
            connected_server,
            revised_server: None,
            // The ed2k→Kad handoff hint (ADR-0067): the Kad UDP port is the
            // high 16 bits of CT_EMULE_UDPPORTS, the Kad version the low nibble
            // of MiscOptions2 — the consume-side counterpart of the ADR-0047
            // advert registry.
            kad_udp_port: kad_udp_port_from_tags(&body.tags),
            // The ADR-0057 source-reask contact: the client-UDP port is the low
            // 16 bits of CT_EMULE_UDPPORTS, the peer-UDP version the UDP nibble
            // of MiscOptions1 (aMule `m_nUDPPort` / `m_byUDPVer`).
            client_udp_port: client_udp_port_from_tags(&body.tags),
            kad_version: MiscOptions2::from_tags(&body.tags).map_or(0, MiscOptions2::kad_version),
            udp_version: MiscOptions1::from_tags(&body.tags).map_or(0, MiscOptions1::udp_version),
            extended_requests_version: MiscOptions1::from_tags(&body.tags)
                .map_or(0, MiscOptions1::extended_requests_version),
            crypt: crypt_stance_from_tags(&body.tags),
            // The IPv6 dialect's two channels (ADR-0087): the claim says what
            // the peer *can* speak, the tag says where it *is*. Both are read;
            // only the second is ever dialed.
            mod_misc: ModMiscOptions::from_tags(&body.tags),
            ipv6_tags: PeerIpv6Tags::from_hello_tags(&body.tags),
            serving_buddy: serving_buddy_from_tags(&body.tags),
            software: ClientSoftware::from_hello_body(body),
            source_exchange: SourceExchangeSupport::default(),
            unknown_tags,
        }
    }

    #[must_use]
    /// Its User Hash.
    pub const fn user_hash(&self) -> UserHash {
        self.user_hash
    }

    #[must_use]
    /// Its Client ID.
    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    #[must_use]
    /// The TCP port it listens on.
    pub const fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    #[must_use]
    /// This identity with `software` in place of what the hello alone says —
    /// what a session read from the hello's trailer and the peer's
    /// `OP_EMULEINFO` as well.
    pub fn with_software(mut self, software: ClientSoftware) -> Self {
        self.software = software;
        self
    }

    /// This identity with the source-exchange facts the session read beside
    /// the hello — the extended protocol lives in the software evidence, which
    /// an `OP_EMULEINFO` before the hello may have set (ADR-0108).
    #[must_use]
    pub const fn with_source_exchange(mut self, support: SourceExchangeSupport) -> Self {
        self.source_exchange = support;
        self
    }

    /// Take the software a later `OP_EMULEINFO` reads as; `true` when it
    /// changed.
    pub(crate) fn revise_software(&mut self, software: ClientSoftware) -> bool {
        let changed = self.software != software;
        self.software = software;
        changed
    }

    /// Take the client-UDP reask contact a legacy `OP_EMULEINFO` named
    /// (`ET_UDPPORT`) — both references keep one `m_nUDPPort` that either
    /// packet sets; `true` when it changed. The session offers it only when
    /// the hello named none.
    pub(crate) const fn revise_reask_contact(&mut self, udp_port: u16, udp_version: u8) -> bool {
        let changed = self.client_udp_port != udp_port || self.udp_version != udp_version;
        self.client_udp_port = udp_port;
        self.udp_version = udp_version;
        changed
    }

    /// Take what the peer now says about source exchange (ADR-0108); `true`
    /// when it changed.
    pub(crate) fn revise_source_exchange(&mut self, support: SourceExchangeSupport) -> bool {
        let changed = self.source_exchange != support;
        self.source_exchange = support;
        changed
    }

    /// Take the Client ID an `OP_CHANGE_CLIENT_ID` says the peer now answers
    /// to, and the server it named beside it, which then stands as the server
    /// it claims; `true` when either changed.
    pub(crate) fn revise_client_id(&mut self, client_id: ClientId, server: Ipv4Addr) -> bool {
        let changed = self.client_id != client_id || self.revised_server != Some(server);
        self.client_id = client_id;
        self.revised_server = Some(server);
        changed
    }

    /// Take the IPv6 an `OP_CHANGE_CLIENT_IP` says the peer now holds
    /// (ADR-0087), already past `IsUsableTagIdentity`; `true` when it changed.
    pub(crate) fn revise_peer_ipv6(&mut self, address: Ipv6Addr) -> bool {
        let changed = self.ipv6_tags.peer_ipv6 != Some(address);
        self.ipv6_tags.peer_ipv6 = Some(address);
        changed
    }

    #[must_use]
    /// Which client it runs, as its hello tells it.
    pub const fn software(&self) -> &ClientSoftware {
        &self.software
    }

    #[must_use]
    /// Its nickname, when the hello named one.
    pub fn nickname(&self) -> Option<&Ed2kText> {
        self.nickname.as_ref()
    }

    #[must_use]
    /// The protocol version tag it advertised, when it sent one.
    pub const fn protocol_version(&self) -> Option<u32> {
        self.protocol_version
    }

    #[must_use]
    /// The server it says it is on, or `None` for the zero endpoint.
    pub const fn connected_server(&self) -> Option<Ipv4Endpoint> {
        self.connected_server
    }

    /// The peer's **Kad bootstrap UDP port**, or `None` when the peer is not a
    /// usable Kad handoff candidate — the peer-tag consume of the ed2k→Kad
    /// handoff (ADR-0067). Applies aMule's `CUpDownClient::ConnectionEstablished`
    /// condition `KadPort ∧ KadVersion > 1`: the peer must advertise a non-zero
    /// Kad UDP port *and* a Kad version above 1 (a v0/v1 peer cannot really
    /// participate in Kad2). Core pairs this port with the live connection's IP
    /// (the hello carries only the port) and brokers the endpoint to the Kad
    /// node while Kad is running.
    #[must_use]
    pub const fn kad_bootstrap_port(&self) -> Option<u16> {
        if self.kad_udp_port != 0 && self.kad_version > 1 {
            Some(self.kad_udp_port)
        } else {
            None
        }
    }

    /// Whether the peer can serve as a **UDP Firewall Helper**: its hello
    /// named a Kad UDP port and a Kad version of at least 6 — the two facts
    /// aMule checks before it sends `OP_FWCHECKUDPREQ`, cancelling the test
    /// otherwise (`BaseClient.cpp:3972-3979` @ab483654).
    #[must_use]
    pub const fn serves_udp_firewall_checks(&self) -> bool {
        self.kad_udp_port != 0 && self.kad_version > 5
    }

    /// The peer's advertised **client-UDP reask contact**: its client-UDP port
    /// paired with its peer-UDP version, or `None` when it advertised no
    /// client-UDP port (a source rmule can only TCP-reask). The ADR-0057
    /// downloader keys its `OP_REASKFILEPING` (`0x90`) on this — the low half of
    /// `CT_EMULE_UDPPORTS` with the `MiscOptions1` UDP-version nibble (aMule
    /// `CUpDownClient::UDPReaskForDownload`'s `m_nUDPPort != 0` gate).
    #[must_use]
    pub const fn client_udp_reask(&self) -> Option<(u16, u8)> {
        if self.client_udp_port != 0 {
            Some((self.client_udp_port, self.udp_version))
        } else {
            None
        }
    }

    /// What the peer said about source exchange (ADR-0108).
    #[must_use]
    pub const fn source_exchange(&self) -> SourceExchangeSupport {
        self.source_exchange
    }

    /// The extended-requests version the peer's hello claimed (`MiscOptions1`
    /// bits [8..12), aMule `GetExtendedRequestsVersion()`), `0` when it sent no
    /// `MiscOptions1`. The ask side negotiates with it; the serve side
    /// reads it as aMule's `ProcessExtendedInfo` does, discarding the part
    /// status a `0` claimant writes.
    #[must_use]
    pub const fn extended_requests_version(&self) -> u8 {
        self.extended_requests_version
    }

    /// The peer's advertised **protocol-obfuscation stance** (`MiscOptions2`
    /// crypt bits, ADR-0042/0046): what it says it will accept, initiate, and
    /// require. Both crypt surfaces read it — the stream dial (whether to
    /// obfuscate-dial this peer) and the per-datagram peer-UDP send gate, whose
    /// aMule predicate `CUpDownClient::ShouldReceiveCryptUDPPackets()` needs
    /// `SupportsCryptLayer()` and `RequestsCryptLayer()`. A peer that advertised
    /// no `MiscOptions2` tag reads as [`CryptStance::disabled`] — plaintext only.
    #[must_use]
    pub const fn crypt_stance(&self) -> CryptStance {
        self.crypt
    }

    /// The peer's **peer-UDP crypt target** (ADR-0046): its User Hash keys a
    /// datagram obfuscated toward it, and its stance says whether it accepts
    /// one at all ([`PeerUdpCryptTarget::should_receive_crypt_udp_packets`]).
    #[must_use]
    pub const fn udp_crypt_target(&self) -> PeerUdpCryptTarget {
        PeerUdpCryptTarget::new(self.user_hash, self.crypt)
    }

    /// The peer as a source of the files it deals in (ADR-0055 §Serving): its
    /// advertised `(client id, listen port)` with its User Hash, and the
    /// usable IPv6 its hello (or a later `OP_CHANGE_CLIENT_IP`) named as the
    /// source's IPv6 half. emule-qt writes `CT_MOD_IP_V6` for any source with
    /// one, High ID included (`KnownFile.cpp:937`), and only an ExtSX record
    /// can carry it (ADR-0087). A Low-ID client with an IPv6 is a source over
    /// that IPv6 alone, the client emule-qt's writer keeps
    /// (`KnownFile.cpp:846-854`); any other Low-ID client is a source an
    /// answer filters out.
    #[must_use]
    pub fn source_coordinate(&self) -> SourceSighting {
        let classic = PeerSource::new(self.client_id, self.tcp_port);
        let ipv6 = self
            .peer_ipv6()
            .map(|address| Ipv6Endpoint::new(address, self.tcp_port));
        let source = match ipv6 {
            Some(endpoint) if !classic.is_high_id() => PeerSource::Ipv6(endpoint),
            _ => classic,
        };
        SourceSighting::new(source, Some(self.user_hash), None).with_ipv6_half(ipv6)
    }

    /// Whether the peer claims to be logged in to `server` — the "on our
    /// server" half of the **Low-ID abuse guard**. A claim of `0.0.0.0:0`
    /// is no server, so it never matches. After an `OP_CHANGE_CLIENT_ID` the
    /// claim is the server that packet named, matched by address alone: it
    /// names no port, and the server a node knows by that address is the one
    /// whose port aMule takes (`ClientTCPSocket.cpp:751-776`).
    #[must_use]
    pub fn is_on_server(&self, server: Ipv4Endpoint) -> bool {
        match self.revised_server {
            Some(named) => named == server.ip,
            None => self.connected_server == Some(server),
        }
    }

    /// The peer's **Static Capability Claim** (`CT_MOD_MISCOPTIONS`,
    /// ADR-0087), or `None` when it sent none. Gates what rmule may *send*
    /// this peer — the ExtSX record form and its optional tags — never what
    /// rmule believes about where the peer is.
    #[must_use]
    pub const fn mod_misc_options(&self) -> Option<ModMiscOptions> {
        self.mod_misc
    }

    /// The peer's own reachable IPv6 (`CT_MOD_IP_V6`), or `None`. **The fact**
    /// of the dialect: a peer that claims the IPv6 bit but sends no tag is not
    /// dialable over IPv6, and a peer that sends the tag is, bit or no bit.
    #[must_use]
    pub const fn peer_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6_tags.peer_ipv6
    }

    /// The peer's view of *our* IPv6 (`CT_MOD_YOUR_IP`, hash form only), or
    /// `None`. One **Address Observation** vote for the ADR-0084 quorum — the
    /// integer form of the tag is refused outright, so a peer can never set
    /// what rmule believes its own public IPv4 to be.
    #[must_use]
    pub const fn reflected_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6_tags.reflected_ipv6
    }

    /// The peer's buddy's IPv6 (`CT_EMULE_SERVINGBUDDYIPV6`), or `None` — the
    /// v6 half of the ADR-0061 buddy contact.
    #[must_use]
    pub const fn serving_buddy_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6_tags.serving_buddy_ipv6
    }

    /// The peer's **serving buddy** — where a Low-ID peer that cannot be
    /// dialed takes its buddy callback (ADR-0061) — or `None` when its hello
    /// named no usable one. The IPv4 endpoint is the fact; the IPv6 rides
    /// beside it, recognised but never dialed (aMule `BaseClient.cpp:703-714`,
    /// "recognition only"), so a hello with `0xA0` and no `0xFC`/`0xFD` still
    /// answers `None` here and is read by [`Self::serving_buddy_ipv6`] alone.
    #[must_use]
    pub const fn serving_buddy(&self) -> Option<ServingBuddyAdvert> {
        self.serving_buddy
    }

    #[must_use]
    /// The tags this crate does not model, in wire order.
    pub fn unknown_tags(&self) -> &[Tag] {
        &self.unknown_tags
    }
}

/// Project the peer's `MiscOptions2` crypt bits onto a [`CryptStance`]. Absent
/// tag ⇒ disabled (no crypt claimed). The stance constructor re-applies aMule's
/// cumulative ladder (`requests &= supports; requires &= requests`), so a peer
/// advertising a dishonest ladder is read at the tier it can actually honour.
///
/// Sharing [`CryptStance::new`] with the *advert* side is parity here, not an
/// own-advert rule leaking into the read path: aMule runs the identical two-step
/// ladder on **receive**, three lines below its bit reads of this same tag
/// (`BaseClient.cpp#L600-601` in `ProcessHelloTypePacket`, reads at `#L591-593`).
/// A `0x0280` advert — supports ∧ requires, requests dark — therefore reads
/// crypt-*optional* on both clients, so rmule dials it exactly where aMule would.
/// The other aMule receive path deliberately does *not* ladder: the
/// source-exchange / callback crypt-options byte (`SetConnectOptions`,
/// `BaseClient.cpp#L2987-2991`) sets its three bits independently, and rmule's
/// counterpart `rmule_primitives::SourceCryptOptions` keeps them independent to
/// match. Two surfaces, two rules, both mirrored.
fn crypt_stance_from_tags(tags: &[Tag]) -> CryptStance {
    MiscOptions2::from_tags(tags).map_or(CryptStance::disabled(), |misc2| {
        CryptStance::new(
            misc2.supports_crypt_layer(),
            misc2.requests_crypt_layer(),
            misc2.requires_crypt_layer(),
        )
    })
}

/// The **client-UDP** port a peer advertises in `CT_EMULE_UDPPORTS` — the low 16
/// bits of the packed int (the high 16 are the Kad UDP port). `0` when the tag
/// is absent or carries no client half. aMule `ProcessHelloTypePacket`:
/// `m_nUDPPort = temptag.GetInt() & 0xFFFF`.
fn client_udp_port_from_tags(tags: &[Tag]) -> u16 {
    hello_int(tags, CT_EMULE_UDPPORTS).map_or(0, |packed| (packed & 0xFFFF) as u16)
}

/// The serving buddy a peer's hello names, by aMule's read rules
/// (`ProcessHelloTypePacket`, `BaseClient.cpp:542-557`):
///
/// - `CT_EMULE_BUDDYIP` (`0xFC`) is any integer tag (`GetInt()`), truncated to
///   32 bits (`m_nBuddyIP`), whose little-endian bytes are the address octets
///   in wire order — `fc 2d37c802` is `45.55.200.2`, the inverse of the writer
///   in [`crate::handshake`];
/// - `CT_EMULE_BUDDYUDP` (`0xFD`) is any integer tag whose low 16 bits are the
///   port (`(uint16)GetInt()`), the high 16 reserved;
/// - the pair is usable only when both are non-zero — the gate every aMule
///   reader of them applies (`GetBuddyIP() && GetBuddyPort()`,
///   `BaseClient.cpp:2134`, `DownloadClient.cpp:1409`);
/// - `CT_EMULE_SERVINGBUDDYIPV6` (`0xA0`, already past `IsUsableTagIdentity`)
///   rides beside a usable pair, never alone.
///
/// One deviation: aMule's `GetInt()` throws on a non-integer tag and so fails
/// the whole hello; here such a tag is only left unread, as every other hello
/// tag rmule reads is.
fn serving_buddy_from_tags(tags: &[Tag]) -> Option<ServingBuddyAdvert> {
    let integer = |id: u8| {
        tags.iter()
            .rev()
            .find_map(|tag| match (tag.name().id(), tag.value()) {
                (Some(found), TagValue::U8(v)) if found == id => Some(u64::from(*v)),
                (Some(found), TagValue::U16(v)) if found == id => Some(u64::from(*v)),
                (Some(found), TagValue::U32(v)) if found == id => Some(u64::from(*v)),
                (Some(found), TagValue::U64(v)) if found == id => Some(*v),
                _ => None,
            })
    };
    #[allow(clippy::cast_possible_truncation)] // aMule's own `uint32`/`uint16` truncations
    let (ip, port) = (
        integer(CT_EMULE_BUDDYIP)? as u32,
        integer(CT_EMULE_BUDDYUDP)? as u16,
    );
    (ip != 0 && port != 0).then(|| ServingBuddyAdvert {
        buddy_udp: Ipv4Endpoint::new(Ipv4Addr::from(ip.to_le_bytes()), port),
        ipv6: PeerIpv6Tags::from_hello_tags(tags).serving_buddy_ipv6,
    })
}

/// The **Kad** UDP port a peer advertises in `CT_EMULE_UDPPORTS` — the high 16
/// bits of the packed int (the low 16 are the client UDP port, ADR-0057's
/// concern). `0` when the tag is absent or carries no Kad half. aMule
/// `ProcessHelloTypePacket`: `m_nKadPort = temptag.GetInt() >> 16`.
fn kad_udp_port_from_tags(tags: &[Tag]) -> u16 {
    hello_int(tags, CT_EMULE_UDPPORTS).map_or(0, |packed| (packed >> 16) as u16)
}
