//! `OP_LOGINREQUEST` (0x01): the hello that opens a server session, carrying
//! this node's user hash, endpoint and capability tags.
//!
//! The advertised tag set is pinned to what aMule actually emits (ADR-0047),
//! down to the tags it deliberately never sends — a caller-supplied extra tag
//! cannot smuggle one of those back onto the wire.

use std::net::Ipv6Addr;

use rmule_primitives::{
    CT_MOD_IP_V6, Capabilities, ClientId, ClientIdentity, Packet, PacketProtocol, Tag, TagName,
    TagValue, UserHash, ipv6_address_tag,
};

use crate::{Ed2kError, Opcode, Result};

/// aMule client login tag IDs (per the handwritten login fixture and
/// `src/include/protocol/ed2k/Client2Server/TCP.h` / `ClientTCPSocket.cpp`
/// references in `docs/reference/notes/ed2k-server-protocol.md`).
/// `CLIENT_TAG_PORT` is never emitted — aMule 2.3.3 sends the port only as
/// the login's fixed field (`ServerConnect.cpp#L232` keeps the tag
/// commented out) — but stays in the collision-drop set so an `extra_tags`
/// caller cannot smuggle it back onto the wire (ADR-0047).
const CLIENT_TAG_NAME: u8 = 0x01;
const CLIENT_TAG_PORT: u8 = 0x0F;
const CLIENT_TAG_VERSION: u8 = 0x11;
const CLIENT_TAG_SERVER_FLAGS: u8 = 0x20;
const CLIENT_TAG_EMULE_VERSION: u8 = 0xFB;

/// `CT_SERVER_FLAGS` capability bits, pinned from aMule
/// `src/include/protocol/ed2k/Client2Server/TCP.h#L109-L120` @ `4e8f2b3c`
/// (`SRVCAP_*`). Only the bits rmule can honestly light are named;
/// `SRVCAP_IP_IN_LOGIN 0x02` stays unmodelled (aMule never sends it
/// either).
const SRVCAP_ZLIB: u32 = 0x0001;
const SRVCAP_AUXPORT: u32 = 0x0004;
const SRVCAP_NEWTAGS: u32 = 0x0008;
const SRVCAP_UNICODE: u32 = 0x0010;
const SRVCAP_LARGEFILES: u32 = 0x0100;
const SRVCAP_SUPPORTCRYPT: u32 = 0x0200;
const SRVCAP_REQUESTCRYPT: u32 = 0x0400;
const SRVCAP_REQUIRECRYPT: u32 = 0x0800;
/// `SRVCAP_IPV6` (ADR-0087 §4.1) — deliberately **not** derived from the
/// capability registry beside the bits above, and the one flag here that is
/// not a statement about what rmule can speak.
///
/// It is strictly coupled to the `CT_MOD_IP_V6` tag ("send both or neither"),
/// so it says *where rmule can be found*, which is a fact about an address and
/// not a capability. ADR-0047's Honest Capability Advertisement is untouched:
/// the registry still owns every bit that claims an ability, and this one is
/// written by the same `if let` that writes the tag, so the two cannot
/// disagree.
///
/// Which of the pair a server actually gates on is server-dependent and is
/// **not** the bit: at least one ignores `CT_SERVER_FLAGS` except for the
/// crypt bits and decides sentinel-safety from the tag's presence, or from the
/// session having arrived over IPv6.
const SRVCAP_IPV6: u32 = 0x1000;

/// Pack the `CT_SERVER_FLAGS` value from the capability registry
/// (ADR-0047): every bit is registry-derived, never aspirational —
/// aMule's inline `CAPABLE_*` assembly (`ServerConnect.cpp#L241`) with
/// the honest-advert invariant enforced by the registry instead of the
/// emit site.
#[must_use]
pub fn server_capability_flags(capabilities: &Capabilities) -> u32 {
    let mut flags = 0;
    if capabilities.accepts_compressed_server_frames() {
        flags |= SRVCAP_ZLIB;
    }
    if capabilities.supports_aux_port() {
        flags |= SRVCAP_AUXPORT;
    }
    if capabilities.accepts_new_tags() {
        flags |= SRVCAP_NEWTAGS;
    }
    if capabilities.accepts_unicode() {
        flags |= SRVCAP_UNICODE;
    }
    if capabilities.supports_large_files() {
        flags |= SRVCAP_LARGEFILES;
    }
    let crypt = capabilities.crypt();
    if crypt.supports() {
        flags |= SRVCAP_SUPPORTCRYPT;
    }
    if crypt.requests() {
        flags |= SRVCAP_REQUESTCRYPT;
    }
    if crypt.requires() {
        flags |= SRVCAP_REQUIRECRYPT;
    }
    flags
}

const LOGIN_FIXED_BODY_LEN: usize = 26;

/// `CT_EMULE_UDPPORTS` (`0xF9`) as a **login** tag: `(kadUDP << 16) |
/// clientUDP`. On the peer hello this tag is old and universal; on the server
/// login it is ed2k-server's NAT-T contract (ADR-0091), where it does double
/// duty — it tells the server where a punch should be aimed when it has
/// observed nothing better, and its presence **is** the capability flag: a
/// client that sent none is refused as a punch target (`FAIL_TARGET_NO_UDP`).
/// Lugdunum-family servers already parse the tag, so it is safe to send to a
/// server that does nothing with it.
const CT_EMULE_UDPPORTS: u8 = 0xF9;

/// The two UDP ports the login's `0xF9` tag carries.
///
/// Its presence claims rmule can be punched, so it is built only by a caller
/// that holds a bound client-UDP socket — Honest Capability Advertisement
/// (ADR-0047) applied to a tag that happens to be a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpPortsAdvert {
    /// Our Kad UDP port, or `0` when Kad is not running.
    pub kad_udp: u16,
    /// Our client-UDP port — where a punch must land, and the socket the
    /// `0x9F` keepalive leaves from.
    pub client_udp: u16,
}

impl UdpPortsAdvert {
    /// The tag's value.
    #[must_use]
    pub const fn word(self) -> u32 {
        (self.kad_udp as u32) << 16 | self.client_udp as u32
    }
}

/// What a login says beyond identity and capabilities — each field a fact
/// settled elsewhere and absent by default, so a login with none of them is
/// byte for byte aMule 2.3.3's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoginAdvert {
    /// ADR-0087: the address the Advertised Endpoints chooser settled. Rides
    /// as `CT_MOD_IP_V6` together with `SRVCAP_IPV6`, or not at all.
    pub ipv6: Option<Ipv6Addr>,
    /// ADR-0091: the `0xF9` tag, when a client-UDP socket is bound.
    pub udp_ports: Option<UdpPortsAdvert>,
}

/// `OP_LOGINREQUEST`: who we are and what we can do, the first thing a client
/// sends.
///
/// The capability tags are what decide how the rest of the session is spoken,
/// so the server's answer is a reply to this packet's claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginRequest {
    user_hash: UserHash,
    client_id: ClientId,
    tcp_port: u16,
    tags: Vec<Tag>,
}

impl LoginRequest {
    /// A login from its four wire fields, with the tag list supplied as-is —
    /// see [`Self::from_identity`] for the capability-registry path.
    #[must_use]
    pub fn new(user_hash: UserHash, client_id: ClientId, tcp_port: u16, tags: Vec<Tag>) -> Self {
        Self {
            user_hash,
            client_id,
            tcp_port,
            tags,
        }
    }

    /// Build a login packet from application-layer identity plus the
    /// capability registry (ADR-0047). Server assigns the real `client_id`
    /// later (so `0` here is the standard placeholder). No IPv6 advert —
    /// [`from_identity_advertising`](Self::from_identity_advertising) is the
    /// path that carries one. The wire shape matches aMule 2.3.3 exactly
    /// (`ServerConnect.cpp#L219-L259`):
    /// tagcount 4 — `CT_NAME`, `CT_VERSION`, `CT_SERVER_FLAGS`,
    /// `CT_EMULE_VERSION` in that order, the port riding only the fixed
    /// field (no `CT_PORT` tag). The flags and version tags are
    /// registry-derived, never aspirational. Tags in
    /// `ClientIdentity::extra_tags` whose name collides with a canonical
    /// ID (including the never-emitted `CLIENT_TAG_PORT`) are silently
    /// dropped to keep the typed emission authoritative —
    /// `ClientIdentity` is a config struct without invariant enforcement,
    /// so this is the defensive boundary.
    #[must_use]
    pub fn from_identity(identity: &ClientIdentity, capabilities: &Capabilities) -> Self {
        Self::from_identity_advertising(identity, capabilities, LoginAdvert::default())
    }

    /// [`from_identity`](Self::from_identity) plus ADR-0087's IPv6 advert: the
    /// `CT_MOD_IP_V6` (`0xAE`) tag and the `SRVCAP_IPV6` (`0x1000`) flag bit,
    /// written **together or not at all**.
    ///
    /// `advertised_ipv6` is what the Advertised Endpoints chooser settled
    /// (ADR-0084: Known *and* not probed-unreachable), so the pair only rides
    /// for an address a server could actually reach — the tag is the fact, and
    /// a tag naming an address rmule cannot be reached at would open a capable
    /// server's sentinel gate and then publish a dead source.
    ///
    /// ADR-0091's `CT_EMULE_UDPPORTS` (`0xF9`) rides after it when
    /// [`LoginAdvert::udp_ports`] is set — see [`UdpPortsAdvert`].
    ///
    /// `ST_IPV6_STATUS` is never sent by a client; it is receive-only.
    /// `OP_OFFERFILES` carries no IPv6 tag either.
    ///
    /// The tag rides the **old** length-prefixed name format like every other
    /// login tag: the server has not parsed `SRVCAP_NEWTAGS` when it starts
    /// reading them, and a new-format tag is a parse failure and an immediate
    /// disconnect on real servers.
    #[must_use]
    pub fn from_identity_advertising(
        identity: &ClientIdentity,
        capabilities: &Capabilities,
        advert: LoginAdvert,
    ) -> Self {
        let advertised_ipv6 = advert.ipv6;
        let extras = identity.extra_tags();
        let mut tags = Vec::with_capacity(6 + extras.len());
        tags.push(Tag::new(
            TagName::length_prefixed_id(CLIENT_TAG_NAME),
            TagValue::String(identity.nickname().clone()),
        ));
        tags.push(Tag::new(
            TagName::length_prefixed_id(CLIENT_TAG_VERSION),
            TagValue::U32(identity.protocol_version()),
        ));
        let mut flags = server_capability_flags(capabilities);
        if advertised_ipv6.is_some() {
            flags |= SRVCAP_IPV6;
        }
        tags.push(Tag::new(
            TagName::length_prefixed_id(CLIENT_TAG_SERVER_FLAGS),
            TagValue::U32(flags),
        ));
        tags.push(Tag::new(
            TagName::length_prefixed_id(CLIENT_TAG_EMULE_VERSION),
            TagValue::U32(capabilities.emule_version_word()),
        ));
        if let Some(address) = advertised_ipv6 {
            // The fifth tag, and the flag bit above, are one decision written
            // in one place — the coupling the spec states as "send both or
            // neither" is therefore structural rather than a rule to remember.
            tags.push(ipv6_address_tag(CT_MOD_IP_V6, address));
        }
        if let Some(ports) = advert.udp_ports {
            // After the IPv6 tag, so neither advert moves the other. Old
            // length-prefixed name format, for the reason given above.
            tags.push(Tag::new(
                TagName::length_prefixed_id(CT_EMULE_UDPPORTS),
                TagValue::U32(ports.word()),
            ));
        }
        tags.extend(
            extras
                .iter()
                .filter(|t| !is_canonical_login_tag(t))
                .cloned(),
        );
        Self {
            user_hash: identity.user_hash(),
            client_id: ClientId::from_u32(0),
            tcp_port: identity.tcp_port(),
            tags,
        }
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidLogin {
                reason: "unsupported packet protocol",
            });
        }
        let opcode = Opcode::from_u8(packet.opcode())?;
        if opcode != Opcode::LoginRequest {
            return Err(Ed2kError::InvalidLogin {
                reason: "wrong login opcode",
            });
        }

        let payload = packet.payload();
        if payload.len() < LOGIN_FIXED_BODY_LEN {
            return Err(Ed2kError::InvalidLogin {
                reason: "truncated login body",
            });
        }

        let user_hash = UserHash::from_bytes(
            payload[0..16]
                .try_into()
                .expect("validated login user hash length"),
        );
        let client_id = ClientId::from_u32(u32::from_le_bytes(
            payload[16..20]
                .try_into()
                .expect("validated login client ID length"),
        ));
        let tcp_port = u16::from_le_bytes(
            payload[20..22]
                .try_into()
                .expect("validated login TCP port length"),
        );
        let tag_count = u32::from_le_bytes(
            payload[22..26]
                .try_into()
                .expect("validated login tag count length"),
        );
        let tag_count = usize::try_from(tag_count).map_err(|_| Ed2kError::InvalidLogin {
            reason: "tag count too large",
        })?;

        let (tags, consumed) = Tag::decode_block(&payload[LOGIN_FIXED_BODY_LEN..], tag_count)?;
        let position = LOGIN_FIXED_BODY_LEN + consumed;
        if position != payload.len() {
            return Err(Ed2kError::InvalidLogin {
                reason: "trailing login bytes",
            });
        }

        Ok(Self {
            user_hash,
            client_id,
            tcp_port,
            tags,
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        let mut payload = Vec::with_capacity(LOGIN_FIXED_BODY_LEN + encoded_tag_len(&self.tags));
        payload.extend_from_slice(self.user_hash.as_bytes());
        payload.extend_from_slice(&self.client_id.as_u32().to_le_bytes());
        payload.extend_from_slice(&self.tcp_port.to_le_bytes());
        payload.extend_from_slice(
            &u32::try_from(self.tags.len())
                .expect("login tag count exceeds u32")
                .to_le_bytes(),
        );
        for tag in &self.tags {
            payload.extend_from_slice(&tag.encode());
        }
        Packet::new(
            PacketProtocol::Edonkey,
            Opcode::LoginRequest.as_u8(),
            payload,
        )
    }

    /// The identity we log in under — stable across sessions, unlike the
    /// assigned client id.
    #[must_use]
    pub const fn user_hash(&self) -> UserHash {
        self.user_hash
    }

    /// The id we claim; the server overrides it with the one it assigns.
    #[must_use]
    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// The port we listen on — what the server dials back to decide High or
    /// Low ID.
    #[must_use]
    pub const fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    /// The capability tags, in wire order.
    #[must_use]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }
}

fn encoded_tag_len(tags: &[Tag]) -> usize {
    tags.iter().map(|tag| tag.encode().len()).sum()
}

/// Match a tag whose numeric name collides with one of the canonical
/// login-tag IDs that `from_identity` already emits typed — or with
/// `CLIENT_TAG_PORT`, which aMule never sends and must not reappear via
/// `extra_tags`. Returns false for text-named tags (which can't collide
/// with numeric IDs).
fn is_canonical_login_tag(tag: &Tag) -> bool {
    matches!(
        tag.name().id(),
        Some(
            CLIENT_TAG_NAME
                | CLIENT_TAG_VERSION
                | CLIENT_TAG_PORT
                | CLIENT_TAG_SERVER_FLAGS
                | CLIENT_TAG_EMULE_VERSION
                // `CT_MOD_IP_V6` joins the drop set for the same reason as the
                // rest: an `extra_tags` caller naming an address rmule never
                // settled would break the tag/flag coupling from the outside.
                | CT_MOD_IP_V6
                // And `0xF9`: its presence is a capability claim, so it is
                // never an `extra_tags` caller's to make.
                | CT_EMULE_UDPPORTS
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made bytes, not a capture: a well-formed login body whose tag count is
    /// `u32::MAX` with one tag behind it.
    #[test]
    fn a_made_login_claiming_four_billion_tags_is_refused_without_reserving_them() {
        let mut payload: Vec<u8> = (0x40..0x50).collect();
        payload.extend_from_slice(&[0, 0, 0, 0, 0x36, 0x12]);
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        payload.extend_from_slice(&[0x89, 0x11, 0x3C]);
        let packet = Packet::new(PacketProtocol::Edonkey, 0x01, payload);

        assert!(LoginRequest::decode_packet(&packet).is_err());
    }
}
