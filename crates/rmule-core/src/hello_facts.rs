//! What a test peer's hello says, as the facts both halves of a connection
//! read off it, turned into the identity its session reports: one hello body
//! built from them, read by the peer crate's own reader.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_peer::{
    CT_EMULE_BUDDYIP, CT_EMULE_BUDDYUDP, ClientSoftware, ConnectionEvent, MiscOptions1,
    MiscOptions2, PeerHelloBody, PeerIdentity, SourceExchangeSupport, UdpPortsAdvert,
};
use rmule_primitives::{
    CT_MOD_IP_V6, ClientId, CryptStance, Ipv4Endpoint, Tag, TagName, TagValue, UserHash,
    ipv6_address_tag,
};

use crate::adapters::ServeInput;

/// A hello's facts, field by field.
pub(crate) struct HelloFacts {
    /// The user hash it names.
    pub(crate) user_hash: UserHash,
    /// Its server-assigned id.
    pub(crate) client_id: ClientId,
    /// The server it says it is logged in to.
    pub(crate) connected_server: Option<Ipv4Endpoint>,
    /// Its eD2k listen port.
    pub(crate) tcp_port: u16,
    /// Its client-UDP port (`CT_EMULE_UDPPORTS` low half), `0` for none.
    pub(crate) udp_port: u16,
    /// Its peer-UDP version (`MiscOptions1`).
    pub(crate) udp_version: u8,
    /// Its extended-requests claim (`MiscOptions1`).
    pub(crate) extended_requests_version: u8,
    /// Its crypt stance (`MiscOptions2`).
    pub(crate) crypt: CryptStance,
    /// The IPv6 it names (`CT_MOD_IP_V6`).
    pub(crate) ipv6: Option<Ipv6Addr>,
    /// The software it reads as.
    pub(crate) software: ClientSoftware,
    /// The serving buddy it names (`CT_EMULE_BUDDYIP` + `CT_EMULE_BUDDYUDP`).
    pub(crate) serving_buddy: Option<Ipv4Endpoint>,
    /// What its session read about source exchange (ADR-0108).
    pub(crate) source_exchange: SourceExchangeSupport,
}

impl HelloFacts {
    /// A hello naming `user_hash` and little else: a High ID on 4662 on no
    /// server, crypt-capable as aMule 2.3.3 advertises by default, claiming
    /// extended requests as aMule 2.3.3 does, with no reask contact, no
    /// IPv6, no buddy, nothing said about source exchange, and naming no
    /// client.
    pub(crate) fn of(user_hash: UserHash) -> Self {
        Self {
            user_hash,
            client_id: ClientId::from_u32(0x0100_007F),
            connected_server: None,
            tcp_port: 4662,
            udp_port: 0,
            udp_version: 0,
            extended_requests_version: 2,
            crypt: CryptStance::new(true, true, false),
            ipv6: None,
            software: nameless_software(),
            serving_buddy: None,
            source_exchange: SourceExchangeSupport::default(),
        }
    }

    /// The identity a session reads off a hello saying these facts.
    pub(crate) fn identity(self) -> PeerIdentity {
        let mut tags = vec![
            MiscOptions1::from_bits(u32::from(self.extended_requests_version) << 8)
                .with_udp_version(self.udp_version)
                .to_tag(),
            MiscOptions2::from_stance(self.crypt).to_tag(),
        ];
        if self.udp_port != 0 {
            tags.push(UdpPortsAdvert::new(self.udp_port, 0).to_tag());
        }
        if let Some(address) = self.ipv6 {
            tags.push(ipv6_address_tag(CT_MOD_IP_V6, address));
        }
        if let Some(buddy) = self.serving_buddy {
            let ip = u32::from_le_bytes(buddy.ip.octets());
            tags.push(Tag::new(
                TagName::compact_id(CT_EMULE_BUDDYIP),
                TagValue::U32(ip),
            ));
            tags.push(Tag::new(
                TagName::compact_id(CT_EMULE_BUDDYUDP),
                TagValue::U32(u32::from(buddy.port)),
            ));
        }
        PeerIdentity::from_hello_body(&PeerHelloBody {
            user_hash: self.user_hash,
            client_id: self.client_id,
            tcp_port: self.tcp_port,
            tags,
            connected_server: self
                .connected_server
                .unwrap_or_else(|| Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)),
        })
        .with_software(self.software)
        .with_source_exchange(self.source_exchange)
    }

    /// The identification its connection hands the Serve State.
    pub(crate) fn identified(self) -> ServeInput {
        ServeInput::Connection(ConnectionEvent::Identified {
            identity: self.identity(),
        })
    }
}

/// The identification a hello naming no user yields — what a test peer that
/// says nothing about its client is read as.
pub(crate) fn nameless_software() -> ClientSoftware {
    ClientSoftware::from_hello_body(&PeerHelloBody {
        user_hash: UserHash::from_bytes([0; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0),
        tcp_port: 0,
        tags: Vec::new(),
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    })
}
