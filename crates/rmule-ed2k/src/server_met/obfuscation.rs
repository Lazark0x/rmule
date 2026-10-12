//! A server.met row's obfuscation facts: the tags aMule reads to know how to
//! key traffic to a server. `ST_UDPFLAGS` (whose `TCPOBFUSCATION` bit says it
//! takes obfuscated TCP) and `ST_TCPPORTOBFUSCATION` (where) —
//! `SupportsObfuscationTCP()` needs both (`Server.h:163-168`) — and the UDP
//! half: `ST_UDPPORTOBFUSCATION`, the `ServerUDPKey` in `ST_UDPKEY` and the
//! public IPv4 it was learned under in `ST_UDPKEYIP`. aMule reads them back
//! in `CServer::AddTagFromFile` (`Server.cpp:236-251`) and writes each only
//! when non-zero (`ServerList.cpp:783-797`).

use std::net::Ipv4Addr;

use rmule_primitives::{Tag, TagName, TagValue};

/// `ST_UDPFLAGS` — the server's UDP flags word.
const TAG_UDPFLAGS: u8 = 0x92;
/// `ST_UDPKEY` — the `ServerUDPKey` the server derived for us.
const TAG_UDPKEY: u8 = 0x95;
/// `ST_UDPKEYIP` — our public IPv4 when that key was learned.
const TAG_UDPKEYIP: u8 = 0x96;
/// `ST_TCPPORTOBFUSCATION` — the port it takes obfuscated TCP on, a `u16`.
const TAG_TCPPORTOBFUSCATION: u8 = 0x97;
/// `ST_UDPPORTOBFUSCATION` — the port it takes obfuscated UDP on, a `u16`.
const TAG_UDPPORTOBFUSCATION: u8 = 0x98;

/// What one server.met row said about obfuscated TCP. Each field is `None`
/// when its tag was absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerMetObfuscation {
    /// `ST_UDPFLAGS`, as written.
    pub udp_flags: Option<u32>,
    /// `ST_TCPPORTOBFUSCATION`, narrowed to `u16` as aMule's setter does.
    pub tcp_port: Option<u16>,
    /// `ST_UDPPORTOBFUSCATION`, narrowed to `u16` as aMule's setter does.
    pub udp_port: Option<u16>,
    /// `ST_UDPKEY`: the `ServerUDPKey`. A zero is aMule's "no key" and reads
    /// as absent.
    pub udp_key: Option<u32>,
    /// `ST_UDPKEYIP`: our public IPv4 when the key was learned, in the byte
    /// order every address in the file has. A zero reads as absent.
    pub udp_key_ip: Option<Ipv4Addr>,
}

impl ServerMetObfuscation {
    /// A row that said nothing about obfuscation.
    pub const NONE: Self = Self {
        udp_flags: None,
        tcp_port: None,
        udp_port: None,
        udp_key: None,
        udp_key_ip: None,
    };

    /// Fold one tag of a row in; a tag that is not an obfuscation fact is
    /// left alone.
    pub(super) fn read(&mut self, tag: &Tag) {
        let value = match tag.value() {
            TagValue::U8(v) => u32::from(*v),
            TagValue::U16(v) => u32::from(*v),
            TagValue::U32(v) => *v,
            _ => return,
        };
        match tag.name().id() {
            Some(TAG_UDPFLAGS) => self.udp_flags = Some(value),
            Some(TAG_TCPPORTOBFUSCATION) => self.tcp_port = Some(value as u16),
            Some(TAG_UDPPORTOBFUSCATION) => self.udp_port = Some(value as u16),
            Some(TAG_UDPKEY) => self.udp_key = Some(value).filter(|key| *key != 0),
            Some(TAG_UDPKEYIP) => {
                self.udp_key_ip =
                    Some(Ipv4Addr::from(value.to_le_bytes())).filter(|ip| !ip.is_unspecified());
            }
            _ => {}
        }
    }

    /// Take the facts `fresh` states, keeping ours where it is silent.
    pub(super) fn overlaid_by(self, fresh: Self) -> Self {
        Self {
            udp_flags: fresh.udp_flags.or(self.udp_flags),
            tcp_port: fresh.tcp_port.or(self.tcp_port),
            udp_port: fresh.udp_port.or(self.udp_port),
            udp_key: fresh.udp_key.or(self.udp_key),
            udp_key_ip: fresh.udp_key_ip.or(self.udp_key_ip),
        }
    }

    /// The tags these facts write, each only when present — the reader's
    /// inverse.
    pub(super) fn tags(&self) -> Vec<Tag> {
        let mut tags = Vec::new();
        if let Some(flags) = self.udp_flags {
            tags.push(Tag::new(
                TagName::compact_id(TAG_UDPFLAGS),
                TagValue::U32(flags),
            ));
        }
        if let Some(port) = self.tcp_port {
            tags.push(Tag::new(
                TagName::compact_id(TAG_TCPPORTOBFUSCATION),
                TagValue::U16(port),
            ));
        }
        if let Some(key) = self.udp_key {
            tags.push(Tag::new(
                TagName::compact_id(TAG_UDPKEY),
                TagValue::U32(key),
            ));
        }
        if let Some(ip) = self.udp_key_ip {
            tags.push(Tag::new(
                TagName::compact_id(TAG_UDPKEYIP),
                TagValue::U32(u32::from_le_bytes(ip.octets())),
            ));
        }
        if let Some(port) = self.udp_port {
            tags.push(Tag::new(
                TagName::compact_id(TAG_UDPPORTOBFUSCATION),
                TagValue::U16(port),
            ));
        }
        tags
    }
}
