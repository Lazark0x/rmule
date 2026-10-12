//! `OP_EMULEINFO` (`0xC5 0x01`) and `OP_EMULEINFOANSWER` (`0xC5 0x02`): the
//! capability exchange of the mules before 0.42 put `CT_EMULE_*` tags in the
//! hello — `<mule-version u8><protocol u8><count u32><tags>`.
//!
//! Read as aMule (`BaseClient.cpp:1106-1262`, Fork Pin `ab483654`) and eMule
//! (`BaseClient.cpp:734-884`, emule-qt `73fff714`) read it: protocol `0x01` is
//! the legacy block whose `ET_*` tags name a pre-0.42 mule's capabilities,
//! compatible code, mod and — in its first byte — the only version it sends;
//! `0xFF` is aMule's OS-info block, which says nothing about the client. The
//! tags are read with the hello's tolerance and bounds ([`crate::hello`]).
//!
//! rmule writes the legacy block only as the references do — answering one, or
//! to an accepted non-mule hello behind eMule's hash mark — and projects it from
//! the hello it advertises, so the two can never claim different capabilities
//! (ADR-0047).

use rmule_primitives::{Ed2kText, Packet, PacketProtocol, Tag, TagName, TagValue, WireReader};

use crate::capability::{CT_EMULE_UDPPORTS, MiscOptions1};
use crate::error::EmuleInfoDecodeError;
use crate::hello::{PeerHelloBody, decode_tags, hello_int, hello_text};
use crate::hello_tag::{CT_EMULE_VERSION, CT_MOD_VERSION};
use crate::software::ClientMod;

/// `OP_EMULEINFO` under the eMule protocol byte.
pub(crate) const OP_EMULEINFO: u8 = 0x01;
/// `OP_EMULEINFOANSWER` under the eMule protocol byte.
pub(crate) const OP_EMULEINFOANSWER: u8 = 0x02;
const EMULE_PROTOCOL: u8 = 0x01;
const OS_INFO_PROTOCOL: u8 = 0xFF;

const ET_COMPRESSION: u8 = 0x20;
const ET_UDPPORT: u8 = 0x21;
const ET_UDPVER: u8 = 0x22;
const ET_SOURCEEXCHANGE: u8 = 0x23;
const ET_COMMENTS: u8 = 0x24;
const ET_EXTENDEDREQUEST: u8 = 0x25;
const ET_COMPATIBLECLIENT: u8 = 0x26;
const ET_FEATURES: u8 = 0x27;
const ET_OS_INFO: u8 = 0x94;

/// The mule-version byte rmule writes: aMule's `CURRENT_VERSION_SHORT`
/// (`include/common/ClientVersion.h:39`), the first byte of stock aMule's own
/// `OP_EMULEINFO` in run `1790208592`'s capture — aMule's value, as rmule's
/// `CT_EMULE_VERSION` word is aMule's (ADR-0047).
const PARITY_MULE_VERSION: u8 = 0x47;

/// One `OP_EMULEINFO` / `OP_EMULEINFOANSWER` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmuleInfo {
    /// Protocol `0x01`: a pre-0.42 mule's capability block.
    Legacy(LegacyMuleInfo),
    /// Protocol `0xFF`: aMule's OS-info block, sent only to a peer whose hello
    /// asked for it (`CT_EMULECOMPAT_OPTIONS`, which rmule never sends).
    /// Identification is untouched by it (aMule `BaseClient.cpp:1113-1126`).
    OsInfo {
        /// `ET_OS_INFO`, when it rode.
        os: Option<Ed2kText>,
    },
    /// Any other protocol byte: aMule stops reading after the tag count
    /// (stock 2.3.3 `BaseClient.cpp:857`, `:893-895`), so its tags are never
    /// read and cannot fail the block. Its version byte is still recorded
    /// (`:886-891`).
    Other {
        /// The protocol byte it carried.
        protocol: u8,
        /// The mule-version byte (`0x2B` already read as `0x22`).
        mule_version: u8,
    },
}

/// A pre-0.42 mule's `OP_EMULEINFO` block, with the capabilities its version
/// implies already applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyMuleInfo {
    mule_version: u8,
    compatible_client: u8,
    client_mod: Option<ClientMod>,
    capabilities: MiscOptions1,
    udp_port: u16,
}

impl EmuleInfo {
    /// Read either opcode's body.
    ///
    /// # Errors
    /// A frame under another protocol byte or opcode, a body shorter than its
    /// header, or a tag the hello reader would also refuse.
    pub fn decode_packet(packet: &Packet) -> Result<Self, EmuleInfoDecodeError> {
        if packet.protocol() != PacketProtocol::Emule {
            return Err(EmuleInfoDecodeError::UnsupportedProtocol);
        }
        if !matches!(packet.opcode(), OP_EMULEINFO | OP_EMULEINFOANSWER) {
            return Err(EmuleInfoDecodeError::WrongOpcode {
                opcode: packet.opcode(),
            });
        }
        let mut reader = WireReader::new(packet.payload());
        let version = reader.read_u8("version")?;
        let protocol = reader.read_u8("protocol")?;
        let count = reader.read_u32_le("tag count")?;
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        let tag_bytes = reader.remaining_bytes();
        // The protocol byte decides before any tag is read: under any other
        // byte aMule returns with the count read and the tags unread.
        let tags = || decode_tags(tag_bytes, count).map(|(tags, _)| tags);
        Ok(match protocol {
            EMULE_PROTOCOL => Self::Legacy(LegacyMuleInfo::read(version, &tags()?)),
            OS_INFO_PROTOCOL => Self::OsInfo {
                os: hello_text(&tags()?, ET_OS_INFO).cloned(),
            },
            protocol => Self::Other {
                protocol,
                mule_version: read_mule_version(version),
            },
        })
    }
}

/// Both references read eMule 0.22b's `0x2B` as `0x22`, under any protocol
/// byte but OS info (stock aMule 2.3.3 `BaseClient.cpp:887-891`, eMule
/// `:742-743`).
const fn read_mule_version(byte: u8) -> u8 {
    if byte == 0x2B { 0x22 } else { byte }
}

impl LegacyMuleInfo {
    fn read(mule_version: u8, tags: &[Tag]) -> Self {
        let mule_version = read_mule_version(mule_version);
        let int = |id| hello_int(tags, id);
        let nibble = |id, implied: u8| int(id).map_or(implied, |v| (v & 0x0F) as u8);
        // The capabilities an old version implies (eMule `:746-749`), each
        // overridden by its tag.
        let udp_version = nibble(ET_UDPVER, u8::from((0x23..=0x24).contains(&mule_version)));
        let mut source_exchange = nibble(
            ET_SOURCEEXCHANGE,
            u8::from((0x22..=0x24).contains(&mule_version)),
        );
        let mut comments = nibble(ET_COMMENTS, u8::from(mule_version == 0x24));
        let compression = nibble(ET_COMPRESSION, 0);
        let mut extended_requests = nibble(ET_EXTENDEDREQUEST, 0);
        #[allow(clippy::cast_possible_truncation)] // both keep the port's 16 bits
        let mut udp_port = int(ET_UDPPORT).map_or(0, |port| port as u16);
        // A block without compression was a client that knew none of the
        // extended protocol (aMule `:1234-1239`, eMule `:872-877`).
        if compression == 0 {
            source_exchange = 0;
            extended_requests = 0;
            comments = 0;
            udp_port = 0;
        }
        let features = int(ET_FEATURES).unwrap_or(0);
        let capabilities = MiscOptions1::from_bits(
            (u32::from(udp_version) << 24)
                | (u32::from(compression) << 20)
                | ((features & 0x03) << 16)
                | (u32::from(source_exchange) << 12)
                | (u32::from(extended_requests) << 8)
                | (u32::from(comments) << 4)
                | ((features >> 7) & 0x01),
        );
        let client_mod = hello_text(tags, CT_MOD_VERSION)
            .map(|text| ClientMod::Named(text.clone()))
            .or_else(|| int(CT_MOD_VERSION).map(ClientMod::Numbered));
        Self {
            mule_version,
            // Reset to 0 before the tags are read (both references).
            compatible_client: int(ET_COMPATIBLECLIENT).map_or(0, |code| (code & 0xFF) as u8),
            client_mod,
            capabilities,
            udp_port,
        }
    }

    /// rmule's own block: every field projected from the hello it advertises
    /// (`advertised`), so an old mule is told exactly what a new one is.
    #[must_use]
    pub fn advertised(advertised: &PeerHelloBody) -> Self {
        let tags = &advertised.tags;
        #[allow(clippy::cast_possible_truncation)] // the low half is the client-UDP port
        let udp_port = hello_int(tags, CT_EMULE_UDPPORTS).map_or(0, |packed| packed as u16);
        Self {
            mule_version: PARITY_MULE_VERSION,
            compatible_client: hello_int(tags, CT_EMULE_VERSION)
                .map_or(0, |word| (word >> 24) as u8),
            client_mod: hello_text(tags, CT_MOD_VERSION).map(|text| ClientMod::Named(text.clone())),
            capabilities: MiscOptions1::from_tags(tags).unwrap_or(MiscOptions1::from_bits(0)),
            udp_port,
        }
    }

    /// The mule-version byte (`0x2B` already read as `0x22`).
    #[must_use]
    pub const fn mule_version(&self) -> u8 {
        self.mule_version
    }

    /// `ET_COMPATIBLECLIENT`, `0` when absent.
    #[must_use]
    pub const fn compatible_client(&self) -> u8 {
        self.compatible_client
    }

    /// `CT_MOD_VERSION`, when it rode.
    #[must_use]
    pub const fn client_mod(&self) -> Option<&ClientMod> {
        self.client_mod.as_ref()
    }

    /// The capabilities the block names, as the hello's `CT_EMULE_MISCOPTIONS1`
    /// word would carry them.
    #[must_use]
    pub const fn capabilities(&self) -> MiscOptions1 {
        self.capabilities
    }

    /// `ET_UDPPORT`, `0` when absent or cleared by a zero compression.
    #[must_use]
    pub const fn udp_port(&self) -> u16 {
        self.udp_port
    }

    /// Frame this block as `OP_EMULEINFO`, or as `OP_EMULEINFOANSWER` when
    /// `answer`. Tags in aMule's order (`BaseClient.cpp:1030-1081`), each an
    /// old-format length-prefixed name as aMule's captured block writes them.
    #[must_use]
    pub fn encode_packet(&self, answer: bool) -> Packet {
        let caps = self.capabilities;
        let bits = |shift: u32| (caps.bits() >> shift) & 0x0F;
        let mut tags = vec![
            int_tag(ET_COMPRESSION, bits(20)),
            int_tag(ET_UDPVER, bits(24)),
            int_tag(ET_UDPPORT, u32::from(self.udp_port)),
            int_tag(ET_SOURCEEXCHANGE, bits(12)),
            int_tag(ET_COMMENTS, bits(4)),
            int_tag(ET_EXTENDEDREQUEST, bits(8)),
            int_tag(ET_FEATURES, (bits(16) & 0x03) | ((caps.bits() & 0x01) << 7)),
            int_tag(ET_COMPATIBLECLIENT, u32::from(self.compatible_client)),
        ];
        match &self.client_mod {
            Some(ClientMod::Named(text)) => tags.push(Tag::new(
                TagName::length_prefixed_id(CT_MOD_VERSION),
                TagValue::String(text.clone()),
            )),
            Some(ClientMod::Numbered(id)) => tags.push(int_tag(CT_MOD_VERSION, *id)),
            None => {}
        }
        let mut payload = vec![self.mule_version, EMULE_PROTOCOL];
        payload.extend_from_slice(
            &u32::try_from(tags.len())
                .expect("a handful of tags")
                .to_le_bytes(),
        );
        for tag in &tags {
            payload.extend_from_slice(&tag.encode());
        }
        let opcode = if answer {
            OP_EMULEINFOANSWER
        } else {
            OP_EMULEINFO
        };
        Packet::new(PacketProtocol::Emule, opcode, payload)
    }
}

fn int_tag(id: u8, value: u32) -> Tag {
    Tag::new(TagName::length_prefixed_id(id), TagValue::U32(value))
}
