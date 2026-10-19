//! Protocol primitives for rmule: the value types every other crate speaks in.
//!
//! Everything here is pure data — hashes, endpoints, identities, links, frames,
//! tags, text, search and source rows, plus the obfuscation and Secure User
//! Identification cryptography the wire formats need. No I/O, no runtime, no
//! session state beyond the [`session`] traits the sans-I/O protocol crates
//! implement.

#![warn(missing_docs)]

mod address;
mod aich;
mod capabilities;
mod datagram_obfuscation;
mod endpoint;
mod error;
mod file_class;
mod file_name;
mod hash;
mod identity;
mod ipv6_dialect;
mod link;
mod obfuscation;
mod opcode_macro;
mod packed_frame;
mod packet;
mod peer;
mod peer_crypt;
mod search;
mod secure_ident;
mod server;
pub mod session;
mod source;
mod tag;
mod text;
mod wire_reader;

pub use address::{Informant, is_reserved_address, is_reserved_ipv4, is_reserved_ipv6};
pub use aich::{AichHashSet, EMBLOCKSIZE, aich_block_hash};
pub use capabilities::{Capabilities, CryptStance};
pub use datagram_obfuscation::{
    ClientDecryptKeys, ClientEncryptKey, DatagramKeyFamily, DatagramNonce, DatagramSenderAddress,
    DecryptedDatagram, MAGICVALUE_UDP, MAGICVALUE_UDP_CLIENTSERVER, MAGICVALUE_UDP_SERVERCLIENT,
    MAGICVALUE_UDP_SYNC_CLIENT, MAGICVALUE_UDP_SYNC_SERVER, ServerCryptDirection,
    datagram_key_ed2k, datagram_key_kad_node, datagram_key_kad_verify, datagram_key_server,
    decrypt_datagram_client, decrypt_datagram_server, ed2k_key_material, encrypt_datagram_client,
    encrypt_datagram_server, is_udp_plaintext_marker, marker_family,
};
pub use endpoint::{AddressFamily, Ipv4Endpoint, Ipv6Endpoint};
pub use error::{PrimitiveError, Result};
pub use file_class::Ed2kFileClass;
pub use file_name::SafeFileName;
pub use hash::{
    AichRootHash, ED2K_PART_SIZE, FileHash, FileHashSummary, MAX_ED2K_FILE_SIZE, PartHash,
    PartHashSet, ServerHash, UserHash, ed2k_status_part_count, kad_wire_id, part_count,
};
pub use hash::{OLD_MAX_FILE_SIZE, is_large_file};
pub use identity::{ClientId, ClientIdentity, ServerEndpoint};
pub use ipv6_dialect::{
    AccountingKey, CT_EMULE_SERVINGBUDDYIPV6, CT_MOD_IP_V6, CT_MOD_MISCOPTIONS, CT_MOD_SVR_IP_V6,
    CT_MOD_YOUR_IP, ST_IPV6, ST_IPV6_STATUS, ServerIpv6Status, ipv6_address_tag,
    ipv6_address_tag_compact, is_usable_tag_identity, read_ipv6_address_tag,
};
pub use link::{
    Ed2kFileLink, Ed2kLink, Ed2kServerLink, Ed2kServerListLink, LinkPeer, LinkPeerHost, LinkRead,
    LinkSourceExpiry, LinkSources,
};
pub use obfuscation::{
    DH_PRIME_SIZE, ENM_OBFUSCATION, MAGICVALUE_REQUESTER, MAGICVALUE_SERVER, MAGICVALUE_SYNC,
    ObfuscationDhKeypair, ObfuscationKeys, ObfuscationRole, Rc4, derive_peer_keys,
    derive_server_keys, is_plaintext_marker,
};
pub use packed_frame::{SkipReason, inflate, pack_if_smaller};
pub use packet::{Packet, PacketProtocol};
pub use peer::PeerEndpoint;
pub use peer_crypt::{OutboundCrypt, PeerCrypt};
pub use search::{
    KeywordQuery, QueryFault, RelatedFilesQuery, SearchQuery, SearchResult, SearchResultKey,
    SearchResultOrigin,
};
pub use secure_ident::{SUI_RSA_KEY_BITS, SecureIdentKey, SecureIdentPublicKey};
pub use server::{
    ServerIdentSource, ServerIdentity, ServerStatusReport, ServerTcpFlag, ServerTcpFlags,
    ServerUdpFlag, ServerUdpFlags,
};
pub use session::{SessionCore, SessionOutput};
pub use source::{
    PeerSource, SightedBuddy, SourceClaim, SourceCryptOptions, SourceListTail, SourceLookupTarget,
    SourceRoad, SourceSighting,
};
pub use tag::{HASH_TAG_LEN, Tag, TagName, TagNameEncoding, TagValue};
pub use text::Ed2kText;
pub use wire_reader::{WireReader, WireTruncated};
