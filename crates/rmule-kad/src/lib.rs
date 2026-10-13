//! The sans-I/O Kad protocol surface: the Kad2 node state machine, its wire
//! codecs, and the routing, storage and walk machinery it drives. Nothing here
//! reads a clock, opens a socket or draws randomness — a driver feeds
//! datagrams, commands and instants in, and drains datagrams and events out
//! (ADR-0043).

#![warn(missing_docs)]

mod bootstrap;
mod buddy;
mod envelope;
mod evidence;
mod flood;
mod id;
pub mod ipv6_tags;
pub mod keyword;
pub mod keyword_publisher;
pub mod keyword_store;
mod lookup;
mod lookup_walk;
mod messages;
mod net;
mod node;
mod nodes_dat;
mod nodes_dat_bootstrap;
pub mod notes;
pub mod opcode;
mod reachability;
mod routing;
pub mod search_tree;
mod source_result;
mod source_store;
mod time;
mod udp_key;
mod wire_fields;

pub use bootstrap::{BootstrapDialList, KadBootstrapNode, KadNodeEndpoint};
pub use buddy::BuddyDecodeError;
pub use envelope::{
    KadDecoded, KadEnvelope, KadEnvelopeDecodeError, KadProtocol, MAX_INFLATED_KAD_PAYLOAD,
    decode_exact,
};
pub use evidence::KadEvidence;
pub use id::{KadDistance, KadId};
pub use keyword::KadKeywordSearchRequest;
pub use keyword_publisher::KadSharedFile;
pub use keyword_store::{KadKeywordResult, KeywordResultRow};
pub use lookup::{
    KadBuddyContact, KadPublishPosture, KadPublishRequest, KadSourceCandidate, KadSourceDiagnostic,
    KadSourceLookupRequest, KadSourceRowFacts,
};
pub use lookup_walk::{KadPublishEnd, KadSearchEnd};
pub use messages::{
    Kad2Message, Kad2MessageDecodeError, Kad2NodeInfo, KadPublishedSource,
    MISC_OPTIONS_ACK_REQUEST, MISC_OPTIONS_TCP_FIREWALLED, MISC_OPTIONS_UDP_FIREWALLED,
};
pub use node::{
    KadCallbackWalkEnd, KadCommand, KadContactAdmission, KadEvent, KadNode, KadNodeConfig,
    KadNodeDiagnostic, KadNodeStart, KadObfuscation, KadOutput, KadPublishRejection,
    KadReachability, KadSelfCheck, RoutingCensus, UdpFirewallHelper,
};
pub use nodes_dat::{CONTACT_FILE_LIMIT, MIN_CONTACTS_TO_WRITE, NodesDat, NodesDatError};
pub use nodes_dat_bootstrap::BootstrapEditionError;
pub use reachability::FirewallDecodeError;
pub use routing::{
    KadAdmissionCap, KadContact, KadContactState, KadRoutingTable, KadRoutingUpdate,
};
pub use source_result::{
    KadSourceResultDecodeError, KadSourceRow, SOURCE_RESULT_BLOCKED_BY,
    SOURCE_RESULT_ROWS_PER_DATAGRAM, decode_source_result, encode_source_result,
};
pub use time::KadInstant;
pub use udp_key::{KadUdpKey, udp_verify_key};

/// Re-exported for [`KadNodeConfig`] construction: drivers inject the eD2k
/// User Hash the publisher announces without needing a direct
/// `rmule-primitives` dependency.
pub use rmule_primitives::UserHash;

/// Re-exported for publish/search request construction ([`KadPublishRequest`],
/// [`KadSourceLookupRequest`]): the interop stimulus node names the file to
/// publish and search for without a direct `rmule-primitives` dependency.
pub use rmule_primitives::{FileHash, SourceLookupTarget};

/// Re-exported because it is the parameter type of
/// [`KadObfuscation::new`]: a driver supplying the per-packet
/// entropy has to be able to name what it returns.
pub use rmule_primitives::DatagramNonce;
