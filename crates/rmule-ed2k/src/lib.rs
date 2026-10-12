//! The eD2k **server** protocol: what a client says to an index server.
//!
//! Sans-I/O throughout — a codec per server opcode and the [`Ed2kSession`]
//! state machine that sequences a whole conversation, from login through
//! search, source lookup and the UDP status chain. The driver that owns the
//! socket and the clock lives in `rmule-net` (ADR-0081, ADR-0021).
//!
//! A well-formed frame rmule has no model for keeps its bytes rather than
//! ending the session (ADR-0018).

#![warn(missing_docs)]

mod callback;
mod client_packet;
mod close_reason;
mod compressed_frame;
mod error;
mod found_sources;
mod get_server_list;
mod get_sources;
mod holepunch;
mod id_change;
mod login;
mod obfuscation;
mod offer_files;
mod opcode;
mod peer_callback;
mod reject;
mod related_search_request;
mod search_more_request;
mod search_request;
mod search_result;
mod server_ident;
mod server_list;
mod server_message;
mod server_met;
mod server_packet;
mod server_status;
mod server_tcp_flags;
mod server_udp;
mod service;
mod session;
mod source_record;

pub use callback::{CallbackFailed, CallbackRequest};
pub use client_packet::ClientPacket;
pub use close_reason::CloseReason;
pub use compressed_frame::{CompressedFrameSkipReason, SERVER_COMPRESSED_FRAME_LIMIT};
pub use error::{Ed2kError, Result};
pub use found_sources::{FoundSources, FoundSourcesObfu};
pub use get_server_list::GetServerList;
pub use get_sources::GetSourcesRequest;
pub use holepunch::{
    HolepunchFail, HolepunchFailReason, HolepunchInfo, HolepunchRequest, HolepunchRole,
    natt_keepalive_datagram, natt_keepalive_port,
};
pub use id_change::IdChange;
pub use login::{LoginAdvert, LoginRequest, UdpPortsAdvert, server_capability_flags};
pub use obfuscation::{ServerObfuscation, ServerObfuscationStep};
pub use offer_files::{
    COMPLETE_FILE_ID, COMPLETE_FILE_PORT, FileCompleteness, INCOMPLETE_FILE_ID,
    INCOMPLETE_FILE_PORT, OfferEntry, OfferFiles, OfferedFile,
};
pub use opcode::Opcode;
pub use peer_callback::{PeerCallback, PeerCallbackCrypt, PeerCallbackIpv6};
pub use reject::Reject;
pub use related_search_request::RelatedSearchRequest;
pub use rmule_primitives::{ServerTcpFlags, ServerUdpFlags};
pub use search_more_request::QueryMoreResults;
pub use search_request::{MAX_EXPRESSION_DEPTH, SearchRequest};
pub use search_result::{SearchResultSkipReason, SearchResults};
pub use server_ident::ServerIdent;
pub use server_list::{ServerList, ServerListTail};
pub use server_message::ServerMessage;
pub use server_met::{
    ServerMet, ServerMetEntry, ServerMetError, ServerMetFigures, ServerMetObfuscation,
    ServerPriority,
};
pub use server_packet::ServerPacket;
pub use server_status::ServerStatus;
pub use server_tcp_flags::ServerGrants;
pub use server_udp::{
    GlobCallbackRequest, GlobFoundSources, GlobGetSources, GlobGetSources2, GlobSearchReq,
    GlobSearchRes, GlobSearchVariant, GlobServStatReq, GlobServStatRes, ServerDescReq,
    ServerDescRes, ServerDescTags, crypt_ping_challenge, crypt_ping_padding_len,
};
pub use service::{
    CommandRejectReason, Ed2kCommand, Ed2kCommandKind, Ed2kEvent, ServerAssignedFacts,
    ServerCapability,
};
pub use session::{Ed2kSession, Output, SessionError};
