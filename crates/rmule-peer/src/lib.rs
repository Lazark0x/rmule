//! The eD2k **peer** protocol: what one client says to another.
//!
//! Sans-I/O throughout — codecs for every peer-to-peer opcode rmule models,
//! and the [`PeerSession`] state machine that sequences them. No socket, no
//! clock, no runtime: the driver half lives in `rmule-net` (ADR-0081).
//!
//! A connection carries both capabilities at once (ADR-0031): the
//! **Requester Capability** that chases parts and the **Server Capability**
//! that serves them. Unknown well-formed frames keep their bytes rather than
//! ending the conversation (ADR-0018).

#![warn(missing_docs)]

mod aich;
mod buddy;
mod capability;
mod compress;
mod compressed_frame;
mod emule_info;
mod error;
pub mod file;
mod file_request;
mod handshake;
mod hash_set;
mod hello;
mod hello_tag;
mod human_layer;
mod identity;
mod ipv6;
pub mod multipacket;
pub mod natt;
mod obfuscation;
mod opcode;
mod packet;
mod parts;
mod reask;
mod secure_ident;
mod session;
mod slot;
mod software;
mod source_exchange;

pub use aich::{AichAnswer, AichDecodeError, AichFileHashAns, AichFileHashReq, AichRequest};
pub use buddy::{BuddyRelayDecodeError, Callback, ReaskCallbackTcp};
pub use capability::{MiscOptions1, MiscOptions2, ModMiscOptions, UdpPortsAdvert};
pub use compress::InflateFailed;
pub use compressed_frame::{
    CompressedFrameSkipReason, PEER_COMPRESSED_FRAME_LIMIT, PEER_PACK_THRESHOLD,
};
pub use emule_info::{EmuleInfo, LegacyMuleInfo};
pub use error::{
    EmuleInfoDecodeError, FileRequestDecodeError, HashSetDecodeError, HumanLayerDecodeError,
    PartsDecodeError, PartsEncodeError, PeerHelloDecodeError, PeerIpv6DecodeError,
    PeerPacketDecodeError, ReaskDecodeError, RequestSources2DecodeError, RequestSourcesDecodeError,
    SlotDecodeError,
};
pub use file::{PartBitmap, PartBitmapDecodeError, PartIndex};
pub use file_request::{
    ExtendedRequests, FileReqAnsNoFil, FileSizedStatus, FileStatus, PartStatusTail,
    ReqFileNameAnswer, RequestFileName, SetReqFileId,
};
pub use handshake::{
    CT_EMULE_BUDDYIP, CT_EMULE_BUDDYUDP, HelloAdvert, PeerHandshakeContext, SecureIdentConfig,
    ServingBuddyAdvert,
};
pub use hash_set::{HashSetAnswer, HashSetRequest};
pub use hello::{Hello, HelloAnswer, HelloRefusal, HelloRefusalCode, HelloTrailer, PeerHelloBody};
pub use human_layer::{ChangeClientId, FileDesc, Message, PublicIpAnswer};
pub use identity::PeerIdentity;
pub use ipv6::{ChangeClientIpV6, PeerIpv6Tags};
pub use multipacket::{
    AnswerItem, BundleCut, BundledAsk, MultiPacketAnswer, MultiPacketDecodeError,
    MultiPacketRequest, RequestItem, UnknownSub,
};
pub use obfuscation::{PeerObfuscation, PeerObfuscationStep};
pub use opcode::PeerOpcode;
pub use packet::PeerPacket;
pub use parts::{
    CompressedPart, EMBLOCKSIZE, PartOffsetWidth, PartRanges, PartRangesError, RequestParts,
    SendingPart,
};
pub use reask::{
    BUDDY_ID_LEN, ClientUdpOpcode, DirectCallbackReq, PingStatus, ReaskAck, ReaskCallbackUdp,
    ReaskFilePing, file_not_found_datagram, queue_full_datagram,
};
pub use secure_ident::{
    CRYPT_CIP_LOCALCLIENT, CRYPT_CIP_NONECLIENT, CRYPT_CIP_REMOTECLIENT, PublicKeyPacket,
    SecIdentState, SecIdentStatePacket, SignaturePacket, SuiDecodeError,
};
pub use session::{
    FileProbeStatus, PeerCloseReason, PeerCommand, PeerError, PeerEvent, PeerOutput, PeerSession,
    SecureIdentFailure, SlotReleaseReason, SourceExchangeSupport,
};
pub use slot::{AcceptUploadReq, CancelTransfer, OutOfPartReqs, QueueRanking, StartUploadReq};
pub use software::{ClientFamily, ClientMod, ClientSoftware, ClientVersion, SoftwareEvidence};
pub use source_exchange::{
    AnswerSources, AnswerSources2, AnswerSources2DecodeError, AnswerSourcesDecodeError,
    AnswerSourcesSkip, ExtSourceRecordError, ExtSxEmission, RequestSources as RequestSourcesPacket,
    RequestSources2, ServedSourcesVersion, SourceExchangeClaim, SourceExchangeEntry,
    SourceExchangeVersion,
};
