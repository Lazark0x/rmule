//! Every client-to-server and server-to-client eD2k opcode rmule models, with
//! its byte defined exactly once.

use crate::{Ed2kError, Result};
use rmule_primitives::opcodes;

opcodes! {
    /// Every eD2k client↔server opcode rmule models.
    ///
    /// A byte outside this set is not an error — it decodes as an unknown
    /// packet whose bytes are kept (ADR-0018).
    pub enum Opcode {
        LoginRequest = 0x01,
        Reject = 0x05,
        GetServerList = 0x14,
        OfferFiles = 0x15,
        SearchRequest = 0x16,
        GetSources = 0x19,
        CallbackRequest = 0x1C,
        QueryMoreResult = 0x21,
        GetSourcesObfu = 0x23,
        PeerCallbackIpv6 = 0x26,
        ServerList = 0x32,
        SearchResult = 0x33,
        ServerStatus = 0x34,
        PeerCallback = 0x35,
        CallbackFail = 0x36,
        ServerMessage = 0x38,
        IdChange = 0x40,
        ServerIdent = 0x41,
        FoundSources = 0x42,
        FoundSourcesObfu = 0x44,
        LowIdHolepunchRequest = 0x60,
        LowIdHolepunchInfo = 0x61,
        LowIdHolepunchFail = 0x62,
        GlobSearchReq3 = 0x90,
        GlobSearchReq2 = 0x92,
        GlobGetSources2 = 0x94,
        GlobServStatReq = 0x96,
        GlobServStatRes = 0x97,
        GlobSearchReq = 0x98,
        GlobSearchRes = 0x99,
        GlobGetSources = 0x9A,
        GlobFoundSources = 0x9B,
        GlobCallbackRequest = 0x9C,
        ServerNattKeepalive = 0x9F,
        ServerDescReq = 0xA2,
        ServerDescRes = 0xA3,
    }
}

impl Opcode {
    /// Decode a server/client opcode byte, erroring on bytes rmule does
    /// not model (preserves the existing `from_u8` contract).
    pub fn from_u8(opcode: u8) -> Result<Self> {
        Self::try_from_u8(opcode).ok_or(Ed2kError::UnsupportedOpcode { opcode })
    }
}
