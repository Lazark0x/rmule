//! Server-UDP codec. Global source discovery (ADR-0051):
//! `OP_GLOBGETSOURCES` (0x9A) encode — packed 16-byte file hashes — and
//! `OP_GLOBFOUNDSOURCES` (0x9B) decode — the same body as the TCP
//! `OP_FOUNDSOURCES`. Status chain (ADR-0052): `OP_GLOBSERVSTATREQ` (0x96)
//! challenge ping and `OP_GLOBSERVSTATRES` (0x97) progressive-body reply.
//! Global search (ADR-0051): the `OP_GLOBSEARCHREQ` variant family
//! (0x98/0x92/0x90) — one query tree, three wrappers — and the
//! `OP_GLOBSEARCHRES` (0x99) per-packet result walk. Wire pinned in
//! `docs/reference/notes/server-udp.md` (aMule `SendNextUDPPacket` /
//! `ServerUDPSocket.cpp` / `ServerList.cpp` / `SearchList.cpp`);
//! cite-and-rewrite only (ADR-0004).
//!
//! ## Layout
//!
//! One submodule per exchange: `sources` (0x9A/0x94/0x9B), `status`
//! (0x96/0x97), `description` (0xA2/0xA3) and `search` (0x98/0x92/0x90 and
//! 0x99). Every codec re-exports through here.

mod description;
mod search;
mod sources;
mod status;

use rmule_primitives::{PacketProtocol, WrongFrame};

use crate::Result;

pub use self::description::{ServerDescReq, ServerDescRes, ServerDescTags};
pub use self::search::{GlobSearchReq, GlobSearchRes, GlobSearchVariant};
pub use self::sources::{GlobFoundSources, GlobGetSources, GlobGetSources2};
pub use self::status::{
    GlobServStatReq, GlobServStatRes, crypt_ping_challenge, crypt_ping_padding_len,
};

/// A UDP datagram's body, once its `[protocol 0xE3][opcode]` head proves to be
/// `opcode`'s.
fn datagram_body(bytes: &[u8], opcode: u8) -> Result<&[u8]> {
    match bytes {
        [protocol, op, body @ ..]
            if *protocol == PacketProtocol::Edonkey.as_byte() && *op == opcode =>
        {
            Ok(body)
        }
        _ => Err(WrongFrame {
            protocol: PacketProtocol::Edonkey,
            opcode,
        }
        .into()),
    }
}
