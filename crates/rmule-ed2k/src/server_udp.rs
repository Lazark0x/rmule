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
//! One submodule per exchange: `sources` (0x9A/0x94/0x9B), `callback`
//! (0x9C), `status` (0x96/0x97), `description` (0xA2/0xA3) and `search`
//! (0x98/0x92/0x90 and 0x99). Every codec re-exports through here.

mod callback;
mod description;
mod search;
mod sources;
mod status;

pub use self::callback::GlobCallbackRequest;
pub use self::description::{ServerDescReq, ServerDescRes, ServerDescTags};
pub use self::search::{GlobSearchReq, GlobSearchRes, GlobSearchVariant};
pub use self::sources::{GlobFoundSources, GlobGetSources, GlobGetSources2};
pub use self::status::{
    GlobServStatReq, GlobServStatRes, crypt_ping_challenge, crypt_ping_padding_len,
};
