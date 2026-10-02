//! The **Related-Files Search** on the wire (ADR-0037): an
//! ordinary `OP_SEARCHREQUEST` whose tree is the single string term
//! `related::<HASH>`, the hash as 32 upper-case hex characters.
//!
//! This is the form both reference clients write, byte for byte. eMule builds
//! `"related"` and appends `"::" + md4str(hash)` (`SearchResultsWnd.cpp:1678-1685`),
//! uppercase by `base16Chars` (`OtherFunctions.cpp:60,1191-1193`); aMule builds
//! `related` plus `"::" + GetFileHash().Encode()` (`SearchListCtrl.cpp:1003-1012`),
//! uppercase by `EncodeSTL` (`MD4Hash.h:182-196`). Both lex the string as one
//! token and write it as node `0x01` (eMule `Scanner.l:76,317`,
//! `SearchResultsWnd.cpp:869-873`; aMule `Scanner.l:45,59-62`). eMule adds no
//! constraint terms (`SearchResultsWnd.cpp:1677-1678`); aMule may append the
//! dialog's extended constraints (`SearchDlg.cpp:1472-1507`), which rmule does
//! not — a related query carries none.
//!
//! One hash per request: the wire admits `related::H1::H2…`, but no rmule
//! front-end selects several rows.

use rmule_primitives::{Ed2kText, FileHash, Packet, RelatedFilesQuery};

use crate::search_request::phrase_only_packet;

/// A related-files request ready for the wire. It holds the hash alone: the
/// query's display name never leaves rmule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelatedSearchRequest {
    file_hash: FileHash,
}

impl RelatedSearchRequest {
    /// The request for `query`'s file.
    #[must_use]
    pub const fn from_query(query: &RelatedFilesQuery) -> Self {
        Self {
            file_hash: query.file_hash(),
        }
    }

    /// The single string term the server reads: `related::` and the hash in
    /// upper-case hex.
    #[must_use]
    pub fn term(&self) -> String {
        format!("related::{}", self.file_hash.to_hex_upper())
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        phrase_only_packet(Ed2kText::from_utf8(self.term()))
    }
}
