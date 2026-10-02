//! `OP_REJECT` (0x05): the server discarded the client's last command. Empty
//! body — the opcode is the whole answer.

use rmule_primitives::empty_body_codec;

use crate::{Ed2kError, Opcode};

empty_body_codec! {
    /// `OP_REJECT` (0x05). Server discarded the client's last command. Payload is
    /// empty per cited sources — see
    /// `docs/reference/notes/ed2k-welcome-packets.md` OP_REJECT section. If a
    /// future fixture surfaces a reason field this becomes a struct.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    Reject, Ed2kError, Opcode::Reject.as_u8(), "OP_REJECT"
}
