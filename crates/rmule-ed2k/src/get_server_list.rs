//! `OP_GETSERVERLIST` (0x14): ask the connected server for the servers it
//! knows. Empty body — the opcode is the whole request.

use rmule_primitives::empty_body_codec;

use crate::{Ed2kError, Opcode};

empty_body_codec! {
    /// `OP_GETSERVERLIST` (0x14): ask the connected server which other
    /// servers it knows. The opcode is the whole request.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    GetServerList, Ed2kError, Opcode::GetServerList.as_u8(), "OP_GETSERVERLIST"
}
