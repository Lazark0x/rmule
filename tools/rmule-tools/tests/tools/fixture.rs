//! What more than one leg here needs. Anything a second crate reaches for
//! belongs in `rmule-testkit` instead.

/// The file the transfer legs move: a synthetic hash, shared so the CLI leg
/// and the protocol-level replay name the same file.
pub const FILE_HASH: [u8; 16] = [0x55; 16];
