//! `SplitMix64`, the one mixer rmule draws non-cryptographic numbers from. The
//! quality bar is diffusion, not secrecy: a caller needing a capability makes it
//! from a secret, never from this function.

/// Advance `state` and answer the next number of its stream.
pub const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
