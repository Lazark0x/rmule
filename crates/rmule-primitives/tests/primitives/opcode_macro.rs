//! The `opcodes!` macro defines each byte once and generates a
//! round-tripping `as_u8` / `try_from_u8` pair.
use rmule_primitives::opcodes;

opcodes! {
    enum SampleOpcode {
        Alpha = 0x01,
        Omega = 0xFE,
    }
}

#[test]
fn as_u8_matches_declared_byte() {
    assert_eq!(SampleOpcode::Alpha.as_u8(), 0x01);
    assert_eq!(SampleOpcode::Omega.as_u8(), 0xFE);
}

#[test]
fn try_from_u8_round_trips_known_bytes() {
    assert_eq!(SampleOpcode::try_from_u8(0x01), Some(SampleOpcode::Alpha));
    assert_eq!(SampleOpcode::try_from_u8(0xFE), Some(SampleOpcode::Omega));
}

#[test]
fn try_from_u8_rejects_unknown_bytes() {
    assert_eq!(SampleOpcode::try_from_u8(0x00), None);
    assert_eq!(SampleOpcode::try_from_u8(0x55), None);
}
