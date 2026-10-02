//! `Ed2kText` as a lossless byte string: non-UTF-8 input round-trips, strict
//! decode still fails on it, and display is lossy.

use rmule_primitives::Ed2kText;

#[test]
fn utf8_constructor_preserves_input_bytes() {
    let text = Ed2kText::from_utf8("hello");
    assert_eq!(text.as_bytes(), b"hello");
    assert_eq!(text.try_as_str().unwrap(), "hello");
}

#[test]
fn non_utf8_bytes_round_trip_losslessly_and_fail_strict_decode() {
    let raw = vec![0xff, 0xfe, b'h', b'i'];
    let text = Ed2kText::from_bytes(raw.clone());
    assert_eq!(text.as_bytes(), raw.as_slice());
    assert!(text.try_as_str().is_err());
}

#[test]
fn display_string_is_lossy_with_replacement_char() {
    let text = Ed2kText::from_bytes(vec![0xff, b'h', b'i']);
    let display = text.to_display_string();
    assert!(display.contains('\u{FFFD}'));
    assert!(display.ends_with("hi"));
}

#[test]
fn into_bytes_yields_the_underlying_vec() {
    let raw = vec![0xde, 0xad, 0xbe, 0xef];
    assert_eq!(Ed2kText::from_bytes(raw.clone()).into_bytes(), raw);
}
