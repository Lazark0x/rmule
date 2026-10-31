//! `Tag`: no panic, and a tag that decodes writes back as a tag that reads the same.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_primitives::Tag;

fuzz_target!(|data: &[u8]| {
    if let Ok((tag, _)) = Tag::decode_prefix(data) {
        let (again, _) = Tag::decode_prefix(&tag.encode()).expect("an encoded tag decodes");
        assert_eq!(again.name(), tag.name());
    }
    let _ = Tag::decode_or_step_prefix(data);
    let _ = Tag::decode_block(data, usize::from(data.first().copied().unwrap_or(0)));
});
