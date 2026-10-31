//! `Ed2kLink::read`: no panic, and a link that reads writes back as one that reads
//! the same.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_primitives::Ed2kLink;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(read) = Ed2kLink::read(input) {
        let again = Ed2kLink::parse(&read.link.to_string()).expect("a written link parses");
        assert_eq!(again, read.link);
    }
});
