//! The list files a mirror serves: `server.met` and `nodes.dat`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rmule_ed2k::ServerMet;
use rmule_kad::NodesDat;

fuzz_target!(|data: &[u8]| {
    let _ = ServerMet::decode(data);
    let _ = NodesDat::decode(data);
});
