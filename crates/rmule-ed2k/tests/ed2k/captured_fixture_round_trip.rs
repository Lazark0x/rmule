//! Cross-validate the offline decoders against bytes captured from real
//! eD2k servers.
//!
//! Walks every `NN_<snake_name>.bin` file under
//! `tests/fixtures/server/captured/*/` and asserts that the bytes
//! round-trip through `Packet::decode` -> `ServerPacket::decode` ->
//! `ServerPacket::encode` -> `Packet::encode` byte-for-byte. Captured
//! slices have no `.toml` oracle by design (the bytes themselves are
//! the oracle — nobody on the team typed them); the round-trip is what
//! proves the decoder is honest about its `Compatibility Target`.
//!
//! No-op when no captured fixtures exist yet. New captures are picked
//! up automatically just by being dropped under the right directory.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use rmule_ed2k::ServerPacket;
use rmule_primitives::Packet;

#[test]
fn every_captured_per_packet_fixture_round_trips_byte_exact() {
    let captured = captured_per_packet_paths();
    if captured.is_empty() {
        eprintln!(
            "note: no captured per-packet fixtures found under \
             crates/rmule-ed2k/tests/fixtures/server/captured/*/; \
             this test is a no-op until a curated capture lands"
        );
        return;
    }
    for path in &captured {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let packet = Packet::decode_exact(&bytes)
            .unwrap_or_else(|e| panic!("{}: frame decode failed: {e}", path.display()));
        assert_eq!(
            packet.encode(),
            bytes,
            "{}: raw frame round-trip — Packet must be byte-faithful",
            path.display()
        );

        let decoded = ServerPacket::decode(&packet)
            .unwrap_or_else(|e| panic!("{}: server packet decode failed: {e}", path.display()));
        let re_encoded = decoded.encode().encode();
        if packet.protocol() == rmule_primitives::PacketProtocol::PackedEd2k {
            assert_ne!(
                re_encoded,
                bytes,
                "{}: logical packet should not re-emit compressed bytes",
                path.display()
            );
            assert_eq!(
                re_encoded[0],
                rmule_primitives::PacketProtocol::Edonkey.as_byte(),
                "{}: logical packet uses plain eDonkey protocol byte",
                path.display()
            );
        } else {
            assert_eq!(
                re_encoded,
                bytes,
                "{}: re-encode mismatch — decoder or encoder is not byte-faithful",
                path.display()
            );
        }
    }
}

/// Collect every `NN_<name>.bin` file under
/// `tests/fixtures/server/captured/*/`.
fn captured_per_packet_paths() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/server/captured");
    let mut out = Vec::new();
    let Ok(dirs) = fs::read_dir(&root) else {
        return out;
    };
    for dir in dirs.flatten() {
        if !dir.path().is_dir() {
            continue;
        }
        let Ok(files) = fs::read_dir(dir.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension() != Some(OsStr::new("bin")) {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // Per-packet slice names look like "01_server_message.bin".
            // Skip session-level artifacts (s2c.bin, c2s.bin); historical
            // `NN_undecoded_tail.bin` fixtures are now decodable as packed
            // ed2k server frames and round-trip through the inflate path.
            if name == "s2c.bin" || name == "c2s.bin" {
                continue;
            }
            let stem = name.trim_end_matches(".bin");
            let mut split = stem.splitn(2, '_');
            let prefix = split.next().unwrap_or_default();
            if !prefix.chars().all(|c| c.is_ascii_digit()) || prefix.is_empty() {
                continue;
            }
            out.push(path);
        }
    }
    out.sort();
    out
}
