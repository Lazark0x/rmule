//! Verifies manually promoted captured Kad source-lookup fixtures.
//!
//! This test never fails merely because no capture has been promoted yet: the
//! private bootstrap evidence gate may legitimately stay blocked. When a
//! captured fixture directory exists, every promoted fixture is checked
//! strictly so an invented or under-described fixture cannot slip in.

use std::path::{Path, PathBuf};

use toml::Value;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source_lookup")
}

fn read_toml(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    toml::from_str::<Value>(&text)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn captured_source_lookup_fixtures_are_well_formed_or_explicitly_blocked() {
    let captured = fixtures_root().join("captured");
    let promoted = promoted_dirs(&captured);

    if promoted.is_empty() {
        // No capture promoted yet: the blocked metadata must still name the
        // missing High ID source-result evidence so the gate stays explicit.
        let minimal = read_toml(&fixtures_root().join("minimal.toml"));
        assert_eq!(
            minimal["status"].as_str(),
            Some("blocked"),
            "minimal.toml must remain blocked until a fixture is promoted"
        );
        assert_eq!(
            minimal["missing_evidence"]["captured_high_id_source_result"].as_bool(),
            Some(true),
            "blocked metadata must still name the missing captured High ID source result"
        );
        return;
    }

    for dir in promoted {
        verify_promoted_fixture(&dir);
    }
}

fn promoted_dirs(captured: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(captured) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn verify_promoted_fixture(dir: &Path) {
    let label = dir.display();

    let metadata_path = dir.join("metadata.toml");
    assert!(
        metadata_path.is_file(),
        "{label}: metadata.toml is required"
    );
    assert!(
        dir.join("request_0x34.bin").is_file(),
        "{label}: request_0x34.bin is required"
    );
    assert!(
        dir.join("result_0x3b_high_id.bin").is_file(),
        "{label}: result_0x3b_high_id.bin is required"
    );

    let metadata = read_toml(&metadata_path);

    assert_eq!(
        metadata["provenance"].as_str(),
        Some("captured"),
        "{label}: promoted fixtures must be captured, not invented"
    );
    assert_eq!(
        metadata["public_kad_used"].as_bool(),
        Some(false),
        "{label}: public Kad must never be used"
    );

    assert_eq!(
        metadata["request"]["protocol"].as_str(),
        Some("0xE4"),
        "{label}: request must be plain Kad 0xE4"
    );
    assert_eq!(
        metadata["request"]["opcode"].as_str(),
        Some("0x34"),
        "{label}: request opcode must be KADEMLIA2_SEARCH_SOURCE_REQ (0x34)"
    );
    assert_eq!(
        metadata["result"]["protocol"].as_str(),
        Some("0xE4"),
        "{label}: result must be plain Kad 0xE4"
    );
    assert_eq!(
        metadata["result"]["opcode"].as_str(),
        Some("0x3B"),
        "{label}: result opcode must be KADEMLIA2_SEARCH_RES (0x3B)"
    );

    let nodes = metadata["nodes"]
        .as_array()
        .unwrap_or_else(|| panic!("{label}: metadata must list [[nodes]]"));
    let roles: Vec<&str> = nodes
        .iter()
        .filter_map(|node| node.get("role").and_then(Value::as_str))
        .collect();
    assert!(
        roles.contains(&"requester"),
        "{label}: metadata must include the requester role"
    );
    assert!(
        roles.contains(&"publisher"),
        "{label}: metadata must include the publisher role"
    );
    assert!(
        nodes.iter().any(|node| node
            .get("kad_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())),
        "{label}: metadata must record observed Kad IDs for promoted endpoints"
    );
}
