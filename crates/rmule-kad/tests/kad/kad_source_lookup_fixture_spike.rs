//! The minimal source-lookup transcript recorded while `0x3B` capture was
//! blocked: it asserts the fixture still says so, so the block cannot be
//! silently forgotten.

#[test]
fn kad_source_lookup_fixture_spike_records_blocked_minimal_transcript() {
    let raw = include_str!("../fixtures/source_lookup/minimal.toml");
    let value: toml::Value = toml::from_str(raw).expect("fixture metadata must be TOML");

    assert_eq!(value["status"].as_str(), Some("blocked"));
    assert_eq!(
        value["known_evidence"]["source_lookup_request_opcode"].as_str(),
        Some("0x34")
    );
    assert_eq!(
        value["known_evidence"]["source_lookup_result_opcode"].as_str(),
        Some("0x3B")
    );
    // The fixture must document every gap the source-result decoder is blocked
    // on (`SOURCE_RESULT_BLOCKED_BY`): Kad ID byte order, source IP tag byte
    // order, source ID meaning, and a captured High ID result.
    assert_eq!(
        value["missing_evidence"]["kad_id_byte_order"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["missing_evidence"]["source_ip_tag_byte_order"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["missing_evidence"]["source_id_identity_meaning"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["missing_evidence"]["captured_high_id_source_result"].as_bool(),
        Some(true)
    );
}
