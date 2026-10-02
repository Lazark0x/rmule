//! The eD2k hash tree against recorded cases: every `tests/fixtures/hashes`
//! file names an input pattern and the summary hash plus part hashes aMule
//! produces for it.

use rmule_primitives::{FileHashSummary, PartHashSet};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct HashFixture {
    name: String,
    provenance: String,
    source_note: String,
    accepted: bool,
    input: HashInput,
    expected: ExpectedHash,
}

#[derive(Debug, Deserialize)]
struct HashInput {
    pattern: String,
    byte: String,
    len: usize,
}

#[derive(Debug, Deserialize)]
struct ExpectedHash {
    file_hash: String,
    #[serde(default)]
    part_hashes: Vec<String>,
}

#[test]
fn hash_fixtures_match_expected_ed2k_behavior() {
    for fixture in crate::fixture::cases::<HashFixture>("hashes") {
        assert!(fixture.accepted, "{} should be accepted", fixture.name);
        assert!(
            !fixture.provenance.is_empty(),
            "{} provenance",
            fixture.name
        );
        assert!(
            !fixture.source_note.is_empty(),
            "{} source_note",
            fixture.name
        );

        let input = fixture.input.materialize();
        let summary = FileHashSummary::digest_bytes(&input);
        // The streaming digest agrees byte for byte, across short reads that
        // straddle every part boundary.
        assert_eq!(
            FileHashSummary::digest_reader(Trickle(&input)).unwrap(),
            summary,
            "{} streamed",
            fixture.name
        );

        assert_eq!(
            summary.file_hash().to_hex_upper(),
            fixture.expected.file_hash,
            "{} file hash",
            fixture.name
        );

        let expected_count = PartHashSet::expected_hash_count(summary.file_size()).unwrap();
        assert_eq!(
            expected_count,
            fixture.expected.part_hashes.len(),
            "{} expected hashset count",
            fixture.name
        );

        let actual_hashes: Vec<String> = summary
            .part_hash_set()
            .map(|set| {
                set.hashes()
                    .iter()
                    .map(|hash| hash.to_hex_upper())
                    .collect()
            })
            .unwrap_or_default();

        assert_eq!(
            actual_hashes, fixture.expected.part_hashes,
            "{} part hashes",
            fixture.name
        );
    }
}

impl HashInput {
    fn materialize(&self) -> Vec<u8> {
        assert_eq!(self.pattern, "repeat-byte");
        let byte = u8::from_str_radix(&self.byte, 16).expect("fixture byte");
        vec![byte; self.len]
    }
}

/// A reader that hands out an odd-sized slice per call, so no read lines up
/// with a part boundary.
struct Trickle<'a>(&'a [u8]);

impl std::io::Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let take = buf.len().min(self.0.len()).min(1_000_003);
        buf[..take].copy_from_slice(&self.0[..take]);
        self.0 = &self.0[take..];
        Ok(take)
    }
}
