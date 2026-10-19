//! The seed fixture writer: gap runs, the `.part.met` layout aMule's loader walks, the staged `.part` and its date, seed specs.

use std::collections::BTreeSet;

use rmule_primitives::{ED2K_PART_SIZE, FileHash, PartHash, Tag, TagValue};

use super::{
    PART_DATE_UNIX_SECS, PART_FILE, PART_MET_FILE, PartMet, SeedHolding, default_seeds, gaps,
    part_met, stage_partial_seed, write_stream_file,
};

const P: u64 = ED2K_PART_SIZE;

fn set(parts: &[u32]) -> BTreeSet<u32> {
    parts.iter().copied().collect()
}

/// Missing parts merge into one gap per run, ends exclusive, and the last
/// gap stops at the file's end, not the part boundary.
#[test]
fn a_gap_is_one_run_of_missing_parts_ending_at_the_file_end() {
    assert_eq!(
        gaps(4 * P + 5, &set(&[0, 3])),
        vec![(P, 3 * P), (4 * P, 4 * P + 5)]
    );
    assert_eq!(gaps(2 * P, &set(&[0, 1])), Vec::<(u64, u64)>::new());
    assert_eq!(gaps(2 * P, &set(&[])), vec![(0, 2 * P)]);
}

/// The bytes aMule's `LoadPartFile` walks: version, date, file hash, every
/// part hash, then name, size, paused status and the gap pairs it keys by
/// the decimal after the mark byte.
#[test]
fn the_part_met_reads_back_as_the_amule_loader_walks_it() {
    let hashes: Vec<PartHash> = (0..4_u8).map(|n| PartHash::from_bytes([n; 16])).collect();
    let met = part_met(&PartMet {
        file_hash: FileHash::from_bytes([0xAB; 16]),
        part_hashes: &hashes,
        size: 3 * P,
        name: "stream.mkv",
        date: 0x0102_0304,
        held: &set(&[1]),
    })
    .unwrap();
    assert_eq!(met[0], 0xE0);
    assert_eq!(&met[1..5], &0x0102_0304_u32.to_le_bytes());
    assert_eq!(&met[5..21], &[0xAB; 16]);
    assert_eq!(&met[21..23], &4_u16.to_le_bytes());
    let tags_at = 23 + 4 * 16;
    assert_eq!(&met[23..39], &[0; 16]);
    let count = u32::from_le_bytes(met[tags_at..tags_at + 4].try_into().unwrap());
    let (tags, used) = Tag::decode_block(&met[tags_at + 4..], count as usize).unwrap();
    assert_eq!(tags_at + 4 + used, met.len());
    let by_id = |id: u8| {
        tags.iter()
            .find(|tag| tag.name().id() == Some(id))
            .map(|tag| tag.value().clone())
    };
    assert!(
        matches!(by_id(0x01), Some(TagValue::String(name)) if name.as_bytes() == b"stream.mkv")
    );
    assert_eq!(by_id(0x02), Some(TagValue::U32(3 * P as u32)));
    assert_eq!(by_id(0x14), Some(TagValue::U32(1)));
    let gap_tags: Vec<(String, TagValue)> = tags
        .iter()
        .filter_map(|tag| Some((tag.name().text_value()?.to_owned(), tag.value().clone())))
        .collect();
    assert_eq!(
        gap_tags,
        vec![
            ("\u{9}0".to_owned(), TagValue::U32(0)),
            ("\u{a}0".to_owned(), TagValue::U32(P as u32)),
            ("\u{9}1".to_owned(), TagValue::U32(2 * P as u32)),
            ("\u{a}1".to_owned(), TagValue::U32(3 * P as u32)),
        ]
    );
}

/// The staged `.part` carries the held part's own bytes, zeros where a gap
/// is, the file's full length, and the date its `.part.met` names — the
/// stamp aMule compares before it trusts the gaps.
#[test]
fn a_staged_part_file_holds_its_parts_and_the_named_date() {
    let dir = tempfile::tempdir().unwrap();
    let stream = write_stream_file(&dir.path().join("synthetic"), 2 * P + 10, 7).unwrap();
    let temp = dir.path().join("temp");
    stage_partial_seed(&temp, &stream, &set(&[1])).unwrap();

    let source = std::fs::read(&stream.path).unwrap();
    let part = std::fs::read(temp.join(PART_FILE)).unwrap();
    assert_eq!(part.len(), source.len());
    assert!(part[..P as usize].iter().all(|byte| *byte == 0));
    assert_eq!(
        &part[P as usize..2 * P as usize],
        &source[P as usize..2 * P as usize]
    );
    assert!(part[2 * P as usize..].iter().all(|byte| *byte == 0));

    let stamped = std::fs::metadata(temp.join(PART_FILE))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let met = std::fs::read(temp.join(PART_MET_FILE)).unwrap();
    assert_eq!(stamped, u64::from(PART_DATE_UNIX_SECS));
    assert_eq!(&met[1..5], &PART_DATE_UNIX_SECS.to_le_bytes());
    // Three hashes for two parts and a ten-byte tail: aMule's
    // `GetED2KPartHashCount`, which the loader demands before it shares.
    assert_eq!(&met[21..23], &3_u16.to_le_bytes());
    assert!(stream.link.contains("stream.mkv"));
}

#[test]
fn a_seed_spec_reads_ranges_and_complete() {
    assert_eq!(
        SeedHolding::parse("0-2, 7").unwrap(),
        SeedHolding::Partial(set(&[0, 1, 2, 7]))
    );
    assert_eq!(
        SeedHolding::parse("complete").unwrap(),
        SeedHolding::Complete
    );
    assert!(SeedHolding::parse("4-1").is_err());
    assert!(SeedHolding::parse("x").is_err());
}

/// The default pair: each seed holds parts only it holds, and the shared
/// parts are the Preview Band's ends and the middle.
#[test]
fn the_default_seeds_each_hold_a_part_the_other_lacks() {
    let seeds = default_seeds(12);
    let a = seeds[0].parts(12);
    let b = seeds[1].parts(12);
    assert_eq!(a.union(&b).count(), 12);
    assert_eq!(
        a.intersection(&b).copied().collect::<Vec<_>>(),
        vec![0, 6, 11]
    );
    assert_eq!(a.difference(&b).count(), 5);
    assert_eq!(b.difference(&a).count(), 4);
}
