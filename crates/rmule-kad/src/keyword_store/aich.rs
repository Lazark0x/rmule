//! The AICH roots a keyword answer carries (ADR-0038): `TAG_KADAICHHASHRESULT`,
//! a `BSOB` of `<count>{<popularity><AICH root>}` an eMule-family storer at Kad
//! v9 or later writes beside `TAG_PUBLISHINFO` (eMule 0.70b `Entry.cpp:680-710`),
//! read into [`KadAichRootReport`]s and written back in the same shape. The tag
//! model has no `BSOB` (ADR-0053), so the roots ride the row beside its tags.

use rmule_primitives::AichRootHash;

use super::TAG_KADAICHHASHRESULT;

/// One root's bytes on the wire: its popularity, then the 20-byte root.
const PAIR_LEN: usize = 1 + AichRootHash::BYTE_LEN;

/// `TAGTYPE_BSOB`, the type the storer writes the roots under.
const TAGTYPE_BSOB: u8 = 0x0A;

/// One AICH root a **Kad Storer** says publishers reported for a file, with
/// how many of them did: one pair of `TAG_KADAICHHASHRESULT`. Both numbers
/// are the storer's word (ADR-0038).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KadAichRootReport {
    /// How many of the file's publishers reported the root, by the storer's
    /// count.
    pub popularity: u8,
    /// The AICH master root they reported.
    pub root: AichRootHash,
}

/// The reports a `TAG_KADAICHHASHRESULT` value holds, read as aMule 3.1.0
/// reads it (`AICHHashList.cpp:149-177`): a root no publisher reported is
/// skipped, bytes past the count are ignored, and a value too short for its
/// count holds none.
pub(super) fn decode(value: &[u8]) -> Vec<KadAichRootReport> {
    let Some((&count, pairs)) = value.split_first() else {
        return Vec::new();
    };
    let Some(pairs) = pairs.get(..usize::from(count) * PAIR_LEN) else {
        return Vec::new();
    };
    pairs
        .chunks_exact(PAIR_LEN)
        .filter_map(|pair| {
            let (&popularity, root) = pair.split_first()?;
            let root = AichRootHash::from_bytes(root.try_into().ok()?);
            (popularity > 0).then_some(KadAichRootReport { popularity, root })
        })
        .collect()
}

/// The `TAG_KADAICHHASHRESULT` entry for `reports` as eMule's storer writes it:
/// a `BSOB` under the length-prefixed name `0x37`.
///
/// # Panics
/// Past twelve reports, which a `BSOB`'s one-byte length cannot hold.
pub(super) fn encode_tag(reports: &[KadAichRootReport]) -> Vec<u8> {
    let count = u8::try_from(reports.len()).expect("a BSOB holds at most twelve roots");
    let mut value = vec![count];
    for report in reports {
        value.push(report.popularity);
        value.extend_from_slice(report.root.as_bytes());
    }
    let len = u8::try_from(value.len()).expect("a BSOB holds at most twelve roots");
    let mut tag = vec![TAGTYPE_BSOB, 0x01, 0x00, TAG_KADAICHHASHRESULT, len];
    tag.extend_from_slice(&value);
    tag
}
