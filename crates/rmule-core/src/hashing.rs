//! What a download is allowed to trust. [`resolve_hash_set_authority`] decides
//! whether a file's part hashes come from its own link (authoritative) or only
//! from the file hash (provisional), and the verify helpers run the MD4 that
//! settles each part and the completed file against it. Every byte a download
//! keeps passes through one of these.

use std::io::Read;

use ed2k::digest::Digest;
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink, FileHash, PartHash, PartHashSet};

use crate::{DownloadFailure, VerificationAuthority};

#[derive(Debug)]
pub(crate) struct ResolvedHashSet {
    pub authority: VerificationAuthority,
    pub hashes: Vec<PartHash>,
}

pub(crate) fn resolve_hash_set_authority(
    link_hash_set: Option<&PartHashSet>,
    peer_hashes: Option<&[PartHash]>,
) -> Result<ResolvedHashSet, DownloadFailure> {
    match (link_hash_set, peer_hashes) {
        (Some(link), Some(peer)) if link.hashes() != peer => Err(DownloadFailure::HashSetMismatch),
        (Some(link), _) => Ok(ResolvedHashSet {
            authority: VerificationAuthority::LinkPartHashSet,
            hashes: link.hashes().to_vec(),
        }),
        (None, Some(peer)) => Ok(ResolvedHashSet {
            authority: VerificationAuthority::PeerHashSet,
            hashes: peer.to_vec(),
        }),
        (None, None) => Ok(ResolvedHashSet {
            authority: VerificationAuthority::FileHashOnly,
            hashes: Vec::new(),
        }),
    }
}

/// Whether a peer-supplied part hash set is `file_hash`'s own: the count
/// `file_size` implies, and — for a file with a set at all — the MD4 of the
/// part hashes laid end to end equals the file hash. aMule's rule for a
/// received set, `CKnownFile::LoadHashsetFromFile(.., checkhash = true)`
/// (`src/KnownFile.cpp:521-543` at `4e8f2b3c`: the count at `:524`, the
/// hash of the list at `:535-536` via `CreateHashFromHashlist`, `:787-799`).
/// A set that fails it is proven wrong by the file hash alone — no peer's word
/// needed — so its sender can be distrusted (ADR-0090 "Source ownership").
pub(crate) fn hash_set_proves_file(
    file_hash: FileHash,
    file_size: u64,
    hashes: &[PartHash],
) -> bool {
    PartHashSet::from_hashes(file_size, hashes.to_vec()).is_ok_and(|set| set.belongs_to(file_hash))
}

/// The link's part hash set, when it is the file's own; `None` otherwise, so
/// the first peer set proven against the file hash verifies the parts. aMule
/// checks a link's set when the download is made from it
/// (`src/PartFile.cpp:248-251` at `4e8f2b3c`) and drops one that fails.
/// Parsing already drops such a set; this is the download start's own check,
/// for a link built without parsing.
pub(crate) fn proven_link_hash_set(file: &Ed2kFileLink) -> Option<PartHashSet> {
    file.part_hash_set
        .clone()
        .filter(|set| set.belongs_to(file.file_hash))
}

/// The hash a received part must match on arrival: its entry in the resolved
/// set, or — for a file below one part, whose one part is the whole file — the
/// file hash itself (aMule `CPartFile::HashSinglePart`,
/// `src/PartFile.cpp:2338-2343` at `4e8f2b3c`). `None` only for a multi-part
/// file with no set yet, which the whole-file check at finalize judges.
pub(crate) fn part_hash_on_arrival(
    resolved: &ResolvedHashSet,
    file: &Ed2kFileLink,
    part_index: u32,
) -> Option<PartHash> {
    resolved
        .hashes
        .get(part_index as usize)
        .copied()
        .or_else(|| {
            (file.size < ED2K_PART_SIZE).then(|| PartHash::from_bytes(*file.file_hash.as_bytes()))
        })
}

/// The eD2k part hash of `bytes`.
pub(crate) fn part_hash_of(bytes: &[u8]) -> PartHash {
    PartHash::from_bytes(ed2k::Ed2kBlue::digest(bytes).into())
}

pub(crate) fn verify_part_bytes(expected: PartHash, bytes: &[u8]) -> Result<(), DownloadFailure> {
    if part_hash_of(bytes) == expected {
        Ok(())
    } else {
        Err(DownloadFailure::PartVerificationFailed)
    }
}

/// The eD2k file hash of the first `file_size` bytes `reader` yields, read one
/// part at a time: no read asks for more than [`ED2K_PART_SIZE`] bytes, so a
/// file of any size is hashed in one part's worth of memory. Fewer than
/// `file_size` bytes is [`std::io::ErrorKind::UnexpectedEof`]. Blocking: an
/// async caller runs it on the blocking pool.
pub(crate) fn file_hash_streamed<R: Read>(
    mut reader: R,
    file_size: u64,
) -> std::io::Result<FileHash> {
    let chunk = usize::try_from(ED2K_PART_SIZE.min(file_size)).unwrap_or(usize::MAX);
    let mut buffer = vec![0; chunk];
    let mut hasher = ed2k::Ed2kRed::default();
    let mut remaining = file_size;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(ED2K_PART_SIZE)).unwrap_or(chunk);
        let bytes = &mut buffer[..take];
        reader.read_exact(bytes)?;
        hasher.update(&*bytes);
        remaining -= take as u64;
    }
    Ok(FileHash::from_bytes(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed2k::digest::Digest;
    use rmule_primitives::{FileHashSummary, PartHash, PartHashSet};

    #[test]
    fn link_part_hash_set_is_authority_when_present_and_peer_matches() {
        let hash = PartHash::from_bytes([0x11; 16]);
        let link = PartHashSet::from_hashes(
            rmule_primitives::ED2K_PART_SIZE,
            vec![
                hash,
                PartHash::from_bytes(ed2k::Ed2kBlue::digest([]).into()),
            ],
        )
        .unwrap();

        let resolved = resolve_hash_set_authority(Some(&link), Some(link.hashes())).unwrap();

        assert_eq!(resolved.authority, VerificationAuthority::LinkPartHashSet);
        assert_eq!(resolved.hashes, link.hashes());
    }

    #[test]
    fn link_peer_hash_mismatch_fails() {
        let link_hash = PartHash::from_bytes([0x11; 16]);
        let peer_hash = PartHash::from_bytes([0x22; 16]);
        let trailing_empty = PartHash::from_bytes(ed2k::Ed2kBlue::digest([]).into());
        let link = PartHashSet::from_hashes(
            rmule_primitives::ED2K_PART_SIZE,
            vec![link_hash, trailing_empty],
        )
        .unwrap();
        let peer_hashes = vec![peer_hash, trailing_empty];

        let err = resolve_hash_set_authority(Some(&link), Some(&peer_hashes)).unwrap_err();

        assert_eq!(err, DownloadFailure::HashSetMismatch);
    }

    /// The unit half of `small_file_without_part_hash_set_rejects_corrupt_bytes_on_arrival`
    /// A sub-part file's one part is checked against the file hash
    /// the moment it arrives.
    #[test]
    fn small_file_without_part_hash_set_checks_its_part_against_the_file_hash() {
        let bytes = b"abc";
        let summary = FileHashSummary::digest_bytes(bytes);
        let file = Ed2kFileLink {
            name: rmule_primitives::Ed2kText::from_utf8("abc"),
            size: summary.file_size(),
            file_hash: summary.file_hash(),
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        };
        let resolved = resolve_hash_set_authority(None, None).unwrap();

        let expected = part_hash_on_arrival(&resolved, &file, 0).unwrap();

        verify_part_bytes(expected, bytes).unwrap();
        assert!(verify_part_bytes(expected, b"abd").is_err());
    }

    /// A reader that refuses any single read larger than one part, so a hash
    /// that pulls the whole file in one go fails rather than passes.
    struct PartBoundedReader<'a> {
        bytes: &'a [u8],
    }

    impl Read for PartBoundedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                buf.len() as u64 <= ED2K_PART_SIZE,
                "a read of {} bytes exceeds one part",
                buf.len()
            );
            self.bytes.read(buf)
        }
    }

    /// Two whole parts and a short tail, each byte a function of its offset.
    fn two_and_a_half_parts() -> Vec<u8> {
        let len = usize::try_from(ED2K_PART_SIZE * 2 + ED2K_PART_SIZE / 2).unwrap();
        (0..len).map(|at| (at * 7 + at / 251) as u8).collect()
    }

    #[test]
    fn finalize_hash_reads_at_most_one_part_at_a_time() {
        let bytes = two_and_a_half_parts();

        let streamed =
            file_hash_streamed(PartBoundedReader { bytes: &bytes }, bytes.len() as u64).unwrap();

        assert_eq!(streamed, FileHashSummary::digest_bytes(&bytes).file_hash());
    }

    #[test]
    fn finalize_hash_of_a_short_file_is_an_early_end() {
        let bytes = two_and_a_half_parts();

        let error = file_hash_streamed(PartBoundedReader { bytes: &bytes }, bytes.len() as u64 + 1)
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
