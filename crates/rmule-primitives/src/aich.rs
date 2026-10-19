//! AICH (Advanced Intelligent Corruption Handling) SHA-1 hash tree.
//!
//! An [`AichHashSet`] is the per-file SHA-1 hash tree whose leaves are the
//! SHA-1 of each 180 KiB ([`EMBLOCKSIZE`]) block and whose root is the file's
//! [`AichRootHash`] ("master hash"). It is the SHA-1 sibling of
//! [`PartHashSet`](crate::PartHashSet): it enables sub-part block recovery, not
//! file identity (ADR-0038).
//!
//! Two directions are supported, sharing one tree shape:
//! - **build** ([`AichHashSet::from_bytes`]) — compute the whole tree (and its
//!   master root) from a complete file's bytes, and serialize a part's
//!   [recovery data](AichHashSet::create_part_recovery_data) (answer side).
//! - **verify** ([`AichHashSet::verify_part`]) — read a part's recovery data,
//!   confirm it chains to a *trusted* master root, then localize which 180 KiB
//!   blocks of the downloaded part are corrupt (receive side).
//!
//! The tree shape, split rule, node-combine rule, and recovery-data layout are
//! pinned from aMule `src/SHAHashSet.cpp` (`CAICHHashTree` / `CAICHHashSet`) at
//! commit `377ec8d9`; the behaviour is cited and rewritten in idiomatic Rust,
//! never ported (ADR-0004/0013). SHA-1 comes from the `sha1` crate wrapped
//! behind rmule types (ADR-0012).

use crate::{AichRootHash, ED2K_PART_SIZE, WireReader, WireTruncated};
use sha1::{Digest, Sha1};

/// Size in bytes of one SHA-1 hash (`HASHSIZE` in aMule).
const HASHSIZE: usize = 20;

/// eMule AICH leaf block size (`EMBLOCKSIZE`): the 180 KiB unit each tree leaf
/// hashes. Equal in value to the peer transfer block (`rmule_peer::EMBLOCKSIZE`).
pub const EMBLOCKSIZE: u64 = 184_320;

/// Why reading a peer's AICH recovery data failed. All variants are
/// non-terminal at the session level (the part takes the path of a part with no
/// trusted root and the peer connection stays open, ADR-0038).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AichRecoveryError {
    /// The recovery data was truncated, carried an out-of-range part, or a hash
    /// identifier pointed outside the tree.
    #[error("AICH recovery data was malformed")]
    Malformed,
    /// The recovery data did not recompute to the trusted master root — the
    /// sender's hashes are not authentic for this file.
    #[error("AICH recovery data did not chain to the trusted root")]
    Untrusted,
    /// The recovery data verified but did not carry a block hash for every
    /// block of the part, so corruption cannot be localized.
    #[error("AICH recovery data was missing a block hash for the part")]
    IncompletePart,
}

impl From<WireTruncated> for AichRecoveryError {
    fn from(_: WireTruncated) -> Self {
        Self::Malformed
    }
}

/// The AICH hash of one block of at most [`EMBLOCKSIZE`] bytes: a leaf of the
/// tree, the SHA-1 a part's recovery data names that block by. A part that
/// failed with no trusted root compares its cells' hashes across the refetch
/// (ADR-0117).
#[must_use]
pub fn aich_block_hash(block: &[u8]) -> [u8; HASHSIZE] {
    sha1_bytes(block)
}

/// SHA-1 of a byte run — one AICH leaf hash.
fn sha1_bytes(data: &[u8]) -> [u8; HASHSIZE] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// AICH node-combine rule: a parent hash is `SHA-1(left ‖ right)` over the two
/// 20-byte child hashes, with nothing else mixed in (aMule
/// `CAICHHashTree::ReCalculateHash`).
fn sha1_pair(left: &[u8; HASHSIZE], right: &[u8; HASHSIZE]) -> [u8; HASHSIZE] {
    let mut hasher = Sha1::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// One node of the AICH binary hash tree (aMule `CAICHHashTree`). A node is
/// either a leaf (`data_size <= base_size`) or an internal node with both
/// children present. `hash` is `None` in an unfilled skeleton node (aMule's
/// `m_bHashValid == false`).
#[derive(Clone, Debug)]
struct AichHashTree {
    /// Bytes of the file covered by this node.
    data_size: u64,
    /// Block size the lowest hash under this node is based on — `EMBLOCKSIZE`
    /// within a part, `PARTSIZE` above the part level.
    base_size: u64,
    /// Whether this node is the left branch of its parent (drives the split rule
    /// and the recovery-data hash-identifier path bits).
    is_left_branch: bool,
    hash: Option<[u8; HASHSIZE]>,
    left: Option<Box<AichHashTree>>,
    right: Option<Box<AichHashTree>>,
}

impl AichHashTree {
    /// Base size for a node covering `data_size` bytes: blocks below the part
    /// level, parts above it (aMule `(size <= PARTSIZE) ? EMBLOCKSIZE : PARTSIZE`).
    fn base_size_for(data_size: u64) -> u64 {
        if data_size <= ED2K_PART_SIZE {
            EMBLOCKSIZE
        } else {
            ED2K_PART_SIZE
        }
    }

    /// Split rule (aMule `FindHash`): the byte size of the left child of a node
    /// covering `data_size`. The left child gets a whole number of base-size
    /// blocks, biased by one extra block on a left branch.
    fn split_left_size(data_size: u64, base_size: u64, is_left_branch: bool) -> u64 {
        let n_blocks = data_size.div_ceil(base_size);
        let blocks_left = if is_left_branch {
            n_blocks + 1
        } else {
            n_blocks
        };
        (blocks_left / 2) * base_size
    }

    /// Left-child byte size for this node.
    fn left_size(&self) -> u64 {
        Self::split_left_size(self.data_size, self.base_size, self.is_left_branch)
    }

    /// Recursively build the subtree covering `data` (aMule `FindHash` split +
    /// `SetBlockHash` leaves + `ReCalculateHash` fold, done eagerly top-down).
    fn build(data: &[u8], is_left_branch: bool) -> Self {
        Self::build_over(0, data.len() as u64, is_left_branch, &|start, size| {
            sha1_bytes(&data[start as usize..(start + size) as usize])
        })
    }

    /// Build the subtree covering the `data_size` bytes at file offset `start`,
    /// taking each leaf block's hash from `leaf_hash(start, size)`. The split
    /// rule alone shapes the tree, so a tree over a file too large to hold in
    /// memory is the same shape as one built from its bytes.
    fn build_over(
        start: u64,
        data_size: u64,
        is_left_branch: bool,
        leaf_hash: &impl Fn(u64, u64) -> [u8; HASHSIZE],
    ) -> Self {
        let base_size = Self::base_size_for(data_size);

        if data_size <= base_size {
            return Self {
                data_size,
                base_size,
                is_left_branch,
                hash: Some(leaf_hash(start, data_size)),
                left: None,
                right: None,
            };
        }

        let n_left = Self::split_left_size(data_size, base_size, is_left_branch);
        let left = Box::new(Self::build_over(start, n_left, true, leaf_hash));
        let right = Box::new(Self::build_over(
            start + n_left,
            data_size - n_left,
            false,
            leaf_hash,
        ));
        let hash = sha1_pair(
            &left.hash.expect("built leaf/node has a hash"),
            &right.hash.expect("built leaf/node has a hash"),
        );
        Self {
            data_size,
            base_size,
            is_left_branch,
            hash: Some(hash),
            left: Some(left),
            right: Some(right),
        }
    }

    /// A childless node covering `data_size` bytes with no hash yet. The receive
    /// side grows the verify tree from one of these, creating only the nodes a
    /// recovery datagram actually addresses (aMule builds its verify tree on
    /// demand in `SetHash`), so a part-level *sibling* stays childless — a leaf
    /// carrying just its aggregate hash — instead of expanding into block nodes
    /// that were never sent and could never be filled.
    fn childless(data_size: u64, is_left_branch: bool) -> Self {
        Self {
            data_size,
            base_size: Self::base_size_for(data_size),
            is_left_branch,
            hash: None,
            left: None,
            right: None,
        }
    }

    /// The node exactly covering `[start, start+size)`, or `None` if none does
    /// (immutable aMule `FindHash`).
    fn find(&self, start: u64, size: u64) -> Option<&Self> {
        if start == 0 && size == self.data_size {
            return Some(self);
        }
        if self.data_size <= self.base_size {
            return None;
        }
        let n_left = self.left_size();
        if start < n_left {
            self.left.as_deref()?.find(start, size)
        } else {
            self.right.as_deref()?.find(start - n_left, size)
        }
    }

    /// Depth (root..target node inclusive) of the node exactly covering
    /// `[start, start+size)` (aMule `FindHash`'s `nLevel` out-parameter).
    fn find_level(&self, start: u64, size: u64, level: u8) -> Option<u8> {
        let level = level + 1;
        if start == 0 && size == self.data_size {
            return Some(level);
        }
        if self.data_size <= self.base_size {
            return None;
        }
        let n_left = self.left_size();
        if start < n_left {
            self.left.as_ref()?.find_level(start, size, level)
        } else {
            self.right.as_ref()?.find_level(start - n_left, size, level)
        }
    }

    /// Append this node's tree-position identifier (the path bits including its
    /// own branch bit) and its 20-byte hash (aMule `CAICHHashTree::WriteHash`).
    fn write_hash(&self, ident: u32, out: &mut Vec<u8>, use_32: bool) {
        let ident = (ident << 1) | u32::from(self.is_left_branch);
        write_ident(ident, out, use_32);
        out.extend_from_slice(&self.hash.expect("built node has a hash"));
    }

    /// Append every leaf (block) hash under this node, left to right, each with
    /// its identifier (aMule `CAICHHashTree::WriteLowestLevelHashs`).
    fn write_lowest_level_hashs(&self, ident: u32, out: &mut Vec<u8>, use_32: bool) {
        let ident = (ident << 1) | u32::from(self.is_left_branch);
        match (&self.left, &self.right) {
            (None, None) => {
                write_ident(ident, out, use_32);
                out.extend_from_slice(&self.hash.expect("built leaf has a hash"));
            }
            (Some(left), Some(right)) => {
                left.write_lowest_level_hashs(ident, out, use_32);
                right.write_lowest_level_hashs(ident, out, use_32);
            }
            _ => debug_assert!(false, "incomplete AICH tree node"),
        }
    }

    /// Serialize the recovery data for the part covering `[start, start+size)`:
    /// the sibling hash at each descent level, then the part's block hashes
    /// (aMule `CAICHHashTree::CreatePartRecoveryData`).
    fn create_part_recovery_data(
        &self,
        start: u64,
        size: u64,
        ident: u32,
        out: &mut Vec<u8>,
        use_32: bool,
    ) {
        if start == 0 && size == self.data_size {
            self.write_lowest_level_hashs(ident, out, use_32);
            return;
        }
        let ident = (ident << 1) | u32::from(self.is_left_branch);
        let n_left = self.left_size();
        let (Some(left), Some(right)) = (&self.left, &self.right) else {
            debug_assert!(false, "incomplete AICH tree node");
            return;
        };
        if start < n_left {
            right.write_hash(ident, out, use_32);
            left.create_part_recovery_data(start, size, ident, out, use_32);
        } else {
            left.write_hash(ident, out, use_32);
            right.create_part_recovery_data(start - n_left, size, ident, out, use_32);
        }
    }

    /// Place `hash` at the node addressed by `ident` (the leading 1 is the root
    /// sentinel; the bits below it are the left/right path, MSB first — aMule
    /// `CAICHHashTree::SetHash`), creating path nodes on demand. Existing hashes
    /// are never overwritten.
    fn set_hash(&mut self, ident: u32, hash: [u8; HASHSIZE]) -> Result<(), AichRecoveryError> {
        if ident == 0 {
            return Err(AichRecoveryError::Malformed);
        }
        let mut node = self;
        let mut level = ident.ilog2();
        while level > 0 {
            level -= 1;
            if node.data_size <= node.base_size {
                // The identifier descends past a leaf — outside the tree.
                return Err(AichRecoveryError::Malformed);
            }
            let n_left = node.left_size();
            let n_right = node.data_size - n_left;
            let next = if (ident >> level) & 1 == 1 {
                node.left
                    .get_or_insert_with(move || Box::new(AichHashTree::childless(n_left, true)))
            } else {
                node.right
                    .get_or_insert_with(move || Box::new(AichHashTree::childless(n_right, false)))
            };
            node = next.as_mut();
        }
        if node.hash.is_none() {
            node.hash = Some(hash);
        }
        Ok(())
    }

    /// Fill internal-node hashes from their children where both are known
    /// (aMule `CAICHHashTree::ReCalculateHash`, `bDontReplace = true`). Returns
    /// whether the subtree is internally consistent enough to continue.
    fn recalculate(&mut self) -> bool {
        let (Some(left), Some(right)) = (self.left.as_mut(), self.right.as_mut()) else {
            // A leaf (both children absent) is fine; a half-built node is not.
            return self.left.is_none() && self.right.is_none();
        };
        if !left.recalculate() || !right.recalculate() {
            return false;
        }
        let children = (left.hash, right.hash);
        if self.hash.is_some() {
            return true;
        }
        match children {
            (Some(lh), Some(rh)) => {
                self.hash = Some(sha1_pair(&lh, &rh));
                true
            }
            _ => false,
        }
    }

    /// Check that every internal node's hash equals the combine of its children
    /// (aMule `CAICHHashTree::VerifyHashTree`). With the root preset to a trusted
    /// value, a `true` result means the whole subtree chains to that root.
    fn verify(&self) -> bool {
        let Some(mine) = self.hash else {
            return false;
        };
        match (self.left.as_deref(), self.right.as_deref()) {
            (Some(left), Some(right)) => match (left.hash, right.hash) {
                (Some(lh), Some(rh)) => {
                    sha1_pair(&lh, &rh) == mine && left.verify() && right.verify()
                }
                // Nothing populated below: this is the deepest verified hash.
                (None, None) => true,
                // One branch present, one missing: cannot be verified.
                _ => false,
            },
            (None, None) => true,
            _ => false,
        }
    }
}

/// Append a hash identifier as a `u16` (or `u32` for large files).
fn write_ident(ident: u32, out: &mut Vec<u8>, use_32: bool) {
    if use_32 {
        out.extend_from_slice(&ident.to_le_bytes());
    } else {
        out.extend_from_slice(&(ident as u16).to_le_bytes());
    }
}

/// The per-file AICH SHA-1 hash tree (ADR-0038). Built from a file's bytes; its
/// root is the file's [`AichRootHash`].
#[derive(Clone, Debug)]
pub struct AichHashSet {
    tree: AichHashTree,
}

impl AichHashSet {
    /// Build the AICH hash tree over `bytes` and compute its master root. The
    /// root node is the left branch of an empty parent (aMule `CAICHHashSet`
    /// constructs `m_pHashTree(0, true, PARTSIZE)`).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            tree: AichHashTree::build(bytes, true),
        }
    }

    /// The file's AICH master root — the root of the hash tree.
    #[must_use]
    pub fn master_root(&self) -> AichRootHash {
        AichRootHash::from_bytes(self.tree.hash.expect("a built tree has a root hash"))
    }

    /// Serialize the AICH recovery data for the part beginning at
    /// `part_start_pos`: the sibling hashes along the path from the root to the
    /// part, then the part's block hashes, each tagged with its tree-position
    /// identifier (aMule `CAICHHashSet::CreatePartRecoveryData`). Returns `None`
    /// for a file too small to have an AICH tree (one block or less) or an
    /// out-of-range part. Wire layout:
    /// `[u16 count16][(u16 ident, hash20)…][u16 count32][(u32 ident, hash20)…]`,
    /// with 32-bit identifiers only for a large file (aMule
    /// `bUse32BitIdentifier = IsLargeFile()`, `SHAHashSet.cpp:495`; see
    /// [`is_large_file`](crate::is_large_file)).
    #[must_use]
    pub fn create_part_recovery_data(&self, part_start_pos: u64) -> Option<Vec<u8>> {
        let file_size = self.tree.data_size;
        if file_size <= EMBLOCKSIZE || part_start_pos >= file_size {
            return None;
        }
        let part_size = ED2K_PART_SIZE.min(file_size - part_start_pos);
        let level = self.tree.find_level(part_start_pos, part_size, 0)?;
        let n_blocks = part_size.div_ceil(EMBLOCKSIZE);
        let n_hashs = (u64::from(level) - 1) + n_blocks;
        let use_32 = crate::is_large_file(file_size);

        let mut out = Vec::new();
        if use_32 {
            out.extend_from_slice(&0u16.to_le_bytes()); // no 16-bit hashs
        }
        out.extend_from_slice(&(n_hashs as u16).to_le_bytes());
        self.tree
            .create_part_recovery_data(part_start_pos, part_size, 0, &mut out, use_32);
        if !use_32 {
            out.extend_from_slice(&0u16.to_le_bytes()); // no 32-bit hashs
        }
        Some(out)
    }

    /// Read a part's `recovery_data`, confirm it chains to `trusted_root`, then
    /// return the indices (within the part) of the 180 KiB blocks whose bytes in
    /// `part_bytes` do not match their AICH block hash — the corrupt blocks
    /// (aMule `CAICHHashSet::ReadRecoveryData` + block comparison). An empty
    /// result means the whole part is intact. `part_bytes` must be the complete
    /// assembled part. Errors are non-terminal (ADR-0038): the caller takes the
    /// path of a part with no trusted root.
    pub fn verify_part(
        file_size: u64,
        part_start_pos: u64,
        part_bytes: &[u8],
        recovery_data: &[u8],
        trusted_root: AichRootHash,
    ) -> Result<Vec<u16>, AichRecoveryError> {
        if file_size <= EMBLOCKSIZE || part_start_pos >= file_size {
            return Err(AichRecoveryError::Malformed);
        }
        let part_size = ED2K_PART_SIZE.min(file_size - part_start_pos);
        if part_bytes.len() as u64 != part_size {
            return Err(AichRecoveryError::Malformed);
        }

        let mut tree = AichHashTree::childless(file_size, true);
        tree.hash = Some(*trusted_root.as_bytes());

        // Load the recovery hashes into the skeleton by their identifiers. The
        // master identifier (1) is never accepted, so a sender cannot overwrite
        // the trusted root (aMule rejects ident 1 / ident > 0x400000).
        let mut reader = WireReader::new(recovery_data);
        let count16 = reader.read_u16_le("recovery hash count")?;
        for _ in 0..count16 {
            let ident = u32::from(reader.read_u16_le("recovery hash ident")?);
            let hash = reader.read_array("recovery hash")?;
            if ident <= 1 {
                return Err(AichRecoveryError::Malformed);
            }
            tree.set_hash(ident, hash)?;
        }
        if count16 == 0 && reader.remaining() >= 2 {
            let count32 = reader.read_u16_le("recovery hash count")?;
            for _ in 0..count32 {
                let ident = reader.read_u32_le("recovery hash ident")?;
                let hash = reader.read_array("recovery hash")?;
                if ident <= 1 || ident > 0x0040_0000 {
                    return Err(AichRecoveryError::Malformed);
                }
                tree.set_hash(ident, hash)?;
            }
        }

        // Recompute internal nodes and confirm everything chains to the trusted
        // root. A sender who lies about any hash fails this (SHA-1 preimage
        // resistance), so the recovered block hashes below are now trusted.
        tree.recalculate();
        if !tree.verify() {
            return Err(AichRecoveryError::Untrusted);
        }

        // Localize: compare each downloaded block against its trusted block hash.
        let mut corrupt = Vec::new();
        let mut offset = 0u64;
        let mut block_index = 0u16;
        while offset < part_size {
            let block_size = EMBLOCKSIZE.min(part_size - offset);
            let leaf = tree
                .find(part_start_pos + offset, block_size)
                .and_then(|node| node.hash)
                .ok_or(AichRecoveryError::IncompletePart)?;
            let block = &part_bytes[offset as usize..(offset + block_size) as usize];
            if sha1_bytes(block) != leaf {
                corrupt.push(block_index);
            }
            offset += block_size;
            block_index += 1;
        }
        Ok(corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_root_of_a_sub_block_file_is_sha1_of_its_bytes() {
        // A file no larger than one EMBLOCKSIZE leaf is a single AICH leaf, so
        // its master root is plain SHA-1 of the bytes. Anchored to the FIPS-180
        // SHA-1("abc") test vector, which externally pins both the SHA-1 wrap
        // and the leaf-only tree.
        let root = AichHashSet::from_bytes(b"abc").master_root();
        assert_eq!(
            root.as_bytes(),
            &[
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ],
        );
    }

    #[test]
    fn two_block_file_splits_at_emblocksize_and_combines_left_then_right() {
        // A file of EMBLOCKSIZE + 1 bytes is two leaves: block 0 is the first
        // EMBLOCKSIZE bytes, block 1 is the trailing byte. The split must land
        // exactly on the EMBLOCKSIZE boundary and fold left-then-right, so the
        // master root is SHA-1( SHA-1(block0) ‖ SHA-1(block1) ). A wrong split
        // boundary or child order would hash different leaf bytes and fail.
        let size = (EMBLOCKSIZE + 1) as usize;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (block0, block1) = bytes.split_at(EMBLOCKSIZE as usize);

        let expected = sha1_pair(&sha1_bytes(block0), &sha1_bytes(block1));
        let root = AichHashSet::from_bytes(&bytes).master_root();
        assert_eq!(root.as_bytes(), &expected);
    }

    #[test]
    fn recovery_data_for_a_single_part_file_has_one_hash_per_block() {
        // A 3-block file is one AICH part at the tree root (level 1, so no
        // sibling hashes), so its recovery data is exactly the three block
        // hashes: header count16 = 3, a (u16 ident, 20-byte hash) per block,
        // trailing count32 = 0.
        let bytes = vec![0u8; (3 * EMBLOCKSIZE) as usize];
        let rec = AichHashSet::from_bytes(&bytes)
            .create_part_recovery_data(0)
            .expect("a multi-block file has recovery data");

        assert_eq!(u16::from_le_bytes([rec[0], rec[1]]), 3);
        assert_eq!(
            u16::from_le_bytes([rec[rec.len() - 2], rec[rec.len() - 1]]),
            0,
        );
        // 2 (count16) + 3 × (2 ident + 20 hash) + 2 (count32).
        assert_eq!(rec.len(), 2 + 3 * (2 + HASHSIZE) + 2);
    }

    #[test]
    fn a_file_one_byte_past_old_max_file_size_writes_32_bit_identifiers() {
        // aMule `CreatePartRecoveryData` keys the identifier width on
        // `IsLargeFile()` (`SHAHashSet.cpp:495`), strictly past
        // OLD_MAX_FILE_SIZE. A large file writes `[u16 0]`, `[u16 n]` and n ×
        // (u32 ident, hash20); any other file writes `[u16 n]`, n × (u16
        // ident, hash20) and `[u16 0]`. Part 0 of either size sits ten levels
        // down (442 or 441 parts, then 221, 111, 56, 28, 14, 7, 4, 2, 1 under
        // the left-branch split), so n is 9 sibling hashes plus its 53 block
        // hashes. Leaf hashes are synthetic: the width and the count follow
        // from the tree's shape alone, and 4 GiB of bytes would not.
        let synthetic =
            |start: u64, size: u64| sha1_bytes(&[start.to_le_bytes(), size.to_le_bytes()].concat());
        let part_zero = |file_size| {
            AichHashSet {
                tree: AichHashTree::build_over(0, file_size, true, &synthetic),
            }
            .create_part_recovery_data(0)
            .expect("a multi-part file has recovery data")
        };
        let count = 9 + 53;
        let word = |data: &[u8], at: usize| u16::from_le_bytes([data[at], data[at + 1]]);

        let large = part_zero(crate::OLD_MAX_FILE_SIZE + 1);
        assert_eq!(word(&large, 0), 0, "no 16-bit hashes");
        assert_eq!(usize::from(word(&large, 2)), count);
        assert_eq!(
            large.len(),
            4 + count * (4 + HASHSIZE),
            "nothing trails the 32-bit list"
        );

        let old_max = part_zero(crate::OLD_MAX_FILE_SIZE);
        assert_eq!(usize::from(word(&old_max, 0)), count);
        assert_eq!(old_max.len(), 2 + count * (2 + HASHSIZE) + 2);
        assert_eq!(word(&old_max, old_max.len() - 2), 0, "no 32-bit hashes");

        // Both name the same first tree position, in their own width.
        let ident32 = u32::from_le_bytes(large[4..8].try_into().expect("four bytes"));
        assert_eq!(ident32, u32::from(word(&old_max, 2)));
    }

    #[test]
    fn recovery_data_round_trips_and_localizes_a_corrupt_block() {
        // A 2-part file: part 0 is full (PARTSIZE), part 1 is three blocks.
        // Serializing part 1's recovery data (the sibling hash for part 0 plus
        // part 1's three block hashes) and reading it back against the trusted
        // master root must verify, report no bad blocks for the true bytes, and
        // pinpoint exactly the one block we corrupt — proving the sibling-path
        // navigation, the chain-to-root check, and block localization.
        let part1_blocks = 3u64;
        let file_size = ED2K_PART_SIZE + part1_blocks * EMBLOCKSIZE;
        let bytes: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
        let full = AichHashSet::from_bytes(&bytes);
        let root = full.master_root();

        let part_start = ED2K_PART_SIZE;
        let part_bytes = &bytes[part_start as usize..];
        let rec = full
            .create_part_recovery_data(part_start)
            .expect("recovery data for part 1");

        let clean =
            AichHashSet::verify_part(file_size, part_start, part_bytes, &rec, root).unwrap();
        assert!(clean.is_empty(), "intact part has no corrupt blocks");

        let mut corrupt = part_bytes.to_vec();
        corrupt[EMBLOCKSIZE as usize] ^= 0xFF; // flip a byte in block 1
        let bad = AichHashSet::verify_part(file_size, part_start, &corrupt, &rec, root).unwrap();
        assert_eq!(bad, vec![1], "only the corrupted block is localized");
    }

    #[test]
    fn recovery_data_that_does_not_chain_to_the_trusted_root_is_rejected() {
        // A liar's recovery data (a tampered hash) cannot recompute to the
        // trusted master root, so verification rejects it before any block is
        // trusted.
        let file_size = 3 * EMBLOCKSIZE;
        let bytes: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
        let full = AichHashSet::from_bytes(&bytes);
        let mut rec = full
            .create_part_recovery_data(0)
            .expect("recovery data for the single part");
        rec[10] ^= 0xFF; // flip a byte inside the first block hash

        let err = AichHashSet::verify_part(file_size, 0, &bytes, &rec, full.master_root())
            .expect_err("tampered recovery data must be rejected");
        assert_eq!(err, AichRecoveryError::Untrusted);
    }

    #[test]
    fn recovery_data_cut_at_any_byte_is_rejected() {
        let part1_blocks = 3u64;
        let file_size = ED2K_PART_SIZE + part1_blocks * EMBLOCKSIZE;
        let bytes: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
        let full = AichHashSet::from_bytes(&bytes);
        let part_start = ED2K_PART_SIZE;
        let rec = full
            .create_part_recovery_data(part_start)
            .expect("recovery data for part 1");
        // The trailing 32-bit-ident count is read only when the 16-bit count is
        // zero (aMule), so the cuts that matter end inside the 16-bit section.
        let count16 = usize::from(u16::from_le_bytes([rec[0], rec[1]]));
        let section_end = 2 + count16 * (2 + HASHSIZE);
        assert!(count16 > 0 && section_end <= rec.len());
        for cut in 0..section_end {
            assert!(
                AichHashSet::verify_part(
                    file_size,
                    part_start,
                    &bytes[part_start as usize..],
                    &rec[..cut],
                    full.master_root()
                )
                .is_err(),
                "recovery data cut to {cut} of {} bytes verified",
                rec.len()
            );
        }
    }
}
