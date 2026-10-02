//! The **Synthetic File** a NAT or dialect flow hands a body to share, hashed
//! in process so the link a requester is given names exactly the bytes on
//! disk.
//!
//! In process rather than through the `Ed2kHashCommand` hook the older flows
//! use: this crate already depends on `rmule-primitives`, and a subprocess
//! would put a second hasher between the bytes on disk and the link.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// A written **Synthetic File** and the link that names it.
pub(crate) struct SyntheticFile {
    /// Where it was written (`<dir>/shared.bin`).
    pub(crate) path: PathBuf,
    /// Its canonical ed2k link.
    pub(crate) link: String,
    /// Its file hash, upper-case hex.
    pub(crate) file_hash: String,
    /// Its size in bytes.
    pub(crate) size: u64,
}

/// Write `bytes` of the deterministic pattern (`byte = offset % 251`) to
/// `<dir>/shared.bin` and compute its ed2k link.
pub(crate) fn write_hashed(dir: &Path, bytes: u64) -> Result<SyntheticFile> {
    let path = dir.join("shared.bin");
    let mut file =
        std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let mut buffer = vec![0u8; 8192];
    let mut written = 0u64;
    while written < bytes {
        let count = buffer.len().min((bytes - written) as usize);
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = ((written + index as u64) % 251) as u8;
        }
        file.write_all(&buffer[..count])
            .with_context(|| format!("write {}", path.display()))?;
        written += count as u64;
    }
    file.flush()
        .with_context(|| format!("flush {}", path.display()))?;
    drop(file);

    let handle = std::fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let summary = rmule_primitives::FileHashSummary::digest_reader(handle)
        .with_context(|| format!("hash {}", path.display()))?;
    let link = rmule_primitives::Ed2kLink::File(rmule_primitives::Ed2kFileLink {
        name: rmule_primitives::Ed2kText::from_utf8("shared.bin"),
        size: summary.file_size(),
        file_hash: summary.file_hash(),
        part_hash_set: summary.part_hash_set().cloned(),
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    });
    Ok(SyntheticFile {
        path,
        link: link.to_string(),
        file_hash: summary.file_hash().to_hex_upper(),
        size: summary.file_size(),
    })
}
