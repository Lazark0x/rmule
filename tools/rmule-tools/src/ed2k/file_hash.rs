//! The `ed2k hash-file` / `part-hashes` commands: hash a local file the way an
//! eD2k client does and print the summary, either as a canonical link or as the
//! per-part hash list the link's hash set is folded from.

use std::path::Path;

use anyhow::{Context, Result};
use rmule_primitives::{Ed2kFileLink, Ed2kLink, Ed2kText, FileHashSummary};

fn hash_path(path: &Path) -> Result<FileHashSummary> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    FileHashSummary::digest_reader(file).with_context(|| format!("hash {}", path.display()))
}

pub(crate) fn hash_file(path: &Path) -> Result<()> {
    let summary = hash_path(path)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("path has no valid UTF-8 file name")?;
    let link = Ed2kLink::File(Ed2kFileLink {
        name: Ed2kText::from_utf8(file_name),
        size: summary.file_size(),
        file_hash: summary.file_hash(),
        part_hash_set: summary.part_hash_set().cloned(),
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    });

    println!("size: {}", summary.file_size());
    println!("file_hash: {}", summary.file_hash().to_hex_upper());
    println!(
        "part_hash_count: {}",
        summary
            .part_hash_set()
            .map(|set| set.hashes().len())
            .unwrap_or_default()
    );
    println!("canonical_link: {link}");
    Ok(())
}

pub(crate) fn part_hashes(path: &Path) -> Result<()> {
    let summary = hash_path(path)?;
    println!("file_size: {}", summary.file_size());
    let Some(part_hash_set) = summary.part_hash_set() else {
        println!("part_hash_count: 0");
        return Ok(());
    };
    println!("part_hash_count: {}", part_hash_set.hashes().len());
    for (index, hash) in part_hash_set.hashes().iter().enumerate() {
        println!("{index}: {}", hash.to_hex_upper());
    }
    Ok(())
}
