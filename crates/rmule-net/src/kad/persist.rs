//! Persisting a live routing table as a v2 `nodes.dat`.
//!
//! The [`rmule_kad::NodesDat::encode_v2`] codec is pure; this module is the
//! I/O **edge** that snapshots a node's contacts and lands the bytes in the
//! config dir, so the sans-I/O node never touches the filesystem. It applies
//! aMule's `CRoutingZone::WriteFile` write **policy** (the codec faithfully
//! encodes whatever set it is handed, but the decision to write at all is the
//! edge's) and writes atomically — a sibling temp file renamed over the
//! target — so a crash mid-write never truncates a good saved table.

use std::path::{Path, PathBuf};

use rmule_kad::{KadContact, MIN_CONTACTS_TO_WRITE, NodesDat};

/// Persist `contacts` as a v2 `nodes.dat` at `path`, atomically. Returns
/// whether a file was written.
///
/// Applies aMule's `WriteFile` floor: below [`MIN_CONTACTS_TO_WRITE`]
/// contacts nothing is written (aMule's `numContacts < 25` early return), so a
/// nearly-empty table — a node still mid-bootstrap — never clobbers a good
/// saved file. aMule's separate bootstrap-unfinished guard (`!s_bootstrapList
/// .empty() && GetNumContacts() == 0`) collapses into this one floor for rmule,
/// since a node that has not finished bootstrapping holds fewer than 25
/// contacts. The count cap ([`rmule_kad::CONTACT_FILE_LIMIT`]) lives in the
/// codec.
///
/// The write is atomic and durable: the encoded bytes go to `path` + `.tmp`,
/// are fsynced, then a rename swaps them over `path` (aMule's `write_safe`).
/// A failed encode/write/rename leaves any prior `nodes.dat` untouched and
/// removes the temp stage (best-effort) instead of leaking it. The fsync
/// before the rename means a power loss right after the swap cannot leave a
/// truncated *new* file in place of a good old one.
pub async fn write_nodes_dat(path: &Path, contacts: &[KadContact]) -> std::io::Result<bool> {
    if contacts.len() < MIN_CONTACTS_TO_WRITE {
        return Ok(false);
    }
    let bytes = NodesDat::encode_v2(contacts);
    let tmp = temp_path(path);
    let staged = async {
        let mut file = tokio::fs::File::create(&tmp).await?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;
        file.sync_all().await?;
        tokio::fs::rename(&tmp, path).await
    }
    .await;
    if staged.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    staged.map(|()| true)
}

/// The sibling temp path the atomic write stages through: `path` with `.tmp`
/// appended to its file name (kept in the same directory so the rename is a
/// same-filesystem, atomic operation).
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_kad::{KadId, KadNodeEndpoint};

    use super::*;

    fn verified_contact(seed: u8) -> KadContact {
        KadContact::new(
            KadId::from_bytes([seed; KadId::BYTE_LEN]),
            KadNodeEndpoint::new(Ipv4Addr::new(45, 55, seed, 2), 4672),
            4662,
            8,
        )
        .into_verified()
    }

    #[tokio::test]
    async fn writes_and_reloads_a_routing_table_across_the_edge() {
        // The restart-continuity property for routing contacts: a table with
        // >= 25 contacts writes, and reloads to the same verified contacts.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.dat");
        let contacts: Vec<KadContact> = (1..=30).map(verified_contact).collect();

        let wrote = write_nodes_dat(&path, &contacts).await.unwrap();
        assert!(wrote, "a >= 25-contact table must be written");

        let bytes = tokio::fs::read(&path).await.unwrap();
        let reloaded = NodesDat::decode(&bytes).expect("our own v2 output decodes");
        assert_eq!(
            reloaded.contacts(),
            contacts.as_slice(),
            "routing contacts must survive the save+load cycle unchanged"
        );
    }

    #[tokio::test]
    async fn a_table_below_the_floor_is_not_written() {
        // aMule's `numContacts < 25` skip: a mid-bootstrap table must not
        // clobber a good saved file with a near-empty one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.dat");
        let contacts: Vec<KadContact> = (1..=24).map(verified_contact).collect();

        let wrote = write_nodes_dat(&path, &contacts).await.unwrap();
        assert!(!wrote, "a < 25-contact table is skipped");
        assert!(!path.exists(), "no file is left behind on a skipped write");
    }

    #[tokio::test]
    async fn a_failed_rename_leaves_no_temp_residue() {
        // Rename over an existing directory fails; the staged `.tmp` must be
        // cleaned up on that path, not leaked beside the target forever.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.dat");
        tokio::fs::create_dir(&path).await.unwrap();

        let result =
            write_nodes_dat(&path, &(1..=30).map(verified_contact).collect::<Vec<_>>()).await;

        assert!(result.is_err(), "renaming a file over a directory fails");
        assert!(
            !temp_path(&path).exists(),
            "the temp stage is removed on a failed rename"
        );
    }

    #[tokio::test]
    async fn a_fresh_write_replaces_a_prior_file_atomically() {
        // A second flush overwrites the first via the temp+rename, and leaves
        // no `.tmp` residue.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.dat");

        write_nodes_dat(&path, &(1..=30).map(verified_contact).collect::<Vec<_>>())
            .await
            .unwrap();
        write_nodes_dat(&path, &(1..=26).map(verified_contact).collect::<Vec<_>>())
            .await
            .unwrap();

        let bytes = tokio::fs::read(&path).await.unwrap();
        assert_eq!(NodesDat::decode(&bytes).unwrap().contacts().len(), 26);
        assert!(!temp_path(&path).exists(), "the temp stage is renamed away");
    }
}
