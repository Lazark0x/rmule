//! The completion move as attach meets it (ADR-0115): a row a crash left
//! `Completing` is started again and resolved by what is on disk — moved
//! again when its part file is still there, completed when the finished file
//! already stands in place — and either way its registry row is written at
//! the destination before its part file goes, and it ends `Completed`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rmule_core::{
    Core, CoreConfig, CoreEvent, CoreSettings, DownloadEvent, DownloadId, DownloadLifecycle,
    DownloadPaths, DownloadRepository, DurableDownloadRepository, ServeEvent, SharedFileRegistry,
    VerifiedPartRecord, open_durable_store,
};
use rmule_core::{DurableSharedFileRegistry, ShareGuards};
use rmule_primitives::{ED2K_PART_SIZE, Ed2kFileLink};
use rmule_testkit::file_link;

use crate::fixture::next_expected;

/// Two parts: one whole, and a tail.
fn two_parts(fill: u8) -> Vec<u8> {
    let mut bytes = vec![fill; ED2K_PART_SIZE as usize];
    bytes.extend_from_slice(&[fill; 3]);
    bytes
}

/// A row whose every part is recorded and whose move has begun: `Completing`
/// with its destination stored.
fn completing(
    repo: &DurableDownloadRepository,
    link: &Ed2kFileLink,
    paths: &DownloadPaths,
) -> DownloadId {
    let id = repo.create_download(link, None, paths).unwrap().id();
    let hashes = link.part_hash_set.as_ref().unwrap().hashes();
    for (index, hash) in hashes.iter().enumerate() {
        let part_index = u32::try_from(index).unwrap();
        let offset = u64::from(part_index) * ED2K_PART_SIZE;
        repo.record_verified_part(
            id,
            VerifiedPartRecord {
                part_index,
                offset,
                len: (link.size - offset).min(ED2K_PART_SIZE),
                part_hash: *hash,
            },
        )
        .unwrap();
    }
    repo.set_lifecycle(id, DownloadLifecycle::Active).unwrap();
    repo.set_completing(id, paths.final_path()).unwrap();
    id
}

#[tokio::test]
async fn attach_resolves_completing_rows_by_the_disk_and_shares_each_before_its_part_goes() {
    let root = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(root.path()).unwrap();
    let (downloads, temp, data) = (root.join("dl"), root.join("temp"), root.join("data"));
    for dir in [&downloads, &temp, &data] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let store = open_durable_store(&data).unwrap();
    let repo = DurableDownloadRepository::new(Arc::clone(&store));
    let paths =
        |name: &str| DownloadPaths::new(downloads.join(name), temp.join(format!("{name}.part")));

    // Its part file is still there, a crashed copy's leftover beside the
    // destination: it moves again.
    let again = two_parts(0x5A);
    let again_link = file_link("again.bin", &again);
    let again_paths = paths("again.bin");
    let again_id = completing(&repo, &again_link, &again_paths);
    std::fs::write(again_paths.part_path(), &again).unwrap();
    std::fs::write(downloads.join(".again.bin.completing"), b"half").unwrap();

    // Its rename landed before the crash: the part file is gone and the
    // finished file stands in place.
    let landed = two_parts(0xA5);
    let landed_link = file_link("landed.bin", &landed);
    let landed_paths = paths("landed.bin");
    let landed_id = completing(&repo, &landed_link, &landed_paths);
    std::fs::write(landed_paths.final_path(), &landed).unwrap();

    let mut core = Core::builder(
        CoreConfig {
            download_restore_pace: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        Arc::clone(&store),
    )
    .settings(CoreSettings {
        download_dir: Some(downloads.clone()),
        temp_dir: Some(temp.clone()),
        ..crate::fixture::attach_settings().await
    })
    .share_guards(ShareGuards {
        home: None,
        data_dir: Some(data.clone()),
    })
    .restore_at_attach()
    .build();

    let mut shared = Vec::new();
    let mut completed = Vec::new();
    while completed.len() < 2 {
        match next_expected(&mut core, "both downloads completed", |event| {
            matches!(
                event,
                CoreEvent::Serve(ServeEvent::FileShared { .. })
                    | CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
            )
        })
        .await
        {
            CoreEvent::Serve(ServeEvent::FileShared { file_hash }) => shared.push(file_hash),
            CoreEvent::Download(DownloadEvent::DownloadCompleted {
                download_id,
                final_path,
            }) => completed.push((download_id, final_path)),
            _ => unreachable!("the matcher takes these two"),
        }
    }
    completed.sort_by_key(|(id, _)| id.as_u64());
    assert_eq!(
        completed,
        [
            (again_id, again_paths.final_path().to_path_buf()),
            (landed_id, landed_paths.final_path().to_path_buf())
        ]
    );
    for hash in [again_link.file_hash, landed_link.file_hash] {
        assert!(shared.contains(&hash), "shared before it completed");
    }

    let registry = DurableSharedFileRegistry::new(Arc::clone(&store));
    for (id, link, paths, bytes) in [
        (again_id, &again_link, &again_paths, &again),
        (landed_id, &landed_link, &landed_paths, &landed),
    ] {
        assert_eq!(
            repo.load_download(id).unwrap().lifecycle(),
            DownloadLifecycle::Completed
        );
        let row = registry.get(link.file_hash).unwrap().expect("its row");
        assert_eq!(row.path, paths.final_path());
        assert_eq!(&std::fs::read(paths.final_path()).unwrap(), bytes);
        assert!(!paths.part_path().exists());
    }
    assert!(!Path::new(&downloads.join(".again.bin.completing")).exists());
}
