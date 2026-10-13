//! A flow's files shared the way the operator shares them: a throwaway
//! directory holding them is added to the **Shared Directory List** and its
//! confirm answered yes (ADR-0101, "Shared Directories"). Core shares no lone
//! file, so a driver that serves one builds a directory around it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmule_core::run_log::Level;
use rmule_core::{Core, CoreCommand, CoreEvent, ScanCommand, ScanEvent, ServeEvent};

/// The longest a directory's first pass may take: it hashes every byte of
/// the flow's files, which on a bench run tens of MiB.
const SHARE_BUDGET: Duration = Duration::from_secs(600);

/// A shared throwaway directory. Its files stay shared while it lives; the
/// directory and its links go with it.
pub(crate) struct ScratchShare {
    dir: tempfile::TempDir,
}

impl ScratchShare {
    /// Place `file` in the directory now: the directory's watch shares it,
    /// answered by its `FileShared` on the event stream.
    ///
    /// # Errors
    /// The file has no name, the name is already taken, or it cannot be
    /// linked or copied in.
    pub(crate) fn add(&self, file: &Path) -> Result<()> {
        place(self.dir.path(), file)
    }
}

/// Share `files` from a fresh throwaway directory and wait for its first
/// pass to end, printing every event met on the way and handing it to
/// `observe`. Returns once every file is shared: serving is ready.
///
/// # Errors
/// A file cannot be placed, the add is refused, the pass shares fewer files
/// than given (two files of one content, or a name the scan skips: a leading
/// dot, a part file's), the stream ends, or the pass outlasts its budget.
pub(crate) async fn share_files(
    core: &mut Core,
    files: &[PathBuf],
    mut observe: impl FnMut(&CoreEvent),
) -> Result<ScratchShare> {
    let dir = tempfile::Builder::new()
        .prefix("rmule-tools-share-")
        .tempdir()
        .context("create the throwaway shared directory")?;
    for file in files {
        place(dir.path(), file)?;
    }
    core.send(CoreCommand::Scan(ScanCommand::AddSharedDirectory {
        path: dir.path().to_path_buf(),
    }))
    .await?;
    // Core names a directory by its canonical path; another directory's
    // confirm or pass (the download directory's first share) is not this one's.
    let own = std::fs::canonicalize(dir.path()).unwrap_or_else(|_| dir.path().to_path_buf());
    let ours = |asked: &Path| asked == own || asked == dir.path();
    let mut shared = 0;
    let deadline = tokio::time::Instant::now() + SHARE_BUDGET;
    loop {
        let Ok(event) = tokio::time::timeout_at(deadline, core.next_event()).await else {
            bail!(
                "the shared directory's pass did not end within {}s",
                SHARE_BUDGET.as_secs()
            );
        };
        let Some(event) = event else {
            bail!("the event stream ended before the shared directory's pass did");
        };
        println!("{}", event.record().render(Level::Full));
        observe(&event);
        match event {
            // The confirm a front end would put to the operator: this driver
            // is the operator, and it placed every file there itself.
            CoreEvent::Scan(ScanEvent::ConsentRequested { dir: asked, .. }) if ours(&asked) => {
                core.send(CoreCommand::Scan(ScanCommand::Answer {
                    dir: asked,
                    share: true,
                }))
                .await?;
            }
            CoreEvent::Scan(ScanEvent::DirectoryRefused {
                dir: refused,
                reason,
            }) if ours(&refused) => {
                bail!("{} was not shared: {reason:?}", refused.display());
            }
            CoreEvent::Serve(ServeEvent::FileShared { .. }) => shared += 1,
            CoreEvent::Scan(ScanEvent::Finished { dir: finished, .. }) if ours(&finished) => break,
            _ => {}
        }
    }
    // Another directory's pass may share files meanwhile; fewer than ours
    // is what says ours were not all taken.
    if shared < files.len() {
        bail!(
            "{shared} of {} files shared: two of one content, or a name the scan skips",
            files.len()
        );
    }
    Ok(ScratchShare { dir })
}

/// Put `file` into `dir` under its own name: a hard link where the two share
/// a filesystem, a copy where they do not. Never a symlink, which the scan
/// does not follow.
fn place(dir: &Path, file: &Path) -> Result<()> {
    let name = file
        .file_name()
        .with_context(|| format!("{} names no file", file.display()))?;
    let target = dir.join(name);
    if target.exists() {
        bail!("two files named {} to share", name.to_string_lossy());
    }
    if std::fs::hard_link(file, &target).is_err() {
        std::fs::copy(file, &target)
            .with_context(|| format!("copy {} into the shared directory", file.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rmule_core::{Core, CoreConfig, open_durable_store_in_memory};

    use super::share_files;

    /// Files from two directories are shared from one throwaway directory,
    /// each by its own content, and the directory is gone with the share.
    #[tokio::test(flavor = "multi_thread")]
    async fn files_from_two_places_are_shared_from_one_directory() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let one = a.path().join("one.bin");
        let two = b.path().join("two.bin");
        std::fs::write(&one, b"first file, its own bytes").unwrap();
        std::fs::write(&two, b"second file, other bytes!").unwrap();
        let mut core = Core::builder(
            CoreConfig::default(),
            open_durable_store_in_memory().unwrap(),
        )
        .settings(rmule_core::CoreSettings::default())
        .build();

        let mut seen = 0;
        let share = share_files(&mut core, &[one, two], |_| seen += 1)
            .await
            .expect("both shared");
        let dir = share.dir.path().to_path_buf();
        assert!(seen > 0, "the events met are handed on");
        drop(share);
        assert!(!dir.exists());
        core.shutdown().await;
    }

    /// The download directory's first-share confirm, met during the pass,
    /// is handed on unanswered and its pass does not end this one: only the
    /// flow's own file is shared.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_download_directorys_confirm_is_left_to_the_caller() {
        let (ours, downloads) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let one = ours.path().join("one.bin");
        std::fs::write(&one, b"the flow's own file, shared").unwrap();
        std::fs::write(downloads.path().join("done.bin"), b"a finished download").unwrap();
        let mut core = Core::builder(
            CoreConfig::default(),
            open_durable_store_in_memory().unwrap(),
        )
        .settings(rmule_core::CoreSettings {
            download_dir: Some(downloads.path().to_path_buf()),
            ..rmule_core::CoreSettings::default()
        })
        .build();

        let mut asked = Vec::new();
        let mut shared = Vec::new();
        let share = share_files(&mut core, &[one], |event| match event {
            rmule_core::CoreEvent::Scan(rmule_core::ScanEvent::ConsentRequested {
                adding: false,
                ..
            }) => asked.push(()),
            rmule_core::CoreEvent::Serve(rmule_core::ServeEvent::FileShared { file_hash }) => {
                shared.push(*file_hash);
            }
            _ => {}
        })
        .await
        .expect("the flow's file is shared");
        assert_eq!(asked.len(), 1, "the download directory asked once");
        assert_eq!(shared.len(), 1, "nothing under the download directory");
        drop(share);
        core.shutdown().await;
    }

    /// Two files of one name cannot sit in one directory: refused before
    /// anything is sent.
    #[tokio::test]
    async fn two_files_of_one_name_are_refused() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(a.path().join("same.bin"), b"left").unwrap();
        std::fs::write(b.path().join("same.bin"), b"right").unwrap();
        let mut core = Core::builder(
            CoreConfig::default(),
            open_durable_store_in_memory().unwrap(),
        )
        .settings(rmule_core::CoreSettings::default())
        .build();

        let refused = share_files(
            &mut core,
            &[a.path().join("same.bin"), b.path().join("same.bin")],
            |_| {},
        )
        .await;
        assert!(refused.is_err());
        core.shutdown().await;
    }
}
