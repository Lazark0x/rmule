//! The `rmule-tools` driver image: a thin runtime around the binary the warm
//! host-cached prebuild already produced.
//!
//! The image used to compile `rmule-tools` inside `docker build`, from a cold
//! `cargo build --release` that no layer cache survived (the legacy builder
//! keeps its stage cache as dangling images, and a prune deletes them). The
//! Kad flows build the same crate through the host-persisted target cache in
//! seconds, so the driver image takes that binary instead: [`build`] runs the
//! prebuild, stages the binary beside the recipe's `Dockerfile` and entrypoint
//! in a small context, and builds the runtime from it. An unchanged binary is
//! an unchanged `COPY`, so an unchanged tree rebuilds nothing.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::docker::{Docker, is_retriable_build_export_failure};
use crate::flow::bench::run_checked;

/// Where, under the workspace, the staged build context is kept: the host
/// scratch directory the target caches already live in (gitignored).
const STAGED_CONTEXT: &str = ".scratch/interop-rmule-tools-context";

/// The recipe's entrypoint, which sits beside its `Dockerfile`.
const ENTRYPOINT: &str = "entrypoint.sh";

/// Build the `rmule-tools` driver image `tag` from the recipe at `dockerfile`
/// around the prebuilt binary of the workspace at `workspace`.
///
/// The build retries exactly once when it fails with
/// [`is_retriable_build_export_failure`]: the legacy (non-BuildKit) builder's
/// image export flaked twice in one bench session, each failure unrelated to
/// the Dockerfile, and a second attempt against the same, now-warm context
/// cleared it both times. Any other failure is returned as-is.
///
/// This does not remove the "Created" container a flaked attempt may leave
/// behind: the legacy builder gives a build no name, label, or id for that
/// container to reclaim it by — see `CONTEXT.md`.
///
/// # Errors
/// If the prebuild, the staging or the image build fails; the error names the
/// step.
pub(crate) fn build(docker: &Docker, tag: &str, dockerfile: &Path, workspace: &Path) -> Result<()> {
    let binary = crate::rmule::prebuild_driver_binary(docker, workspace)?;
    let context = stage_context(workspace, dockerfile, &binary)?;
    let phase = "build rmule-tools driver image";
    let command = docker.build_image_with_dockerfile(
        tag,
        context.join("Dockerfile").as_os_str(),
        context.as_os_str(),
    );
    match run_checked(command.clone(), phase) {
        Ok(_) => Ok(()),
        Err(err) if is_retriable_build_export_failure(&err.to_string()) => {
            println!("{phase}: retrying once after a legacy-builder export flake: {err}");
            run_checked(command, phase).map(|_| ())
        }
        Err(err) => Err(err),
    }
}

/// Lay the recipe's `Dockerfile` and entrypoint and the prebuilt `binary` out
/// as one flat directory under `workspace`, replacing what an earlier build
/// left there. Returns that directory.
fn stage_context(workspace: &Path, dockerfile: &Path, binary: &Path) -> Result<PathBuf> {
    let recipe = dockerfile
        .parent()
        .ok_or_else(|| anyhow!("{} has no directory", dockerfile.display()))?;
    let context = workspace.join(STAGED_CONTEXT);
    if context.exists() {
        fs::remove_dir_all(&context).with_context(|| format!("clear {}", context.display()))?;
    }
    fs::create_dir_all(&context).with_context(|| format!("create {}", context.display()))?;
    for (from, name) in [
        (dockerfile.to_path_buf(), "Dockerfile"),
        (recipe.join(ENTRYPOINT), ENTRYPOINT),
        (binary.to_path_buf(), "rmule-tools"),
    ] {
        fs::copy(&from, context.join(name))
            .with_context(|| format!("stage {} into the driver image context", from.display()))?;
    }
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::stage_context;

    /// The staged context holds exactly what the runtime recipe `COPY`s, and a
    /// second staging replaces the first rather than layering on it.
    #[test]
    fn the_context_holds_the_recipe_and_the_prebuilt_binary_only() {
        let workspace = tempfile::tempdir().unwrap();
        let recipe = workspace.path().join("recipe");
        std::fs::create_dir(&recipe).unwrap();
        std::fs::write(recipe.join("Dockerfile"), "FROM scratch\n").unwrap();
        std::fs::write(recipe.join("entrypoint.sh"), "#!/bin/sh\n").unwrap();
        let binary = workspace.path().join("rmule-tools-built");
        std::fs::write(&binary, b"elf").unwrap();

        let context = stage_context(workspace.path(), &recipe.join("Dockerfile"), &binary).unwrap();
        std::fs::write(context.join("stale"), b"left by the last build").unwrap();
        let context = stage_context(workspace.path(), &recipe.join("Dockerfile"), &binary).unwrap();

        let mut names: Vec<_> = std::fs::read_dir(&context)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["Dockerfile", "entrypoint.sh", "rmule-tools"]);
        assert_eq!(std::fs::read(context.join("rmule-tools")).unwrap(), b"elf");
    }

    /// A prebuild that left no binary is named, not built around.
    #[test]
    fn a_missing_binary_fails_naming_the_file() {
        let workspace = tempfile::tempdir().unwrap();
        let recipe = workspace.path().join("recipe");
        std::fs::create_dir(&recipe).unwrap();
        std::fs::write(recipe.join("Dockerfile"), "").unwrap();
        std::fs::write(recipe.join("entrypoint.sh"), "").unwrap();
        let error = stage_context(
            workspace.path(),
            &recipe.join("Dockerfile"),
            &workspace.path().join("absent"),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("absent"), "{error:#}");
    }
}
