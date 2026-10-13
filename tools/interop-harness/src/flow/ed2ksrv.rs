//! The `ed2ksrv` coordinator's pin of record, and its clone-and-build step.
//!
//! The pin is written once, in the image recipe's `pin.env`, which `build.sh`
//! verifies a clone against and stamps onto the image as labels. The rule every
//! pinned counterparty follows (build through `build.sh`, check the label
//! before starting, read the verdict's pin off it) lives in
//! [`crate::flow::pinned_image`]; [`ED2KSRV`] is this counterparty's entry.
//!
//! `--build-images` builds the image the one way that stamps the pin:
//! [`build`] hands a clean clone at the pinned commit to the recipe's own
//! `build.sh`. A bare `docker build` of the recipe directory cannot work — the
//! build context is the server's source tree, not the recipe.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::flow::pinned_image::Counterparty;

/// The recipe's pin file, compiled in so the harness and `build.sh` read one
/// source.
const PIN_ENV: &str = include_str!("../../images/ed2ksrv/pin.env");

/// Set to an existing clone of the server's repository to build from it
/// instead of a fresh clone; `build.sh` still refuses it unless it sits clean
/// at the pin.
pub(crate) const SOURCE_ENV: &str = "ED2KSRV_SRC";

/// The `ed2ksrv` coordinator under the shared pinned-image rule.
pub(crate) static ED2KSRV: Counterparty = Counterparty {
    noun: "the ed2k-server image",
    recipe: "images/ed2ksrv",
    commit_label: "org.rmule.ed2ksrv.commit",
    tag_env: "ED2KSRV_TAG",
    variant: None,
    off_pin_env: "RMULE_BENCH_ED2KSRV_OFF_PIN",
    commit,
    text: pin_text,
    rebuild: "tools/interop-harness/images/ed2ksrv/build.sh <clone>",
};

/// One `KEY=value` line of the pin file.
fn field(key: &str) -> &'static str {
    PIN_ENV
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| name.trim() == key)
        .map_or("", |(_, value)| value.trim())
}

/// The pinned commit, full length.
fn commit() -> &'static str {
    field("ED2KSRV_COMMIT")
}

/// Build the `ed2ksrv` image `tag` with the recipe's `build.sh` in `recipe`
/// (`images/ed2ksrv`): from [`SOURCE_ENV`]'s clone when set, else from a fresh
/// clone of the pinned repository checked out at the pinned commit under
/// `scratch`, removed once the build ends. `build.sh` verifies the clone
/// against the pin and stamps the labels [`Counterparty::check`] reads; it
/// calls `docker` itself, whatever `--container-runtime` names.
///
/// # Errors
/// If the clone, the checkout or `build.sh` fails; the error names the step.
pub(crate) fn build(tag: &str, recipe: &Path, scratch: &Path) -> Result<()> {
    if !recipe.join("build.sh").is_file() {
        bail!(
            "--build-images builds the ed2k-server image with {}, which is missing",
            recipe.join("build.sh").display()
        );
    }
    if let Ok(source) = std::env::var(SOURCE_ENV) {
        return run_build_script(recipe, tag, Path::new(&source));
    }
    let clone = scratch.join("ed2ksrv-src");
    if clone.exists() {
        std::fs::remove_dir_all(&clone)
            .with_context(|| format!("remove a stale {}", clone.display()))?;
    }
    let url = format!("https://github.com/{}", field("ED2KSRV_REPO"));
    let built = (|| {
        run(
            Command::new("git")
                .args(["clone", "--quiet", &url])
                .arg(&clone),
            &format!("clone {url} for the ed2k-server image"),
        )?;
        run(
            Command::new("git").arg("-C").arg(&clone).args([
                "checkout",
                "--quiet",
                "--detach",
                commit(),
            ]),
            &format!("check out the ed2k-server pin {}", pin_text()),
        )?;
        run_build_script(recipe, tag, &clone)
    })();
    let removed = std::fs::remove_dir_all(&clone)
        .with_context(|| format!("remove the ed2k-server clone {}", clone.display()));
    built.and(removed)
}

fn run_build_script(script_dir: &Path, tag: &str, source: &Path) -> Result<()> {
    ED2KSRV.build_with(script_dir, tag, &[source])
}

fn run(command: &mut Command, step: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("{step}: could not start"))?;
    if !status.success() {
        bail!("{step}: {status}");
    }
    Ok(())
}

/// The pin as prose names it: repository, short commit, release.
pub(crate) fn pin_text() -> String {
    format!(
        "{} {} ({})",
        field("ED2KSRV_REPO"),
        commit().get(..7).unwrap_or_default(),
        field("ED2KSRV_VERSION"),
    )
}

#[cfg(test)]
mod tests {
    use super::{commit, pin_text};

    #[test]
    fn the_pin_is_read_whole_from_the_recipe_file() {
        assert_eq!(commit().len(), 40, "a full SHA, as build.sh compares it");
        assert!(pin_text().starts_with("andrey23127/ed2k-server "));
        assert!(commit().starts_with(pin_text().split(' ').nth(1).unwrap()));
    }
}
