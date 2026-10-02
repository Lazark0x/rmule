//! The `ed2ksrv` coordinator's pin of record, and the check every flow passes
//! before it starts the image.
//!
//! The pin is written once, in the image recipe's `pin.env`, which `build.sh`
//! verifies a clone against and stamps onto the image as labels. Starting an
//! `ed2ksrv` container goes through [`Ed2ksrvImage::check`]: an image whose
//! `org.rmule.ed2ksrv.commit` label is not the pinned commit — a bare
//! `docker build` of the recipe, an image from before the label existed, a
//! build of another commit — is refused, because every verdict it produced
//! would rest on source nobody can name. A deliberate off-pin run sets
//! [`OFF_PIN_ENV`]; its verdicts then name the pin **unverified** (ADR-0045 as
//! amended 2026-09-16, point 1).
//!
//! `--build-images` builds the image the one way that stamps the pin:
//! [`build`] hands a clean clone at the pinned commit to the recipe's own
//! `build.sh`. A bare `docker build` of the recipe directory cannot work — the
//! build context is the server's source tree, not the recipe.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::docker::{Docker, RunContainer};

/// Set to `1` to start an `ed2ksrv` image whose label does not match the pin;
/// every verdict of that run names the pin unverified.
pub(crate) const OFF_PIN_ENV: &str = "RMULE_BENCH_ED2KSRV_OFF_PIN";

/// The recipe's pin file, compiled in so the harness and `build.sh` read one
/// source.
const PIN_ENV: &str = include_str!("../../images/ed2ksrv/pin.env");

/// Set to an existing clone of the server's repository to build from it
/// instead of a fresh clone; `build.sh` still refuses it unless it sits clean
/// at the pin.
pub(crate) const SOURCE_ENV: &str = "ED2KSRV_SRC";

/// The label `build.sh` stamps the verified commit under.
const COMMIT_LABEL: &str = "org.rmule.ed2ksrv.commit";

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
/// against the pin and stamps the labels [`Ed2ksrvImage::check`] reads; it
/// calls `docker` itself, whatever `--container-runtime` names.
///
/// # Errors
/// If the clone, the checkout or `build.sh` fails; the error names the step.
pub(crate) fn build(tag: &str, recipe: &Path, scratch: &Path) -> Result<()> {
    let script = recipe.join("build.sh");
    if !script.is_file() {
        bail!(
            "--build-images builds the ed2k-server image with {}, which is missing",
            script.display()
        );
    }
    if let Ok(source) = std::env::var(SOURCE_ENV) {
        return run_build_script(&script, tag, Path::new(&source));
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
        run_build_script(&script, tag, &clone)
    })();
    let removed = std::fs::remove_dir_all(&clone)
        .with_context(|| format!("remove the ed2k-server clone {}", clone.display()));
    built.and(removed)
}

fn run_build_script(script: &Path, tag: &str, source: &Path) -> Result<()> {
    run(
        Command::new("bash")
            .arg(script)
            .arg(source)
            .env("ED2KSRV_TAG", tag),
        &format!(
            "build the ed2k-server image {tag} with {}",
            script.display()
        ),
    )
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

/// The pin, qualified by what the image's own label says.
fn qualified(image: &str, label: &str) -> String {
    if label == commit() {
        format!(
            "{}, verified by the image's {COMMIT_LABEL} label",
            pin_text()
        )
    } else {
        format!(
            "{} — UNVERIFIED: {image} carries {COMMIT_LABEL} = {label:?}; only an image \
             built by images/ed2ksrv/build.sh is known to be the pin",
            pin_text()
        )
    }
}

/// The `org.rmule.ed2ksrv.commit` label of `image`; empty when the image is
/// absent, unlabelled or cannot be inspected.
fn commit_label(docker: &Docker, image: &str) -> String {
    docker
        .image_label(image.to_owned(), COMMIT_LABEL)
        .to_command()
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|label| label != "<no value>")
        .unwrap_or_default()
}

/// The `Body.pin` for the `ed2ksrv` image a flow ran. An image that cannot be
/// inspected reads unverified, never pinned.
pub(crate) fn body_pin(docker: &Docker, image: &str) -> String {
    qualified(image, &commit_label(docker, image))
}

/// An `ed2ksrv` image a flow may start: its label matches the pin, or the run
/// set [`OFF_PIN_ENV`].
pub(crate) struct Ed2ksrvImage {
    image: String,
    label: String,
}

impl Ed2ksrvImage {
    /// Read `image`'s commit label and refuse it unless it is the pinned
    /// commit or [`OFF_PIN_ENV`] is set.
    ///
    /// # Errors
    /// When the label does not match the pin and no override is set; the
    /// error names the image, its label, the pin and how to rebuild.
    pub(crate) fn check(docker: &Docker, image: &str) -> Result<Self> {
        let label = commit_label(docker, image);
        let off_pin = std::env::var(OFF_PIN_ENV).is_ok_and(|value| value == "1");
        admit(image, &label, off_pin)?;
        Ok(Self {
            image: image.to_owned(),
            label,
        })
    }

    /// The container to start, before the flow's own network and mounts.
    pub(crate) fn container(&self) -> RunContainer {
        RunContainer::new(&self.image)
    }

    /// The `Body.pin` for this image.
    pub(crate) fn pin(&self) -> String {
        qualified(&self.image, &self.label)
    }
}

/// Whether an image labelled `label` may start.
fn admit(image: &str, label: &str, off_pin: bool) -> Result<()> {
    if label == commit() {
        return Ok(());
    }
    if off_pin {
        println!(
            "ed2ksrv: {image} is off the pin ({COMMIT_LABEL} = {label:?}); {OFF_PIN_ENV}=1, so \
             every verdict names the pin unverified"
        );
        return Ok(());
    }
    let carries = if label.is_empty() {
        "carries no org.rmule.ed2ksrv.commit label".to_owned()
    } else {
        format!("carries {COMMIT_LABEL} = {label}")
    };
    bail!(
        "the ed2k-server image {image} {carries}, but images/ed2ksrv/pin.env pins {}. \
         Rebuild it from a clean clone at {}: \
         `tools/interop-harness/images/ed2ksrv/build.sh <clone>`. To run off the pin on \
         purpose, set {OFF_PIN_ENV}=1; every verdict then names the pin unverified.",
        pin_text(),
        commit(),
    )
}

#[cfg(test)]
mod tests {
    use super::{admit, commit, pin_text, qualified};

    #[test]
    fn the_pin_is_read_whole_from_the_recipe_file() {
        assert_eq!(commit().len(), 40, "a full SHA, as build.sh compares it");
        assert!(pin_text().starts_with("andrey23127/ed2k-server "));
        assert!(commit().starts_with(pin_text().split(' ').nth(1).unwrap()));
    }

    /// An image with no label, or another commit's, never borrows the pin's
    /// name as verified.
    #[test]
    fn only_the_pinned_label_verifies_the_image() {
        assert!(qualified("img", commit()).contains("verified by"));
        assert!(qualified("img", "").contains("UNVERIFIED"));
        assert!(qualified("img", "<no value>").contains("UNVERIFIED"));
        assert!(qualified("img", &"0".repeat(40)).contains("UNVERIFIED"));
    }

    /// Only the pinned label starts without the override; the override starts
    /// anything, and the refusal names the image, its label and the pin.
    #[test]
    fn an_off_pin_image_is_refused_unless_the_run_says_so() {
        assert!(admit("img", commit(), false).is_ok());
        let other = "8c1f3e0a92d4b7c6e5f4a3b2c1d0e9f8a7b6c5d4";
        let refusal = admit("rmule/interop-ed2ksrv:local", other, false)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("rmule/interop-ed2ksrv:local"));
        assert!(refusal.contains(other));
        assert!(refusal.contains(&pin_text()));
        assert!(refusal.contains("build.sh"));
        assert!(
            admit("img", "", false)
                .unwrap_err()
                .to_string()
                .contains("no org.rmule")
        );
        assert!(admit("img", other, true).is_ok());
    }
}
