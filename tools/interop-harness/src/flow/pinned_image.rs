//! The one rule for every pinned counterparty image: the ed2k-server
//! coordinator, kno's aMule and emule-qt.
//!
//! A pinned counterparty's pin is written once, beside its recipe, and its
//! `build.sh` verifies a source clone against it and stamps the verified commit
//! onto the image as a label. Three things follow, the same for each of them:
//!
//! 1. `--build-images` builds the image only through the recipe's `build.sh`
//!    ([`Counterparty::build`]); a bare `docker build` of the recipe cannot
//!    stamp the pin, and for two of them cannot build at all.
//! 2. A flow that starts the image goes through [`Counterparty::check`]: an
//!    image whose commit label is not the pinned commit (a bare build, an image
//!    from before the label existed, a build of another commit) is refused,
//!    because every verdict it produced would rest on source nobody can name. A
//!    deliberate off-pin run sets the counterparty's off-pin variable; its
//!    verdicts then name the pin **unverified** (ADR-0045 as amended).
//! 3. The verdict body's `pin` is [`PinnedImage::pin`], read off the label the
//!    check saw, never a constant.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::docker::{Docker, RunContainer};

/// A second label that tells two builds of one pin apart, and what it must say
/// for a given image tag (kno's `--quic` variant).
#[derive(Clone, Copy)]
pub(crate) struct Variant {
    /// The label `build.sh` stamps the variant under.
    pub(crate) label: &'static str,
    /// What the label must hold for `image`.
    pub(crate) expected: fn(image: &str) -> &'static str,
    /// The `build.sh` flag that builds the variant, when `expected` is `YES`.
    pub(crate) build_arg: &'static str,
}

/// One pinned counterparty: where its pin lives, which label carries it, how it
/// is built and how a deliberate off-pin run is asked for.
pub(crate) struct Counterparty {
    /// The counterparty in prose (`the ed2k-server image`).
    pub(crate) noun: &'static str,
    /// The recipe directory, relative to the harness package.
    pub(crate) recipe: &'static str,
    /// The label `build.sh` stamps the verified commit under.
    pub(crate) commit_label: &'static str,
    /// The environment variable `build.sh` reads the runtime image tag from.
    pub(crate) tag_env: &'static str,
    /// The variant label, when the recipe builds more than one.
    pub(crate) variant: Option<Variant>,
    /// Set to `1` to start an image whose label does not match the pin.
    pub(crate) off_pin_env: &'static str,
    /// The pinned commit, full length, read from the pin of record.
    pub(crate) commit: fn() -> &'static str,
    /// The pin as prose names it, without the label verdict.
    pub(crate) text: fn() -> String,
    /// The `build.sh` invocation that rebuilds an off-pin image, for the refusal.
    pub(crate) rebuild: &'static str,
}

impl Counterparty {
    /// Run the recipe's `build.sh` in `recipe` (the recipe directory) with
    /// `args`, handing it `tag` as the runtime image to build. The script
    /// verifies the source against the pin and stamps the labels
    /// [`Self::check`] reads; it calls `docker` itself, whatever
    /// `--container-runtime` names. A missing script is named; any other
    /// failure carries the script's own message, which already names the
    /// reference clone it needs.
    ///
    /// # Errors
    /// If `build.sh` is missing, cannot start or exits unsuccessfully.
    pub(crate) fn build_with<S: AsRef<OsStr>>(
        &self,
        recipe: &Path,
        tag: &str,
        args: &[S],
    ) -> Result<()> {
        let script = recipe.join("build.sh");
        if !script.is_file() {
            bail!(
                "--build-images builds {} with {}, which is missing",
                self.noun,
                script.display()
            );
        }
        let step = format!("build {} {tag} with {}", self.noun, script.display());
        let status = Command::new("bash")
            .arg(&script)
            .args(args)
            .env(self.tag_env, tag)
            .status()
            .with_context(|| format!("{step}: could not start"))?;
        if !status.success() {
            bail!("{step}: {status}");
        }
        Ok(())
    }

    /// Build `tag` through the recipe's `build.sh` in `recipe` with no source
    /// argument (the script finds its reference clone itself), in the variant
    /// `tag` asks for.
    ///
    /// # Errors
    /// See [`Self::build_with`].
    pub(crate) fn build(&self, tag: &str, recipe: &Path) -> Result<()> {
        let flag = self
            .variant
            .filter(|variant| (variant.expected)(tag) == "YES")
            .map(|variant| variant.build_arg);
        self.build_with(recipe, tag, flag.as_slice())
    }

    /// What `image` says about itself: empty where it is absent, unlabelled or
    /// cannot be inspected.
    fn read(&self, docker: &Docker, image: &str) -> Labels {
        let label = |key: &str| {
            docker
                .image_label(image.to_owned(), key)
                .to_command()
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                .filter(|label| label != "<no value>")
                .unwrap_or_default()
        };
        Labels {
            commit: label(self.commit_label),
            variant: self
                .variant
                .map(|variant| label(variant.label))
                .unwrap_or_default(),
        }
    }

    /// Read `image`'s labels and refuse it unless they are the pin's, or the
    /// run set the off-pin variable.
    ///
    /// # Errors
    /// When a label does not match the pin and no override is set; the error
    /// names the image, its label, the pin and how to rebuild.
    pub(crate) fn check(&'static self, docker: &Docker, image: &str) -> Result<PinnedImage> {
        let labels = self.read(docker, image);
        let off_pin = std::env::var(self.off_pin_env).is_ok_and(|value| value == "1");
        self.admit(image, &labels, off_pin)?;
        crate::run_record::note_image(docker, image, false);
        Ok(PinnedImage {
            counterparty: self,
            image: image.to_owned(),
            labels,
        })
    }

    /// The `Body.pin` for `image`, read off its labels. An image that cannot be
    /// inspected reads unverified, never pinned.
    pub(crate) fn body_pin(&self, docker: &Docker, image: &str) -> String {
        self.qualified(image, &self.read(docker, image))
    }

    fn is_pinned(&self, image: &str, labels: &Labels) -> bool {
        labels.commit == (self.commit)()
            && self
                .variant
                .is_none_or(|variant| labels.variant == (variant.expected)(image))
    }

    /// The pin, qualified by what the image's own labels say.
    fn qualified(&self, image: &str, labels: &Labels) -> String {
        if self.is_pinned(image, labels) {
            format!(
                "{}, verified by the image's {} label",
                (self.text)(),
                self.commit_label
            )
        } else {
            format!(
                "{} — UNVERIFIED: {image} carries {} = {:?}; only an image built by \
                 {}/build.sh is known to be the pin",
                (self.text)(),
                self.commit_label,
                labels.commit,
                self.recipe
            )
        }
    }

    /// Whether an image with `labels` may start.
    fn admit(&self, image: &str, labels: &Labels, off_pin: bool) -> Result<()> {
        if self.is_pinned(image, labels) {
            return Ok(());
        }
        if off_pin {
            println!(
                "{}: {image} is off the pin ({} = {:?}); {}=1, so every verdict names the pin \
                 unverified",
                self.noun, self.commit_label, labels.commit, self.off_pin_env
            );
            return Ok(());
        }
        let carries = if labels.commit.is_empty() {
            format!("carries no {} label", self.commit_label)
        } else if labels.commit == (self.commit)() {
            let label = self.variant.map_or("", |variant| variant.label);
            format!(
                "carries the pinned commit but {label} = {:?}, not {:?}",
                labels.variant,
                self.variant.map_or("", |variant| (variant.expected)(image)),
            )
        } else {
            format!("carries {} = {}", self.commit_label, labels.commit)
        };
        bail!(
            "{} {image} {carries}, but the recipe's pin of record is {}. Rebuild it from a clean \
             clone at {}: `{}`. To run off the pin on purpose, set {}=1; every verdict then names \
             the pin unverified.",
            self.noun,
            (self.text)(),
            (self.commit)(),
            self.rebuild,
            self.off_pin_env,
        )
    }
}

/// What an image's labels say: the commit it was built from and, where the
/// recipe has one, its variant.
struct Labels {
    commit: String,
    variant: String,
}

/// An image a flow may start: its labels match the pin, or the run set the
/// off-pin variable.
pub(crate) struct PinnedImage {
    counterparty: &'static Counterparty,
    image: String,
    labels: Labels,
}

impl PinnedImage {
    /// The container to start, before the flow's own network and mounts.
    pub(crate) fn container(&self) -> RunContainer {
        RunContainer::new(&self.image)
    }

    /// The `Body.pin` for this image.
    pub(crate) fn pin(&self) -> String {
        self.counterparty.qualified(&self.image, &self.labels)
    }
}

/// kno's aMule at its Fork Pin (ADR-0092). The pin of record is the reference
/// sidecar `build.sh` also reads.
pub(crate) static AMULE_KNO: Counterparty = Counterparty {
    noun: "kno's aMule image",
    recipe: "images/amule-kno",
    commit_label: "org.rmule.amule_kno.commit",
    tag_env: "AMULE_KNO_RUNTIME_TAG",
    variant: Some(Variant {
        label: "org.rmule.amule_kno.quic",
        expected: |image| {
            if image.ends_with(":quic") {
                "YES"
            } else {
                "NO"
            }
        },
        build_arg: "--quic",
    }),
    off_pin_env: "RMULE_BENCH_AMULE_KNO_OFF_PIN",
    commit: || sidecar_commit(AMULE_KNO_META),
    text: || {
        format!(
            "kno/amule integration/network-parity {}",
            short(AMULE_KNO_META)
        )
    },
    rebuild: "tools/interop-harness/images/amule-kno/build.sh",
};

/// emule-qt's `emulecored` (ADR-0082).
pub(crate) static EMULEQT: Counterparty = Counterparty {
    noun: "the emule-qt image",
    recipe: "images/emuleqt",
    commit_label: "org.rmule.emuleqt.commit",
    tag_env: "EMULEQT_RUNTIME_TAG",
    variant: None,
    off_pin_env: "RMULE_BENCH_EMULEQT_OFF_PIN",
    commit: || sidecar_commit(EMULEQT_META),
    text: || format!("ModderMule/emule-qt {}", short(EMULEQT_META)),
    rebuild: "tools/interop-harness/images/emuleqt/build.sh",
};

const AMULE_KNO_META: &str =
    include_str!("../../../../docs/reference/amule-kno/amule-kno.meta.toml");
const EMULEQT_META: &str = include_str!("../../../../docs/reference/emule-qt/emule-qt.meta.toml");

/// The `commit = "…"` line of a reference sidecar: the same line `build.sh`
/// reads, so the harness and the script name one pin.
fn sidecar_commit(meta: &'static str) -> &'static str {
    meta.lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "commit").then(|| value.trim().trim_matches('"'))
        })
        .unwrap_or_default()
}

/// The first eight characters of the sidecar's commit, as verdict prose names it.
fn short(meta: &'static str) -> &'static str {
    sidecar_commit(meta).get(..8).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{AMULE_KNO, EMULEQT, Labels};

    /// The compiled-in sidecars name full commits, and the verdict prose carries
    /// the short form the reference tree names.
    #[test]
    fn the_pins_are_read_whole_from_the_reference_sidecars() {
        for counterparty in [&AMULE_KNO, &EMULEQT] {
            let commit = (counterparty.commit)();
            assert_eq!(commit.len(), 40, "a full SHA, as build.sh compares it");
            assert!((counterparty.text)().ends_with(&commit[..8]));
        }
    }

    /// An image with no label, or another commit's, never borrows the pin's name
    /// as verified, and a variant mismatch is refused even on the pinned commit.
    #[test]
    fn only_the_pinned_labels_verify_the_image() {
        let labels = |commit: &str, variant: &str| Labels {
            commit: commit.to_owned(),
            variant: variant.to_owned(),
        };
        let pinned = (AMULE_KNO.commit)();
        assert!(AMULE_KNO.is_pinned("kno:local", &labels(pinned, "NO")));
        assert!(!AMULE_KNO.is_pinned("kno:local", &labels("", "NO")));
        assert!(!AMULE_KNO.is_pinned("kno:local", &labels(&"0".repeat(40), "NO")));
        assert!(
            !AMULE_KNO.is_pinned("kno:quic", &labels(pinned, "NO")),
            "a plain build is not the quic variant"
        );
        assert!(AMULE_KNO.is_pinned("kno:quic", &labels(pinned, "YES")));
    }

    /// Only the pinned label starts without the override; the override starts
    /// anything, and the refusal names the image, its label, the pin and the
    /// script that rebuilds it.
    #[test]
    fn an_off_pin_image_is_refused_unless_the_run_says_so() {
        let other = "8c1f3e0a92d4b7c6e5f4a3b2c1d0e9f8a7b6c5d4";
        let on = |commit: &str| Labels {
            commit: commit.to_owned(),
            variant: String::new(),
        };
        let refusal = EMULEQT
            .admit("rmule/interop-emuleqt:local", &on(other), false)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("rmule/interop-emuleqt:local"));
        assert!(refusal.contains(other));
        assert!(refusal.contains(&(EMULEQT.text)()));
        assert!(refusal.contains("emuleqt/build.sh"));
        assert!(refusal.contains("RMULE_BENCH_EMULEQT_OFF_PIN"));
        assert!(
            EMULEQT
                .admit("img", &on(""), false)
                .unwrap_err()
                .to_string()
                .contains("no org.rmule.emuleqt.commit label")
        );
        assert!(EMULEQT.admit("img", &on(other), true).is_ok());
        assert!(EMULEQT.admit("img", &on((EMULEQT.commit)()), false).is_ok());
    }
}
