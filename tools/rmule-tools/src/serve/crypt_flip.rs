//! The timed obfuscation flips of `ed2k serve start` and `ed2k download start`
//! (`--peer-crypt-flip`):
//! at each one the driver sets the running core's policy through its Core
//! Settings handle, as the operator does from the Settings tab, and prints a
//! `rmule-obfuscation-flip` marker a flow splits its taps on. Every surface
//! reads the policy as it decides (ADR-0046), so what crossed a tap before
//! the marker ran under the old policy and the next dial, accept, datagram,
//! crypt-ping and Kad exchange after it under the new one.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use rmule_core::{Core, ObfuscationPolicy, Setting, TakesEffect};

/// One flip: the policy put in force `after` the run began.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CryptFlip {
    /// Measured from the first login being asked for (serve, as `--switch-after`
    /// is) or from the download's login (download).
    after: Duration,
    /// `None` turns obfuscation off.
    policy: Option<ObfuscationPolicy>,
}

impl CryptFlip {
    /// Whether this flip arms a policy, so the run's Kad node may key on its
    /// seed at some point.
    pub(crate) const fn arms(self) -> bool {
        self.policy.is_some()
    }
}

/// The policy words a flip takes, the stored spelling.
const POLICIES: [(&str, Option<ObfuscationPolicy>); 4] = [
    ("off", None),
    ("supported", Some(ObfuscationPolicy::Supported)),
    ("requested", Some(ObfuscationPolicy::Requested)),
    ("required", Some(ObfuscationPolicy::Required)),
];

/// Parse `<secs>:<policy>`, the policy one of `off`, `supported`,
/// `requested`, `required`.
///
/// # Errors
/// The text is not of that shape.
pub(crate) fn parse(text: &str) -> Result<CryptFlip> {
    let Some((secs, word)) = text.split_once(':') else {
        bail!("expected <secs>:<policy>, got {text:?}");
    };
    let Ok(secs) = secs.parse::<u64>() else {
        bail!("{secs:?} is not a whole number of seconds");
    };
    let Some(&(_, policy)) = POLICIES.iter().find(|(name, _)| *name == word) else {
        bail!("{word:?} is not one of off, supported, requested, required");
    };
    Ok(CryptFlip {
        after: Duration::from_secs(secs),
        policy,
    })
}

/// The flips still to come, earliest first.
pub(crate) struct CryptFlips(Vec<CryptFlip>);

impl CryptFlips {
    pub(crate) fn new(mut flips: Vec<CryptFlip>) -> Self {
        // Latest first, so the next one is popped off the end.
        flips.sort_by_key(|flip| std::cmp::Reverse(flip.after));
        Self(flips)
    }

    /// When the next flip is due, measured from `began`.
    pub(crate) fn next_at(&self, began: tokio::time::Instant) -> Option<tokio::time::Instant> {
        self.0.last().map(|flip| began + flip.after)
    }

    /// Put the next flip's policy in force on `core` and print its marker.
    ///
    /// The marker carries the wall clock the policy took effect at
    /// (`at_unix_ms`), so a flow places it on its taps' own clock instead of
    /// guessing when the run began.
    ///
    /// # Errors
    /// The store refused the write, or the core has stopped and took nothing
    /// up.
    pub(crate) fn fire(&mut self, core: &Core) -> Result<()> {
        let Some(flip) = self.0.pop() else {
            return Ok(());
        };
        let effect = core.settings().set(Setting::Obfuscation(flip.policy))?;
        if effect != TakesEffect::Now {
            bail!("the core took no obfuscation flip up: it has stopped");
        }
        let at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis());
        let word = POLICIES
            .iter()
            .find(|(_, policy)| *policy == flip.policy)
            .map_or("off", |(name, _)| *name);
        println!(
            "rmule-obfuscation-flip after_secs={} policy={word} at_unix_ms={at_unix_ms}",
            flip.after.as_secs()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flip_reads_seconds_and_one_of_the_four_policy_words() {
        assert_eq!(
            parse("90:requested").unwrap(),
            CryptFlip {
                after: Duration::from_secs(90),
                policy: Some(ObfuscationPolicy::Requested),
            }
        );
        assert_eq!(parse("0:off").unwrap().policy, None);
        for bad in ["90", "x:off", "90:on", "-1:off", ":required"] {
            assert!(parse(bad).is_err(), "{bad:?} refused");
        }
    }

    /// Flips fire in time order whatever order they were given, each put in
    /// force on the running core through its settings handle.
    #[tokio::test]
    async fn flips_fire_in_time_order_on_the_running_core() {
        let core = Core::builder(
            rmule_core::CoreConfig::default(),
            rmule_core::open_durable_store_in_memory().unwrap(),
        )
        .settings(rmule_core::CoreSettings::default())
        .build();
        let began = tokio::time::Instant::now();
        let mut flips = CryptFlips::new(vec![
            parse("300:off").unwrap(),
            parse("60:requested").unwrap(),
        ]);
        let policy = || core.settings().read().unwrap().obfuscation;

        assert_eq!(flips.next_at(began), Some(began + Duration::from_secs(60)));
        flips.fire(&core).unwrap();
        assert_eq!(policy(), Some(ObfuscationPolicy::Requested));
        assert_eq!(flips.next_at(began), Some(began + Duration::from_secs(300)));
        flips.fire(&core).unwrap();
        assert_eq!(policy(), None);
        assert_eq!(flips.next_at(began), None);
        core.shutdown().await;
    }
}
