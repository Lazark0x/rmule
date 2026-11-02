//! The process's **Descriptor limit** (ADR-0116, "The Ceiling under the
//! descriptor limit"): raised once, at a binary's start, toward the hard
//! limit, and read back so the binary can hold the Connection Ceiling it
//! hands the core under it. aMule raises its own the same way at start
//! (`UnlimitResource`, stock 2.3.3 `amule.cpp:126-134`, `:144`).
//!
//! Linux and macOS go through `rustix`'s safe `getrlimit` and `setrlimit`.
//! Windows bounds no socket count by a descriptor limit, and states none.

/// Raise the soft open-descriptor limit toward the hard limit — on macOS no
/// higher than `OPEN_MAX`, above which the kernel refuses a soft limit — and
/// answer the limit then in force. A refused raise keeps the limit as it
/// was. `None` where the system states no limit: Windows, and an unlimited
/// soft limit.
#[must_use]
pub fn raise_descriptor_limit() -> Option<u64> {
    imp::raise()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    /// `OPEN_MAX` (`<sys/syslimits.h>`): the most a soft `RLIMIT_NOFILE`
    /// may be set to on macOS, whatever the hard limit says.
    #[cfg(target_os = "macos")]
    const SOFT_CAP: Option<u64> = Some(10_240);
    /// Linux takes any soft limit up to the hard one.
    #[cfg(target_os = "linux")]
    const SOFT_CAP: Option<u64> = None;

    pub(super) fn raise() -> Option<u64> {
        let held = getrlimit(Resource::Nofile);
        let wanted = match (held.maximum, SOFT_CAP) {
            (Some(hard), Some(cap)) => Some(hard.min(cap)),
            (hard, cap) => hard.or(cap),
        };
        if let (Some(current), Some(wanted)) = (held.current, wanted)
            && wanted > current
        {
            // A refusal leaves the limit as it was, which is read back below.
            let _ = setrlimit(
                Resource::Nofile,
                Rlimit {
                    current: Some(wanted),
                    maximum: held.maximum,
                },
            );
        }
        getrlimit(Resource::Nofile).current
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    pub(super) fn raise() -> Option<u64> {
        None
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use rustix::process::{Resource, getrlimit};

    use super::raise_descriptor_limit;

    /// The raise never lowers the limit, and what it answers is the limit in
    /// force.
    #[test]
    fn the_raise_never_lowers_the_limit_and_answers_the_one_in_force() {
        let before = getrlimit(Resource::Nofile).current;
        let after = raise_descriptor_limit();
        assert_eq!(after, getrlimit(Resource::Nofile).current);
        if let (Some(before), Some(after)) = (before, after) {
            assert!(after >= before, "{before} → {after}");
        }
    }
}
