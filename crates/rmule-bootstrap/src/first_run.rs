//! The cold-start acquisition decisions.
//!
//! Two pure predicates over the facts a caller already holds — enabled
//! protocols, whether anything is persisted yet, and the operator switch — so
//! the trigger policy is assertable as a truth table with nothing mocked. The
//! hook that supplies the facts and runs the pipeline on a `true` is the Join
//! Sequence in `rmule_core::join` (ADR-0067).

/// Should rmule auto-fetch a server list on this cold start?
///
/// amuled fetches **unconditionally** on first run. rmule reproduces that
/// default exactly but gates it, fetching iff:
///
/// - `ed2k_enabled` — eD2k participation is on (no point acquiring servers we
///   will never connect to), and
/// - `server_list_empty` — the managed server list is empty *at session
///   start* (a returning user with a persisted list is not on a cold start),
///   and
/// - `auto_fetch_enabled` — the operator switch
///   ([`BootstrapConfig::auto_fetch_server_met`](crate::BootstrapConfig::auto_fetch_server_met),
///   default ON) is on.
///
/// With the switch left at its default this is byte-identical to amuled's
/// cold start; the only divergence is that flipping it off is possible at all.
#[must_use]
pub const fn should_auto_fetch_server_met(
    ed2k_enabled: bool,
    server_list_empty: bool,
    auto_fetch_enabled: bool,
) -> bool {
    ed2k_enabled && server_list_empty && auto_fetch_enabled
}

/// Should rmule acquire a nodes.dat on this cold start?
///
/// The mirror of [`should_auto_fetch_server_met`] with the **opposite
/// default**, and the asymmetry is aMule's own: `UpdateNotesDat` is
/// user-/EC-triggered only, so nothing in aMule ever fetches nodes.dat
/// unattended and
/// [`auto_fetch_nodes_dat`](crate::BootstrapConfig::auto_fetch_nodes_dat) is
/// OFF by default. Acquire iff:
///
/// - `kad_enabled` — Kad participation is on (no point acquiring contacts for
///   a network we will never join), and
/// - `no_seeds` — no seeds were resolved from any other route: the persisted
///   `nodes.dat`, the operator's configured endpoints. A warm restart is not a
///   cold start, and the file is re-read every run, and
/// - `auto_fetch_enabled` — the caller opted in (default OFF, so a library or
///   headless caller stays byte-identical to aMule; the `rmule` TUI opts in,
///   per the ADR-0067 amendment that wires Kad autoconnect into the app).
#[must_use]
pub const fn should_auto_fetch_nodes_dat(
    kad_enabled: bool,
    no_seeds: bool,
    auto_fetch_enabled: bool,
) -> bool {
    kad_enabled && no_seeds && auto_fetch_enabled
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default amuled cold start: eD2k on, no persisted servers, switch at
    /// its ON default → fetch.
    #[test]
    fn cold_start_defaults_fetch() {
        assert!(should_auto_fetch_server_met(true, true, true));
    }

    /// The nodes.dat gate is three-way like the server.met one, but its switch
    /// is the *opt-in* half: with the default OFF, even a stranded Kad cold
    /// start acquires nothing — aMule's own posture.
    #[test]
    fn nodes_dat_acquisition_needs_all_three_and_the_switch_is_opt_in() {
        assert!(should_auto_fetch_nodes_dat(true, true, true));
        assert!(
            !should_auto_fetch_nodes_dat(true, true, false),
            "the default-OFF switch is what keeps every other caller at parity"
        );
        assert!(
            !should_auto_fetch_nodes_dat(false, true, true),
            "Kad disabled must not acquire contacts"
        );
        assert!(
            !should_auto_fetch_nodes_dat(true, false, true),
            "seeds already resolved (a persisted nodes.dat) is not a cold start"
        );
    }

    /// Each precondition independently suppresses the fetch — the ADR's
    /// three-way gate, not an implicit two-way one. A returning user (list
    /// non-empty), an eD2k-disabled run, and an operator opt-out each stay
    /// their hand for a distinct reason.
    #[test]
    fn each_false_precondition_suppresses_fetch() {
        assert!(
            !should_auto_fetch_server_met(false, true, true),
            "eD2k disabled must not fetch servers"
        );
        assert!(
            !should_auto_fetch_server_met(true, false, true),
            "a non-empty persisted list is not a cold start"
        );
        assert!(
            !should_auto_fetch_server_met(true, true, false),
            "the operator opt-out must be honoured"
        );
    }
}
