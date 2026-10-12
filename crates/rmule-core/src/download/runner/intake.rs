//! Where the runner lends the brain the intake gate: the IP filter's current
//! view and our Dial Position, taken once per batch of sightings (ADR-0090). A
//! filter reload applies from the next batch; sources already pooled stay as
//! they are.

use rmule_primitives::SourceSighting;

use super::RunnerContext;
use crate::download::source_book::Gate;
use crate::download::state::{Channel, DownloadState, Taken};

/// Hand `sightings` of `channel` to the brain behind the gate at the
/// runner's `now`, and count the ones dropped for an address family this node
/// cannot dial from.
pub(super) fn sight<S, P>(
    runner: &RunnerContext<S, P>,
    state: &mut DownloadState,
    channel: Channel,
    sightings: impl IntoIterator<Item = SourceSighting>,
) -> Taken {
    let filter = runner.rt.ip_filter.read().expect("ip filter lock");
    let gate = Gate {
        filter: &filter,
        dial: runner.dial_position(),
    };
    let taken = state.on_sightings(super::now(), channel, sightings, &gate);
    for _ in 0..taken.tally.family_unreachable {
        runner.rt.diagnostics.count_undialable_family_source();
    }
    taken
}

/// Whether the gate lets any of `sightings` through, as the run's start reads
/// whether a link or its seeds can feed it before a brain exists.
pub(super) fn any_admitted<S, P>(
    runner: &RunnerContext<S, P>,
    sightings: &[SourceSighting],
) -> bool {
    let filter = runner.rt.ip_filter.read().expect("ip filter lock");
    let gate = Gate {
        filter: &filter,
        dial: runner.dial_position(),
    };
    sightings.iter().any(|&sighting| gate.admits(sighting))
}
