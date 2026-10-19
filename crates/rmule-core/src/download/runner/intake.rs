//! Where the runner lends the brain the intake gate: the IP filter's current
//! view and our Dial Position, taken once per batch of sightings (ADR-0090). A
//! filter reload applies from the next batch; sources already pooled stay as
//! they are.

use rmule_primitives::{Informant, Ipv4Endpoint, PeerSource, SourceSighting};

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

/// A server-UDP global answer's `sources` (ADR-0051) as the word of `server`,
/// the server that sent it (ADR-0085). The answer carries no crypt material,
/// so each is a plain record.
pub(super) fn global_answer(
    server: Ipv4Endpoint,
    sources: Vec<PeerSource>,
) -> impl Iterator<Item = SourceSighting> {
    let informant = Informant::Party(std::net::IpAddr::V4(server.ip));
    sources
        .into_iter()
        .map(move |source| SourceSighting::plain(source, informant))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::dialable::DialPosition;
    use crate::download::source_book::Blocked;
    use crate::ip_filter::IpFilter;

    /// A global-UDP answer is judged as the word of the server that sent it:
    /// a loopback row from a remote server is refused, and from a server on
    /// this host it passes.
    #[test]
    fn a_global_row_is_the_word_of_the_server_that_sent_it() {
        let filter = IpFilter::default();
        let gate = Gate {
            filter: &filter,
            dial: DialPosition::default(),
        };
        let loopback = PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4662));
        let remote = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662);
        let local = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4663);

        for sighting in global_answer(remote, vec![loopback]) {
            assert_eq!(gate.judge(sighting), Err(Blocked::Reserved));
        }
        for sighting in global_answer(local, vec![loopback]) {
            assert!(gate.admits(sighting));
        }
    }
}
