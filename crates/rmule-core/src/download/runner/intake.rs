//! Where the runner lends the brain the intake gate: the IP filter's current
//! view and our Dial Position, taken once per batch of sightings (ADR-0090). A
//! filter reload applies from the next batch; sources already pooled stay as
//! they are.

use rmule_primitives::{Informant, SourceSighting};

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
    let sightings = sightings
        .into_iter()
        .map(|sighting| stated_by(channel, sighting));
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

/// `sighting` as the word of the party its channel names: the peer whose
/// source-exchange answer it is, or the server a global-UDP answer came from.
/// Every other channel's producer stamps its own [`Informant`]: the server
/// session, the Kad pump and the serve side, which read the party off the
/// network. A link, a seed and an injected adapter's source stay rmule's own.
fn stated_by(channel: Channel, sighting: SourceSighting) -> SourceSighting {
    match channel {
        Channel::Exchanged(peer) => sighting.with_informant(Informant::Party(peer.ip())),
        Channel::Global(server) => {
            sighting.with_informant(Informant::Party(std::net::IpAddr::V4(server.ip)))
        }
        Channel::Link | Channel::Seed | Channel::Server | Channel::Kad | Channel::Prober => {
            sighting
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, PeerSource};

    use super::*;
    use crate::dialable::DialPosition;
    use crate::download::source_book::Blocked;
    use crate::ip_filter::IpFilter;

    /// A source-exchange or global-UDP answer is judged as the word of the
    /// party its channel names: a loopback row from a remote peer or server is
    /// refused, from a peer on this host it passes, and a link's is rmule's own.
    #[test]
    fn an_exchanged_or_global_row_is_the_word_of_the_party_its_channel_names() {
        let filter = IpFilter::default();
        let gate = Gate {
            filter: &filter,
            dial: DialPosition::default(),
        };
        let loopback = SourceSighting::plain(PeerSource::HighId(Ipv4Endpoint::new(
            Ipv4Addr::LOCALHOST,
            4662,
        )));
        let remote = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662);
        let local = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4663);

        for channel in [
            Channel::Exchanged(PeerEndpoint::V4(remote)),
            Channel::Global(remote),
        ] {
            assert_eq!(
                gate.judge(stated_by(channel, loopback)),
                Err(Blocked::Reserved),
                "{channel:?}"
            );
        }
        for channel in [
            Channel::Exchanged(PeerEndpoint::V4(local)),
            Channel::Global(local),
            Channel::Link,
        ] {
            assert!(gate.admits(stated_by(channel, loopback)), "{channel:?}");
        }
    }
}
