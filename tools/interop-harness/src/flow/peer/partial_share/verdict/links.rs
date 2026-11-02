//! The claims on the links rmule holds with a stock aMule downloader
//! (ADR-0107's one peer, one link; ADR-0057's queue standing): a download of
//! an asker rides the link it asked on, a waiter back on a new link keeps
//! its place, and a peer met inbound is dialled at its socket's address,
//! never at the ID its hello claims. Each is read off the tap's dials,
//! closes and frames; rmule's trail only names the run's moments.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::{Body, Claim, Run, Verdict, id_addresses};
use crate::flow::peer::partial_share::wire::{Close, Item, Said, Udp};

/// How soon after rmule's second dial a peer closing its first link reads
/// as aMule handing the client to the new socket (`ClientList.cpp:395-401`).
const REPLACED_WINDOW_SECS: f64 = 5.0;
/// How soon after rmule's ask a peer closing the link unanswered reads as a
/// drop.
const DROP_WINDOW_SECS: f64 = 2.0;
/// An ID below this is a Low ID: a callback handle, not an address.
const LOW_ID_LIMIT: u32 = 0x0100_0000;

fn v4(address: &SocketAddr) -> Ipv4Addr {
    match address.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

/// One link a body dialled to rmule, from its dial to its first close.
struct Linked<'a> {
    peer: SocketAddr,
    opened: f64,
    closed: Option<&'a Close>,
}

impl Linked<'_> {
    fn live_at(&self, at: f64) -> bool {
        self.opened <= at && self.closed.is_none_or(|close| at < close.at)
    }
}

/// Every link `ip` dialled to rmule, in dial order.
fn inbound<'a>(run: &'a Run<'_>, ip: Ipv4Addr) -> Vec<Linked<'a>> {
    run.wire
        .opens
        .iter()
        .filter(|open| !open.by_rmule && v4(&open.peer) == ip)
        .map(|open| Linked {
            peer: open.peer,
            opened: open.at,
            closed: run
                .wire
                .closes
                .iter()
                .find(|close| close.peer == open.peer && close.at >= open.at),
        })
        .collect()
}

fn on_link<'a>(run: &'a Run<'_>, peer: SocketAddr) -> impl Iterator<Item = &'a Item> + 'a {
    run.wire.items.iter().filter(move |item| item.peer == peer)
}

/// A download of a peer that asked rmule for the partial goes out on the
/// link that peer holds, never on a second one rmule dials while it is up:
/// stock aMule hands a client to its newest socket and drops the first,
/// ending the upload it was taking. Judged only where rmule's dials to the
/// downloaders reached the network.
pub(super) fn rides_the_askers_link(run: &Run<'_>) -> Claim {
    const NAME: &str = "rmule-rides-the-askers-link";
    if !run.topology.knobs.dial_downloaders {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "rmule's dials to the downloaders were dropped on its link, so a second link never reaches the tap",
        );
    }
    let mut failures = Vec::new();
    let mut rides = Vec::new();
    let mut later_dials = Vec::new();
    for body in &run.topology.downloaders {
        let links = inbound(run, body.ip);
        for dial in run
            .wire
            .opens
            .iter()
            .filter(|open| open.by_rmule && v4(&open.peer) == body.ip)
        {
            let Some(link) = links.iter().find(|link| link.live_at(dial.at)) else {
                later_dials.push(format!("{} {} at {:.3}", body.role, dial.peer, dial.at));
                continue;
            };
            let replaced = link
                .closed
                .filter(|close| !close.by_rmule && close.at - dial.at < REPLACED_WINDOW_SECS)
                .map_or_else(String::new, |close| {
                    format!(
                        ", and it closed that link {:.3} s later",
                        close.at - dial.at
                    )
                });
            failures.push(format!(
                "rmule dialled {} at {} at {:.3} while its link from :{} was up{replaced}",
                body.role,
                dial.peer,
                dial.at,
                link.peer.port()
            ));
        }
        for link in &links {
            if let Some(ride) = ride(run, body, link, &mut failures) {
                rides.push(ride);
            }
        }
    }
    let later = if later_dials.is_empty() {
        String::new()
    } else {
        format!("; dials once no link was up: {}", later_dials.join(", "))
    };
    if !failures.is_empty() {
        return Claim::new(
            NAME,
            Verdict::Fail,
            format!("{}{later}", failures.join("; ")),
        );
    }
    if rides.is_empty() {
        let downloaders: BTreeSet<Ipv4Addr> = run.downloaders().collect();
        let selected: Vec<String> = run
            .trail
            .named("download.peer_selected")
            .filter(|mark| mark.peer().is_some_and(|ip| downloaders.contains(&ip)))
            .filter_map(|mark| Some(format!("{} at {:.3}", mark.field("peer")?, mark.at?)))
            .collect();
        return Claim::new(
            NAME,
            Verdict::NotRun,
            format!(
                "rmule's download asked no downloader over its link (selected: {}){later}",
                if selected.is_empty() {
                    "none".to_owned()
                } else {
                    selected.join(", ")
                }
            ),
        );
    }
    Claim::new(
        NAME,
        Verdict::Pass,
        format!(
            "{}; no dial to a downloader while its link was up{later}",
            rides.join("; ")
        ),
    )
}

/// rmule's download asks on `link`, judged: the peer must not drop the link
/// on them, nor end an upload it was taking there.
fn ride(
    run: &Run<'_>,
    body: &Body,
    link: &Linked<'_>,
    failures: &mut Vec<String>,
) -> Option<String> {
    let asks: Vec<&Item> = on_link(run, link.peer)
        .filter(|item| {
            item.from_rmule
                && matches!(&item.said, Said::FileAsk { hash } if *hash == run.stream_hash)
        })
        .collect();
    let first = asks.first()?;
    let answers = on_link(run, link.peer)
        .filter(|item| {
            !item.from_rmule
                && item.at > first.at
                && matches!(&item.said, Said::FileAnswer { hash } if *hash == run.stream_hash)
        })
        .count();
    let blocks = |after: bool| {
        on_link(run, link.peer)
            .filter(|item| item.from_rmule && (item.at > first.at) == after)
            .filter(|item| matches!(item.said, Said::Block { .. }))
            .count()
    };
    let (before, after) = (blocks(false), blocks(true));
    let ended = match link.closed {
        Some(close) if !close.by_rmule => {
            let spoke = on_link(run, link.peer)
                .any(|item| !item.from_rmule && item.at > first.at && item.at <= close.at);
            if !spoke && close.at - first.at < DROP_WINDOW_SECS {
                failures.push(format!(
                    "{} closed its link :{} {:.3} s after rmule's ask, unanswered",
                    body.role,
                    link.peer.port(),
                    close.at - first.at
                ));
            }
            if before > 0 && after == 0 {
                failures.push(format!(
                    "{} took {before} blocks on :{} before rmule's ask at {:.3} and none after: it closed the link at {:.3}",
                    body.role,
                    link.peer.port(),
                    first.at,
                    close.at
                ));
            }
            let cancelled = on_link(run, link.peer)
                .filter(|item| !item.from_rmule && item.at > first.at && item.at <= close.at)
                .find(|item| item.said == Said::Cancel)
                .map_or_else(String::new, |cancel| {
                    format!(" after its own cancel at {:.3}", cancel.at)
                });
            format!("{} closed it at {:.3}{cancelled}", body.role, close.at)
        }
        Some(close) => format!("rmule closed it at {:.3}", close.at),
        None => "open to the tap's end".to_owned(),
    };
    Some(format!(
        "{} asked on its own link :{} from {:.3} ({} asks, {answers} answered; {before} blocks before, {after} after; {ended})",
        body.role,
        link.peer.port(),
        first.at,
        asks.len()
    ))
}

/// What rmule told a body of its upload queue, in order.
enum Told {
    Rank(u16),
    Granted,
}

/// A waiter whose next answer comes over a new TCP link, in the same leg,
/// keeps its place (aMule's `UploadQueue.cpp:402-430`): it is granted or
/// told a rank no worse than the last it was told, never queued again
/// behind its own entry.
pub(super) fn relinked_waiter_keeps_its_place(run: &Run<'_>) -> Claim {
    const NAME: &str = "a-relinked-waiter-keeps-its-place";
    let mut judged = Vec::new();
    let mut failures = Vec::new();
    for body in &run.topology.downloaders {
        let mut told: Vec<(f64, Option<SocketAddr>, Told)> = run
            .wire
            .items
            .iter()
            .filter(|item| item.from_rmule && v4(&item.peer) == body.ip)
            .filter_map(|item| match item.said {
                Said::Rank { rank } => Some((item.at, Some(item.peer), Told::Rank(rank))),
                Said::Accept => Some((item.at, Some(item.peer), Told::Granted)),
                _ => None,
            })
            .collect();
        told.extend(
            run.wire
                .datagrams
                .iter()
                .filter(|datagram| datagram.peer == body.ip)
                .filter_map(|datagram| match datagram.said {
                    Udp::Ack { rank, .. } => Some((datagram.at, None, Told::Rank(rank))),
                    _ => None,
                }),
        );
        told.sort_by(|a, b| a.0.total_cmp(&b.0));
        // The link the body waits on, the rank it was last told, when queued.
        let mut standing: Option<(SocketAddr, u16, f64)> = None;
        for (at, link, answer) in told {
            let relinked = match (&standing, link) {
                (Some((queued_on, _, queued_at)), Some(link)) => {
                    *queued_on != link && run.leg_at(*queued_at) == run.leg_at(at)
                }
                _ => false,
            };
            match (answer, link) {
                (Told::Rank(rank), None) => {
                    if let Some(entry) = standing.as_mut() {
                        entry.1 = rank;
                    }
                }
                (Told::Rank(rank), Some(link)) => {
                    if let (true, Some((queued_on, last, queued_at))) = (relinked, standing) {
                        let line = format!(
                            "{} queued on :{} at {queued_at:.3}, back on :{} ({}) at {at:.3}: rank {rank} after rank {last}",
                            body.role,
                            queued_on.port(),
                            link.port(),
                            dialled_by(run, link)
                        );
                        if rank > last {
                            failures.push(line);
                        } else {
                            judged.push(line);
                        }
                    }
                    standing = Some((link, rank, at));
                }
                (Told::Granted, Some(link)) => {
                    if let (true, Some((queued_on, last, queued_at))) = (relinked, standing) {
                        judged.push(format!(
                            "{} queued on :{} at {queued_at:.3} (rank {last}), granted on :{} ({}) at {at:.3}",
                            body.role,
                            queued_on.port(),
                            link.port(),
                            dialled_by(run, link)
                        ));
                    }
                    standing = None;
                }
                (Told::Granted, None) => {}
            }
        }
    }
    let relinks = run.trail.named("serve.waiter_relinked").count();
    if judged.is_empty() && failures.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            format!(
                "no waiter was answered on a new link inside its leg ({} UDP reasks acked; {relinks} relinks in rmule's trail)",
                run.wire
                    .datagrams
                    .iter()
                    .filter(|datagram| matches!(datagram.said, Udp::Ack { .. }))
                    .count()
            ),
        );
    }
    if !failures.is_empty() {
        return Claim::new(NAME, Verdict::Fail, failures.join("; "));
    }
    Claim::new(
        NAME,
        Verdict::Pass,
        format!("{}; {relinks} relinks in rmule's trail", judged.join("; ")),
    )
}

/// Who opened the link `peer` names, as the tap saw its dial.
fn dialled_by(run: &Run<'_>, peer: SocketAddr) -> &'static str {
    if run
        .wire
        .opens
        .iter()
        .any(|open| !open.by_rmule && open.peer == peer)
    {
        "its own dial"
    } else {
        "rmule's dial"
    }
}

/// A peer met on a link it dialled is dialled back at that link's address
/// with its hello's port, never at an address the High ID its hello claims
/// names (aMule takes the socket's address, `BaseClient.cpp`'s hello read).
pub(super) fn dialled_at_its_address(run: &Run<'_>) -> Claim {
    const NAME: &str = "a-peer-met-inbound-is-dialled-at-its-address";
    let bodies: BTreeSet<Ipv4Addr> = run
        .topology
        .seeds
        .iter()
        .chain(&run.topology.downloaders)
        .map(|body| body.ip)
        .chain(run.topology.stimuli.iter().map(|stimulus| stimulus.ip))
        .collect();
    let dialled_in = |peer: SocketAddr| {
        run.wire
            .opens
            .iter()
            .any(|open| !open.by_rmule && open.peer == peer)
    };
    let mut judged = Vec::new();
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for item in run.wire.items.iter().filter(|item| !item.from_rmule) {
        let Said::Hello { id, port } = item.said else {
            continue;
        };
        let socket = v4(&item.peer);
        if id < LOW_ID_LIMIT || !dialled_in(item.peer) || !seen.insert((socket, id, port)) {
            continue;
        }
        let named = id_addresses(id);
        if named.contains(&socket) {
            continue;
        }
        let named: Vec<Ipv4Addr> = named
            .into_iter()
            .filter(|address| !bodies.contains(address))
            .collect();
        if named.is_empty() {
            continue;
        }
        let dials: Vec<SocketAddr> = run
            .wire
            .opens
            .iter()
            .filter(|open| open.by_rmule && open.at > item.at)
            .map(|open| open.peer)
            .collect();
        for wrong in dials.iter().filter(|dial| named.contains(&v4(dial))) {
            failures.push(format!(
                "{socket}'s hello claimed {id:#010x}; rmule dialled {wrong}"
            ));
        }
        for wrong in dials
            .iter()
            .filter(|dial| v4(dial) == socket && dial.port() != port)
        {
            failures.push(format!(
                "{socket}'s hello names port {port}; rmule dialled {wrong}"
            ));
        }
        let at_socket = dials
            .iter()
            .filter(|dial| v4(dial) == socket && dial.port() == port)
            .count();
        let asked_on_link = run.wire.items.iter().any(|ask| {
            ask.from_rmule
                && v4(&ask.peer) == socket
                && ask.at > item.at
                && matches!(ask.said, Said::FileAsk { .. })
        });
        // A dial to a body that has left dies on the neighbour lookup and
        // never reaches the tap; a dial at the claimed address goes out by
        // the gateway and would. rmule's trail names the dial it chose.
        let coordinate = format!("{socket}:{port}");
        let selected = run
            .trail
            .named("download.peer_selected")
            .filter(|mark| {
                mark.field("peer") == Some(coordinate.as_str())
                    && mark.at.is_some_and(|at| at > item.at)
            })
            .count();
        let mut seen_back = Vec::new();
        if at_socket > 0 {
            seen_back.push(format!("{at_socket} dials at {coordinate}"));
        }
        if asked_on_link {
            seen_back.push("asked on its link".to_owned());
        }
        if selected > 0 {
            seen_back.push(format!(
                "{selected} downloads chose {coordinate} (rmule's trail)"
            ));
        }
        judged.push(if seen_back.is_empty() {
            format!("{socket} claimed {id:#010x}: never dialled nor asked")
        } else {
            format!(
                "{socket} claimed {id:#010x}: {}; no dial at the claimed address",
                seen_back.join(", ")
            )
        });
    }
    if !failures.is_empty() {
        return Claim::new(NAME, Verdict::Fail, failures.join("; "));
    }
    if judged.is_empty() {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            "no peer met on its own dial claimed an ID other than its address",
        );
    }
    if judged
        .iter()
        .all(|line| line.ends_with("never dialled nor asked"))
    {
        return Claim::new(
            NAME,
            Verdict::NotRun,
            format!(
                "rmule never went back to such a peer: {}",
                judged.join("; ")
            ),
        );
    }
    Claim::new(NAME, Verdict::Pass, judged.join("; "))
}
