//! The round walk under explicit time.

use std::time::Duration;

use rmule_ed2k::ServerUdpFlags;
use rmule_primitives::{FileHash, OLD_MAX_FILE_SIZE, ServerEndpoint, SourceLookupTarget};
use tokio::time::Instant;

use super::*;

const SPACING: Duration = Duration::from_secs(1300);
const TICK: Duration = Duration::from_secs(1);

fn server(last: u8) -> ServerEndpoint {
    ServerEndpoint::new(format!("10.0.0.{last}"), 4661).unwrap()
}

fn files(count: u16) -> Vec<SourceLookupTarget> {
    (0..count)
        .map(|n| {
            let mut bytes = [0xA5; 16];
            bytes[..2].copy_from_slice(&n.to_le_bytes());
            SourceLookupTarget::new(FileHash::from_bytes(bytes), 4096)
        })
        .collect()
}

fn ext(_: &ServerEndpoint) -> ServerUdpFlags {
    ServerUdpFlags::from_bits(ServerUdpFlags::EXT_GETSOURCES)
}

/// Walk one tick at a time from `start` until the round ends, collecting
/// what each datagram asked; the instant the round ended comes back.
fn walk_round(
    rounds: &mut UdpRounds,
    start: Instant,
    swept: &[ServerEndpoint],
    queue: &[SourceLookupTarget],
    flags: impl Fn(&ServerEndpoint) -> ServerUdpFlags + Copy,
) -> (Vec<UdpAsk>, Instant) {
    let mut asks = Vec::new();
    let mut now = start;
    loop {
        match rounds.next_ask(now, true, swept, queue, flags) {
            Some(ask) => asks.push(ask),
            None if rounds.walk.is_none() => return (asks, now),
            None => {}
        }
        now += TICK;
    }
}

/// One datagram per tick across every server, never a burst: a second ask at
/// the same instant gets nothing.
#[test]
fn a_round_puts_one_datagram_on_the_wire_per_tick() {
    let start = Instant::now();
    let (swept, queue) = ([server(1), server(2), server(3)], files(2));
    let mut rounds = UdpRounds::new(SPACING, TICK);
    let first = rounds.next_ask(start, true, &swept, &queue, ext);
    assert_eq!(first.map(|ask| ask.server), Some(server(1)));
    assert_eq!(rounds.next_ask(start, true, &swept, &queue, ext), None);
    let second = rounds.next_ask(start + TICK, true, &swept, &queue, ext);
    assert_eq!(second.map(|ask| ask.server), Some(server(2)));
}

/// The next round starts 1300 s after the last ended, not after it started:
/// a long round never overlaps its spacing.
#[test]
fn the_next_round_waits_out_the_spacing_from_the_end_of_the_last() {
    let start = Instant::now();
    let (swept, queue) = ([server(1), server(2)], files(1));
    let mut rounds = UdpRounds::new(SPACING, TICK);
    let (asks, ended) = walk_round(&mut rounds, start, &swept, &queue, ext);
    assert_eq!(asks.len(), 2, "each server heard once");
    let just_before = ended + SPACING - TICK;
    assert_eq!(
        rounds.next_ask(just_before, true, &swept, &queue, ext),
        None
    );
    assert!(
        rounds
            .next_ask(ended + SPACING, true, &swept, &queue, ext)
            .is_some()
    );
}

/// A server hears at most 35 files in a round, 31 and then 4 with
/// `ExtGetSources`; the walk carries over, so the 36th file goes to the next
/// server rather than to nobody.
#[test]
fn a_server_hears_thirty_five_files_and_the_walk_carries_over() {
    let (swept, queue) = ([server(1), server(2)], files(40));
    let mut rounds = UdpRounds::new(SPACING, TICK);
    let (asks, _) = walk_round(&mut rounds, Instant::now(), &swept, &queue, ext);
    let sizes: Vec<(ServerEndpoint, usize)> = asks
        .iter()
        .map(|ask| (ask.server.clone(), ask.targets.len()))
        .collect();
    assert_eq!(
        sizes,
        [(server(1), 31), (server(1), 4), (server(2), 5)],
        "the first server's share, then the rest"
    );
    assert_eq!(asks[2].targets[0], queue[35]);
}

/// A server with no known flags takes one file per datagram and still no
/// more than 35 files in a round.
#[test]
fn a_server_with_no_known_flags_takes_one_file_per_datagram_up_to_the_cap() {
    let (swept, queue) = ([server(1)], files(40));
    let mut rounds = UdpRounds::new(SPACING, TICK);
    let (asks, _) = walk_round(&mut rounds, Instant::now(), &swept, &queue, |_| {
        ServerUdpFlags::default()
    });
    assert_eq!(asks.len(), MAX_REQUESTS_PER_SERVER);
    assert!(asks.iter().all(|ask| ask.targets.len() == 1));
}

/// With no session the walk waits where it stands, and the round goes on
/// with the same server after the login.
#[test]
fn a_session_lost_mid_round_leaves_the_walk_where_it_stood() {
    let start = Instant::now();
    let (swept, queue) = ([server(1), server(2)], files(1));
    let mut rounds = UdpRounds::new(SPACING, TICK);
    assert!(rounds.next_ask(start, true, &swept, &queue, ext).is_some());
    let later = start + Duration::from_secs(5000);
    assert_eq!(rounds.next_ask(later, false, &swept, &queue, ext), None);
    let resumed = rounds.next_ask(later, true, &swept, &queue, ext);
    assert_eq!(resumed.map(|ask| ask.server), Some(server(2)));
}

/// A server that left the swept list mid-round, as the one we log into does,
/// is not asked.
#[test]
fn a_server_gone_from_the_swept_list_is_passed_over() {
    let start = Instant::now();
    let queue = files(1);
    let mut rounds = UdpRounds::new(SPACING, TICK);
    let all = [server(1), server(2), server(3)];
    assert!(rounds.next_ask(start, true, &all, &queue, ext).is_some());
    let remaining = [server(1), server(3)];
    let ask = rounds.next_ask(start + TICK, true, &remaining, &queue, ext);
    assert_eq!(ask.map(|ask| ask.server), Some(server(3)));
}

/// A large file is never named to a server without large-file UDP support,
/// and costs that server none of its share.
#[test]
fn a_large_file_is_skipped_toward_a_server_without_support() {
    let large = SourceLookupTarget::new(FileHash::from_bytes([0x22; 16]), OLD_MAX_FILE_SIZE + 1);
    let small = SourceLookupTarget::new(FileHash::from_bytes([0x11; 16]), 4096);
    let swept = [server(1)];
    let mut rounds = UdpRounds::new(SPACING, TICK);
    let (asks, _) = walk_round(&mut rounds, Instant::now(), &swept, &[large, small], ext);
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].targets, [small]);
}

/// With nobody to ask or nothing to ask for no round starts, so no clock is
/// spent: the first server or file to arrive is asked at once.
#[test]
fn only_a_round_that_can_start_spends_the_clock() {
    let start = Instant::now();
    let (swept, queue) = ([server(1)], files(1));
    let mut rounds = UdpRounds::new(SPACING, TICK);
    assert_eq!(rounds.next_ask(start, true, &[], &queue, ext), None);
    assert_eq!(rounds.next_ask(start, true, &swept, &[], ext), None);
    assert!(rounds.next_ask(start, true, &swept, &queue, ext).is_some());
}

/// A run asks 800 s after its last ask; at the gate it keeps looking and asks
/// once the file falls under it.
#[test]
fn a_run_asks_again_after_the_reask_and_only_under_the_gate() {
    let start = Instant::now();
    let sources = SourceCount::default();
    let mut reask = TcpReask::default();
    assert_eq!(reask.next_look(), None, "nothing owed before the first ask");
    reask.asked(start);
    let due = start + TCP_REASK;
    assert_eq!(reask.next_look(), Some(due));
    assert!(!reask.look(due - TICK, true, &sources));
    sources.publish(TCP_SOURCE_GATE);
    assert!(!reask.look(due, true, &sources));
    let next = reask.next_look().expect("still looking");
    assert!(next > due);
    sources.publish(TCP_SOURCE_GATE - 1);
    assert!(reask.look(next, true, &sources));
}

/// With no session the clock stops owing anything: the next session is an
/// ask of its own, not a timer's.
#[test]
fn a_run_with_no_session_owes_no_reask() {
    let start = Instant::now();
    let mut reask = TcpReask::default();
    reask.asked(start);
    assert!(!reask.look(start + TCP_REASK, false, &SourceCount::default()));
    assert_eq!(reask.next_look(), None);
}
