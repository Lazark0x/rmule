//! The **Callback Pace** (ADR-0061): no two `0x52` reach one IP inside the
//! stock window, whichever download, source, reading or road sent them. Each
//! flow runs its datagrams through [`StockGuard`], stock's own arithmetic, so
//! a schedule that would cost a drop or a debt fails here.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_kad::{
    FileHash, Kad2Message, Kad2NodeInfo, KadCallbackPace, KadCallbackWalkEnd, KadCommand, KadEvent,
    KadId, KadInstant, KadNode, KadNodeEndpoint, KadOutput,
};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{T0, datagrams, deliver, events, node};

const BUDDY_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const PRIMARY: KadId = KadId::from_bytes([0x55; KadId::BYTE_LEN]);
const FALLBACK: KadId = KadId::from_bytes([0x66; KadId::BYTE_LEN]);
const FILE_A: FileHash = FileHash::from_bytes([0x11; 16]);
const FILE_B: FileHash = FileHash::from_bytes([0x22; 16]);
const SPACING: Duration = Duration::from_secs(65);

/// `CPacketTracking::InTrackListCheck` for `KADEMLIA_CALLBACK_REQ`, one IP:
/// `PacketTracking.cpp:158-160` and `:188-215`, stock 2.3.3, the same in
/// 3.1.0 and kno.
#[derive(Default)]
struct StockGuard {
    entry: Option<(u64, u64)>,
}

impl StockGuard {
    /// Whether stock takes a packet that arrives `tick` ms in.
    fn takes(&mut self, tick: u64) -> bool {
        const WINDOW: u64 = 60_000;
        let Some((first_added, count)) = &mut self.entry else {
            self.entry = Some((tick, 1));
            return true;
        };
        if *count > 0 && tick - *first_added > WINDOW {
            let expired = (tick - *first_added) / WINDOW;
            if expired > *count {
                *count = 0;
                *first_added = tick;
            } else {
                *count -= expired;
                *first_added += WINDOW * expired;
            }
        }
        *count += 1;
        *count <= 1
    }
}

fn endpoint_at(ip: Ipv4Addr) -> KadNodeEndpoint {
    KadNodeEndpoint::new(ip, 4672)
}

fn ask(buddy_id: KadId, file_hash: FileHash) -> KadCommand {
    KadCommand::RequestBuddyCallback {
        buddy: endpoint_at(BUDDY_IP),
        buddy_id,
        file_hash,
        tcp_port: 4662,
    }
}

fn paced(outputs: &[KadOutput]) -> Vec<KadCallbackPace> {
    events(outputs)
        .into_iter()
        .filter_map(|event| match event {
            KadEvent::BuddyCallbackPaced { pace, .. } => Some(pace),
            _ => None,
        })
        .collect()
}

fn ms_since_t0(at: KadInstant) -> u64 {
    at.as_millis() - T0.as_millis()
}

/// Run the node to `until`, tick by next wake, recording when each `0x52`
/// left, in ms since [`T0`].
fn run_to(node: &mut KadNode, until: KadInstant, left: &mut Vec<u64>) {
    while let Some(wake) = node.next_wake().filter(|&wake| wake <= until) {
        node.tick(wake);
        let sent = datagrams(&drain(|| node.poll_output()));
        left.extend(sent.iter().map(|_| ms_since_t0(wake)));
    }
}

#[test]
fn a_fallback_asked_at_the_end_of_the_wait_leaves_past_the_stock_window() {
    let mut node = node();
    let mut left = Vec::new();

    node.handle_command(T0, ask(PRIMARY, FILE_A));
    let outputs = drain(|| node.poll_output());
    assert_eq!(paced(&outputs), vec![KadCallbackPace::Left]);
    assert_eq!(datagrams(&outputs).len(), 1);
    left.push(0);

    let wait_lapsed = T0 + Duration::from_secs(30);
    run_to(&mut node, wait_lapsed, &mut left);
    node.handle_command(wait_lapsed, ask(FALLBACK, FILE_A));
    let outputs = drain(|| node.poll_output());
    assert_eq!(
        paced(&outputs),
        vec![KadCallbackPace::Held {
            leaves_in: Duration::from_secs(35)
        }],
    );
    assert!(datagrams(&outputs).is_empty(), "held, not sent");

    run_to(&mut node, T0 + SPACING, &mut left);
    assert_eq!(left, vec![0, 65_000]);

    let mut stock = StockGuard::default();
    assert!(left.iter().all(|&tick| stock.takes(tick)));
}

#[test]
fn two_downloads_behind_one_buddy_share_its_window_in_the_order_they_asked() {
    let mut node = node();
    let mut left = Vec::new();

    // Each download's primary, then each one's fallback when its wait lapses,
    // with neither knowing what the other sent.
    let asks = [
        (0, PRIMARY, FILE_A),
        (1, PRIMARY, FILE_B),
        (30, FALLBACK, FILE_A),
        (31, FALLBACK, FILE_B),
    ];
    for (second, buddy_id, file) in asks {
        let at = T0 + Duration::from_secs(second);
        run_to(&mut node, at, &mut left);
        node.handle_command(at, ask(buddy_id, file));
        let sent = datagrams(&drain(|| node.poll_output()));
        left.extend(sent.iter().map(|_| ms_since_t0(at)));
    }
    run_to(&mut node, T0 + SPACING * 4, &mut left);

    assert_eq!(left, vec![0, 65_000, 130_000, 195_000]);
    let mut stock = StockGuard::default();
    assert!(left.iter().all(|&tick| stock.takes(tick)));
}

#[test]
fn another_buddy_is_another_window() {
    let mut node = node();
    node.handle_command(T0, ask(PRIMARY, FILE_A));
    node.handle_command(
        T0,
        KadCommand::RequestBuddyCallback {
            buddy: endpoint_at(Ipv4Addr::new(203, 0, 113, 10)),
            buddy_id: PRIMARY,
            file_hash: FILE_A,
            tcp_port: 4662,
        },
    );
    assert_eq!(datagrams(&drain(|| node.poll_output())).len(), 2);
}

#[test]
fn a_held_send_is_no_later_than_stock_needs_and_a_late_ask_waits_for_nothing() {
    let mut node = node();
    node.handle_command(T0, ask(PRIMARY, FILE_A));
    drain(|| node.poll_output());

    let past_window = T0 + SPACING;
    node.handle_command(past_window, ask(FALLBACK, FILE_A));
    let outputs = drain(|| node.poll_output());
    assert_eq!(paced(&outputs), vec![KadCallbackPace::Left]);
    assert_eq!(datagrams(&outputs).len(), 1);
}

#[test]
fn an_ask_too_far_behind_a_busy_buddy_is_refused_and_nothing_leaves_for_it() {
    let mut node = node();
    let mut paces = Vec::new();
    for _ in 0..6 {
        node.handle_command(T0, ask(PRIMARY, FILE_A));
        paces.extend(paced(&drain(|| node.poll_output())));
    }
    assert_eq!(
        paces
            .iter()
            .filter(|p| **p == KadCallbackPace::Refused)
            .count(),
        1
    );
    assert_eq!(paces.last(), Some(&KadCallbackPace::Refused));

    let mut left = Vec::new();
    run_to(&mut node, T0 + SPACING * 10, &mut left);
    assert_eq!(left.len(), 4, "the held four, and no refused one");
}

/// A contact near [`PRIMARY`]: within `SEARCHTOLERANCE` of the walk's target.
fn near_id() -> KadId {
    let mut bytes = [0x55; KadId::BYTE_LEN];
    bytes[4..].fill(0x00);
    KadId::from_bytes(bytes)
}

fn walk_to_convergence(
    node: &mut KadNode,
    at: KadInstant,
    contact: KadNodeEndpoint,
) -> Vec<KadOutput> {
    node.handle_command(
        at,
        KadCommand::CallbackWalk {
            buddy_id: PRIMARY,
            file_hash: FILE_A,
            tcp_port: 4662,
        },
    );
    drain(|| node.poll_output());
    deliver(
        node,
        at,
        contact,
        &Kad2Message::LookupRes {
            target: PRIMARY,
            contacts: Vec::new(),
        },
    );
    drain(|| node.poll_output())
}

fn seat_near_contact(node: &mut KadNode, at: KadNodeEndpoint) {
    let info = Kad2NodeInfo {
        id: near_id(),
        tcp_port: 4761,
        version: 8,
        udp_port_tag: None,
        misc_options: 0,
    };
    deliver(node, T0, at, &Kad2Message::HelloReq(info));
    drain(|| node.poll_output());
}

fn walk_end(outputs: &[KadOutput]) -> Option<KadCallbackWalkEnd> {
    events(outputs).into_iter().find_map(|event| match event {
        KadEvent::CallbackWalkEnded { end, .. } => Some(end),
        _ => None,
    })
}

#[test]
fn a_walk_sends_inside_the_same_window_as_a_direct_callback() {
    let mut node = node();
    let contact = endpoint_at(BUDDY_IP);
    seat_near_contact(&mut node, contact);
    node.handle_command(T0, ask(FALLBACK, FILE_A));
    drain(|| node.poll_output());

    let at = T0 + Duration::from_secs(5);
    let outputs = walk_to_convergence(&mut node, at, contact);
    assert_eq!(
        walk_end(&outputs),
        Some(KadCallbackWalkEnd::Held {
            asked: 1,
            leaves_in: Duration::from_secs(60)
        }),
    );

    // Whatever else the node sends, the walked contact's `0x52` lands on the
    // booked instant.
    let mut left = Vec::new();
    run_to(
        &mut node,
        T0 + (SPACING - Duration::from_millis(1)),
        &mut left,
    );
    let before = left.len();
    run_to(&mut node, T0 + SPACING, &mut left);
    assert_eq!(left.len(), before + 1);
    assert_eq!(left.last(), Some(&65_000));
}

#[test]
fn a_direct_callback_waits_out_a_walk_that_just_asked_that_ip() {
    let mut node = node();
    let contact = endpoint_at(BUDDY_IP);
    seat_near_contact(&mut node, contact);

    let outputs = walk_to_convergence(&mut node, T0, contact);
    assert_eq!(walk_end(&outputs), Some(KadCallbackWalkEnd::Asked(1)));

    let at = T0 + Duration::from_secs(5);
    node.handle_command(at, ask(FALLBACK, FILE_A));
    assert_eq!(
        paced(&drain(|| node.poll_output())),
        vec![KadCallbackPace::Held {
            leaves_in: Duration::from_secs(60)
        }],
    );
}
