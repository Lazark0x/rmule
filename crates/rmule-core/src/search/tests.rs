//! Search unit tests, both surfaces: the sweep's variant choice from a server's
//! advertised UDP flags, its one-datagram-per-tick pacing with the connected
//! server skipped and each datagram sized for its addressee, the answer forwarder handing
//! `0x99` rows to every live search they prove, and the task
//! merging attributed and Kad batches into one deduplicated result set. One
//! module because every producer's rows are built by the same `result` helper.

use std::net::Ipv4Addr;
use std::sync::Mutex;

use rmule_ed2k::{GlobSearchReq, GlobSearchVariant, Opcode, SearchRequest, ServerUdpFlags};
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Ipv4Endpoint, KeywordQuery, PacketProtocol, PeerSource,
    ServerEndpoint,
};

use super::global_sweep::*;
use super::*;
use crate::adapters::ServerUdpTransport;
use crate::server_capabilities::SharedServerCapabilities;
use crate::server_udp::ServerUdpDatagram;
use crate::server_udp::tests::{plain_seal, seal_over, udp};

mod kad_leg;
mod lifecycle;
mod sweep_tally;

/// The next event that is not a leg picture (`SearchLegsChanged`).
async fn next_past_legs(evt_rx: &mut mpsc::Receiver<CoreEvent>) -> Option<CoreEvent> {
    loop {
        match evt_rx.recv().await? {
            CoreEvent::Search(SearchEvent::SearchLegsChanged { .. }) => {}
            event => return Some(event),
        }
    }
}

fn flags(bits: u32) -> Option<ServerUdpFlags> {
    Some(ServerUdpFlags::from_bits(bits))
}

#[test]
fn variant_selection_follows_the_advertised_flags() {
    let ext = ServerUdpFlags::EXT_GETFILES;
    let large = ServerUdpFlags::LARGEFILES;
    // No record and no relevant flags → baseline.
    assert_eq!(select_variant(None), GlobSearchVariant::Baseline);
    assert_eq!(select_variant(flags(0)), GlobSearchVariant::Baseline);
    // ExtGetFiles alone → 0x92; with LargeFiles → 0x90; LargeFiles alone
    // does not upgrade.
    assert_eq!(select_variant(flags(ext)), GlobSearchVariant::ExtGetFiles);
    assert_eq!(
        select_variant(flags(ext | large)),
        GlobSearchVariant::LargeFiles
    );
    assert_eq!(select_variant(flags(large)), GlobSearchVariant::Baseline);
}

/// A transport that records every send's `(server, opcode)`; `recv`
/// pends forever (the sweep never reads).
struct RecordingTransport {
    sends: Mutex<Vec<(Ipv4Endpoint, u8)>>,
    datagrams: Mutex<Vec<Vec<u8>>>,
}

impl RecordingTransport {
    fn new() -> Self {
        Self {
            sends: Mutex::new(Vec::new()),
            datagrams: Mutex::new(Vec::new()),
        }
    }
}

impl ServerUdpTransport for &'static RecordingTransport {
    async fn send_to(&self, to: Ipv4Endpoint, datagram: Vec<u8>) {
        self.sends.lock().unwrap().push((to, datagram[1]));
        self.datagrams.lock().unwrap().push(datagram);
    }

    async fn recv(&self) -> Option<ServerUdpDatagram> {
        std::future::pending().await
    }
}

fn server(host: &str, port: u16) -> ServerEndpoint {
    ServerEndpoint::new(host, port).expect("valid endpoint")
}

use crate::server_capabilities::test_record_with_flags as caps_with_flags;

fn abba() -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8("abba")).expect("valid phrase")
}

/// A bound one past `u32::MAX`: a `0x08` term toward a large-file server, a
/// clamped `0x03` toward any other.
fn oversize_query() -> KeywordQuery {
    abba().with_min_size(u64::from(u32::MAX) + 1)
}

#[tokio::test]
async fn sweep_paces_one_variant_datagram_per_server_and_skips_the_connected_one() {
    let transport: &'static RecordingTransport = Box::leak(Box::new(RecordingTransport::new()));
    let capabilities = SharedServerCapabilities::default();
    capabilities.lock().unwrap().insert(
        Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 4661),
        caps_with_flags(ServerUdpFlags::EXT_GETFILES | ServerUdpFlags::LARGEFILES),
    );
    capabilities.lock().unwrap().insert(
        Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 4), 4661),
        caps_with_flags(ServerUdpFlags::EXT_GETFILES),
    );

    let asked = GlobalSearchSweep {
        seal: plain_seal(transport),
        servers: vec![
            server("10.0.0.1", 4661), // the connected server — skipped
            server("10.0.0.2", 4661), // ExtGetFiles + LargeFiles → 0x90
            server("10.0.0.3", 4661), // no capability record → 0x98
            server("10.0.0.4", 4661), // ExtGetFiles → 0x92
        ],
        capabilities,
        connected: server("10.0.0.1", 4661),
        query: abba(),
        pacer: UdpSearchPacer::default(),
        tick: Duration::from_millis(1),
    }
    .run()
    .await;

    let sends = transport.sends.lock().unwrap().clone();
    assert_eq!(
        sends,
        vec![
            (udp(&server("10.0.0.2", 4661), 4), 0x90),
            (udp(&server("10.0.0.3", 4661), 4), 0x98),
            (udp(&server("10.0.0.4", 4661), 4), 0x92),
        ],
        "one datagram per non-connected server, variant per its flags"
    );
    assert_eq!(asked, 3, "the sweep counts the servers it asked");
}

/// Each datagram is sized for its addressee (ADR-0051): the
/// oversize bound widens toward the server advertising large-file UDP support
/// and clamps toward the one that does not — both are asked.
#[tokio::test]
async fn a_sweep_widens_a_large_bound_only_where_the_server_takes_it() {
    let transport: &'static RecordingTransport = Box::leak(Box::new(RecordingTransport::new()));
    let capabilities = SharedServerCapabilities::default();
    capabilities.lock().unwrap().insert(
        Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 4661),
        caps_with_flags(ServerUdpFlags::EXT_GETFILES | ServerUdpFlags::LARGEFILES),
    );

    GlobalSearchSweep {
        seal: plain_seal(transport),
        servers: vec![server("10.0.0.2", 4661), server("10.0.0.3", 4661)],
        capabilities,
        connected: server("10.0.0.9", 4661),
        query: oversize_query(),
        pacer: UdpSearchPacer::default(),
        tick: Duration::from_millis(1),
    }
    .run()
    .await;

    let wide = GlobSearchReq::new(
        SearchRequest::from_query(oversize_query()).with_large_file_support(true),
    )
    .encode_packet(GlobSearchVariant::LargeFiles)
    .encode_udp();
    let clamped = GlobSearchReq::new(SearchRequest::from_query(oversize_query()))
        .encode_packet(GlobSearchVariant::Baseline)
        .encode_udp();
    assert_eq!(*transport.datagrams.lock().unwrap(), vec![wide, clamped]);
}

/// Searches started together share each server's spacing: their datagrams
/// reach one server at least `UDP_SEARCH_SPACING` apart, below ed2k-server's
/// bot detector (run 1790605441 drew its 24 h ban from 30 sent together).
#[tokio::test(start_paused = true)]
async fn sweeps_started_together_reach_one_server_spaced() {
    let transport: &'static RecordingTransport = Box::leak(Box::new(RecordingTransport::new()));
    let pacer = UdpSearchPacer::default();
    let sweep = || GlobalSearchSweep {
        seal: plain_seal(transport),
        servers: vec![server("10.0.0.2", 4661)],
        capabilities: SharedServerCapabilities::default(),
        connected: server("10.0.0.9", 4661),
        query: abba(),
        pacer: pacer.clone(),
        tick: Duration::from_millis(1),
    };
    let start = tokio::time::Instant::now();
    tokio::join!(sweep().run(), sweep().run(), sweep().run());
    assert_eq!(transport.sends.lock().unwrap().len(), 3);
    assert_eq!(start.elapsed(), 2 * UDP_SEARCH_SPACING);
}

/// A server whose UDP key we hold gets its search datagram sealed at its
/// obfuscation port; a server without one gets it plain at standard port + 4.
#[tokio::test]
async fn a_sweep_seals_its_datagram_toward_a_keyed_server() {
    const KEY: u32 = 0x05A6_8835;
    let ours = Ipv4Addr::new(203, 0, 113, 3);
    let transport: &'static RecordingTransport = Box::leak(Box::new(RecordingTransport::new()));
    let capabilities = SharedServerCapabilities::default();
    let mut keyed = caps_with_flags(ServerUdpFlags::UDPOBFUSCATION);
    keyed.udp_crypt = Some(crate::server_list::ServerUdpCrypt {
        obfuscation_udp_port: 4675,
        obfuscation_tcp_port: 4661,
        udp_key: KEY,
        key_ip: Some(ours),
    });
    capabilities
        .lock()
        .unwrap()
        .insert(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 4661), keyed);
    let own = crate::own_identity::SharedOwnIdentity::default();
    own.addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            ours,
        ));

    GlobalSearchSweep {
        seal: seal_over(
            transport,
            crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
                rmule_net::peer::ObfuscationPolicy::Requested,
            )),
            own,
            capabilities.clone(),
            crate::server_list::ServerFacts::default(),
        ),
        servers: vec![server("10.0.0.2", 4661), server("10.0.0.3", 4661)],
        capabilities,
        connected: server("10.0.0.9", 4661),
        query: abba(),
        pacer: UdpSearchPacer::default(),
        tick: Duration::from_millis(1),
    }
    .run()
    .await;

    let baseline = GlobSearchReq::new(SearchRequest::from_query(abba()))
        .encode_packet(GlobSearchVariant::Baseline)
        .encode_udp();
    let sends = transport.sends.lock().unwrap().clone();
    let datagrams = transport.datagrams.lock().unwrap().clone();
    assert_eq!(
        sends[0].0,
        Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 4675)
    );
    assert_eq!(
        rmule_primitives::decrypt_datagram_server(
            &datagrams[0],
            KEY,
            rmule_primitives::ServerCryptDirection::ToServer
        ),
        Some(baseline.clone())
    );
    assert_eq!(
        (sends[1].0, &datagrams[1]),
        (udp(&server("10.0.0.3", 4661), 4), &baseline)
    );
}

fn result(hash: u8, name: &str) -> SearchResult {
    SearchResult::new(
        FileHash::from_bytes([hash; FileHash::BYTE_LEN]),
        4096,
        vec![Ed2kText::from_utf8(name)],
        vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4662)],
    )
    .expect("valid result")
}

/// One `0x99` datagram carrying one row for `hash` named `name`.
fn glob_search_res_datagram(hash: u8, name: &str) -> Vec<u8> {
    let mut out = vec![
        PacketProtocol::Edonkey.as_byte(),
        Opcode::GlobSearchRes.as_u8(),
    ];
    out.extend_from_slice(&[hash; FileHash::BYTE_LEN]);
    out.extend_from_slice(&0x0100_007F_u32.to_le_bytes());
    out.extend_from_slice(&4662_u16.to_le_bytes());
    out.extend_from_slice(&2_u32.to_le_bytes());
    out.extend_from_slice(&[0x02, 0x01, 0x00, 0x01]); // FT_FILENAME string tag
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&[0x03, 0x01, 0x00, 0x02]); // FT_FILESIZE u32 tag
    out.extend_from_slice(&4096_u32.to_le_bytes());
    out
}

/// Sweeps run side by side: a `0x99` names no search and has no
/// place, so each row reaches every live keyword search it proves and no
/// other; a row no live search proves is counted; a malformed datagram drops.
#[tokio::test]
async fn global_answers_reach_every_search_they_prove_and_no_other() {
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    let live = LiveSearches::new(diagnostics.clone());
    let mut abba = live.register(SearchId::from_u64(1), phrase("abba").into());
    let mut gold = live.register(SearchId::from_u64(2), phrase("abba gold").into());
    let mut related = live.register(
        SearchId::from_u64(3),
        rmule_primitives::RelatedFilesQuery::new(
            FileHash::from_bytes([0x5A; FileHash::BYTE_LEN]),
            Ed2kText::from_utf8("x"),
        )
        .into(),
    );

    forward_one_answer(
        &glob_search_res_datagram(0xAA, "ABBA - Gold.mp3"),
        server_udp(7),
        &live,
    );
    forward_one_answer(
        &glob_search_res_datagram(0xBB, "abba-waterloo.mp3"),
        server_udp(7),
        &live,
    );
    forward_one_answer(
        &glob_search_res_datagram(0xCC, "queen.mp3"),
        server_udp(7),
        &live,
    );
    forward_one_answer(&[0xE3, 0x99, 0x01], server_udp(7), &live);

    let hashes = |rows: Vec<SearchResult>| -> Vec<u8> {
        rows.iter()
            .map(|row| row.file_hash().as_bytes()[0])
            .collect()
    };
    assert_eq!(hashes(abba.drain()), [0xAA, 0xBB]);
    assert_eq!(hashes(gold.drain()), [0xAA]);
    assert!(
        related.drain().is_empty(),
        "content never reaches a related search"
    );
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .search_rows_unattributed_total,
        1
    );

    // An ended search is no longer live: its rows are counted, not shown.
    drop(gold);
    forward_one_answer(
        &glob_search_res_datagram(0xDD, "abba gold 2.mp3"),
        server_udp(7),
        &live,
    );
    assert_eq!(hashes(abba.drain()), [0xDD]);

    // The engine-fed loop drives the same step per demuxed datagram.
    let (inbox_tx, inbox_rx) = mpsc::channel(8);
    tokio::spawn(forward_global_search_answers(inbox_rx, live.clone()));
    let src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    inbox_tx
        .send((glob_search_res_datagram(0xEE, "abba.flac"), src))
        .await
        .expect("inbox open");
    let batch = tokio::time::timeout(Duration::from_secs(2), abba.recv())
        .await
        .expect("delivered within 2s")
        .expect("registered");
    assert_eq!(hashes(batch.rows), [0xEE]);
    assert!(batch.new_answerer, "the answer names its server");
}

fn phrase(text: &str) -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8(text)).expect("valid phrase")
}

/// Every leg's window set to `window`: a silent leg settles after one, and
/// the quiet window follows.
fn windows(window: Duration) -> SearchWindows {
    SearchWindows {
        quiet: window,
        kad_lifetime: window,
    }
}

/// A server's UDP address as a `0x99` arrives from it.
fn server_udp(last_octet: u8) -> rmule_primitives::Ipv4Endpoint {
    rmule_primitives::Ipv4Endpoint::new(std::net::Ipv4Addr::new(192, 0, 2, last_octet), 4665)
}

/// A global leg with no sweep: its sender already dropped.
fn sweep_already_done() -> crate::search::SweepDone {
    oneshot::channel().1
}

/// A search task's attributed rows, registered under `id` in `live`.
fn attributed(live: &LiveSearches, id: u64) -> AttributedRows {
    live.register(SearchId::from_u64(id), phrase("a").into())
}

#[tokio::test]
async fn merges_attributed_and_kad_batches_into_one_result_set() {
    let (tcp_tx, tcp_rx) = mpsc::channel(8);
    let live = LiveSearches::default();
    let (kad_tx, kad_rx) = crate::search::kad_keyword_leg();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (_cancel_tx, cancel_rx) = watch::channel(false);

    let task = tokio::spawn(
        SearchTask {
            search_id: SearchId::from_u64(7),
            stream: SearchStream { event_rx: tcp_rx },
            rows: attributed(&live, 7),
            kad_rx,
            global_sweep: sweep_already_done(),
            windows: windows(Duration::from_millis(200)),
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(
                rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8("a"))
                    .expect("a query")
                    .into(),
            ),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: tokio::sync::mpsc::unbounded_channel().0,
        }
        .run(),
    );

    // The server's answer, attributed to its owner, lands first; its
    // snapshot is awaited before the next batch, so the merge order is
    // deterministic. The leg then settles.
    live.deliver(vec![result(0xAA, "a.bin")], Some(SearchId::from_u64(7)));
    drop(tcp_tx);
    let first = tokio::time::timeout(Duration::from_secs(2), next_past_legs(&mut evt_rx))
        .await
        .expect("first snapshot within 2s")
        .expect("events open");
    let CoreEvent::Search(SearchEvent::SearchResultsReceived { results, .. }) = first else {
        panic!("expected a results snapshot, got {first:?}");
    };
    assert_eq!(results.len(), 1);

    // Then a global batch carrying a duplicate of the same file (an alias
    // name) plus a new one.
    live.deliver(
        vec![result(0xAA, "a-alias.bin"), result(0xBB, "a-b.bin")],
        None,
    );
    let second = tokio::time::timeout(Duration::from_secs(2), next_past_legs(&mut evt_rx))
        .await
        .expect("merged snapshot within 2s")
        .expect("events open");
    let CoreEvent::Search(SearchEvent::SearchResultsReceived { results, .. }) = second else {
        panic!("expected a merged snapshot, got {second:?}");
    };
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].names().len(), 2, "the global alias merged");

    // Then a Kad keyword batch (ADR-0062 requester) carrying another alias of
    // 0xAA plus a keyword-only file 0xDD: it merges into the SAME set.
    kad_tx
        .send(vec![result(0xAA, "a-kad-alias.bin"), result(0xDD, "d.bin")])
        .await
        .expect("kad open");
    let third = tokio::time::timeout(Duration::from_secs(2), next_past_legs(&mut evt_rx))
        .await
        .expect("kad-merged snapshot within 2s")
        .expect("events open");
    let CoreEvent::Search(SearchEvent::SearchResultsReceived { results, .. }) = third else {
        panic!("expected a kad-merged snapshot, got {third:?}");
    };
    assert_eq!(
        results.len(),
        3,
        "0xDD is new; 0xAA deduped across all three"
    );
    assert_eq!(
        results[0].names().len(),
        3,
        "the Kad alias merged onto the same 0xAA result"
    );

    // The Kad walk ends; with every leg settled, the quiet timeout completes
    // the search across all three producers.
    drop(kad_tx);
    let completed = tokio::time::timeout(Duration::from_secs(2), next_past_legs(&mut evt_rx))
        .await
        .expect("completion within 2s")
        .expect("events open");
    let CoreEvent::Search(SearchEvent::SearchCompleted { total_results, .. }) = completed else {
        panic!("expected completion, got {completed:?}");
    };
    assert_eq!(total_results, 3);

    // Completed, and no server holds more for it: it ended on its own.
    assert_eq!(
        task.await.expect("task ended cleanly"),
        crate::search::SearchEnd::Ended
    );

    // The search is over: it is no longer live, so its rows are not its.
    live.deliver(vec![result(0xEE, "a-late.bin")], None);
}

/// A related search whose answer could not be told from a late one fails
/// saying so, rather than show another search's rows.
#[tokio::test]
async fn an_unattributable_related_answer_fails_the_search() {
    let (tcp_tx, tcp_rx) = mpsc::channel(8);
    let live = LiveSearches::default();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let task = tokio::spawn(
        SearchTask {
            search_id: SearchId::from_u64(8),
            stream: SearchStream { event_rx: tcp_rx },
            rows: attributed(&live, 8),
            kad_rx: crate::search::KadKeywordLeg::settled(),
            global_sweep: sweep_already_done(),
            windows: windows(Duration::from_secs(3600)),
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(
                rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8("a"))
                    .expect("a query")
                    .into(),
            ),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: tokio::sync::mpsc::unbounded_channel().0,
        }
        .run(),
    );
    tcp_tx
        .send(ServerSearchEvent::RelatedAnswerUnattributable)
        .await
        .expect("leg open");
    let event = tokio::time::timeout(Duration::from_secs(2), next_past_legs(&mut evt_rx))
        .await
        .expect("an event within 2s")
        .expect("events open");
    assert!(
        matches!(
            event,
            CoreEvent::Search(SearchEvent::SearchFailed {
                reason: SearchFailure::RelatedAnswerUnattributable,
                ..
            })
        ),
        "got {event:?}"
    );
    task.await.expect("task ended cleanly");
}

/// The closed-channel rule's twin, on the search side: a **dropped** cancel
/// sender ends the search task, exactly as a stop does.
///
/// A dropped `watch::Sender` makes `changed()` answer `Err` immediately and
/// forever, so an arm that only acted on a `true` would leave the loop
/// spinning at full speed, holding the `CoreEvent` sender `Core::shutdown`
/// waits to see dropped. Like a stop it says nothing: the word is its
/// retire's, and a ledger dropped whole has no one to tell.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_cancel_sender_ends_the_search_task() {
    let (_tcp_tx, tcp_rx) = mpsc::channel(8);
    let live = LiveSearches::default();
    let (_kad_tx, kad_rx) = crate::search::kad_keyword_leg();
    let (evt_tx, mut evt_rx) = mpsc::channel(16);
    let (cancel_tx, cancel_rx) = watch::channel(false);

    let task = tokio::spawn(
        SearchTask {
            search_id: SearchId::from_u64(310),
            stream: SearchStream { event_rx: tcp_rx },
            rows: attributed(&live, 310),
            kad_rx,
            // Far past the test's own budget: the task must leave because its
            // owner dropped, not because the search quietly completed.
            global_sweep: sweep_already_done(),
            windows: windows(Duration::from_secs(3600)),
            evt_tx,
            cancel_rx,
            paging: crate::search::Paging::inert(
                rmule_primitives::KeywordQuery::new(rmule_primitives::Ed2kText::from_utf8("a"))
                    .expect("a query")
                    .into(),
            ),
            legs: crate::service::SearchLegs::SENT,
            late: crate::search::LateLegs::default(),
            lost: tokio::sync::mpsc::unbounded_channel().0,
        }
        .run(),
    );

    drop(cancel_tx);

    let end = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the search task ends when its owner drops")
        .expect("the search task did not panic");
    assert_eq!(end, SearchEnd::Stopped);
    let said = tokio::time::timeout(Duration::from_secs(5), next_past_legs(&mut evt_rx))
        .await
        .expect("the event stream closes with the task");
    assert!(said.is_none(), "a stopped task says nothing, got {said:?}");
}
