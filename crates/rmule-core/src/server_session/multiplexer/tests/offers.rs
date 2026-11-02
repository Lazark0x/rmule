//! The Offer Queue on the session (ADR-0099): what crosses the link of a share
//! set, in what batches and at what pace, and the opening ask that draws the
//! ident the pace is read from.

use std::time::Duration;

use rmule_ed2k::{FileCompleteness, ServerGrants};
use rmule_primitives::{Ed2kText, ServerIdentity, Tag, TagName, TagValue};
use tokio::time::Instant;

use super::super::super::tests::{FakeLink, client_id, connected, test_sinks};
use super::*;
use crate::diagnostics::SharesToServer;

/// How long the first batch waits for an ident with none coming.
const WAIT: Duration = Duration::from_secs(5);

struct Bench {
    handle: ServerSessionHandle,
    events: mpsc::Sender<Ed2kEvent>,
    sent: mpsc::Receiver<Ed2kCommand>,
}

impl Bench {
    fn new() -> Self {
        Self::with(test_sinks(SharedOwnIdentity::default()))
    }

    fn with(sinks: SessionSinks) -> Self {
        let (events, evt_rx) = mpsc::channel(8);
        let (cmd_tx, sent) = mpsc::channel(8);
        let link = FakeLink {
            events: evt_rx,
            sent: cmd_tx,
        };
        let handle = ServerSession::spawn(link, client_id(), sinks);
        Self {
            handle,
            events,
            sent,
        }
    }

    async fn identified(&self, tags: Vec<Tag>) {
        let identity = ServerIdentity {
            extra_tags: tags,
            ..ServerIdentity::default()
        };
        self.events
            .send(Ed2kEvent::ServerIdentified { identity })
            .await
            .unwrap();
    }

    /// The next offer, and when it left.
    async fn offer(&mut self) -> (Vec<OfferedFile>, Instant) {
        match self.sent.recv().await.unwrap() {
            Ed2kCommand::OfferFiles { files, .. } => (files, Instant::now()),
            other => panic!("unexpected command {other:?}"),
        }
    }

    async fn nothing_more(&mut self) {
        let waited = tokio::time::timeout(Duration::from_secs(3600), self.sent.recv()).await;
        assert!(waited.is_err(), "nothing more goes: {waited:?}");
    }
}

fn file(index: u32) -> OfferedFile {
    let mut bytes = [0u8; FileHash::BYTE_LEN];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    OfferedFile::new(
        FileHash::from_bytes(bytes),
        1024,
        Ed2kText::from_utf8("a.bin"),
    )
}

fn files(range: std::ops::Range<u32>) -> Vec<OfferedFile> {
    range.map(file).collect()
}

fn numbered(id: u8, value: u32) -> Tag {
    Tag::new(TagName::compact_id(id), TagValue::U32(value))
}

fn named(name: &str, value: u32) -> Tag {
    Tag::new(TagName::text(name).unwrap(), TagValue::U32(value))
}

/// A complete OFFERFILES v1 advertisement.
fn advert(soft: u32, hard: u32, batch_max: u32, interval_ms: u32) -> Vec<Tag> {
    vec![
        numbered(0x88, soft),
        numbered(0x89, hard),
        named("offerfiles_v", 1),
        named("offerfiles_batch_max", batch_max),
        named("offerfiles_min_interval_ms", interval_ms),
    ]
}

/// The whole share in one packet closes the session on a server's hard limit,
/// and on a Lugdunum risks the address: aMule's 200 a minute, as a bucket.
#[tokio::test(start_paused = true)]
async fn a_share_past_one_batch_goes_at_the_legacy_pace() {
    let mut bench = Bench::new();
    let start = Instant::now();
    bench.handle.announce(files(0..450)).await.unwrap();

    let (first, sent) = bench.offer().await;
    assert_eq!(first.len(), 200);
    assert_eq!(sent - start, WAIT, "no ident came");
    let (second, sent) = bench.offer().await;
    assert_eq!(second.len(), 200);
    assert_eq!(sent - start, WAIT + Duration::from_secs(60));
    let (third, sent) = bench.offer().await;
    assert_eq!(third.len(), 50);
    assert_eq!(sent - start, WAIT + Duration::from_secs(120));
    assert_eq!(third.last(), Some(&file(449)));
    bench.nothing_more().await;
}

/// aMule marks what a connection was told: a new set sends its difference,
/// and a file goes again only when its completeness changed.
#[tokio::test(start_paused = true)]
async fn only_what_the_connection_was_not_told_goes() {
    let mut bench = Bench::new();
    bench.identified(Vec::new()).await;
    bench.handle.announce(files(0..2)).await.unwrap();
    assert_eq!(bench.offer().await.0, files(0..2));

    bench.handle.announce(files(0..3)).await.unwrap();
    assert_eq!(bench.offer().await.0, files(2..3));

    let finished = file(1).with_completeness(FileCompleteness::Incomplete);
    let set = vec![file(0), finished.clone(), file(2)];
    bench.handle.announce(set.clone()).await.unwrap();
    assert_eq!(bench.offer().await.0, [finished]);

    bench.handle.announce(set).await.unwrap();
    bench.nothing_more().await;
}

/// The newest set replaces what was queued: a file gone from the share before
/// its turn is never offered.
#[tokio::test(start_paused = true)]
async fn a_newer_set_replaces_the_queue() {
    let mut bench = Bench::new();
    bench.identified(Vec::new()).await;
    bench.handle.announce(files(0..300)).await.unwrap();
    assert_eq!(bench.offer().await.0.len(), 200);

    bench.handle.announce(files(0..250)).await.unwrap();
    assert_eq!(bench.offer().await.0, files(200..250));
    bench.nothing_more().await;
}

/// An advert sets the size and the pace for the connection, and a later ident
/// changes neither.
#[tokio::test(start_paused = true)]
async fn the_first_ident_settles_the_pace_for_the_session() {
    let mut bench = Bench::new();
    let start = Instant::now();
    bench.identified(advert(5_000, 7_500, 150, 500)).await;
    bench.identified(advert(5_000, 7_500, 10, 1)).await;
    bench.handle.announce(files(0..400)).await.unwrap();

    for (batch, at) in [(150, 0), (150, 500), (100, 1000)] {
        let (offered, sent) = bench.offer().await;
        assert_eq!(offered.len(), batch);
        assert_eq!(sent - start, Duration::from_millis(at));
    }
}

/// A server that sends no advert in its first ident is legacy for good: a
/// later advert must not be believed, as the server holds it to neither.
#[tokio::test(start_paused = true)]
async fn an_ident_without_an_advert_is_legacy_for_the_session() {
    let mut bench = Bench::new();
    let start = Instant::now();
    bench.identified(Vec::new()).await;
    bench.identified(advert(5_000, 7_500, 150, 500)).await;
    bench.handle.announce(files(0..250)).await.unwrap();

    assert_eq!(bench.offer().await.0.len(), 200);
    let (rest, sent) = bench.offer().await;
    assert_eq!(rest.len(), 50);
    assert_eq!(sent - start, Duration::from_secs(60));
}

/// `ST_SOFTFILES` caps a legacy batch as it does aMule's
/// (`SharedFileList.cpp:707-710`), and `ST_HARDFILES` is a boundary for all.
#[tokio::test(start_paused = true)]
async fn a_legacy_batch_stays_under_the_limits_the_ident_stated() {
    let mut bench = Bench::new();
    bench.identified(vec![numbered(0x88, 120)]).await;
    bench.handle.announce(files(0..130)).await.unwrap();
    assert_eq!(bench.offer().await.0.len(), 120);

    let mut bench = Bench::new();
    bench.identified(vec![numbered(0x89, 50)]).await;
    bench.handle.announce(files(0..130)).await.unwrap();
    assert_eq!(bench.offer().await.0.len(), 49);
}

/// On v1 the soft budget ends the publishing: a new file past it would not be
/// indexed, and a re-offer takes none of it (README, *Re-offers*).
#[tokio::test(start_paused = true)]
async fn a_spent_soft_budget_stops_new_files_and_leaves_a_re_offer() {
    let mut bench = Bench::new();
    bench.identified(advert(3, 100, 2, 100)).await;
    bench.handle.announce(files(0..5)).await.unwrap();

    assert_eq!(bench.offer().await.0, files(0..2));
    assert_eq!(bench.offer().await.0, files(2..3));
    let finished = file(1).with_completeness(FileCompleteness::Incomplete);
    let mut set = files(0..5);
    set[1] = finished.clone();
    bench.handle.announce(set).await.unwrap();
    assert_eq!(bench.offer().await.0, [finished]);
    bench.nothing_more().await;
}

/// aMule skips the large file (`SharedFileList.cpp:732`); the rest of the
/// share still reaches a server that takes no large files.
#[tokio::test(start_paused = true)]
async fn a_large_file_is_left_out_of_an_offer_the_server_cannot_take() {
    let mut bench = Bench::with(SessionSinks {
        grants: ServerGrants::default(),
        ..test_sinks(SharedOwnIdentity::default())
    });
    bench.identified(Vec::new()).await;
    let large = OfferedFile::new(
        file(1).file_hash(),
        5 << 30,
        Ed2kText::from_utf8("large.iso"),
    );
    bench.handle.announce(vec![file(0), large]).await.unwrap();
    assert_eq!(bench.offer().await.0, [file(0)]);
}

/// The level follows the batches, so a long publish reads as what it is, and
/// a set a spent budget left part-told does not read as out.
#[tokio::test(start_paused = true)]
async fn the_level_says_how_much_of_the_set_was_told() {
    let (facts, diagnostics) = crate::server_list::test_facts(&[connected()]);
    let mut bench = Bench::with(SessionSinks {
        facts,
        ..test_sinks(SharedOwnIdentity::default())
    });
    let level = || {
        diagnostics
            .snapshot()
            .share_announcement
            .map(|told| told.shares)
    };
    bench.identified(advert(250, 1_000, 200, 100)).await;
    bench.handle.announce(files(0..300)).await.unwrap();
    assert_eq!(bench.offer().await.0.len(), 200);
    assert_eq!(bench.offer().await.0.len(), 50);
    bench.nothing_more().await;
    assert_eq!(
        level(),
        Some(SharesToServer::Announcing { told: 250, of: 300 })
    );
}

/// The policy switched on mid-way sends no more of the set.
#[tokio::test(start_paused = true)]
async fn halting_stops_the_queue() {
    let mut bench = Bench::new();
    bench.identified(Vec::new()).await;
    bench.handle.announce(files(0..300)).await.unwrap();
    assert_eq!(bench.offer().await.0.len(), 200);

    bench.handle.halt_offers().await;
    bench.nothing_more().await;
}

/// An ident that took its time still sets the first batch's size; the wait
/// only ends early.
#[tokio::test(start_paused = true)]
async fn the_first_batch_waits_for_the_ident() {
    let mut bench = Bench::new();
    let start = Instant::now();
    bench.handle.announce(files(0..300)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    bench.identified(advert(5_000, 7_500, 50, 500)).await;

    let (batch, sent) = bench.offer().await;
    assert_eq!(
        batch.len(),
        50,
        "not the 200 a batch_max of 50 would refuse"
    );
    assert_eq!(sent - start, Duration::from_secs(1));
}

/// Sends everything to the channel, the opening ask included.
struct WholeLink(mpsc::Sender<Ed2kCommand>, mpsc::Receiver<Ed2kEvent>);

impl ServerLink for WholeLink {
    async fn send(&self, command: Ed2kCommand) -> Result<(), ()> {
        self.0.send(command).await.map_err(|_| ())
    }
    async fn next_event(&mut self) -> Option<Ed2kEvent> {
        self.1.recv().await
    }
}

/// A login draws no ident on either server: the ask does, once per session,
/// and its list goes nowhere.
#[tokio::test(start_paused = true)]
async fn a_session_opens_by_asking_for_the_server_list_once() {
    let (events, evt_rx) = mpsc::channel(8);
    let (cmd_tx, mut sent) = mpsc::channel(8);
    let (facts, _diagnostics) = crate::server_list::test_facts(&[connected()]);
    let before = facts.listed().unwrap().len();
    let _handle = ServerSession::spawn(
        WholeLink(cmd_tx, evt_rx),
        client_id(),
        SessionSinks {
            facts: facts.clone(),
            ..test_sinks(SharedOwnIdentity::default())
        },
    );
    assert!(matches!(
        sent.recv().await,
        Some(Ed2kCommand::RequestServerList)
    ));
    let offered = Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 9), 4661);
    events
        .send(Ed2kEvent::ServerListReceived {
            servers: vec![offered],
            ipv6_servers: Vec::new(),
        })
        .await
        .unwrap();
    let quiet = tokio::time::timeout(Duration::from_secs(3600), sent.recv()).await;
    assert!(quiet.is_err(), "the ask goes once: {quiet:?}");
    assert_eq!(
        facts.listed().unwrap().len(),
        before,
        "the list is not folded"
    );
}
