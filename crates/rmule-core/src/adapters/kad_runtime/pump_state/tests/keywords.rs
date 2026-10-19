//! The ADR-0062 keyword requester through the Kad Pump State: one walk per
//! lead keyword, every search on it subscribed with its own query and told
//! what the walk finds and how it ends. The effects are carried onto each
//! search's own leg here, as the driver carries them, and read off the leg.

use rmule_ed2k::SearchResultSkipReason;
use rmule_kad::{KadCommand, KadKeywordResult, KadNodeDiagnostic, KadSearchEnd};
use rmule_primitives::{Ed2kText, KeywordQuery};

use super::*;
use crate::adapters::kad_runtime::KadPumpCommand;
use crate::search::{KadKeywordLeg, KadLegNews, kad_keyword_leg};
use crate::service::{LegNotSent, SearchLegState};

fn query(phrase: &str) -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8(phrase)).expect("valid phrase")
}

/// The walk target of `word`, as the node is asked for it.
fn keyword(word: &str) -> KadId {
    rmule_kad::KadKeywordSearchRequest::new(word)
        .target()
        .expect("a walkable word")
}

fn walk(word: &str) -> KadPumpEffect {
    KadPumpEffect::Node(NodeCommand::Ask(KadCommand::SearchKeywords {
        request: rmule_kad::KadKeywordSearchRequest::new(word),
    }))
}

/// Carry every search effect onto its sink, as the driver does.
fn carry(effects: &[KadPumpEffect]) {
    for effect in effects {
        if let KadPumpEffect::Search { sink, news } = effect {
            match news {
                SearchNews::Rows(rows) => {
                    sink.offer(rows.clone());
                }
                SearchNews::Fact(fact) => sink.tell(*fact),
            }
        }
    }
}

/// The core's ask to search `query` for the search behind `sink`.
fn searching(query: KeywordQuery, sink: crate::KadKeywordSink) -> KadPumpInput {
    KadPumpInput::Command(
        Box::new(KadPumpCommand::SearchKeyword {
            query,
            results: sink,
        }),
        behind_nat(),
    )
}

/// Start a search on `phrase` and carry out what the brain decides, the
/// node taking every command: the effects, and the search's leg.
fn search(state: &mut KadPumpState, phrase: &str) -> (Vec<KadPumpEffect>, KadKeywordLeg) {
    let (sink, leg) = kad_keyword_leg();
    let effects = step(state, searching(query(phrase), sink), Instant::now());
    carry(&effects);
    (effects, leg)
}

fn row(byte: u8, name: &str) -> KadKeywordResult {
    KadKeywordResult {
        file_id: KadId::from_bytes([byte; KadId::BYTE_LEN]),
        filename: Some(name.to_owned()),
        size: Some(1_024),
        file_type: None,
        complete_sources: None,
        publish_info: None,
        aich_roots: Vec::new(),
    }
}

/// The node's event on the walk toward `word`, carried onto the legs.
fn hear(state: &mut KadPumpState, event: KadEvent) {
    carry(&step(state, KadPumpInput::Event(event), Instant::now()));
}

fn found(word: &str, results: Vec<KadKeywordResult>) -> KadEvent {
    KadEvent::KeywordsFound {
        keyword: keyword(word),
        results,
    }
}

fn complete(word: &str, ended_by: KadSearchEnd) -> KadEvent {
    KadEvent::KeywordSearchComplete {
        keyword: keyword(word),
        result_rows: 0,
        ended_by,
    }
}

/// The next news on `leg`; a leg that hears nothing fails the test rather
/// than hang it.
async fn next(leg: &mut KadKeywordLeg) -> KadLegNews {
    tokio::time::timeout(Duration::from_secs(5), leg.next())
        .await
        .expect("the leg hears news")
}

/// The next news on `leg`, which must be rows: their names.
async fn names(leg: &mut KadKeywordLeg) -> Vec<String> {
    match next(leg).await {
        KadLegNews::Rows(rows) => rows
            .iter()
            .map(|row| row.primary_name().to_display_string())
            .collect(),
        other => panic!("rows expected, got {other:?}"),
    }
}

/// The next news on `leg`, which must be its end: where it stands.
async fn ended(leg: &mut KadKeywordLeg) -> SearchLegState {
    match next(leg).await {
        KadLegNews::Ended(state) => state,
        other => panic!("the end expected, got {other:?}"),
    }
}

/// Every search on a lead keyword rides the one walk, each hearing only the
/// rows its own query proves — the operator's size bound included — and the
/// walk's end settles every one of them.
#[tokio::test]
async fn searches_on_one_lead_keyword_share_one_walk_each_screened_by_its_own_query() {
    let mut state = started(None, behind_nat(), Instant::now());
    let (first, mut iso) = search(&mut state, "ubuntu iso");
    let (second, mut deb) = search(&mut state, "ubuntu deb");
    assert_eq!(first, [walk("ubuntu")]);
    assert_eq!(second, [], "the walk is running: no second walk");

    hear(
        &mut state,
        found(
            "ubuntu",
            vec![row(1, "ubuntu server.iso"), row(2, "ubuntu desktop.deb")],
        ),
    );
    assert_eq!(names(&mut iso).await, ["ubuntu server.iso"]);
    assert_eq!(names(&mut deb).await, ["ubuntu desktop.deb"]);

    // A row neither proves reaches neither.
    hear(
        &mut state,
        found("ubuntu", vec![row(3, "ubuntu notes.txt")]),
    );
    assert!(iso.try_rows().is_none());
    assert!(deb.try_rows().is_none());

    hear(&mut state, complete("ubuntu", KadSearchEnd::WindowElapsed));
    assert_eq!(ended(&mut iso).await, SearchLegState::Settled);
    assert_eq!(ended(&mut deb).await, SearchLegState::Settled);
}

/// A search joining a running walk is replayed what the walk found so far —
/// the rows its own query proves, and why every row the walk could not keep
/// was dropped — then hears the rest.
#[tokio::test]
async fn a_search_joining_a_running_walk_is_replayed_its_rows_and_its_drops() {
    let mut state = started(None, behind_nat(), Instant::now());
    let (_, _first) = search(&mut state, "ubuntu");
    hear(
        &mut state,
        found(
            "ubuntu",
            vec![
                row(1, "ubuntu desktop.deb"),
                row(2, "ubuntu server.iso"),
                KadKeywordResult {
                    size: None,
                    ..row(3, "ubuntu sizeless.deb")
                },
            ],
        ),
    );

    let (effects, mut joiner) = search(&mut state, "ubuntu deb");
    assert!(
        !effects.contains(&walk("ubuntu")),
        "no second walk for a joiner"
    );
    assert!(matches!(
        next(&mut joiner).await,
        KadLegNews::RowSkipped(SearchResultSkipReason::MissingFileSize)
    ));
    assert_eq!(names(&mut joiner).await, ["ubuntu desktop.deb"]);

    hear(
        &mut state,
        found("ubuntu", vec![row(4, "Ubuntu Desktop 24.deb")]),
    );
    assert_eq!(names(&mut joiner).await, ["Ubuntu Desktop 24.deb"]);
}

/// A walk that asked nobody, or that another walk's target held, ends every
/// search riding it as not sent, and says why; a walk that put off the
/// keyword's publish round tells its searches first.
#[tokio::test]
async fn a_walk_that_asked_nobody_says_why_and_a_deferred_publish_round_is_told() {
    let mut state = started(None, behind_nat(), Instant::now());
    let (_, mut held) = search(&mut state, "ubuntu");
    let (_, mut lonely) = search(&mut state, "debian");

    hear(
        &mut state,
        KadEvent::Diagnostic(KadNodeDiagnostic::KeywordPublishPreempted {
            keyword: keyword("ubuntu"),
        }),
    );
    hear(&mut state, complete("ubuntu", KadSearchEnd::TargetHeld));
    hear(
        &mut state,
        complete("debian", KadSearchEnd::NoSearchableContacts),
    );
    assert!(matches!(next(&mut held).await, KadLegNews::PublishDeferred));
    assert_eq!(
        ended(&mut held).await,
        SearchLegState::NotSent(LegNotSent::KadKeywordHeld)
    );
    assert_eq!(
        ended(&mut lonely).await,
        SearchLegState::NotSent(LegNotSent::NoKadContact)
    );
}

/// Kad stopping never reads as a walk done: a walk the node never took —
/// its driver gone, or the walk still waiting for room when the pump stops —
/// ends its searches as not sent, and a walk Kad stopped under ends them as
/// stopped, the rows they heard standing.
#[tokio::test]
async fn a_walk_kad_never_took_or_stopped_under_says_so() {
    let now = Instant::now();
    let mut state = started(None, behind_nat(), now);
    let (_, mut cut) = search(&mut state, "ubuntu");
    hear(&mut state, found("ubuntu", vec![row(1, "ubuntu.iso")]));

    let (gone_sink, mut gone) = kad_keyword_leg();
    let asked = state.handle(searching(query("debian"), gone_sink), now);
    let [KadPumpEffect::Node(walk)] = asked.as_slice() else {
        panic!("one walk asked for: {asked:?}");
    };
    carry(&state.handle(
        KadPumpInput::Delivered(walk.clone(), Delivery::NodeGone),
        now,
    ));
    assert_eq!(
        ended(&mut gone).await,
        SearchLegState::NotSent(LegNotSent::KadStopped)
    );

    let (waiting_sink, mut waiting) = kad_keyword_leg();
    let mut fresh = started(None, behind_nat(), now);
    let asked = fresh.handle(searching(query("arch"), waiting_sink), now);
    let [KadPumpEffect::Node(walk)] = asked.as_slice() else {
        panic!("one walk asked for: {asked:?}");
    };
    fresh.handle(
        KadPumpInput::Delivered(walk.clone(), Delivery::InboxFull),
        now,
    );
    carry(&fresh.handle(KadPumpInput::Stop, now));
    assert_eq!(
        ended(&mut waiting).await,
        SearchLegState::NotSent(LegNotSent::KadStopped)
    );

    carry(&state.handle(KadPumpInput::Stop, now));
    assert_eq!(names(&mut cut).await, ["ubuntu.iso"]);
    assert_eq!(ended(&mut cut).await, SearchLegState::WalkStopped);
}

/// A query with no word a walk can target ends its leg at once, and the node
/// is asked for nothing.
#[tokio::test]
async fn an_unsearchable_query_ends_its_leg_at_once_and_asks_the_node_nothing() {
    let mut state = started(None, behind_nat(), Instant::now());
    let (effects, mut leg) = search(&mut state, "a");
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, KadPumpEffect::Node(_))),
        "{effects:?}"
    );
    drop(effects);
    assert_eq!(
        ended(&mut leg).await,
        SearchLegState::NotSent(LegNotSent::NoKadKeyword)
    );
}
