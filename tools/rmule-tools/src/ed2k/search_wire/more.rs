//! The more-results walk: a search whose answer should need more
//! than one page, then `OP_QUERY_MORE_RESULT` for each further page, one more
//! past the last, and one after another search has gone out — each request a
//! second apart (Lugdunum's spacing, `docs/protocol/search-request.md` ruling
//! 4). The report says, per answer, its row count, its more-results byte, and
//! whether its rows carry the walked word; the server tap holds the frames.

use std::time::Duration;

use anyhow::Result;
use rmule_ed2k::Ed2kCommand;
use tokio::time::Instant;

use super::{Collected, Report, Session, keyword, take};

/// Between two requests on the link: past Lugdunum's one-second floor.
const SPACING: Duration = Duration::from_millis(1100);

/// A word no walked row carries: the other search of the lapse probe.
const OTHER_WORD: &str = "kw01x";

pub(super) async fn walk(
    session: &mut Session,
    report: &mut Report,
    word: &str,
    asks: u8,
    answer_wait: Duration,
) -> Result<()> {
    let search = || -> Result<Ed2kCommand> {
        Ok(Ed2kCommand::Search {
            query: keyword(word)?.into(),
        })
    };
    // Every page, then one request past the last.
    let mut more = ask(session, report, word, "page[0]", search()?, answer_wait).await?;
    let mut page = 0;
    while more && page < asks {
        page += 1;
        more = ask(
            session,
            report,
            word,
            &format!("page[{page}]"),
            Ed2kCommand::QueryMoreResults,
            answer_wait,
        )
        .await?;
    }
    ask(
        session,
        report,
        word,
        "past-last",
        Ed2kCommand::QueryMoreResults,
        answer_wait,
    )
    .await?;
    // A page on offer, another search, then a request for more: whose rows?
    ask(session, report, word, "lapse-first", search()?, answer_wait).await?;
    ask(
        session,
        report,
        word,
        "lapse-other",
        Ed2kCommand::Search {
            query: keyword(OTHER_WORD)?.into(),
        },
        answer_wait,
    )
    .await?;
    ask(
        session,
        report,
        word,
        "lapse-more",
        Ed2kCommand::QueryMoreResults,
        answer_wait,
    )
    .await?;
    Ok(())
}

/// Send one request a spacing after the last and take its answer; whether
/// the answer said more.
async fn ask(
    session: &mut Session,
    report: &mut Report,
    word: &str,
    label: &str,
    command: Ed2kCommand,
    answer_wait: Duration,
) -> Result<bool> {
    tokio::time::sleep(SPACING).await;
    let label = format!("more[{word}] {label}");
    let Some(conn) = session.conn(report).await? else {
        report.line(format!("{label}: login refused"));
        return Ok(false);
    };
    let start = Instant::now();
    let mut collected = Collected::closed("");
    collected.disconnected = None;
    if conn.send(command).await.is_err() {
        report.line(format!("{label}: link closed before the send"));
        session.conn = None;
        return Ok(false);
    }
    while collected.answers.is_empty() && collected.rejected.is_empty() {
        match tokio::time::timeout(answer_wait, conn.next_event()).await {
            Ok(event) => {
                if !take(&mut collected, event, start) {
                    break;
                }
            }
            Err(_waited_out) => break,
        }
    }
    let more = collected.answers.first().is_some_and(|answer| answer.more);
    match collected.answers.first() {
        Some(answer) => {
            let lowered = word.to_lowercase();
            let carrying = answer
                .rows
                .iter()
                .filter(|row| {
                    row.names()
                        .iter()
                        .any(|name| name.to_display_string().to_lowercase().contains(&lowered))
                })
                .count();
            report.line(format!(
                "{label}: rows={} more={} rows_with_word={carrying} latency_ms={}",
                answer.rows.len(),
                u8::from(answer.more),
                answer.latency.as_millis(),
            ));
        }
        None => report.line(format!(
            "{label}: no answer within {} s rejected={:?} disconnected={}",
            answer_wait.as_secs(),
            collected.rejected,
            collected.disconnected.as_deref().unwrap_or("no"),
        )),
    }
    if collected.disconnected.is_some() {
        session.conn = None;
    }
    Ok(more)
}
