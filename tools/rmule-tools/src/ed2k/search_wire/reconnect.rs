//! The reconnect leg: whether a server's one-second search rule counts per
//! link or per address. One search goes out on a live login, the probe closes
//! the link, logs in again at once, and sends a second search a set gap after
//! the first; a third search on the new link, well past the rule, shows whether
//! the address is still heard. Gaps run widest first, so a silence one gap
//! provokes does not taint a wider one.

use std::time::Duration;

use anyhow::Result;
use rmule_primitives::SearchQuery;
use tokio::time::Instant;

use super::{Report, Session, keyword, report_single, send_and_collect};

/// Between the second search and the one that reads whether the address is
/// still heard: three times past the one-second rule.
const SETTLE: Duration = Duration::from_secs(3);

/// Run the leg for each gap in `gaps`, taking the search words in threes from
/// `words`.
pub(super) async fn walk(
    session: &mut Session,
    report: &mut Report,
    gaps: &[Duration],
    words: &[String],
    answer_wait: Duration,
) -> Result<()> {
    for (gap, words) in gaps.iter().zip(words.chunks_exact(3)) {
        let label = format!("reconnect[{}ms]", gap.as_millis());
        let query = |word: &String| -> Result<Vec<SearchQuery>> { Ok(vec![keyword(word)?.into()]) };

        let Some(conn) = session.conn(report).await? else {
            report.line(format!("{label}: login refused"));
            continue;
        };
        let first_sent = Instant::now();
        let first = send_and_collect(conn, query(&words[0])?, Duration::ZERO, answer_wait).await;
        report_single(report, &format!("{label} first[{}]", words[0]), &first);

        // Drop the link from our side and log in again at once.
        if let Some(conn) = session.conn.take() {
            let _ = conn.shutdown().await;
        }
        let dropped = Instant::now();
        let Some(_) = session.conn(report).await? else {
            report.line(format!("{label}: login refused after the drop"));
            continue;
        };
        report.line(format!(
            "{label}: relogin_ms={}",
            dropped.elapsed().as_millis()
        ));
        tokio::time::sleep_until(first_sent + *gap).await;
        let second_sent = Instant::now();
        let Some(conn) = session.conn.as_mut() else {
            continue;
        };
        let second = send_and_collect(conn, query(&words[1])?, Duration::ZERO, answer_wait).await;
        report.line(format!(
            "{label}: second_sent_after_first_ms={}",
            second_sent.duration_since(first_sent).as_millis()
        ));
        report_single(report, &format!("{label} second[{}]", words[1]), &second);
        if second.disconnected.is_some() {
            session.conn = None;
        }

        tokio::time::sleep(SETTLE).await;
        let after = session
            .search(report, query(&words[2])?, Duration::ZERO, answer_wait)
            .await?;
        report_single(report, &format!("{label} after[{}]", words[2]), &after);
        tokio::time::sleep(SETTLE).await;
    }
    Ok(())
}
