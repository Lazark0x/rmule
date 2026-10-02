//! The `ed2k server search-wire` command: what a live server does
//! with searches sent together, how it reads a query's words, and how it
//! answers a Related-Files Search — reported as `key: value` lines that double
//! as the bench's evidence file, with every inbound TCP frame captured raw
//! beside them (the reply's more-results byte and row cap are read there).
//!
//! Every search goes out through the eD2k session, so its bytes are the ones
//! rmule sends (`docs/protocol/search-request.md`).

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use rmule_ed2k::{
    Ed2kCommand, Ed2kEvent, GlobSearchReq, GlobSearchRes, GlobSearchVariant, GlobServStatReq,
    SearchRequest,
};
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_primitives::{
    ClientIdentity, Ed2kText, KeywordQuery, RelatedFilesQuery, SearchQuery, SearchResult,
    ServerEndpoint, UserHash,
};
use tokio::time::Instant;

use crate::ed2k::probe::{await_login, spawn_hello_answering_listener};

mod more;
mod reconnect;
use crate::ed2k::server_udp::{
    SERVER_UDP_PLAIN_OFFSET, os_rand16, recv_datagram, resolve_server_ipv4,
};
use crate::operand::parse_user_hash;

/// The search-wire probe: bursts of back-to-back `OP_SEARCHREQUEST`s with
/// disjoint queries, tokenisation probes, Related-Files Searches, and a
/// `0x98` burst.
#[derive(Debug, Args)]
pub(crate) struct SearchWireArgs {
    /// Server endpoint as `host:port` (the eD2k TCP port).
    endpoint: String,
    /// Directory for `search-wire.txt` and the raw TCP capture.
    #[arg(long)]
    out: PathBuf,
    /// Burst sizes; burst `n` sends the first `n` burst words back to back.
    /// The flag with no sizes sends no burst.
    #[arg(long, value_delimiter = ',', num_args = 0.., default_values_t = [3_usize, 10, 30])]
    bursts: Vec<usize>,
    /// One word per burst query, each in exactly one shared name and no other
    /// query's word inside it.
    #[arg(long, value_delimiter = ',')]
    burst_words: Vec<String>,
    /// Spacings to try between four successive searches, milliseconds, widest
    /// first so a throttle met late does not taint the wider ones.
    #[arg(long, value_delimiter = ',', default_values_t = [3000_u64, 2000, 1500, 1000, 500, 250, 100, 0])]
    spacings_ms: Vec<u64>,
    /// Pause between probe searches, milliseconds, so one probe's answer is
    /// not read under another's throttle.
    #[arg(long, default_value_t = 3000)]
    probe_gap_ms: u64,
    /// A tokenisation probe: a query sent alone, the names it returns recorded.
    /// Repeatable.
    #[arg(long = "probe-query")]
    probe_queries: Vec<String>,
    /// A Related-Files Search for the file this word finds: the word is
    /// searched first and the first row's hash is asked about. Repeatable.
    #[arg(long = "related-via")]
    related_via: Vec<String>,
    /// How many `OP_GLOBSEARCHREQ` (`0x98`) to send back to back to the
    /// server's UDP port; 0 skips the burst.
    #[arg(long, default_value_t = 40)]
    udp_burst: usize,
    /// Log in without answering the High-ID port check, so the server can
    /// only assign a Low ID.
    #[arg(long)]
    low_id: bool,
    /// How long one answer is waited for, seconds (amule-kno waits 12).
    #[arg(long, default_value_t = 12)]
    answer_wait: u64,
    /// Login timeout, seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// Client nickname tag value.
    #[arg(long, default_value = "rmule-search-wire")]
    nickname: String,
    /// 16-byte user hash as upper-case hex (32 chars).
    #[arg(long, default_value = "57495245574952455749524557495245")]
    user_hash: String,
    /// Local TCP port advertised in the login packet.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// Walk `OP_QUERY_MORE_RESULT` on a search for this word:
    /// every page, one request past the last, and one after another search.
    #[arg(long)]
    more_query: Option<String>,
    /// Pages past the first the walk asks for — eMule's `MAX_MORE_SEARCH_REQ`.
    #[arg(long, default_value_t = 5)]
    more_asks: u8,
    /// Gaps to try between a search, a drop and re-login, and a second search,
    /// milliseconds, widest first; each takes three burst words. Empty skips
    /// the reconnect leg.
    #[arg(long, value_delimiter = ',')]
    reconnect_gaps_ms: Vec<u64>,
}

/// The report's lines, printed live and written to `search-wire.txt`.
struct Report {
    lines: Vec<String>,
}

impl Report {
    fn line(&mut self, line: String) {
        println!("{line}");
        self.lines.push(line);
    }
}

/// One answer as it arrived: its place among the answers, its delay after the
/// burst's first send, and its rows.
struct Answer {
    latency: Duration,
    rows: Vec<SearchResult>,
    /// The answer's more-results byte, as rmule reads it.
    more: bool,
}

/// What a batch of sends drew before the answers stopped coming.
struct Collected {
    answers: Vec<Answer>,
    skipped_rows: usize,
    messages: Vec<String>,
    disconnected: Option<String>,
    rejected: Vec<String>,
}

impl Collected {
    /// Nothing collected: the link was gone for `why`.
    fn closed(why: &str) -> Self {
        Self {
            answers: Vec::new(),
            skipped_rows: 0,
            messages: Vec::new(),
            disconnected: Some(why.to_owned()),
            rejected: Vec::new(),
        }
    }
}

/// The live login, re-made after the server closes it.
struct Session {
    endpoint: ServerEndpoint,
    identity: ClientIdentity,
    out: PathBuf,
    timeout: Duration,
    logins: usize,
    conn: Option<Connection>,
}

impl Session {
    /// The connection, logging in again when the last one was closed; `None`
    /// when the login fails.
    async fn conn(&mut self, report: &mut Report) -> Result<Option<&mut Connection>> {
        if self.conn.is_none() {
            self.logins += 1;
            let options = ConnectOptions {
                capture_dir: Some(self.out.join(format!("tcp-capture-{}", self.logins))),
                connect_timeout: self.timeout,
                login_timeout: self.timeout,
                ..ConnectOptions::default()
            };
            let mut conn = Connection::connect_with_options(
                self.endpoint.clone(),
                self.identity.clone(),
                options,
            )
            .await
            .context("connect to the server")?;
            match await_login(&mut conn, self.timeout).await {
                Some((client_id, tcp_flags)) => {
                    report.line(format!(
                        "login[{}]: accepted client_id={} high_id={} related_search_granted={}",
                        self.logins,
                        client_id.as_u32(),
                        client_id.is_high_id(),
                        tcp_flags.is_some_and(|flags| flags.supports_related_search())
                    ));
                    self.conn = Some(conn);
                }
                None => {
                    report.line(format!("login[{}]: refused", self.logins));
                    return Ok(None);
                }
            }
        }
        Ok(self.conn.as_mut())
    }

    /// Send `queries` spaced `gap` apart on a live login and take the answers;
    /// a closed link is dropped so the next call logs in again.
    async fn search(
        &mut self,
        report: &mut Report,
        queries: Vec<SearchQuery>,
        gap: Duration,
        answer_wait: Duration,
    ) -> Result<Collected> {
        let Some(conn) = self.conn(report).await? else {
            return Ok(Collected::closed("login refused"));
        };
        let collected = send_and_collect(conn, queries, gap, answer_wait).await;
        if collected.disconnected.is_some() {
            self.conn = None;
            // Let the server forget the dropped session before the next login.
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        Ok(collected)
    }
}

pub(crate) async fn search_wire(args: SearchWireArgs) -> Result<()> {
    let endpoint = ServerEndpoint::parse_host_port(&args.endpoint)
        .with_context(|| format!("parse endpoint {}", args.endpoint))?;
    if let Some(&largest) = args.bursts.iter().max()
        && largest > args.burst_words.len()
    {
        bail!(
            "a burst of {largest} needs {largest} burst words, got {}",
            args.burst_words.len()
        );
    }
    std::fs::create_dir_all(&args.out).with_context(|| format!("create {}", args.out.display()))?;
    let mut report = Report { lines: Vec::new() };
    report.line(format!("endpoint: {}", args.endpoint));
    report.line(format!(
        "requester: {}",
        if args.low_id { "low-id" } else { "high-id" }
    ));

    let identity = ClientIdentity::new(
        UserHash::from_bytes(parse_user_hash(&args.user_hash)?),
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        60,
    );
    let listener = if args.low_id {
        None
    } else {
        Some(spawn_hello_answering_listener(identity.clone(), &endpoint).await?)
    };
    let mut session = Session {
        endpoint,
        identity,
        out: args.out.clone(),
        timeout: Duration::from_secs(args.timeout),
        logins: 0,
        conn: None,
    };
    let answer_wait = Duration::from_secs(args.answer_wait);
    let probe_gap = Duration::from_millis(args.probe_gap_ms);

    for probe in &args.probe_queries {
        let collected = session
            .search(
                &mut report,
                vec![keyword(probe)?.into()],
                Duration::ZERO,
                answer_wait,
            )
            .await?;
        report_single(&mut report, &format!("probe[{probe}]"), &collected);
        tokio::time::sleep(probe_gap).await;
    }

    for word in &args.related_via {
        let found = session
            .search(
                &mut report,
                vec![keyword(word)?.into()],
                Duration::ZERO,
                answer_wait,
            )
            .await?;
        tokio::time::sleep(probe_gap).await;
        let Some(row) = found.answers.first().and_then(|answer| answer.rows.first()) else {
            report.line(format!(
                "related[{word}]: the word found no file to ask about"
            ));
            continue;
        };
        let hash = row.file_hash();
        report.line(format!(
            "related[{word}]: file={} hash={} reported_sources={:?}",
            row.primary_name().to_display_string(),
            hash.to_hex_upper(),
            row.reported_availability()
        ));
        let query = RelatedFilesQuery::new(hash, row.primary_name().clone());
        let collected = session
            .search(&mut report, vec![query.into()], Duration::ZERO, answer_wait)
            .await?;
        report_single(&mut report, &format!("related[{word}]"), &collected);
        tokio::time::sleep(probe_gap).await;
    }

    // The walk and the reconnect leg go before the spacing sweep and the
    // bursts: a server that floods out a client may keep ignoring its address.
    if let Some(word) = &args.more_query {
        more::walk(&mut session, &mut report, word, args.more_asks, answer_wait).await?;
        tokio::time::sleep(probe_gap).await;
    }

    if !args.reconnect_gaps_ms.is_empty() {
        let gaps: Vec<Duration> = args
            .reconnect_gaps_ms
            .iter()
            .map(|&ms| Duration::from_millis(ms))
            .collect();
        if args.burst_words.len() < 3 * gaps.len() {
            bail!(
                "{} reconnect gaps need {} burst words, got {}",
                gaps.len(),
                3 * gaps.len(),
                args.burst_words.len()
            );
        }
        reconnect::walk(
            &mut session,
            &mut report,
            &gaps,
            &args.burst_words,
            answer_wait,
        )
        .await?;
        tokio::time::sleep(probe_gap).await;
    }

    // The same four queries at each spacing: where the answers stop coming
    // back empty is the spacing the server keeps.
    for &spacing in &args.spacings_ms {
        let words: Vec<String> = args.burst_words.iter().take(4).cloned().collect();
        let queries: Vec<SearchQuery> = words
            .iter()
            .map(|word| keyword(word).map(SearchQuery::from))
            .collect::<Result<_>>()?;
        let collected = session
            .search(
                &mut report,
                queries,
                Duration::from_millis(spacing),
                answer_wait,
            )
            .await?;
        report_burst(
            &mut report,
            &format!("spacing[{spacing}ms]"),
            &words,
            &collected,
        );
        tokio::time::sleep(probe_gap).await;
    }

    // Bursts last: a server that floods out a client may keep ignoring it.
    for &size in &args.bursts {
        let words = &args.burst_words[..size];
        let queries: Vec<SearchQuery> = words
            .iter()
            .map(|word| keyword(word).map(SearchQuery::from))
            .collect::<Result<_>>()?;
        let collected = session
            .search(&mut report, queries, Duration::ZERO, answer_wait)
            .await?;
        report_burst(&mut report, &format!("burst[{size}]"), words, &collected);
        tokio::time::sleep(probe_gap).await;
    }

    if let Some(task) = listener {
        task.abort();
    }
    if let Some(conn) = session.conn.take() {
        let _ = conn.shutdown().await;
    }

    if args.udp_burst > 0 {
        udp_burst(&args, &mut report).await?;
    }
    write_report(&args, &report)
}

fn keyword(phrase: &str) -> Result<KeywordQuery> {
    KeywordQuery::new(Ed2kText::from_utf8(phrase)).with_context(|| format!("query {phrase:?}"))
}

/// Send the queries `gap` apart (all at once for a zero gap), then take
/// answers until as many have come as were sent, the link closes, or one
/// answer wait passes with nothing new. Latency counts from the first send.
async fn send_and_collect(
    conn: &mut Connection,
    queries: Vec<SearchQuery>,
    gap: Duration,
    answer_wait: Duration,
) -> Collected {
    let expected = queries.len();
    let start = Instant::now();
    let mut collected = Collected::closed("");
    collected.disconnected = None;
    for (index, query) in queries.into_iter().enumerate() {
        if index > 0 && !gap.is_zero() {
            // Answers that land while waiting are taken as they come.
            let until = Instant::now() + gap;
            while let Ok(event) = tokio::time::timeout_at(until, conn.next_event()).await {
                if !take(&mut collected, event, start) {
                    return collected;
                }
            }
        }
        if conn.send(Ed2kCommand::Search { query }).await.is_err() {
            collected.disconnected = Some("link closed before the send".to_owned());
            return collected;
        }
    }
    while collected.answers.len() + collected.rejected.len() < expected {
        match tokio::time::timeout(answer_wait, conn.next_event()).await {
            Ok(event) => {
                if !take(&mut collected, event, start) {
                    break;
                }
            }
            Err(_waited_out) => break,
        }
    }
    collected
}

/// Fold one event in; `false` once the link is gone.
fn take(collected: &mut Collected, event: Option<Ed2kEvent>, start: Instant) -> bool {
    match event {
        Some(Ed2kEvent::SearchResultsFound {
            results,
            skipped,
            more_available,
        }) => {
            collected.skipped_rows += skipped.len();
            collected.answers.push(Answer {
                latency: start.elapsed(),
                rows: results,
                more: more_available,
            });
        }
        Some(Ed2kEvent::SearchResultSkipped { .. }) => collected.skipped_rows += 1,
        Some(Ed2kEvent::ServerMessageReceived { text }) => {
            collected.messages.push(text.to_display_string());
        }
        Some(Ed2kEvent::CommandRejected { command, reason }) => {
            collected.rejected.push(format!("{command:?}: {reason:?}"));
        }
        Some(Ed2kEvent::Disconnected { reason }) => {
            collected.disconnected = Some(format!("{reason:?}"));
            return false;
        }
        None => {
            collected.disconnected = Some("link closed".to_owned());
            return false;
        }
        Some(_) => {}
    }
    true
}

/// Which of `words` every row of `rows` carries, lower-cased, in one of its
/// names — `None` when no word, or more than one, fits them all.
fn answered_word(rows: &[SearchResult], words: &[String]) -> Option<usize> {
    let fits = |word: &String| {
        let word = word.to_lowercase();
        rows.iter().all(|row| {
            row.names()
                .iter()
                .any(|name| name.to_display_string().to_lowercase().contains(&word))
        })
    };
    let mut fitting = words.iter().enumerate().filter(|(_, word)| fits(word));
    match (fitting.next(), fitting.next()) {
        (Some((index, _)), None) if !rows.is_empty() => Some(index),
        _ => None,
    }
}

fn report_burst(report: &mut Report, label: &str, words: &[String], collected: &Collected) {
    for (place, answer) in collected.answers.iter().enumerate() {
        let answered = answered_word(&answer.rows, words);
        report.line(format!(
            "{label} answer[{place}]: rows={} latency_ms={} answers_query={} in_place={}",
            answer.rows.len(),
            answer.latency.as_millis(),
            answered.map_or_else(|| "unknown".to_owned(), |index| index.to_string()),
            answered == Some(place),
        ));
    }
    report_tail(report, label, words.len(), collected);
}

fn report_single(report: &mut Report, label: &str, collected: &Collected) {
    for answer in &collected.answers {
        let names: Vec<String> = answer
            .rows
            .iter()
            .map(|row| row.primary_name().to_display_string())
            .collect();
        report.line(format!(
            "{label}: rows={} latency_ms={} names={names:?}",
            answer.rows.len(),
            answer.latency.as_millis(),
        ));
    }
    report_tail(report, label, 1, collected);
}

fn report_tail(report: &mut Report, label: &str, sent: usize, collected: &Collected) {
    report.line(format!(
        "{label}: sent={sent} answers={} skipped_rows={} rejected={:?} disconnected={}",
        collected.answers.len(),
        collected.skipped_rows,
        collected.rejected,
        collected.disconnected.as_deref().unwrap_or("no"),
    ));
    for message in &collected.messages {
        report.line(format!("{label}: server_message={message:?}"));
    }
}

/// `args.udp_burst` `0x98`s back to back, each a different word; the `0x99`s
/// that come back; then a status ping, which a server that banned us leaves
/// unanswered.
async fn udp_burst(args: &SearchWireArgs, report: &mut Report) -> Result<()> {
    let ip: Ipv4Addr = resolve_server_ipv4(&args.endpoint).await?;
    let endpoint = ServerEndpoint::parse_host_port(&args.endpoint)?;
    let port = endpoint
        .port()
        .checked_add(SERVER_UDP_PLAIN_OFFSET)
        .context("server UDP port (TCP+4) overflows")?;
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("bind the UDP burst socket")?;
    let start = Instant::now();
    for index in 0..args.udp_burst {
        let word = args
            .burst_words
            .get(index)
            .cloned()
            .unwrap_or_else(|| format!("udpburst{index:02}"));
        let request = GlobSearchReq::new(SearchRequest::from_query(keyword(&word)?));
        socket
            .send_to(
                &request
                    .encode_packet(GlobSearchVariant::Baseline)
                    .encode_udp(),
                (ip, port),
            )
            .await
            .context("send 0x98")?;
    }
    let sent_in = start.elapsed();
    let mut answers = 0;
    let mut rows = 0;
    while let Some(reply) = recv_datagram(&socket, Duration::from_secs(args.answer_wait)).await? {
        answers += 1;
        if let Ok(answer) = GlobSearchRes::decode_udp(&reply) {
            rows += answer.results().len();
        }
    }
    report.line(format!(
        "udp_burst: sent={} in_ms={} answers={answers} rows={rows}",
        args.udp_burst,
        sent_in.as_millis()
    ));
    let status = GlobServStatReq::mint(os_rand16());
    socket
        .send_to(&status.encode_packet().encode_udp(), (ip, port))
        .await
        .context("send 0x96")?;
    let answered = recv_datagram(&socket, Duration::from_secs(args.answer_wait))
        .await?
        .is_some();
    report.line(format!(
        "udp_burst: status_ping_after={}",
        if answered { "answered" } else { "silent" }
    ));
    Ok(())
}

fn write_report(args: &SearchWireArgs, report: &Report) -> Result<()> {
    let path = args.out.join("search-wire.txt");
    let mut body = report.lines.join("\n");
    body.push('\n');
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use rmule_primitives::{Ed2kText, FileHash, SearchResult};

    use super::answered_word;

    fn row(name: &str) -> SearchResult {
        SearchResult::new(
            FileHash::from_bytes([1; 16]),
            1,
            vec![Ed2kText::from_utf8(name)],
            Vec::new(),
        )
        .expect("a row")
    }

    #[test]
    fn an_answer_is_placed_by_the_one_query_word_all_its_rows_carry() {
        let words = ["kw01x".to_owned(), "kw02x".to_owned()];
        assert_eq!(answered_word(&[row("wire-KW02X.bin")], &words), Some(1));
        assert_eq!(
            answered_word(&[row("wire-kw01x.bin"), row("wire-kw02x.bin")], &words),
            None
        );
        assert_eq!(
            answered_word(&[], &words),
            None,
            "an empty answer names no query"
        );
    }
}
