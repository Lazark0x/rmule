//! What a server grants and what it was told (ADR-0080, ADR-0099): the
//! selected server's detail words under the Networks tab's server table, and
//! the Networks log's line when the connected server's shares are news.

use std::time::Duration;

use rmule_core::diagnostics::{ServerDiagnostics, SharesToServer};
use rmule_core::{DeadSince, ServerHealth, ServerPolicy};
use rmule_primitives::{
    ServerEndpoint, ServerTcpFlag, ServerTcpFlags, ServerUdpFlag, ServerUdpFlags,
};

use super::super::Sentence;
use super::server_label;

/// A named `SRV_TCPFLG_*` grant as the operator reads it.
fn tcp_grant_word(flag: ServerTcpFlag) -> &'static str {
    match flag {
        ServerTcpFlag::Compression => "compression",
        ServerTcpFlag::NewTags => "new tags",
        ServerTcpFlag::Unicode => "unicode",
        ServerTcpFlag::RelatedSearch => "related search",
        ServerTcpFlag::TypeTagInteger => "integer type tags",
        ServerTcpFlag::LargeFiles => "large files",
        ServerTcpFlag::TcpObfuscation => "obfuscation",
        ServerTcpFlag::Ipv6 => "IPv6",
    }
}

/// A named `SRV_UDPFLG_*` flag as the operator reads it.
fn udp_flag_word(flag: ServerUdpFlag) -> &'static str {
    match flag {
        ServerUdpFlag::ExtGetSources => "get sources",
        ServerUdpFlag::ExtGetFiles => "get files",
        ServerUdpFlag::NewTags => "new tags",
        ServerUdpFlag::Unicode => "unicode",
        ServerUdpFlag::ExtGetSources2 => "get sources 2",
        ServerUdpFlag::LargeFiles => "large files",
        ServerUdpFlag::UdpObfuscation => "UDP obfuscation",
        ServerUdpFlag::TcpObfuscation => "TCP obfuscation",
        ServerUdpFlag::Ipv6 => "IPv6",
    }
}

/// The TCP grants word in words.
fn tcp_grant_words(flags: ServerTcpFlags) -> String {
    flag_words(flags.named().map(tcp_grant_word), flags.unnamed_bits())
}

/// The UDP flags word in words.
fn udp_flag_words(flags: ServerUdpFlags) -> String {
    flag_words(flags.named().map(udp_flag_word), flags.unnamed_bits())
}

/// A flags word in words, bit order: the named flags, then the `rest` by
/// position (bit 0 is `0x1`) — rmule names every bit aMule 2.3.3 and eMule
/// define, so the rest are a server's private bits — and nothing at all said
/// as such.
fn flag_words<'a>(named: impl Iterator<Item = &'a str>, rest: u32) -> String {
    let mut words: Vec<String> = named.map(str::to_string).collect();
    let positions: Vec<String> = (0..u32::BITS)
        .filter(|at| rest & (1 << at) != 0)
        .map(|at| at.to_string())
        .collect();
    if let Some((last, before)) = positions.split_last() {
        let lead = if words.is_empty() { "" } else { "and " };
        let named = if before.is_empty() {
            format!("bit {last}")
        } else {
            format!("bits {} and {last}", before.join(", "))
        };
        words.push(format!("{lead}{named}, which no client names"));
    }
    if words.is_empty() {
        "nothing".to_string()
    } else {
        words.join(", ")
    }
}

/// The selected server's collapsed detail line: what it granted at its last
/// login and what its last status answer named, each with how long ago —
/// `age` words a duration the way the table's Age column does.
#[must_use]
pub fn grants_line(row: &ServerDiagnostics, age: impl Fn(Duration) -> String) -> String {
    format!(
        "{} · {}",
        grants_sentence(row, &age),
        udp_sentence(row, &age)
    )
}

/// What the server granted at its last login, with how long ago.
fn grants_sentence(row: &ServerDiagnostics, age: &impl Fn(Duration) -> String) -> String {
    match (row.server.grants, row.grants_age) {
        (Some(report), Some(ago)) => format!(
            "Grants at login ({} ago): {}",
            age(ago),
            tcp_grant_words(report.tcp_flags)
        ),
        _ => "Grants: never logged in, so it has not said what it grants".to_string(),
    }
}

/// What the server's last status answer named, with how long ago.
fn udp_sentence(row: &ServerDiagnostics, age: &impl Fn(Duration) -> String) -> String {
    match (
        row.server.figures.as_ref().map(|figures| figures.udp_flags),
        row.age,
    ) {
        (Some(Some(flags)), Some(ago)) => {
            format!("UDP ({} ago): {}", age(ago), udp_flag_words(flags))
        }
        (Some(None), _) => "UDP: its status answers named no flags".to_string(),
        _ => "UDP: no status answer yet".to_string(),
    }
}

/// What the detail pane needs beyond the row: the level's word on the
/// connected session and the policy the operator set.
#[derive(Clone, Copy, Debug)]
pub struct DetailContext {
    /// The selected row is the connected server.
    pub connected: bool,
    /// What the connected session was told of the shares, when the row is
    /// the server it was told to.
    pub told: Option<SharesToServer>,
    /// The **Server Policy** in force: the dead limit and the
    /// **Announce Policy**.
    pub policy: ServerPolicy,
}

/// The selected server's detail pane (ADR-0080, "The detail pane"): its
/// grants, its UDP flags, its health and its shares, one sentence each, in
/// that order.
#[must_use]
pub fn detail_pane(
    row: &ServerDiagnostics,
    context: DetailContext,
    age: impl Fn(Duration) -> String,
) -> [String; 4] {
    [
        grants_sentence(row, &age),
        udp_sentence(row, &age),
        health_sentence(row, context.policy.dead_after, &age),
        shares_sentence(row, context),
    ]
}

/// `n try` or `n tries`.
fn tries(count: u32) -> String {
    if count == 1 {
        "1 try".to_string()
    } else {
        format!("{count} tries")
    }
}

/// The server's **Server Health** (ADR-0052) in words, and for a row listed
/// by name what that name resolved to. A dead one is dated by the moment it
/// died (ADR-0052, "Dead since when").
fn health_sentence(
    row: &ServerDiagnostics,
    limit: u32,
    age: &impl Fn(Duration) -> String,
) -> String {
    let health = health_words(row, limit, age);
    match super::resolved_address_words(&row.server.endpoint, row.resolved_address) {
        Some(address) => format!("{health}; {address}"),
        None => health,
    }
}

/// [`health_sentence`]'s health half.
fn health_words(row: &ServerDiagnostics, limit: u32, age: &impl Fn(Duration) -> String) -> String {
    // A login is an answer too: the later of the two is the last one.
    let last = match (row.age, row.grants_age) {
        (Some(status), Some(login)) => Some(status.min(login)),
        (status, login) => status.or(login),
    };
    let failures = row.server.fail_count;
    match row.health {
        ServerHealth::Answered => match last {
            Some(ago) => format!("Health: answering — its last answer came {} ago", age(ago)),
            None => "Health: answering".to_string(),
        },
        ServerHealth::Unproven => {
            "Health: not reached yet — no answer and no failed try so far".to_string()
        }
        ServerHealth::Failing => format!(
            "Health: failing — {failures} of {limit} tries in a row went unanswered; at \
             {limit} it is marked dead"
        ),
        ServerHealth::Dead => format!(
            "Health: dead since {} — {} in a row went unanswered (limit {limit})",
            // The level dates every dead row; one it has not dated was dead
            // before it could see the death happen.
            match row.dead_since.unwrap_or(DeadSince::BeforeThisRun) {
                DeadSince::For(ago) => format!("{} ago", age(ago)),
                DeadSince::BeforeThisRun => "before this run started".to_string(),
            },
            tries(failures),
        ),
    }
}

/// Whether the server has the shares: for the connected one, what its
/// session was told; for any other, what its next login would do.
fn shares_sentence(row: &ServerDiagnostics, context: DetailContext) -> String {
    if let Some(told) = context.told {
        return shares_line(told)
            .unwrap_or(super::SHARES_ANNOUNCED)
            .to_string();
    }
    if context.connected {
        return "Shares: not announced to this session yet".to_string();
    }
    if !context.policy.withhold_from_related_search {
        return "Shares: announced at its next login, as to every server".to_string();
    }
    match row.server.grants {
        Some(report) if report.tcp_flags.contains(ServerTcpFlag::RelatedSearch) => {
            "Shares: withheld at its next login — it answered related searches when last \
             logged in"
                .to_string()
        }
        Some(_) => "Shares: announced at its next login — it did not answer related searches \
                    when last logged in"
            .to_string(),
        None => "Shares: withheld at its next login only if it answers related searches — it \
                 has not said yet"
            .to_string(),
    }
}

/// What the connected server was told of the share set, when it is news:
/// withheld, or told before withholding was switched on.
#[must_use]
pub fn shares_line(shares: SharesToServer) -> Option<&'static str> {
    use SharesToServer as S;
    match shares {
        S::Announced => None,
        S::Withheld => Some(
            "Shares withheld from this server: it answers related searches, which would tell \
             anyone which files you share together. Kad and other servers still have them",
        ),
        S::AnnouncedBeforeWithholding => Some(
            "This server was told your shares before withholding was switched on; they stay \
             with it until you disconnect",
        ),
    }
}

/// The Networks log's line when the connected server's shares are withheld,
/// or were told before withholding: the detail line, named.
#[must_use]
pub fn shares_log_line(server: &ServerEndpoint, what: &str) -> Sentence {
    Sentence::owned(format!("{}: {what}", server_label(server)))
}

#[cfg(test)]
mod tests {
    use rmule_core::{ManagedServer, ServerGrantsReport};

    use super::*;

    fn row(grants: Option<u32>, health: ServerHealth, fail_count: u32) -> ServerDiagnostics {
        row_at("192.0.2.7", grants, health, fail_count)
    }

    fn row_at(
        host: &str,
        grants: Option<u32>,
        health: ServerHealth,
        fail_count: u32,
    ) -> ServerDiagnostics {
        let mut server = ManagedServer::listed(ServerEndpoint::new(host, 4661).unwrap());
        server.fail_count = fail_count;
        server.grants = grants.map(|tcp_flags| ServerGrantsReport {
            tcp_flags: ServerTcpFlags::from_bits(tcp_flags),
            reported_at: 1_700_000_000,
        });
        let mut row = ServerDiagnostics::listed(server);
        row.grants_age = grants.map(|_| Duration::from_secs(60));
        row.health = health;
        row
    }

    fn pane(row: &ServerDiagnostics, withhold: bool) -> [String; 4] {
        let context = DetailContext {
            connected: false,
            told: None,
            policy: ServerPolicy {
                dead_after: 5,
                withhold_from_related_search: withhold,
            },
        };
        detail_pane(row, context, |ago| format!("{}s", ago.as_secs()))
    }

    /// Under the Announce Policy a server that is not connected is judged by
    /// the grants it last reported: related search withholds, its absence
    /// announces, and no report leaves the answer open.
    /// Bits no client names are said by position, so the sentence can be
    /// checked against the raw word the Run Log holds.
    #[test]
    fn unnamed_bits_are_said_by_position() {
        assert_eq!(
            tcp_grant_words(ServerTcpFlags::from_bits(0x0000_A011)),
            "compression, unicode, and bits 13 and 15, which no client names"
        );
        assert_eq!(
            udp_flag_words(ServerUdpFlags::from_bits(0x0000_0004)),
            "bit 2, which no client names"
        );
        assert_eq!(
            tcp_grant_words(ServerTcpFlags::from_bits(0x8000_1804)),
            "bits 2, 11, 12 and 31, which no client names"
        );
    }

    #[test]
    fn the_next_login_is_judged_by_the_last_reported_grants() {
        let related = row(
            Some(ServerTcpFlags::RELATEDSEARCH | ServerTcpFlags::COMPRESSION),
            ServerHealth::Answered,
            0,
        );
        let plain = row(Some(ServerTcpFlags::COMPRESSION), ServerHealth::Answered, 0);
        let unknown = row(None, ServerHealth::Unproven, 0);
        assert!(pane(&related, true)[3].starts_with("Shares: withheld at its next login"));
        assert!(pane(&plain, true)[3].starts_with("Shares: announced at its next login —"));
        assert!(pane(&unknown, true)[3].contains("only if it answers related searches"));
        assert_eq!(
            pane(&related, false)[3],
            "Shares: announced at its next login, as to every server"
        );
    }

    /// A failing server's tally is said out of the limit; a login counts as
    /// its last answer when no status answer came; a dead one is dated by
    /// its death, not by its last answer.
    #[test]
    fn health_names_the_tally_against_the_limit() {
        assert_eq!(
            pane(&row(None, ServerHealth::Failing, 2), false)[2],
            "Health: failing — 2 of 5 tries in a row went unanswered; at 5 it is marked dead"
        );
        assert_eq!(
            pane(&row(Some(0x1), ServerHealth::Answered, 0), false)[2],
            "Health: answering — its last answer came 60s ago"
        );
        let mut died = row(Some(0x1), ServerHealth::Dead, 6);
        died.dead_since = Some(DeadSince::For(Duration::from_secs(45)));
        assert_eq!(
            pane(&died, false)[2],
            "Health: dead since 45s ago — 6 tries in a row went unanswered (limit 5)"
        );
        died.dead_since = Some(DeadSince::BeforeThisRun);
        assert_eq!(
            pane(&died, false)[2],
            "Health: dead since before this run started — 6 tries in a row went unanswered \
             (limit 5)"
        );
    }

    /// A row listed by name says what its name resolved to after its health;
    /// one listed by address says nothing more (ADR-0052's amendment).
    #[test]
    fn a_named_row_says_what_its_name_resolved_to() {
        let named = |resolved| {
            let mut row = row_at("srv.example.org", None, ServerHealth::Failing, 1);
            row.resolved_address = resolved;
            pane(&row, false)[2].clone()
        };
        assert_eq!(
            named(Some(rmule_core::ResolvedAddress::DoesNotResolve)),
            "Health: failing — 1 of 5 tries in a row went unanswered; at 5 it is marked dead; \
             its name does not resolve, so it cannot be pinged — each pass that finds no \
             address counts as an unanswered try"
        );
        assert!(
            named(Some(rmule_core::ResolvedAddress::Resolved(
                std::net::Ipv4Addr::new(198, 51, 100, 9)
            )))
            .ends_with("; its name resolves to 198.51.100.9")
        );
        assert!(named(None).ends_with("; its name has not been looked up yet"));
        assert!(!pane(&row(None, ServerHealth::Failing, 1), false)[2].contains("name"));
    }
}
