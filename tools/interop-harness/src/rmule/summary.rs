//! What an rmule run reported about itself, parsed out of its stdout and logs.
//! These summaries are stimulus, never evidence (ADR-0045): they say what rmule
//! believes happened, which a flow records for context and pairs with the
//! counterparty's own bytes before writing a verdict. The one
//! check of reality — the byte-for-byte comparison against the synthetic file —
//! lives in `flow::evidence::verify_bytes`.

use anyhow::{Result, bail};

/// What `ed2k download start` reported on stdout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadSummary {
    /// rmule reported completion.
    pub completed: bool,
    /// rmule verified at least one part hash.
    pub part_verified: bool,
    /// Usable High-ID sources rmule's get-sources returned, if reported.
    pub usable_high_id: Option<u64>,
}

/// What `ed2k search` reported on stdout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchSummary {
    /// rmule reported completion.
    pub completed: bool,
    /// The query string appeared in rmule's results.
    pub matched: bool,
}

/// The Low-ID callback compatibility-tier observation (ADR-0040
/// exemption). rmule cannot byte-complete against the Lugdunum eserver — it
/// never surfaces the connected Low-ID aMule as a source (no `OP_FOUNDSOURCES`),
/// so rmule correctly discovers no candidate and never reaches the callback
/// emit. The honest observable is rmule's own **callback capability**, judged
/// from its run logs while it downloads `--serve` against the real server with a
/// real Low-ID aMule sharing the file:
/// - `listener_bound`: rmule bound its inbound peer listener (`serving_started`).
/// - `reachability_probe`: the eserver's HighID back-connect reached that
///   listener (an inbound peer connection from the server's own IP) — the wire
///   proof rmule is reachable, so the server grants it a HighID and a called-back
///   peer can dial it.
///
/// Together these are the ADR-0039 precondition for adopting a called-back peer;
/// the byte-completing adoption is proven in the in-process correctness tier
/// (`callback_loopback`, ADR-0040). The server-assigned HighID value itself is
/// not asserted here: rmule surfaces it as an event only once the (blocked)
/// source lookup returns, which by construction it never does on this eserver.
pub struct CallbackCapabilityReport {
    /// rmule bound its inbound peer listener (`serving_started`).
    pub listener_bound: bool,
    /// The eserver's High-ID back-connect reached that listener.
    pub reachability_probe: bool,
    /// Both halves held: the ADR-0039 precondition for adopting a called-back peer.
    pub callback_capable: bool,
    /// rmule also reported `download finalized` (never, on this eserver).
    pub download_completed: bool,
}

/// Judge callback capability from rmule's own run logs (see
/// [`CallbackCapabilityReport`]). Info-level and format-stable: `serving_started`
/// is rmule's own serve event; the reachability back-connect is any inbound peer
/// connection whose span names the server's IP as the peer.
pub(super) fn judge_callback_capability(
    stdout: &str,
    stderr: &str,
    server_ip: &str,
) -> CallbackCapabilityReport {
    let logged = |needle: &str| stdout.contains(needle) || stderr.contains(needle);
    let listener_bound = logged("serving_started");
    let reachability_probe = logged(&format!("peer={server_ip}:"));
    let download_completed = logged("download finalized");
    CallbackCapabilityReport {
        listener_bound,
        reachability_probe,
        callback_capable: listener_bound && reachability_probe,
        download_completed,
    }
}

/// Parse a search run: it must have printed `search_completed` and the query.
pub fn parse_search_output(output: &str, query: &str) -> Result<SearchSummary> {
    let completed = output
        .lines()
        .any(|line| line.starts_with("search_completed "));
    let matched = output.contains(query);

    if !completed {
        bail!("rmule search output did not contain search_completed");
    }
    if !matched {
        bail!("rmule search output did not contain query `{query}`");
    }

    Ok(SearchSummary { completed, matched })
}

/// Parse a download run: it must have printed `download.completed`.
pub fn parse_download_output(output: &str) -> Result<DownloadSummary> {
    let completed = output
        .lines()
        .any(|line| line.starts_with("download.completed "));
    let part_verified = output
        .lines()
        .any(|line| line.starts_with("download.part_verified "));
    let usable_high_id = output
        .lines()
        .find(|line| line.starts_with("download.sources_found "))
        .and_then(parse_usable_high_id);

    if !completed {
        bail!("rmule download output did not contain download.completed");
    }

    Ok(DownloadSummary {
        completed,
        part_verified,
        usable_high_id,
    })
}

fn parse_usable_high_id(line: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix("usable_high_id="))
        .and_then(|value| value.parse().ok())
}
