//! `rmule-cli kad join` — the user-facing Kad node runner for the manual live
//! smoke (ADR-0043).
//!
//! It reads rmule's persisted Kad identity, spawns one `rmule_net::kad` node on
//! the persisted UDP port, bootstraps to the operator-supplied public
//! endpoint(s), and runs for a bounded window printing routing observability to
//! stdout — never to disk. Optionally it fires one source lookup on a known
//! hash and prints the projected **Peer Source** rows. This is the *node*-level
//! health check the runbook's checkpoints describe; Core's download integration
//! is proven separately by the serverless E2E.
//!
//! **Doctrine:** this is the only place rmule touches the public Kad network. It
//! is manual, never CI, never scored, and it commits **no captured bytes** — the
//! observability is human-readable stdout, and nothing here writes a capture
//! tap. See `crates/rmule-kad/CONTEXT.md`.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmule_kad::{
    KadCommand, KadEvent, KadNodeConfig, KadNodeEndpoint, KadSourceCandidate,
    KadSourceLookupRequest, RoutingCensus, SourceLookupTarget,
};
use rmule_net::kad::{KadNetConfig, spawn};
use rmule_primitives::Ed2kLink;

use rmule_core::{AppConfigStore, CoreSettings};

/// How often the run loop prints a routing-census line while idling.
const CENSUS_INTERVAL: Duration = Duration::from_secs(15);
/// How long to warm the routing table before firing the optional source
/// lookup, so the walk has responded contacts to fan toward.
const SEARCH_WARMUP: Duration = Duration::from_secs(20);

/// Parse an operator-supplied bootstrap endpoint `A.B.C.D:PORT` into a
/// [`KadNodeEndpoint`]. Deliberately IPv4-literal only: the join diagnostic
/// reads neither a `nodes.dat` nor a hostname, so the operator supplies
/// concrete contact endpoints.
pub fn parse_bootstrap(input: &str) -> Result<KadNodeEndpoint> {
    let (host, port) = input
        .rsplit_once(':')
        .with_context(|| format!("bootstrap endpoint must be A.B.C.D:PORT, got \"{input}\""))?;
    let ip: Ipv4Addr = host
        .parse()
        .with_context(|| format!("bootstrap host must be an IPv4 literal, got \"{host}\""))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("bootstrap port must be a u16, got \"{port}\""))?;
    if port == 0 {
        bail!("bootstrap port must be non-zero");
    }
    Ok(KadNodeEndpoint::new(ip, port))
}

/// Render the [`RoutingCensus`] into the periodic `routing:` status line the
/// runbook reads its checkpoints from. The fold itself lives in `rmule-kad`;
/// the CLI only formats it.
pub fn format_census(census: &RoutingCensus, elapsed: Duration) -> String {
    format!(
        "routing: live={} peak={} responded={} served_lookups={} elapsed={}s",
        census.live,
        census.peak_live,
        census.responded,
        census.served_lookups,
        elapsed.as_secs()
    )
}

/// Render the projected source candidates of one `SourcesFound` batch into
/// human-readable lines: each direct **Peer Source** as `dial <ip:port>`, plus a
/// trailing count of non-direct diagnostic rows (firewalled/low-id/etc., which
/// the CLI does not dial).
pub fn format_candidates(candidates: &[KadSourceCandidate]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut diagnostics = 0usize;
    for candidate in candidates {
        match candidate.peer_source().and_then(|s| s.as_peer_endpoint()) {
            Some(endpoint) => lines.push(format!("  source: dial {endpoint}")),
            None => diagnostics += 1,
        }
    }
    if diagnostics > 0 {
        lines.push(format!(
            "  ({diagnostics} non-direct diagnostic row(s), not dialed)"
        ));
    }
    if lines.is_empty() {
        lines.push("  (no rows)".to_owned());
    }
    lines
}

/// Parse an `--search` ed2k *file* link into a [`SourceLookupTarget`].
pub fn parse_search_target(link: &str) -> Result<SourceLookupTarget> {
    match Ed2kLink::parse(link).with_context(|| format!("parse ed2k link {link}"))? {
        Ed2kLink::File(file) => Ok(SourceLookupTarget::new(file.file_hash, file.size)),
        _ => bail!("--search must be an ed2k *file* link"),
    }
}

/// Run the live Kad smoke: spawn the node, bootstrap, observe for `duration`,
/// and (when `search` is set) fire one source lookup after a warmup. The two
/// ports are the ones `settings` name (ADR-0069), the node ID and the user
/// hash the store's identity rows. All observability goes to stdout; nothing
/// is written to disk.
pub async fn run_join(
    store: &dyn AppConfigStore,
    settings: &CoreSettings,
    bootstraps: &[KadNodeEndpoint],
    duration: Duration,
    search: Option<SourceLookupTarget>,
) -> Result<()> {
    if bootstraps.is_empty() {
        bail!("at least one --bootstrap A.B.C.D:PORT is required");
    }
    let id = store.ensure_kad_identity()?.id;

    let mut node = spawn(
        KadNetConfig {
            node: KadNodeConfig {
                id,
                tcp_port: settings.tcp_port,
                udp_port: settings.udp_port,
                user_hash: store.ensure_identity()?.user_hash(),
            },
            // Doctrine: NEVER capture the public network to disk.
            capture_dir: None,
            // ...and never persist a public-network routing table:
            // the smoke path stays ephemeral, writing no bytes to disk.
            nodes_dat_path: None,
            // The public-smoke node runs no ADR-0058 firewall self-check.
            firewall_self_check: false,
            // ...and stays plaintext on the public network: the ADR-0046 crypt and
            // verify-key layers are capture-gated and arm only in the bench.
            obfuscation: None,
            contact_admission: None,
        },
        std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, settings.udp_port)),
    )
    .await
    .context("spawn the Kad node")?;

    println!(
        "kad: node up id={} udp={} — the ONLY public-network path; no bytes are written to disk",
        hex16(id.as_bytes()),
        node.local_addr().port()
    );
    tracing::info!(bootstraps = bootstraps.len(), "kad join: bootstrapping");
    for endpoint in bootstraps {
        node.command(KadCommand::Bootstrap {
            endpoint: *endpoint,
        })
        .await
        .context("issue bootstrap")?;
        println!(
            "kad: bootstrapping to {}:{}",
            endpoint.ip(),
            endpoint.udp_port()
        );
    }

    let start = tokio::time::Instant::now();
    let deadline = start + duration;
    let mut census = RoutingCensus::default();
    let mut census_tick = tokio::time::interval(CENSUS_INTERVAL);
    census_tick.tick().await; // consume the immediate first tick
    let mut search_fired = search.is_none();
    let search_at = start + SEARCH_WARMUP;

    loop {
        let step = tokio::select! {
            () = tokio::time::sleep_until(deadline) => Step::Deadline,
            _ = census_tick.tick() => Step::Census,
            _ = tokio::time::sleep_until(search_at), if !search_fired => Step::FireSearch,
            event = node.next_event() => Step::Event(event),
        };
        match step {
            Step::Deadline => break,
            Step::Census => println!("{}", format_census(&census, start.elapsed())),
            Step::FireSearch => {
                if let Some(target) = search {
                    node.command(KadCommand::SearchSources {
                        request: KadSourceLookupRequest::new(target),
                    })
                    .await
                    .context("issue source lookup")?;
                    println!(
                        "kad: source lookup fired for {}",
                        hex16(target.file_hash().as_bytes())
                    );
                }
                search_fired = true;
            }
            Step::Event(None) => bail!("kad node stopped early"),
            Step::Event(Some(event)) => {
                census.observe(&event);
                if let KadEvent::SourcesFound { candidates, .. } = &event {
                    println!("kad: sources found ({} row(s)):", candidates.len());
                    for line in format_candidates(candidates) {
                        println!("{line}");
                    }
                }
            }
        }
    }

    let summary = node.shutdown().await.context("clean node shutdown")?;
    println!("{}", format_census(&census, start.elapsed()));
    println!(
        "kad: done datagrams_in={} datagrams_out={} non_ipv4_dropped={}",
        summary.datagrams_in, summary.datagrams_out, summary.non_ipv4_dropped
    );
    Ok(())
}

enum Step {
    Deadline,
    Census,
    FireSearch,
    Event(Option<KadEvent>),
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bootstrap_accepts_ipv4_port() {
        let endpoint = parse_bootstrap("203.0.113.7:4672").unwrap();
        assert_eq!(endpoint.ip(), Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(endpoint.udp_port(), 4672);
    }

    #[test]
    fn parse_bootstrap_rejects_hostname_zero_port_and_garbage() {
        assert!(parse_bootstrap("kad.example.org:4672").is_err()); // no hostname warm-start yet
        assert!(parse_bootstrap("203.0.113.7:0").is_err());
        assert!(parse_bootstrap("203.0.113.7").is_err());
        assert!(parse_bootstrap("nonsense").is_err());
    }

    #[test]
    fn format_candidates_renders_direct_sources_and_counts_diagnostics() {
        use rmule_kad::{KadId, KadSourceRow, decode_source_result, encode_source_result};
        // `KadSourceCandidate`'s direct arm is sealed to rmule-kad's decoder, so
        // the dial line only renders for rows that came off the wire: encode one
        // direct (type 1) and one firewalled (type 6) row and decode them back.
        let direct = KadSourceRow {
            source_id: [0x11; 16],
            source_type: 1,
            ip: Ipv4Addr::new(83, 44, 21, 9),
            tcp_port: 4662,
            udp_port: 4672,
            encryption: None,
            buddy: None,
            ipv6: None,
        };
        let firewalled = KadSourceRow {
            source_type: 6,
            ..direct
        };
        let envelopes = encode_source_result(
            KadId::from_bytes([0x01; 16]),
            KadId::from_bytes([0x02; 16]),
            &[direct, firewalled],
        );
        let candidates = decode_source_result(&envelopes[0]).expect("decode own encoding");
        assert_eq!(
            format_candidates(&candidates),
            vec![
                "  source: dial 83.44.21.9:4662".to_owned(),
                "  (1 non-direct diagnostic row(s), not dialed)".to_owned(),
            ]
        );
    }

    #[test]
    fn format_candidates_handles_empty_batch() {
        assert_eq!(format_candidates(&[]), vec!["  (no rows)".to_owned()]);
    }

    #[test]
    fn parse_search_target_requires_a_file_link() {
        assert!(parse_search_target("not-a-link").is_err());
    }
}
