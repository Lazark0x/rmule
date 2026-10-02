//! The auto-update URL-list walk (ADR-0065).
//!
//! Walk **every** configured URL in order, fetching and merging each via the
//! existing [`fetch_server_met`](crate::fetch_server_met) pipeline. One URL
//! failing does not stop the walk; all results (per-URL success and failure)
//! are reported, and the overall merged outcome combines all successful fetches.

use crate::{Fetcher, ServerMetInstall, ServerMetPipelineError};
use rmule_ed2k::ServerMetEntry;

/// Outcome of one URL in the auto-update walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UrlWalkOutcome {
    /// The fetch and merge succeeded; some servers were acquired.
    Ok(ServerMetInstall),
    /// The fetch or parse failed; this URL was skipped.
    Err(ServerMetPipelineError),
}

/// The result of walking all configured auto-update URLs — per-URL outcomes
/// and the overall merged installation plan.
#[derive(Clone, Debug)]
pub struct AutoUpdateWalkResult {
    /// Outcome of each URL walk, in order.
    pub per_url: Vec<UrlWalkOutcome>,
    /// The final merged plan combining all successful fetches.
    pub merged: ServerMetInstall,
}

/// Walk every configured auto-update URL in order, fetching and merging each.
///
/// For each URL in `urls`, call [`fetch_server_met`](crate::fetch_server_met)
/// with the provided `fetcher`. One URL failing (fetch, parse, or size-cap) does
/// not stop the walk; the failure is recorded in [`AutoUpdateWalkResult::per_url`]
/// and the walk continues to the next URL. All successful fetches are merged into
/// a final [`ServerMetInstall`] in [`AutoUpdateWalkResult::merged`], following
/// the add-new / update-known posture.
///
/// # Arguments
///
/// - `fetcher` — the I/O seam, typically a [`ReqwestFetcher`](crate::ReqwestFetcher)
/// - `urls` — the list of URLs to walk, in order
/// - `max_bytes` — the size cap passed to [`crate::Fetcher::get`]
/// - `installed` — the initial installed list (same for each URL, as each merge
///   layer follows aMule's posture)
///
/// # Returns
///
/// [`AutoUpdateWalkResult`] with per-URL outcomes and the final merged plan.
pub async fn fetch_server_met_auto_update<F>(
    fetcher: &F,
    urls: &[String],
    max_bytes: usize,
    installed: Vec<ServerMetEntry>,
) -> AutoUpdateWalkResult
where
    F: Fetcher + Sync,
{
    let mut per_url = Vec::new();
    let mut current = installed;
    let mut added = 0;
    let mut updated = 0;

    for url in urls {
        match crate::fetch_server_met(fetcher, url, max_bytes, current.clone()).await {
            Ok(install) => {
                added += install.added();
                updated += install.updated();
                current = install.servers().to_vec();
                per_url.push(UrlWalkOutcome::Ok(install));
            }
            Err(e) => per_url.push(UrlWalkOutcome::Err(e)),
        }
    }

    // The aggregate cannot recover its counts from the accumulated list: only
    // each per-URL merge knows which of its rows appended and which folded.
    let merged = ServerMetInstall::from_walk(current, added, updated);

    tracing::debug!(
        urls = urls.len(),
        successful = per_url
            .iter()
            .filter(|o| matches!(o, UrlWalkOutcome::Ok(_)))
            .count(),
        total_servers = merged.servers().len(),
        added = merged.added(),
        updated = merged.updated(),
        "auto-update walk completed"
    );

    AutoUpdateWalkResult { per_url, merged }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_ed2k::ServerPriority;

    use super::*;
    use crate::fixture::{
        FakeFetcher, RowSpec, SERVER_MET_CAP as CAP, installed_from, met_bytes, name_of,
    };

    #[tokio::test]
    async fn empty_url_list_produces_no_changes() {
        let installed =
            installed_from(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661).name("Keep")]);
        let fetcher = FakeFetcher::new();

        let result = fetch_server_met_auto_update(&fetcher, &[], CAP, installed.clone()).await;

        assert!(result.per_url.is_empty(), "no URLs, no outcomes");
        assert_eq!(
            result.merged.servers(),
            installed,
            "final list is unchanged when walking nothing"
        );
    }

    #[tokio::test]
    async fn walk_hits_every_url_in_order() {
        let installed = Vec::new();
        let url1 = "http://mirror1/server.met".to_owned();
        let url2 = "http://mirror2/server.met".to_owned();
        let url3 = "http://mirror3/server.met".to_owned();

        let bytes1 = met_bytes(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661).name("Alpha")]);
        let bytes2 = met_bytes(&[RowSpec::new(Ipv4Addr::new(2, 2, 2, 2), 4662).name("Beta")]);
        let bytes3 = met_bytes(&[RowSpec::new(Ipv4Addr::new(3, 3, 3, 3), 4663).name("Gamma")]);

        let fetcher = FakeFetcher::new()
            .add_response(url1.clone(), bytes1)
            .add_response(url2.clone(), bytes2)
            .add_response(url3.clone(), bytes3);

        let urls = vec![url1.clone(), url2.clone(), url3.clone()];
        let result = fetch_server_met_auto_update(&fetcher, &urls, CAP, installed).await;

        assert_eq!(result.per_url.len(), 3, "all URLs walked");
        assert!(matches!(result.per_url[0], UrlWalkOutcome::Ok(_)));
        assert!(matches!(result.per_url[1], UrlWalkOutcome::Ok(_)));
        assert!(matches!(result.per_url[2], UrlWalkOutcome::Ok(_)));

        let names: Vec<_> = result.merged.servers().iter().map(name_of).collect();
        assert_eq!(
            names,
            vec!["Alpha", "Beta", "Gamma"],
            "all servers merged in order"
        );

        // Each URL should have been called exactly once.
        assert_eq!(fetcher.call_count_for(&url1), 1);
        assert_eq!(fetcher.call_count_for(&url2), 1);
        assert_eq!(fetcher.call_count_for(&url3), 1);
    }

    #[tokio::test]
    async fn one_failing_url_does_not_stop_the_walk() {
        let installed = Vec::new();
        let url1 = "http://mirror1/server.met".to_owned();
        let url2 = "http://mirror2/server.met".to_owned();
        let url3 = "http://mirror3/server.met".to_owned();

        let bytes1 = met_bytes(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661).name("Alpha")]);
        // url2 will fail with a transport error
        let bytes3 = met_bytes(&[RowSpec::new(Ipv4Addr::new(3, 3, 3, 3), 4663).name("Gamma")]);

        let fetcher = FakeFetcher::new()
            .add_response(url1.clone(), bytes1)
            .add_error(
                url2.clone(),
                crate::FetchError::Transport {
                    url: url2.clone(),
                    detail: "connection refused".to_owned(),
                },
            )
            .add_response(url3.clone(), bytes3);

        let urls = vec![url1.clone(), url2.clone(), url3.clone()];
        let result = fetch_server_met_auto_update(&fetcher, &urls, CAP, installed).await;

        assert_eq!(result.per_url.len(), 3, "all URLs walked");
        assert!(matches!(result.per_url[0], UrlWalkOutcome::Ok(_)));
        assert!(matches!(result.per_url[1], UrlWalkOutcome::Err(_)));
        assert!(matches!(result.per_url[2], UrlWalkOutcome::Ok(_)));

        let names: Vec<_> = result.merged.servers().iter().map(name_of).collect();
        assert_eq!(
            names,
            vec!["Alpha", "Gamma"],
            "servers from successful URLs are merged, skipping the failed one"
        );
    }

    #[tokio::test]
    async fn each_url_merges_with_the_add_new_update_known_posture() {
        let installed = installed_from(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661)
            .name("Old Name")
            .description("Old description")
            .preference(1)]); // High

        let url1 = "http://mirror1/server.met".to_owned();
        let url2 = "http://mirror2/server.met".to_owned();

        // url1: updates the installed server + adds a new one
        let bytes1 = met_bytes(&[
            RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661)
                .name("Updated Name")
                .preference(2), // Low — must be ignored
            RowSpec::new(Ipv4Addr::new(2, 2, 2, 2), 4662).name("Beta"),
        ]);

        // url2: adds another new one
        let bytes2 = met_bytes(&[RowSpec::new(Ipv4Addr::new(3, 3, 3, 3), 4663).name("Gamma")]);

        let fetcher = FakeFetcher::new()
            .add_response(url1.clone(), bytes1)
            .add_response(url2.clone(), bytes2);

        let urls = vec![url1, url2];
        let result = fetch_server_met_auto_update(&fetcher, &urls, CAP, installed.clone()).await;

        assert_eq!(result.per_url.len(), 2);
        assert!(matches!(result.per_url[0], UrlWalkOutcome::Ok(_)));
        assert!(matches!(result.per_url[1], UrlWalkOutcome::Ok(_)));

        let servers = result.merged.servers();
        assert_eq!(servers.len(), 3);

        // First server (1.1.1.1:4661) must be updated:
        // - name from url1
        // - description from installed (not overwritten by empty)
        // - priority from installed (never overwritten)
        let first = &servers[0];
        assert_eq!(name_of(first), "Updated Name");
        assert_eq!(
            first.description().to_display_string(),
            "Old description",
            "empty fresh description does not overwrite installed"
        );
        assert_eq!(
            first.priority(),
            ServerPriority::High,
            "priority always kept from installed"
        );

        // Second server from url1
        assert_eq!(name_of(&servers[1]), "Beta");

        // Third server from url2
        assert_eq!(name_of(&servers[2]), "Gamma");
    }

    #[tokio::test]
    async fn failure_outcomes_contain_the_error() {
        let installed = Vec::new();
        let url1 = "http://mirror1/server.met".to_owned();
        let url2 = "http://mirror2/server.met".to_owned();

        let bytes1 = met_bytes(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661).name("Alpha")]);

        let fetcher = FakeFetcher::new()
            .add_response(url1.clone(), bytes1)
            .add_error(
                url2.clone(),
                crate::FetchError::Timeout { url: url2.clone() },
            );

        let urls = vec![url1, url2];
        let result = fetch_server_met_auto_update(&fetcher, &urls, CAP, installed).await;

        assert_eq!(result.per_url.len(), 2);
        match &result.per_url[1] {
            UrlWalkOutcome::Err(ServerMetPipelineError::Fetch(crate::FetchError::Timeout {
                ..
            })) => {}
            other => panic!("expected Timeout error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn merged_reports_add_update_totals_summed_across_urls() {
        let installed =
            installed_from(&[RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661).name("Seed")]);

        let url1 = "http://mirror1/server.met".to_owned();
        let url2 = "http://mirror2/server.met".to_owned();

        // url1: folds the installed endpoint + two brand-new endpoints.
        let bytes1 = met_bytes(&[
            RowSpec::new(Ipv4Addr::new(1, 1, 1, 1), 4661).name("Seed Renamed"),
            RowSpec::new(Ipv4Addr::new(2, 2, 2, 2), 4662).name("Beta"),
            RowSpec::new(Ipv4Addr::new(3, 3, 3, 3), 4663).name("Gamma"),
        ]);
        // url2: three further brand-new endpoints.
        let bytes2 = met_bytes(&[
            RowSpec::new(Ipv4Addr::new(4, 4, 4, 4), 4664).name("Delta"),
            RowSpec::new(Ipv4Addr::new(5, 5, 5, 5), 4665).name("Epsilon"),
            RowSpec::new(Ipv4Addr::new(6, 6, 6, 6), 4666).name("Zeta"),
        ]);

        let fetcher = FakeFetcher::new()
            .add_response(url1.clone(), bytes1)
            .add_response(url2.clone(), bytes2);

        let urls = vec![url1, url2];
        let result = fetch_server_met_auto_update(&fetcher, &urls, CAP, installed).await;

        assert_eq!(result.merged.added(), 5, "2 appended by url1 + 3 by url2");
        assert_eq!(result.merged.updated(), 1, "the seed folded by url1");
        assert_eq!(
            result.merged.servers().len(),
            6,
            "the seed plus five fresh endpoints"
        );
    }
}
