//! Connected-server eD2k search diagnostic command (`ed2k search`).

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_core::{
    CoreCommand, CoreConfig, CoreEvent, ManagedServer, SearchCommand as CoreSearchCommand,
    SearchEvent, ServerListCommand, open_durable_store_in_memory,
};
use rmule_primitives::{Ed2kText, KeywordQuery, SearchResult, ServerEndpoint};

use crate::cli::{DownloadIdentityArgs, SearchTypeArg};

#[derive(Debug, Args)]
pub(crate) struct SearchArgs {
    /// eD2k server endpoint as `host:port`.
    #[arg(long)]
    server: String,
    /// Text phrase to search on the connected server.
    #[arg(long)]
    query: String,
    /// Optional first-slice file type filter.
    #[arg(long = "type", value_enum)]
    file_type: Option<SearchTypeArg>,
    /// Optional minimum file size in bytes.
    #[arg(long)]
    min_size: Option<u64>,
    /// Optional maximum file size in bytes.
    #[arg(long)]
    max_size: Option<u64>,
    /// Optional minimum advertised source count.
    #[arg(long)]
    min_availability: Option<u32>,
    /// Optional file extension / format filter.
    #[arg(long)]
    extension: Option<String>,
    /// A second server as `ip:port` to list once the first search completes,
    /// followed by the same search again: the Global Search Sweep of the
    /// second search reaches it (its TCP port + 4), since the swept list is
    /// the managed list as it stands. Give an address: the sweeps walk past a
    /// row named by host name.
    #[arg(long)]
    also_server: Option<String>,
    /// Seconds of result quiet time before reporting completion.
    #[arg(long, default_value_t = 3)]
    quiet_timeout_secs: u64,
    #[command(flatten)]
    identity: DownloadIdentityArgs,
}

pub(crate) async fn run(args: SearchArgs) -> Result<()> {
    let server = ServerEndpoint::parse_host_port(&args.server)
        .with_context(|| format!("parse server endpoint {}", args.server))?;
    let identity = args.identity.client_identity()?;
    let query = search_query_from_args(&args)?;
    let mut also_server = args
        .also_server
        .as_deref()
        .map(|text| {
            ServerEndpoint::parse_host_port(text)
                .with_context(|| format!("parse server endpoint {text}"))
                .map(|server| (server, text.to_owned()))
        })
        .transpose()?;
    let config = CoreConfig {
        search_quiet_timeout: Duration::from_secs(args.quiet_timeout_secs),
        ..Default::default()
    };
    let mut core = args
        .identity
        .core_builder(config, open_durable_store_in_memory()?)?
        .build();

    // The operator's word, given on the command line (ADR-0095): the search
    // waits for the session this connect makes.
    crate::node::connect(&core, &server, identity.clone().into()).await?;
    core.send(CoreCommand::Search(CoreSearchCommand::StartSearch {
        search_id: rmule_core::SearchId::mint(),
        query: query.clone().into(),
    }))
    .await?;

    loop {
        let Some(event) = core.next_event().await else {
            anyhow::bail!("search event stream ended before completion");
        };
        match event {
            CoreEvent::Search(SearchEvent::SearchStarted { search_id }) => {
                println!("search_started id={}", search_id.as_u64());
            }
            CoreEvent::Search(SearchEvent::SearchResultsReceived { results, .. }) => {
                for (index, result) in results.iter().enumerate() {
                    print_search_result(index, result);
                }
            }
            CoreEvent::Search(SearchEvent::SearchResultSkipped { reason, .. }) => {
                println!("search_result_skipped reason={reason:?}");
            }
            CoreEvent::Search(SearchEvent::SearchCompleted {
                search_id,
                total_results,
            }) => {
                println!(
                    "search_completed id={} total={total_results}",
                    search_id.as_u64()
                );
                let Some((server, text)) = also_server.take() else {
                    return Ok(());
                };
                core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
                    server: ManagedServer::listed(server),
                }))
                .await?;
                println!("search_also_server listed={text}");
                core.send(CoreCommand::Search(CoreSearchCommand::StartSearch {
                    search_id: rmule_core::SearchId::mint(),
                    query: query.clone().into(),
                }))
                .await?;
            }
            CoreEvent::Search(SearchEvent::SearchCancelled { search_id }) => {
                anyhow::bail!("search cancelled id={}", search_id.as_u64());
            }
            CoreEvent::Search(SearchEvent::SearchFailed { reason, .. }) => {
                anyhow::bail!("search failed: {reason:?}");
            }
            CoreEvent::CommandRejected { reason } => {
                anyhow::bail!("search command rejected: {reason:?}");
            }
            _ => {}
        }
    }
}

fn search_query_from_args(args: &SearchArgs) -> Result<KeywordQuery> {
    let mut query = KeywordQuery::new(Ed2kText::from_utf8(&args.query))?;
    if let Some(file_type) = args.file_type {
        query = query.with_file_type(file_type.into());
    }
    if let Some(min_size) = args.min_size {
        query = query.with_min_size(min_size);
    }
    if let Some(max_size) = args.max_size {
        query = query.with_max_size(max_size);
    }
    if let Some(min_availability) = args.min_availability {
        query = query.with_min_availability(min_availability);
    }
    if let Some(extension) = args.extension.as_ref() {
        query = query.with_extension(Ed2kText::from_utf8(extension));
    }
    Ok(query)
}

/// One result line. `source_count` is the number of endpoints the answer
/// advertised; `availability`/`complete` are the counts the *server* reported
/// (`FT_SOURCES`/`FT_COMPLETE_SOURCES`), which are what a UI shows and what a
/// capture run needs to see — `-` where the counterparty sent nothing.
fn print_search_result(index: usize, result: &SearchResult) {
    fn count(value: Option<u32>) -> String {
        value.map_or_else(|| "-".to_owned(), |value| value.to_string())
    }

    println!(
        "{index}: file_hash={} size={} primary_name={} source_count={} availability={} complete={} type={}",
        result.file_hash().to_hex_upper(),
        result.file_size(),
        result.primary_name().to_display_string(),
        result.sources().len(),
        count(result.reported_availability()),
        count(result.complete_sources()),
        result
            .file_class()
            .map_or_else(|| "-".to_owned(), |class| class.internal_term().to_owned()),
    );
}
