//! A link's sources as the run's first candidates (ADR-0089):
//! the peers its `sources,` tokens name and the hints its `s6=` tokens
//! name, turned into the records a server's answer is made of, and put ahead
//! of that answer in the ADR-0030 pool. Both references hand them to the
//! download at once — aMule `AddToResolve` → `AddSources(…, SF_LINK)`
//! (`DownloadQueue.cpp:1497-1500`), eMule `AddClientSources`
//! (`DownloadQueue.cpp:262-295`) — resolving a named one first.
//!
//! They are unverified hints, as a server's answer is: the runner's ingest
//! gates (the IP filter, the dial family) judge them the same way.

use rmule_primitives::{
    Ed2kFileLink, ExchangedSource, Ipv4Endpoint, LinkPeer, LinkPeerHost, PeerSource,
};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::name_resolver::SharedNameResolver;

/// Where a later link's sources reach a running download (ADR-0089):
/// the actor keeps the sending half beside the run, and a
/// second `StartDownload` for the file sends its standing sources here
/// instead of minting a row. The run takes them as it takes a server answer
/// that arrives mid-run.
pub(crate) type LaterLinkSources = mpsc::UnboundedSender<Vec<ExchangedSource>>;

/// The run's half of [`LaterLinkSources`].
pub(crate) type LaterLinkInbox = mpsc::UnboundedReceiver<Vec<ExchangedSource>>;

/// Whether a link carries any source at all — a classic peer or an `s6=`
/// hint — before any expiry or resolution is applied.
pub(crate) fn names_sources(file: &Ed2kFileLink) -> bool {
    !file.sources.peers().is_empty() || !file.ipv6_sources.is_empty()
}

/// The link's sources that stand at `unix_seconds`, in the link's order:
/// every classic peer whose `@` date has not passed — a named one only once
/// it resolved — then every `s6=` hint.
pub(crate) async fn link_sources(
    file: &Ed2kFileLink,
    resolver: &SharedNameResolver,
    unix_seconds: u64,
) -> Vec<ExchangedSource> {
    let standing = file
        .sources
        .peers()
        .iter()
        .filter(|peer| !peer.expires.is_some_and(|day| day.has_passed(unix_seconds)))
        .collect::<Vec<_>>();
    let resolved = resolve_names(&standing, resolver).await;
    let classic = standing.iter().filter_map(|peer| {
        let ip = match &peer.host {
            LinkPeerHost::Ipv4(ip) => *ip,
            LinkPeerHost::Name(name) => *resolved.get(name)?,
        };
        Some(ExchangedSource::new(
            PeerSource::HighId(Ipv4Endpoint::new(ip, peer.port)),
            peer.user_hash,
            peer.crypt,
        ))
    });
    let ipv6 = file
        .ipv6_sources
        .iter()
        .map(|endpoint| ExchangedSource::plain(PeerSource::Ipv6(*endpoint)));
    classic.chain(ipv6).collect()
}

/// Every distinct name among `peers`, resolved side by side; a name that
/// does not resolve is absent from the answer.
async fn resolve_names(
    peers: &[&LinkPeer],
    resolver: &SharedNameResolver,
) -> std::collections::HashMap<String, std::net::Ipv4Addr> {
    let mut lookups = JoinSet::new();
    let mut asked = std::collections::HashSet::new();
    for peer in peers {
        if let LinkPeerHost::Name(name) = &peer.host
            && asked.insert(name.clone())
        {
            let lookup = resolver.resolve_ipv4(name.clone());
            let name = name.clone();
            lookups.spawn(async move { (name, lookup.await) });
        }
    }
    let mut resolved = std::collections::HashMap::new();
    while let Some(answer) = lookups.join_next().await {
        if let Ok((name, Some(ip))) = answer {
            resolved.insert(name, ip);
        } else if let Ok((name, None)) = answer {
            tracing::info!(%name, "a link's named source does not resolve; it is not a candidate");
        }
    }
    resolved
}

/// `link` ahead of `server`, each endpoint once: a source both name keeps
/// the link's place and the server's record, the fresher word on its crypt.
pub(super) fn ahead_of(
    link: Vec<ExchangedSource>,
    mut server: Vec<ExchangedSource>,
) -> Vec<ExchangedSource> {
    let mut merged: Vec<ExchangedSource> = Vec::with_capacity(link.len() + server.len());
    for source in link {
        let endpoint = source.as_peer_endpoint();
        if merged
            .iter()
            .any(|kept| endpoint.is_some() && kept.as_peer_endpoint() == endpoint)
        {
            continue;
        }
        let same = server
            .iter()
            .position(|answer| endpoint.is_some() && answer.as_peer_endpoint() == endpoint);
        merged.push(same.map_or(source, |at| server.remove(at)));
    }
    merged.extend(server);
    merged
}

#[cfg(test)]
mod tests;
