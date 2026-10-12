//! Consume-side admission (ADR-0055): which entries of a decoded
//! source answer the session surfaces as candidates.
//!
//! The wire codec in the parent decodes every entry; this module decides
//! survival — the aMule-mirrored sanity filter, the Low-ID routing rule and
//! the cumulative per-file cap — without touching an entry's provenance.

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, PeerSource, SourceSighting};

use super::SourceExchangeEntry;

/// The consume-side per-file source cap (ADR-0055: "Per-file source cap
/// honored (stop accepting past cap)"). No aMule source line pins an exact
/// consume-side figure the way the ADR cites a 500-entry cap for *serving*;
/// reusing that same ceiling here is the honest placeholder — **pending**
/// until a capture or a located aMule consume-side constant confirms it.
pub(super) const PER_FILE_SOURCE_CAP: usize = 500;

/// A dialable entry's derived address is plausible: for IPv4, not `0.x.x.x`
/// (the `[srvIP4]`/id wire convention's "0-IP" degenerate case), not loopback,
/// and not the broadcast address a relayed `0xFFFFFFFF` sentinel id unpacks
/// to; for IPv6, not unspecified and not loopback. aMule-mirrored sanity per
/// ADR-0055 ("drop 0-IP/localhost/... HighIDs"); no ipfilter, no ban list
/// (out of map scope).
pub(super) fn is_plausible_high_id_endpoint(endpoint: PeerEndpoint) -> bool {
    match endpoint {
        PeerEndpoint::V4(ep) => {
            ep.ip.octets()[0] != 0 && !ep.ip.is_loopback() && !ep.ip.is_broadcast()
        }
        PeerEndpoint::V6(ep) => !ep.ip.is_unspecified() && !ep.ip.is_loopback(),
    }
}

/// ADR-0055's per-entry sanity filter and Low-ID routing rule, applied to one
/// decoded entry:
///
/// - **High-ID**: dropped outright if its derived address is 0-IP, loopback,
///   or equal to `own_endpoint` (a peer echoing candidates back to us is
///   never useful, and never sane to self-dial).
/// - **Low-ID**: kept as a candidate only when it declares a plausible server
///   ([`SourceExchangeEntry::server`] is `Some`) *and* that server is
///   `connected_server` — the only dial route rmule has for a Low-ID today is
///   the existing server-callback path (ADR-0039), which can only ask the
///   server we are actually connected to. A Low-ID with no server, or one
///   naming a different server, is **parked**: not dropped as bogus, simply
///   not actionable via any route rmule has yet.
fn keep_entry(
    entry: SourceExchangeEntry,
    own_endpoint: Option<PeerEndpoint>,
    connected_server: Option<Ipv4Endpoint>,
) -> bool {
    match entry.as_peer_endpoint() {
        Some(endpoint) => is_plausible_high_id_endpoint(endpoint) && Some(endpoint) != own_endpoint,
        None => entry.server().is_some() && entry.server() == connected_server,
    }
}

/// The candidate one entry yields, if any: its classic form, naming the
/// server the row declared, when [`keep_entry`] keeps it — **with** the IPv6
/// half an ExtSX record carried
/// beside it, so a dual-stack source surfaces as one source with two
/// addresses and the core Dial Chooser picks the family — and otherwise that
/// IPv6 alone (ADR-0087 judges the two families independently).
///
/// The fallback is what keeps a Low ID that no route can reach — the form
/// emule-qt writes for every server-less peer, `htonl(userIDHybrid)` of a
/// hello that said id 0 — from costing the record its dialable IPv6. The
/// IPv6 half passes the same sanity and self-echo tests a High ID does, and
/// keeps the entry's provenance.
fn admit(
    entry: SourceExchangeEntry,
    own_endpoint: Option<PeerEndpoint>,
    connected_server: Option<Ipv4Endpoint>,
) -> Option<SourceSighting> {
    if keep_entry(entry, own_endpoint, connected_server) {
        // The row's server rides on: a Low ID is read in the namespace of
        // the server that assigned it (aMule `AddClientSources`).
        return Some(entry.source().with_server(entry.server()));
    }
    let ipv6 = entry.ipv6()?;
    let endpoint = PeerEndpoint::V6(ipv6);
    (is_plausible_high_id_endpoint(endpoint) && Some(endpoint) != own_endpoint).then(|| {
        SourceSighting::new(
            PeerSource::Ipv6(ipv6),
            entry.user_hash(),
            entry.crypt_options(),
        )
    })
}

/// ADR-0055's consume-side per-answer processing, applied in
/// answer order: the sanity filter and Low-ID routing rule
/// ([`keep_entry`], with ADR-0087's IPv6 fallback in [`admit`]) first, then
/// the per-file cap ([`PER_FILE_SOURCE_CAP`]) — `already_forwarded` is how many candidates
/// this file has already been handed across earlier answers, so the cap is
/// honored cumulatively rather than reset per packet.
///
/// The surviving [`SourceSighting`]s carry exactly the provenance
/// ([`SourceSighting::user_hash`] / [`SourceSighting::crypt_options`]) they
/// decoded with — the same ADR-0046 model the server `0x44` path feeds, read
/// through [`SourceSighting::peer_crypt`] and met with ours by
/// `PeerCrypt::outbound` (ADR-0049); this function only decides *which*
/// entries survive, never touches their provenance fields.
pub(crate) fn sanitize_and_route(
    entries: Vec<SourceExchangeEntry>,
    own_endpoint: Option<PeerEndpoint>,
    connected_server: Option<Ipv4Endpoint>,
    already_forwarded: usize,
) -> Vec<SourceSighting> {
    let remaining_capacity = PER_FILE_SOURCE_CAP.saturating_sub(already_forwarded);
    entries
        .into_iter()
        .filter_map(|entry| admit(entry, own_endpoint, connected_server))
        .take(remaining_capacity)
        .collect()
}
