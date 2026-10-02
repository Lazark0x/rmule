//! The Kad pump's command arm: each [`KadPumpCommand`] the core sends, turned
//! into the node command that enacts it. Kept apart from the pump loop in
//! `node.rs` so the loop reads as the select it is, and each command's
//! translation into Kad vocabulary sits at one boundary.

use std::collections::HashMap;

use rmule_primitives::FileHash;

use super::KadPumpCommand;
use crate::adapters::ipv6_advert::SharedIpv6Advert;
use crate::search::{KadKeywordEnd, KadWalkFact};

/// Enact one pump command on the running node. `walked` maps each walked Kad
/// target back to the file hash the search was issued for; `callback_walks`
/// remembers who waits on each Callback Walk; `keyword_subscribers` holds each
/// keyword walk's search sink.
pub(super) async fn apply(
    handle: &rmule_net::kad::KadNetHandle,
    command: KadPumpCommand,
    walked: &mut HashMap<rmule_kad::KadId, FileHash>,
    callback_walks: &mut super::callback_walk::CallbackWalks,
    keyword_subscribers: &mut super::keyword_subscribers::KeywordSubscribers,
    ipv6_advert: &SharedIpv6Advert,
) {
    match command {
        KadPumpCommand::Search(target) => {
            let request = rmule_kad::KadSourceLookupRequest::new(target);
            walked.insert(request.kad_target(), target.file_hash());
            let _ = handle
                .command(rmule_kad::KadCommand::SearchSources { request })
                .await;
        }
        KadPumpCommand::Publish(target) => {
            // Carry the chooser's verdict in immediately before the
            // publish (ADR-0087): the `ip6` tag is checked freshly
            // at each advertisement and never cached, because an
            // IPv6 prefix renumber or an RFC 4941 rotation changes
            // what we hold between one publish and the next.
            let _ = handle
                .command(rmule_kad::KadCommand::SetAdvertisedIpv6 {
                    address: ipv6_advert.get(),
                })
                .await;
            let request = rmule_kad::KadPublishRequest::new(target);
            let _ = handle
                .command(rmule_kad::KadCommand::PublishSource { request })
                .await;
        }
        KadPumpCommand::Withdraw(target) => {
            let request = rmule_kad::KadPublishRequest::new(target);
            let _ = handle
                .command(rmule_kad::KadCommand::WithdrawSource { request })
                .await;
        }
        KadPumpCommand::SearchKeyword { query, results } => {
            // ADR-0062 requester: the node walks the lead keyword alone and
            // emits the plain `0x33`; every search on that keyword subscribes
            // to the one walk and hears its `KeywordsFound` rows screened by
            // its own query. A query with no lead keyword,
            // or a node that never took the command, ends the leg with why
            // rather than strand it.
            let request = super::keyword_subscribers::lead_keyword(&query)
                .map(rmule_kad::KadKeywordSearchRequest::new);
            let target = request
                .as_ref()
                .and_then(rmule_kad::KadKeywordSearchRequest::target);
            if keyword_subscribers.subscribe(target, query, results)
                && let (Some(target), Some(request)) = (target, request)
                && handle
                    .command(rmule_kad::KadCommand::SearchKeywords { request })
                    .await
                    .is_err()
            {
                keyword_subscribers.complete(target, KadKeywordEnd::NotTaken);
            }
        }
        KadPumpCommand::BootstrapFromPeer(peer) => {
            // The ed2k→Kad handoff (ADR-0067): convert the
            // projected endpoint to Kad vocabulary at this boundary
            // and hand it to the node, which applies aMule's
            // not-joined + shared 10 s throttle gate before it seeds
            // the one Bootstrap Dial List.
            let endpoint = rmule_kad::KadNodeEndpoint::new(peer.ip, peer.port);
            let _ = handle
                .command(rmule_kad::KadCommand::BootstrapFromPeer { endpoint })
                .await;
        }
        KadPumpCommand::RecheckReachability => {
            // ADR-0086: a fresh Exact port-mapping grant, a gateway
            // epoch reset that re-added the set, or the operator's
            // recheck. The node owns the guards — one recheck at a
            // time, at most one per five minutes — so a burst of
            // triggers costs one round of helper lookups.
            let _ = handle
                .command(rmule_kad::KadCommand::RecheckReachability)
                .await;
        }
        KadPumpCommand::TcpFirewallAck(peer_ip) => {
            // ADR-0058 requester, the v7+ ack path: a helper dialed
            // our eD2k port back and acked over that link. The node
            // checks the IP against its own 180 s outstanding-check
            // windows before it counts a leg, so an unrequested
            // `0xA8` proves nothing.
            let _ = handle
                .command(rmule_kad::KadCommand::TcpFirewallAck { peer_ip })
                .await;
        }
        KadPumpCommand::UdpFirewallRequest {
            requester,
            request,
            caller_known,
        } => {
            let _ = handle
                .command(rmule_kad::KadCommand::UdpFirewallRequest {
                    requester_ip: requester,
                    request,
                    caller_known,
                })
                .await;
        }
        KadPumpCommand::UdpFirewallCheckFailed(helper_ip) => {
            let _ = handle
                .command(rmule_kad::KadCommand::UdpFirewallCheckFailed { helper_ip })
                .await;
        }
        KadPumpCommand::UdpFirewallCheckCancelled(helper_ip) => {
            let _ = handle
                .command(rmule_kad::KadCommand::UdpFirewallCheckCancelled { helper_ip })
                .await;
        }
        KadPumpCommand::BuddyCallback(ask) => {
            // ADR-0061 route 4: the `0x52` to a firewalled
            // source's buddy, which relays it over the link it holds.
            let _ = handle
                .command(rmule_kad::KadCommand::RequestBuddyCallback {
                    buddy: rmule_kad::KadNodeEndpoint::new(ask.buddy_udp.ip, ask.buddy_udp.port),
                    buddy_id: ask.buddy_id,
                    file_hash: ask.file_hash,
                    tcp_port: ask.tcp_port,
                })
                .await;
        }
        KadPumpCommand::CallbackWalk(ask) => callback_walks.begin(handle, ask).await,
    }
}

/// The pump is gone: close its command queue and end every keyword search
/// still queued in it as never taken by the node, so no leg reads a walk
/// that never ran as done.
pub(super) fn refuse_queued(commands: &mut tokio::sync::mpsc::Receiver<KadPumpCommand>) {
    commands.close();
    while let Ok(command) = commands.try_recv() {
        if let KadPumpCommand::SearchKeyword { results, .. } = command {
            results.tell(KadWalkFact::Ended(KadKeywordEnd::NotTaken));
        }
    }
}
