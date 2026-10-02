//! The requester's peer-TCP leg of the ADR-0058 UDP self-check, which only
//! the core can enact: dial an engaged **UDP Firewall Helper**, complete the
//! hello, send the Kad node's `OP_FWCHECKUDPREQ`, hold the link the way an
//! aMule socket would, and report how it ended so the node can count it. The
//! `0x62` the helper answers with never touches this leg — it arrives on the
//! Kad socket and the node matches it by the helper's IP.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{PeerCommand, PeerEvent, PeerHandshakeContext};
use rmule_primitives::{Ipv4Endpoint, PeerCrypt, PeerEndpoint};

use super::{KadPumpCommand, SharedKadPump, push_kad_pump};
use crate::adapters::HelloAdverts;
use crate::peer_roster::SharedPeerRoster;

/// How long the link to a helper is held after the request went out: aMule's
/// idle-socket `CONNECTION_TIMEOUT` (40 s, `protocol/ed2k/Constants.h:34`).
/// aMule never closes this link on purpose — it idles out, and that
/// disconnect is what counts the helper failed if no `0x62` came first.
pub(crate) const UDP_CHECK_LINK_HOLD: Duration = Duration::from_secs(40);

/// How the link to one engaged helper ended — the two outcomes aMule's
/// `CUpDownClient::Disconnected` tells its tester apart
/// (`BaseClient.cpp:1730-1739`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpCheckLinkEnd {
    /// The request never went out: the dial was refused, the hello never
    /// completed, or the helper's hello named no Kad port or a Kad version
    /// below 6 (`:3972-3979`). Counts neither way; the slot is freed.
    Cancelled,
    /// The request went out and the link then closed — by the helper, or by
    /// our idle hold. The ordinary end of every check, the answered ones
    /// included: aMule never closes this link on purpose. Reported to the node
    /// as a failure, which it counts only for a helper whose `0x62` has not
    /// landed (`UdpFirewallTester` drops the rest as already answered), so
    /// the link end alone says nothing about the verdict.
    Closed,
}

impl UdpCheckLinkEnd {
    /// The node command that reports this end for `helper_ip`.
    fn command(self, helper_ip: Ipv4Addr) -> KadPumpCommand {
        match self {
            Self::Cancelled => KadPumpCommand::UdpFirewallCheckCancelled(helper_ip),
            Self::Closed => KadPumpCommand::UdpFirewallCheckFailed(helper_ip),
        }
    }
}

/// Run one helper's check and report its end to the running node through
/// `sink` — the pump's fire-and-forget form of
/// [`enact_udp_firewall_check`]. A node that stopped meanwhile hears nothing.
///
/// **The requester gate runs first** (ADR-0058): aMule's
/// `CClientList::DoRequestFirewallCheckUDP` refuses to test a helper IP the
/// client list already knows (`ClientList.cpp:1204-1211`) — the sans-I/O
/// node cannot hold that state itself, so `roster` applies the gate here,
/// before any dial, and reports the same cancelled outcome an unfit hello
/// would (`:3972-3979`): no request ever leaves, and the slot frees for the
/// next candidate.
pub(crate) async fn run_udp_firewall_check(
    helper: Ipv4Endpoint,
    request: Vec<u8>,
    ctx: PeerHandshakeContext,
    adverts: HelloAdverts,
    sink: SharedKadPump,
    roster: SharedPeerRoster,
) {
    let end = if roster.knows(helper.ip) {
        UdpCheckLinkEnd::Cancelled
    } else {
        enact_udp_firewall_check(helper, request, ctx, &adverts, UDP_CHECK_LINK_HOLD).await
    };
    tracing::debug!(
        ?helper,
        ?end,
        "kad UDP firewall check: helper link ended (the node decides whether it counts)"
    );
    push_kad_pump(&sink, end.command(helper.ip));
}

/// Dial `helper`, complete the eD2k hello, send `request` as
/// `OP_FWCHECKUDPREQ` and hold the link until the helper closes it or `hold`
/// lapses (aMule `KS_QUEUED_FWCHECK_UDP` → `KS_CONNECTING_FWCHECK_UDP` →
/// `KS_FWCHECK_UDP`, `BaseClient.cpp:1987-1988`, `:2520-2522`).
///
/// The hello is the one every outbound connection sends, from the same
/// [`HelloAdverts`] read: the helper learns our ports, Kad version,
/// IPv6 and crypt stance as any other peer would. The dial itself is
/// plaintext, under every policy: the helper's User Hash — the obfuscation
/// key — is not known (aMule creates the helper's client without one,
/// `ClientList.cpp:1212-1218`). Under `Required` this link is an **outbound
/// Test Connection** (ADR-0046): it carries our hello and the
/// request, asks nothing and serves nothing, and states our true crypt stance.
/// aMule's own `Required` dials nothing here and so never verifies UDP ("the
/// whole check won't work on "Require Obfuscation" setting",
/// `ClientList.cpp:1213-1215`); rmule departs so that Kad UDP can read Open
/// under that policy.
pub(crate) async fn enact_udp_firewall_check(
    helper: Ipv4Endpoint,
    request: Vec<u8>,
    ctx: PeerHandshakeContext,
    adverts: &HelloAdverts,
    hold: Duration,
) -> UdpCheckLinkEnd {
    let dialed = dial_plain_test(PeerEndpoint::V4(helper), ctx, adverts).await;
    let Ok((mut conn, identity)) = dialed else {
        return UdpCheckLinkEnd::Cancelled;
    };
    if !identity.serves_udp_firewall_checks() {
        let _ = conn.shutdown().await;
        return UdpCheckLinkEnd::Cancelled;
    }
    if conn
        .send(PeerCommand::SendKadUdpFirewallRequest { request })
        .await
        .is_err()
    {
        return UdpCheckLinkEnd::Cancelled;
    }
    let _ = tokio::time::timeout(hold, async {
        while let Some(event) = conn.next_event().await {
            if matches!(event, PeerEvent::Disconnected { .. }) {
                break;
            }
        }
    })
    .await;
    let _ = conn.shutdown().await;
    UdpCheckLinkEnd::Closed
}

/// Dial `peer` in the clear whatever our policy, and drive the hello until it
/// identifies — the outbound half of a Test Connection (ADR-0046). The
/// session still advertises the policy's crypt stance.
async fn dial_plain_test(
    peer: PeerEndpoint,
    ctx: PeerHandshakeContext,
    adverts: &HelloAdverts,
) -> Result<(PeerConnection, rmule_peer::PeerIdentity), ()> {
    let options = adverts.connect_options(PeerCrypt::unknown());
    let stream = PeerConnection::dial_stream(peer, options.connect_timeout, None)
        .await
        .map_err(|_| ())?;
    let mut conn = PeerConnection::over_stream(
        stream,
        peer,
        rmule_net::peer::PeerStreamRole::Dialer,
        ctx,
        options,
    );
    loop {
        match conn.next_event().await {
            Some(PeerEvent::PeerIdentified { identity }) => return Ok((conn, identity)),
            Some(PeerEvent::Disconnected { .. }) | None => return Err(()),
            Some(_) => {}
        }
    }
}

#[cfg(test)]
mod tests;
