//! The **Side** group of [`PeerCommand`](super::PeerCommand): what core's
//! node-wide services send over the link — the Kad firewall-check frames
//! (ADR-0058) and the buddy relay (ADR-0061). Every decision behind them is
//! core's; the session only frames what it is told, once the hello is done.

use crate::buddy::{Callback, ReaskCallbackTcp};
use crate::packet::PeerPacket;

use super::super::PeerSession;

/// A frame a node-wide service sends over the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SideCommand {
    /// Kad firewall-check **dial-back** ack (ADR-0058 responder, v7+ path): frame
    /// the empty-body `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) over this link. Core sends
    /// it once its Kad-brokered dial-back to a firewalled requester identifies —
    /// the connect-back that proves the requester's TCP port is open. The session
    /// stays Kad-ignorant: it only frames the null packet, guarded by the same
    /// `require_identified` precondition every emit uses (aMule sends the ack in
    /// `KS_CONNECTED_FWCHECK`, i.e. after the dial-back's hello completes).
    SendKadFirewallAck,
    /// Kad UDP firewall-check request (ADR-0058 requester): frame `request` as
    /// `OP_FWCHECKUDPREQ` (`0xA7`) over this link. Core sends it once its dial
    /// to an engaged UDP Firewall Helper identifies — aMule sends it on
    /// `KS_CONNECTING_FWCHECK_UDP` → `KS_FWCHECK_UDP`, i.e. once the hello
    /// completed (`BaseClient.cpp:2520-2522`). The body is the Kad node's,
    /// framed as given.
    SendKadUdpFirewallRequest {
        /// The `<intern port 2><extern port 2><sender key 4>` body.
        request: Vec<u8>,
    },
    /// Open-node buddy relay of a Kad `0x52`→`0x99` callback (ADR-0061):
    /// frame the `OP_CALLBACK` (`0x99`) over *this* buddy link. Core issues it once
    /// its single-slot buddy service verifies the relayed callback's buddy-ID
    /// against our registered buddy; the session only frames the pre-built packet,
    /// guarded by `require_identified` (the buddy link is a completed peer session).
    SendBuddyCallback(Callback),
    /// Open-node buddy relay of a peer-UDP `0x94`→`0x9A` reask (ADR-0061):
    /// frame the `OP_REASKCALLBACKTCP` (`0x9A`) over this buddy link. Emit-side twin
    /// of [`Self::SendBuddyCallback`].
    SendReaskCallbackTcp(ReaskCallbackTcp),
    /// Answer an `OP_BUDDYPING` with `OP_BUDDYPONG` (`0xA0`) over this buddy link
    /// (ADR-0061). Core issues it only when its buddy service confirms the
    /// ping came from our registered buddy (a stranger's ping is refused there);
    /// the session frames the null pong, guarded by `require_identified`.
    SendBuddyPong,
    /// Keep our own buddy link alive with `OP_BUDDYPING` (`0x9F`, ADR-0061
    /// firewalled-node operation): aMule's firewalled client dials its buddy
    /// and pings it for as long as it stays firewalled
    /// ([`BaseClient.cpp#L2544`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L2544),
    /// driven from
    /// [`ClientList.cpp#L662`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L662)).
    /// The cadence is the firewalled front's; the session frames the null
    /// packet, guarded by `require_identified` like every other emit — the
    /// mirror of [`Self::SendBuddyPong`], which answers one.
    SendBuddyPing,
}

impl PeerSession {
    pub(super) fn apply_side(&mut self, command: SideCommand) {
        if !self.require_identified() {
            return;
        }
        let packet = match command {
            SideCommand::SendKadUdpFirewallRequest { request } => {
                PeerPacket::KadUdpFirewallRequest(request).encode()
            }
            // ADR-0058 responder dial-back ack: the null `OP_KAD_FWTCPCHECK_ACK`
            // over this link, sent only once the requester's hello completed
            // (aMule's `KS_CONNECTED_FWCHECK`). Nothing else — the ack's whole
            // meaning is its arrival on the connection we dialed back.
            SideCommand::SendKadFirewallAck => PeerPacket::KadFirewallAck.encode(),
            // ADR-0061 open-node buddy relays: framed directly from the
            // `crate::buddy` codecs, never round-tripped through the umbrella,
            // which parks these opcodes as `Unknown`. The verify decisions
            // (buddy-ID match, the pong's our-buddy gate) already happened
            // core-side.
            SideCommand::SendBuddyCallback(callback) => callback.encode_packet(),
            SideCommand::SendReaskCallbackTcp(relay) => relay.encode_packet(),
            SideCommand::SendBuddyPong => PeerPacket::BuddyPong.encode(),
            SideCommand::SendBuddyPing => PeerPacket::BuddyPing.encode(),
        };
        self.write_packet(packet);
    }
}
