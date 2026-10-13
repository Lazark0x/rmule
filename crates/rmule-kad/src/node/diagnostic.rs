//! The node's diagnostic vocabulary: everything it refused, dropped or found
//! malformed, named precisely enough that a driver can log it without guessing.
//! A diagnostic is never a state change — it is the node saying what it
//! declined to do.

use std::net::Ipv4Addr;

use super::KadPublishRejection;
use crate::buddy::BuddyDecodeError;
use crate::keyword_store::KeywordDecodeError;
use crate::messages::Kad2MessageDecodeError;
use crate::notes::{NotesDecodeError, NotesPublishRefusal};
use crate::reachability::FirewallDecodeError;
use crate::{KadEnvelopeDecodeError, KadId, KadNodeEndpoint, KadSourceResultDecodeError};

/// Why an inbound datagram was rejected or ignored. Diagnostics are ordinary
/// trace data — a hostile or buggy peer must never panic the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadNodeDiagnostic {
    /// The bytes are not a well-formed Kad envelope (bad protocol byte,
    /// truncation, malformed or oversized packed payload).
    UndecodableEnvelope {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the envelope decoder objected to.
        error: KadEnvelopeDecodeError,
    },
    /// The envelope decoded but the payload is not a valid in-role message
    /// (malformed layout or an opcode outside the implemented roles).
    UndecodableMessage {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the message decoder objected to.
        error: Kad2MessageDecodeError,
    },
    /// A `KADEMLIA2_REQ` whose check ID is not this node's ID: misrouted or
    /// forged; aMule validates and drops the same way.
    LookupCheckMismatch {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A hello response from an endpoint this node never probed.
    UnsolicitedHelloRes {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A `0x22` ACK from an endpoint this node never asked to verify (no
    /// outstanding ack-request): unsolicited, dropped without verifying.
    UnsolicitedHelloResAck {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A solicited `0x22` ACK that did not verify its contact: it lacked a valid
    /// receiver key (a plaintext ACK, or one echoing a key we never handed that
    /// IP) or named a stale ID/IP. The solicitation is consumed either way; the
    /// contact stays unverified.
    HelloResAckUnverified {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A bootstrap response from an endpoint this node never bootstrapped to.
    UnsolicitedBootstrapRes {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A lookup response without an outstanding lookup (requester work).
    UnsolicitedLookupRes {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A pong without an outstanding ping.
    UnsolicitedPong {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A probed endpoint answered with a different identity than expected;
    /// the stored contact is evicted and the claimed identity distrusted.
    HelloResIdMismatch {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// The ID we had probed.
        expected: KadId,
        /// The ID the answer claimed instead.
        reported: KadId,
    },
    /// A `KADEMLIA2_SEARCH_RES` from an endpoint no active search sent a
    /// `0x34` to. Its payload is never decoded, let alone projected.
    UnsolicitedSearchRes {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A solicited endpoint answered a search for a different target than it
    /// was asked; the rows are discarded unprojected.
    SearchResTargetMismatch {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A solicited endpoint's search result payload did not decode.
    MalformedSearchRes {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the source-result decoder objected to.
        error: KadSourceResultDecodeError,
    },
    /// A `SearchSources` command for a target that is already being walked;
    /// the existing walk is kept.
    DuplicateSourceSearch {
        /// The key the request named.
        target: KadId,
    },
    /// A `PublishSource` command for a target that is already registered;
    /// the existing registration (and its cadence) is kept.
    DuplicatePublish {
        /// The key the request named.
        target: KadId,
    },
    /// A `KADEMLIA2_PUBLISH_RES` from an endpoint no active publish fanned a
    /// `0x44` to (or after the publish completed).
    UnsolicitedPublishRes {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A solicited endpoint acked a different key than it was sent; the ack
    /// is not counted.
    PublishResTargetMismatch {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A publish for a key too far from this node's ID (the XOR distance's
    /// most significant 32-bit word exceeds the tolerance) from a non-LAN
    /// sender. aMule drops these silently; rmule diagnoses the drop.
    PublishOutsideTolerance {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A well-formed publish the storer declined to index. Never acked —
    /// the publisher sees silence, exactly like aMule's reject path.
    PublishRejected {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// Why the storer declined to index the row.
        reason: KadPublishRejection,
    },
    /// A `0x50`/`0x53` firewall check whose payload failed aMule's size gate
    /// (exact-2 / min-19). Diagnosed and dropped; no `0x58`, no dial-back.
    MalformedFirewallCheck {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the firewall-check decoder objected to.
        error: FirewallDecodeError,
    },
    /// A `0x50`/`0x53` firewall check answered with `0x58` but **not** dialed
    /// back, because that IP has one of our own checks outstanding.
    ///
    /// Two nodes checking each other inside one hello burst would otherwise
    /// collide: the dial-back hands the requester a socket its own responder
    /// adopts instead of dialing, and both checks end proving nothing. A
    /// documented divergence from aMule 2.3.3; see
    /// `KadNode::dial_back_would_poison_our_own_check`.
    DialBackRefusedMutualCheck {
        /// The requester whose check went unanswered by a connect-back.
        from: KadNodeEndpoint,
    },
    /// A datagram from UDP source port 53 was dropped before any decrypt or
    /// decode attempt (ADR-0064's DNS-confusion guard). Plaintext-only
    /// rmule degenerates to drop-all-port-53; the sender-key exemption
    /// activates once ADR-0046 keys are armed.
    Port53Dropped {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A contact intake refused because the endpoint's IP is filtered (the
    /// [`KadContactAdmission`](crate::KadContactAdmission) verdict): aMule's IP-filter consult
    /// at `CRoutingZone::Add` (`RoutingZone.cpp#L406`), the nodes.dat and
    /// bootstrap-file loads (`#L195`, `#L252`), and the lookup-response row
    /// drop (`KademliaUDPListener.cpp#L733`). The contact is never stored,
    /// probed, walked, or dialed.
    ContactIpFiltered {
        /// The endpoint concerned.
        endpoint: KadNodeEndpoint,
    },
    /// A contact the routing table refused because storing it would break an
    /// admission cap (ADR-0064): one contact per IP and ten per /24
    /// table-wide, two per /24 in a bucket. A newcomer is never stored; a known
    /// contact claiming a new IP keeps its old entry.
    ContactOverAdmissionCap {
        /// The endpoint the contact arrived at.
        endpoint: KadNodeEndpoint,
        /// The cap that refused it.
        cap: crate::KadAdmissionCap,
    },
    /// A request opcode's per-`(IP, opcode)` leaky bucket exceeded its
    /// per-minute rate (ADR-0064); the datagram is dropped before
    /// dispatch. Responses are never bucketed — solicitation correlation
    /// owns those.
    FloodLimited {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// The opcode whose bucket the datagram fell in.
        opcode: u8,
    },
    /// A `0x58`/`0x59` firewall **response** with no matching outstanding-check
    /// window — the sender was never asked to check us (or our own check is
    /// disabled), or its 180 s window already lapsed. aMule drops it as an
    /// "unrequested firewall response"; rmule diagnoses the drop. Also carries a
    /// `0x62` UDP result our tester did not request (unarmed, or an IP we never
    /// engaged), the same "unrequested firewall response" aMule logs.
    UnrequestedFirewallResponse {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// The opcode whose bucket the datagram fell in.
        opcode: u8,
    },
    /// An `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) from an IP no TCP check of ours is
    /// outstanding against — never asked, its 180 s window lapsed, a recheck
    /// dropped it, or our check is unarmed. Not counted (aMule
    /// `IsKadFirewallCheckIP`, `ClientTCPSocket.cpp`).
    UnrequestedFirewallAck {
        /// The IP of the peer link the ack arrived on.
        from: Ipv4Addr,
    },
    /// A `0x62 KADEMLIA2_FIREWALLUDP` result whose payload failed the three-byte
    /// gate (ADR-0058 UDP tester). Diagnosed and dropped; the tester is untouched.
    MalformedFirewallUdpResult {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the firewall-check decoder objected to.
        error: FirewallDecodeError,
    },
    /// An `OP_FWCHECKUDPREQ` (`0xA7`) the helper-responder could not honor — its
    /// payload was not the fixed eight bytes, or it named intern port 0 (aMule
    /// `ProcessFirewallCheckUDPRequest`'s reject). No `0x62` is sent.
    UnhonorableFirewallUdpRequest {
        /// The peer that asked.
        requester: Ipv4Addr,
    },
    /// A `0x51`/`0x5A`/`0x52` buddy/callback envelope whose payload failed aMule's
    /// 34-byte gate (ADR-0061). Diagnosed and dropped; no answer, no relay.
    MalformedBuddyMessage {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the buddy decoder objected to.
        error: BuddyDecodeError,
    },
    /// A `0x5A KADEMLIA_FINDBUDDY_RES` with no matching outstanding recruitment —
    /// the sender was never sent a `0x51` (its tracked window lapsed), or its
    /// echoed target failed the XOR-inversion guard (`~buddy_id != ourKadID`, a
    /// stale or spoofed answer). aMule drops it at `CHECK_TRACKED_PACKET` / the
    /// `GetKadID() == check` guard; rmule diagnoses the drop.
    UnrequestedBuddyResponse {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A `0x33`/`0x43` keyword request whose payload did not decode as its
    /// documented layout (or used an unknown search operator). Diagnosed and
    /// dropped; never panics.
    UndecodableKeywordReq {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the keyword decoder objected to.
        error: KeywordDecodeError,
    },
    /// A solicited keyword `0x3B` result whose payload did not decode. The rows
    /// are discarded; the walk keeps its other endpoints' answers.
    MalformedKeywordRes {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A well-formed `KADEMLIA2_PUBLISH_KEY_REQ` the storer refused before
    /// indexing — this node is UDP-firewalled, or the keyword is outside the
    /// tolerance gate. Wire-silent (no `0x4B`), exactly like aMule's early
    /// return.
    KeywordPublishRefused {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
    },
    /// A `SearchKeywords` command whose query has no ≥ 3-byte token, so it
    /// derives no keyword target to walk toward.
    UnsearchableKeywordQuery,
    /// A `SearchKeywords` command for a keyword target a keyword search already
    /// walks: the command joins that walk, whose one `KeywordSearchComplete`
    /// answers both.
    DuplicateKeywordSearch {
        /// The key the request named.
        target: KadId,
    },
    /// A keyword search took the target of a running keyword publish walk: the
    /// publish ended without a completion and its round is due again.
    KeywordPublishPreempted {
        /// The keyword whose publish gave way.
        keyword: KadId,
    },
    /// A `FindBuddyWalk` command for a target already being walked; the walk
    /// in flight is kept, and its own `BuddyWalkEnded` answers for both.
    DuplicateFindBuddyWalk {
        /// The recruitment target the command named.
        target: KadId,
    },
    /// A `0x35`/`0x45` notes request whose payload did not decode as its
    /// documented layout (or used an unknown search operator). Diagnosed and
    /// dropped; never panics, never replies — the existing envelope-tolerance
    /// path (ADR-0063).
    UndecodableNotesReq {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// What the notes decoder objected to.
        error: NotesDecodeError,
    },
    /// A well-formed `0x45` notes publish this node refused (ADR-0063
    /// Empty-Storer Parity) — gate-ordered classification, mirroring aMule's
    /// own check order. Never acked (no `0x4B`): rmule builds no notes state,
    /// so nothing is ever accepted. `reason` is the `refused-*` classification
    /// counter.
    NotesPublishRefused {
        /// Where the datagram came from.
        from: KadNodeEndpoint,
        /// Why the notes publish was refused.
        reason: NotesPublishRefusal,
    },
}
