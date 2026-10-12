//! **Direct-callback consume**: the `OP_DIRECTCALLBACKREQ` (`0x95`) a requester
//! sends straight to our UDP surface when we are TCP-firewalled but UDP-open —
//! the buddy-free path, which is why this node advertises it instead of
//! recruiting.
//!
//! Its refusal matrix, aMule's guards
//! ([`ClientUDPSocket.cpp#L277`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientUDPSocket.cpp#L277)),
//! in the order they are consulted: our TCP verdict reading reachable →
//! [`NotFirewalled`](DirectCallbackRefusal::NotFirewalled) (we advertised
//! direct-callback support while firewalled and may have opened since); Kad not
//! running → [`KadDown`](DirectCallbackRefusal::KadDown); and this source IP
//! honored again inside the window →
//! [`RateLimited`](DirectCallbackRefusal::RateLimited); and the two crypt
//! stances that cannot meet →
//! [`CryptIncompatible`](DirectCallbackRefusal::CryptIncompatible). Everything
//! else is dialed back, obfuscated per the requester's connect-options.
//!
//! The rate limit is an [`IntervalLimiter`](crate::interval_limiter) — the source IP is
//! unauthenticated (it is just the datagram source), so both its per-datagram
//! cost and its memory are bounded against a spoofed-source flood.
//!
//! The crypt stances' two-reading rule itself — [`PeerCrypt::outbound`] — lives
//! in `rmule-primitives`, not here: the ADR-0058
//! firewall-check dial-back reads the identical rule off a `0x53`'s
//! connect-options and every download dial reads it off a source record, so
//! one home serves every route rather than copies drifting apart.

use rmule_primitives::AccountingKey;
use std::time::{Duration, Instant};

use rmule_net::peer::ObfuscationPolicy;
use rmule_peer::peer_udp::crypt::stance_from_connect_options;
use rmule_primitives::{OutboundCrypt, PeerCrypt, PeerEndpoint, UserHash};

use super::FirewalledNode;
use crate::reachability::TcpReachability;

/// Per-source-IP minimum interval between honored direct-callback (`0x95`)
/// requests: aMule's `CClientList::AllowCallbackRequest`
/// ([`ClientList.cpp#L1115`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L1115)),
/// which refuses a source IP seen inside `MIN2MS(3)`. One honored request per
/// IP per three minutes; a flood inside the window is refused, and only the
/// honored one stamps the clock (`AddTrackCallbackRequests`, `:1101`, is called
/// in the accept branch alone).
///
/// **Capture-pinned** (ADR-0045, harness flow N `kad-direct-callback`): seven identical `0x95`
/// datagrams went out at a 30 s cadence and a stock aMule honored exactly two,
/// 180.011 s apart. Not `SEC2MS(45)`: that is the *emit* side's
/// `m_dwDirectCallbackTimeout` (`BaseClient.cpp#L1508`) — how long the
/// requester waits for its answer, a different clock on the other end of the
/// exchange. aMule 2.3.3 has no `DIRECTCALLBACKTIMEOUT` symbol at all.
pub(super) const DIRECT_CALLBACK_MIN_INTERVAL: Duration = Duration::from_secs(3 * 60);

/// Hard cap on tracked honored-`0x95` source IPs. The source IP is
/// unauthenticated (it is just the datagram source), so a spoofed-source
/// flood would otherwise grow the tracker by one entry per distinct IP for
/// the whole 3-minute window — unbounded memory, and a per-datagram map scan
/// would go quadratic with it. aMule prunes its `CClientList`
/// tracked-requests list per call but never caps it; the cap is rmule's own
/// hardening — at the cap the oldest honored entry is evicted, trading an
/// earlier-than-window re-honor of that one IP for bounded memory under
/// flood. 4096 is ~2 orders of magnitude above any legitimate 3-minute
/// honored-request population (each honored request costs us a TCP
/// dial-back).
pub(super) const DIRECT_CALLBACK_TRACKED_MAX: usize = 4096;

/// The parsed `OP_DIRECTCALLBACKREQ` (`0x95`) facts the direct-callback consume
/// reads. [`DirectCallbackReq`](rmule_peer::DirectCallbackReq) decodes the
/// datagram body; the requester's IP is the datagram source (not the body).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectCallbackConsume {
    /// The requester's endpoint: its IP (the datagram source) and the TCP port
    /// its `0x95` body carried — where we dial back.
    ///
    /// Family-generic (ADR-0087): the body names no address, so the requester
    /// *is* the datagram's source and an IPv6 one is dialed back at rung 0
    /// unchanged. The rate limit buckets by **Accounting Key**, a `/64` for
    /// IPv6, so such a requester is limited rather than exempted.
    pub(crate) requester: PeerEndpoint,
    /// The requester's user hash (its `0x95` body) — the key basis for
    /// obfuscating the dial-back.
    pub(crate) user_hash: UserHash,
    /// The requester's connect-options (its crypt stance) — whether/how to
    /// obfuscate the dial-back.
    pub(crate) connect_options: u8,
}

/// Our position the direct-callback consume gates on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectCallbackContext {
    /// Our TCP verdict: the `0x95` is honored **only while we are still
    /// firewalled** — we advertised direct-callback support because we were
    /// firewalled, and we may since have changed status (aMule's re-check).
    pub(crate) tcp: TcpReachability,
    /// Kad is running.
    pub(crate) kad_running: bool,
    /// **Our own** obfuscation policy (`CoreSettings::obfuscation`, ADR-0046) —
    /// `None` when obfuscation is off entirely. It gates the dial-back exactly
    /// as it gates every other dial: a requester that *requires* obfuscation
    /// gets nothing from a node whose crypt is disabled.
    pub(crate) crypt: Option<ObfuscationPolicy>,
}

/// What [`consume_direct_callback`](FirewalledNode::consume_direct_callback)
/// decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectCallbackVerdict {
    /// Dial the requester back over TCP.
    DialBack {
        requester: PeerEndpoint,
        /// The **User Hash** the dial-back's crypt handshake keys on — the
        /// requester's own, out of its `0x95` body — or `None` for a plaintext
        /// dial-back. The initiator always keys on the *target's* hash
        /// (`PeerObfuscationTransport::initiator`), which here is the peer we
        /// are calling back; aMule passes the same one
        /// (`m_socket->SetConnectionEncryption(true, GetUserHash().GetHash(), false)`,
        /// [`BaseClient.cpp#L1615`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1615)).
        obfuscate_toward: Option<UserHash>,
    },
    /// Refuse silently — with the precise reason.
    Refuse { reason: DirectCallbackRefusal },
}

/// Why a `0x95` was refused (aMule's guards).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectCallbackRefusal {
    /// Our TCP surface reads reachable — we are no longer firewalled, so a
    /// direct callback to us is spurious (the status changed since we published).
    NotFirewalled,
    /// Kad is not running.
    KadDown,
    /// This source IP requested again inside the rate-limit window — a flood.
    RateLimited,
    /// The two crypt stances cannot meet: the requester requires obfuscation
    /// and this node does not support it, or this node requires it and the
    /// requester does not support it. aMule refuses the same pair before it
    /// opens a socket (`CUpDownClient::TryToConnect`,
    /// [`BaseClient.cpp#L1409`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1409)),
    /// so a requester that demanded obfuscation from a node with crypt off is
    /// told nothing and dialed nothing — the one refusal that is our *own*
    /// configuration talking, which is why it is counted apart.
    CryptIncompatible,
}

impl FirewalledNode {
    /// Consume an `OP_DIRECTCALLBACKREQ` (`0x95`): rate-limited per source IP,
    /// honored only while we are still firewalled and Kad runs, then dial back
    /// — obfuscated toward the requester's own hash when both stances ask for
    /// it. On accept the source IP's rate-limit clock is stamped.
    ///
    /// The crypt reading comes **after** the limiter on purpose: aMule stamps
    /// its tracker (`AddTrackCallbackRequests`) the moment it decides to honour
    /// the request and only then lets `TryToConnect` refuse the pair, so an
    /// incompatible requester still spends its window rather than being free to
    /// retry every datagram.
    pub(crate) fn consume_direct_callback(
        &mut self,
        req: &DirectCallbackConsume,
        ctx: &DirectCallbackContext,
        now: Instant,
    ) -> DirectCallbackVerdict {
        // aMule `ClientUDPSocket.cpp#L277`: honor the direct callback only while
        // we are actually still firewalled (we may have opened since we published
        // direct-callback support) and Kad runs, and rate-limit it per source IP.
        if ctx.tcp.is_reachable() {
            return DirectCallbackVerdict::Refuse {
                reason: DirectCallbackRefusal::NotFirewalled,
            };
        }
        if !ctx.kad_running {
            return DirectCallbackVerdict::Refuse {
                reason: DirectCallbackRefusal::KadDown,
            };
        }
        if !self
            .direct_callbacks
            .admit(AccountingKey::of(req.requester.ip()), now)
        {
            return DirectCallbackVerdict::Refuse {
                reason: DirectCallbackRefusal::RateLimited,
            };
        }
        let requester = PeerCrypt::new(
            stance_from_connect_options(req.connect_options),
            Some(req.user_hash),
        );
        match requester.outbound(ObfuscationPolicy::stance_of(ctx.crypt)) {
            OutboundCrypt::Plaintext => DirectCallbackVerdict::DialBack {
                requester: req.requester,
                obfuscate_toward: None,
            },
            OutboundCrypt::Obfuscated { toward, .. } => DirectCallbackVerdict::DialBack {
                requester: req.requester,
                obfuscate_toward: Some(toward),
            },
            OutboundCrypt::Incompatible => DirectCallbackVerdict::Refuse {
                reason: DirectCallbackRefusal::CryptIncompatible,
            },
        }
    }
}
