//! The status-challenge gate (ADR-0052): the per-server registry of
//! outstanding `0x96` / crypt-ping challenges, shared between the sweep that
//! mints and registers them before each send and the engine that settles them
//! when a `0x97` echoes one back. The one lookup is the anti-spoof gate for
//! the capability store, the ping measurement, and — for a crypt-ping, whose
//! challenge doubles as the RC4 base key — the reply's decrypt keying
//! (ADR-0046). Also home to the OS-entropy challenge minting both
//! chains draw in production.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmule_primitives::Ipv4Endpoint;

/// One outstanding status-ping challenge: the `u32` rmule sent, when it went
/// out, and whether it was an obfuscated **crypt-ping** (ADR-0046). For a
/// crypt-ping the same value is both the echo the `0x97` must carry *and* the
/// RC4 base key its reply is encrypted under, so the engine keys its dual-path
/// decrypt on it.
///
/// `sent_at` is what makes the **Ping** column measurable (ADR-0080 §Dynamic
/// server facts): the round trip is stamped here, at the last instant before
/// the datagram leaves, and read where the reply passes the gate — the only
/// two points that know it is the same ping.
#[derive(Clone, Copy)]
struct OutstandingPing {
    challenge: u32,
    crypt: bool,
    sent_at: tokio::time::Instant,
}

/// The outstanding status-ping challenges, server TCP endpoint → what rmule
/// sent it (ADR-0052). The anti-spoof gate for the capability store: a
/// `0x97` is consumed only when it echoes the challenge on record for its
/// answering server — an entry exists only for a pinged, known server, so the
/// one lookup covers both "unknown server" and "unsolicited reply". The
/// status-ping sweep registers via [`expect`](Self::expect) (plain) or
/// [`expect_crypt`](Self::expect_crypt) (obfuscated); expiry is replacement —
/// the next sweep's ping overwrites (aMule likewise re-mints per ping and
/// zeroes the challenge once answered).
#[derive(Clone, Default)]
pub(crate) struct StatusChallenges(Arc<Mutex<HashMap<Ipv4Endpoint, OutstandingPing>>>);

impl StatusChallenges {
    /// Record a plain `0x96` challenge just pinged to `server` (its TCP
    /// endpoint), replacing any unanswered one — the sweep's registration hook
    /// (ADR-0052 breakdown 3).
    pub(crate) fn expect(&self, server: Ipv4Endpoint, challenge: u32) {
        self.0
            .lock()
            .expect("outstanding status challenges")
            .insert(
                server,
                OutstandingPing {
                    challenge,
                    crypt: false,
                    sent_at: tokio::time::Instant::now(),
                },
            );
    }

    /// Record an obfuscated crypt-ping challenge (ADR-0046), replacing
    /// any prior entry — a subsequent plain fallback overwrites it back.
    pub(crate) fn expect_crypt(&self, server: Ipv4Endpoint, challenge: u32) {
        self.0
            .lock()
            .expect("outstanding status challenges")
            .insert(
                server,
                OutstandingPing {
                    challenge,
                    crypt: true,
                    sent_at: tokio::time::Instant::now(),
                },
            );
    }

    /// Settle the outstanding challenge for `server` iff `echoed` matches: the
    /// entry is removed, the reply accepted, and the ping's round trip
    /// returned. A mismatch (or no outstanding ping) yields `None` and leaves
    /// the entry untouched — the genuine answer can still arrive after a forged
    /// one.
    pub(crate) fn settle(&self, server: Ipv4Endpoint, echoed: u32) -> Option<Duration> {
        let mut outstanding = self.0.lock().expect("outstanding status challenges");
        match outstanding.get(&server) {
            Some(ping) if ping.challenge == echoed => {
                let round_trip = ping.sent_at.elapsed();
                outstanding.remove(&server);
                Some(round_trip)
            }
            _ => None,
        }
    }

    /// The RC4 base key to decrypt a crypt-ping's `0x97` reply, if an
    /// obfuscated crypt-ping is outstanding for `server` — its challenge
    /// doubles as the base key (aMule keys `DecryptReceivedServer` on
    /// `GetChallenge()` while `CryptPingReplyPending`).
    pub(crate) fn crypt_base_key(&self, server: Ipv4Endpoint) -> Option<u32> {
        self.0
            .lock()
            .unwrap()
            .get(&server)
            .filter(|ping| ping.crypt)
            .map(|ping| ping.challenge)
    }

    /// Whether `challenge` is still the one awaited from `server`: `false`
    /// once its answer settled it, or once a later probe replaced it.
    pub(crate) fn awaits(&self, server: Ipv4Endpoint, challenge: u32) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(&server)
            .is_some_and(|ping| ping.challenge == challenge)
    }

    /// Whether an obfuscated crypt-ping is still outstanding for `server` —
    /// the sweep's fallback gate. A settled reply removes the entry, so
    /// `false` means the probe was answered and no plain fallback is due.
    pub(crate) fn crypt_outstanding(&self, server: Ipv4Endpoint) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(&server)
            .is_some_and(|ping| ping.crypt)
    }
}

/// OS-entropy low half for challenge minting — the production value for the
/// sweep's `0x96` pings and the engine's `0xA2` desc-reqs (tests pass a
/// fixed fn instead).
pub(crate) fn os_rand16() -> u16 {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).expect("OS entropy for server-UDP challenge");
    u16::from_le_bytes(bytes)
}
