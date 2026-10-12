//! The **Status Ping Sweep** (ADR-0052 breakdown 3): the `0x96` pacing loop
//! that solicits every listed server's status — never-probed servers in a
//! first-contact burst, refreshes one per 5 s tick once a server's 20 min
//! re-ask window lapses, a row listed by name resolved when its ping is due
//! (ADR-0052's amendment),
//! fire-and-forget with the challenge registered on the gate before the send —
//! plus its obfuscated crypt-ping arm (ADR-0046): the raw probe to the
//! obfuscation port whose challenge doubles as the reply's RC4 base key, with
//! a 20 s reply grace before the plain fallback, and its verdicts: which
//! unanswered pings count against their server (`verdict`). Home to the crypt-ping nonce
//! (the arm's injected entropy) and its raw-datagram encoding.

use std::collections::HashMap;
use std::time::Duration;

use rmule_ed2k::{GlobServStatReq, crypt_ping_challenge, crypt_ping_padding_len};
use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};

use super::{ServerUdpSeal, StatusChallenges};
use crate::adapters::ServerUdpTransport;
use crate::name_resolver::SharedNameResolver;
use crate::own_identity::SharedOwnIdentity;
use crate::server_capabilities::server_tcp_key;
use crate::server_list::{ManagedServer, ResolvedAddress, ServerFacts};

#[cfg(test)]
mod tests;
mod verdict;

use verdict::{ProbeKind, Stake, Verdicts};

/// How long a plain ping's answer may take before the ping is silent: the
/// crypt-ping's reply grace (aMule's 20 s), the one answer window the sweep
/// already keeps.
pub(crate) const ANSWER_GRACE: Duration = Duration::from_secs(20);

/// How far apart two pings may be sent for one's answer to vouch that the
/// network carried the other (ADR-0052, the offline guard): a minute holds a
/// dozen refreshes at the steady pace and the whole of a small list's pass.
pub(crate) const EVIDENCE_WINDOW: Duration = Duration::from_secs(60);

/// The randomness one obfuscated crypt-ping draws (ADR-0046), injected so
/// the raw-packet construction stays deterministic under test (the entropy-seam
/// pattern the `0x96`/`0xA2` challenges use). aMule's `ServerStats` mints a
/// nonzero 32-bit challenge and `rand() % 16` padding bytes; the challenge is
/// the reply's echo gate *and* the RC4 base key its `0x97` is encrypted under.
#[derive(Clone)]
pub(crate) struct CryptPingNonce {
    /// The nonzero crypt-ping challenge. aMule spreads it as
    /// `(rand << 17) | (rand << 2) | (rand & 3)` then forces non-zero; the
    /// server treats it as an opaque base key, so rmule draws a full-entropy
    /// non-zero `u32` (the bit layout is a PRNG artifact, not load-bearing).
    pub(crate) challenge: u32,
    /// Trailing random padding (aMule's `4 + rand() % 16` packet length,
    /// clamped by [`crypt_ping_padding_len`] to the sub-range every observed
    /// server accepts), varying the datagram size for fingerprint resistance;
    /// the server ignores its content.
    pub(crate) padding: Vec<u8>,
}

/// Encode one raw obfuscated crypt-ping: the 4-byte challenge (LE) then the
/// padding — sent **unencrypted** to the server's obfuscation UDP port, where
/// the server keys its encrypted `0x97` reply's RC4 on the challenge.
/// (aMule `ServerList.cpp` `CServerList::ServerStats` @`4e8f2b3c`),
/// `[pending]` until a crypt-capable eserver ratifies it.
fn encode_crypt_ping(nonce: &CryptPingNonce) -> Vec<u8> {
    let mut datagram = nonce.challenge.to_le_bytes().to_vec();
    datagram.extend_from_slice(&nonce.padding);
    datagram
}

/// OS-entropy crypt-ping nonce (production): a non-zero 32-bit challenge and a
/// padding length drawn inside [`crypt_ping_padding_len`]'s window, so the
/// datagram is one every observed server accepts.
pub(crate) fn os_crypt_ping_nonce() -> CryptPingNonce {
    let mut raw = [0u8; 5];
    getrandom::fill(&mut raw).expect("OS entropy for crypt-ping");
    let challenge = crypt_ping_challenge(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]));
    let mut padding = vec![0u8; crypt_ping_padding_len(raw[4])];
    getrandom::fill(&mut padding).expect("OS entropy for crypt-ping padding");
    CryptPingNonce { challenge, padding }
}

/// A server's place in the sweep's re-ask schedule, stepped once per tick.
#[derive(Clone, Copy)]
enum PingSchedule {
    /// A plain `0x96` was sent (or a crypt-ping the engine has since settled):
    /// next eligible only after the full re-ask window.
    Pinged(tokio::time::Instant),
    /// An obfuscated crypt-ping was sent at this instant to this endpoint and
    /// awaits its reply until the grace elapses; a timeout then falls back to
    /// a plain ping at the same endpoint (aMule's `CryptPingReplyPending` +
    /// 20 s window, ADR-0046).
    CryptPending(tokio::time::Instant, Ipv4Endpoint),
}

/// The status-ping sweep's walk state, stepped once per tick.
pub(crate) struct SweepState {
    /// The persistent list cursor (aMule's `GetNextStatServer` position).
    cursor: usize,
    /// Each listed row's re-ask schedule slot, keyed by the row as the
    /// operator listed it — a name keeps its slot whatever it resolves to —
    /// the clock that makes a non-answer harmless (nothing is retried early;
    /// the server is simply pinged again once its window elapses) and
    /// distinguishes a fresh plain ping from a crypt-ping awaiting its reply
    /// grace.
    schedule: HashMap<ServerEndpoint, PingSchedule>,
    /// When the last refresh probe went out — the steady pace's clock. First
    /// contacts and crypt fallbacks never stamp it.
    last_refresh: Option<tokio::time::Instant>,
    /// The recent pings, awaiting their verdicts.
    verdicts: Verdicts,
}

impl Default for SweepState {
    fn default() -> Self {
        Self {
            cursor: 0,
            schedule: HashMap::new(),
            last_refresh: None,
            verdicts: Verdicts::new(ANSWER_GRACE, EVIDENCE_WINDOW),
        }
    }
}

impl SweepState {
    /// The walk state at attach: a server whose durable figures are
    /// younger than the re-ask window counts as pinged when it last answered,
    /// so it is refreshed at the steady pace once that window lapses; one
    /// with none, or older ones, is a first contact and joins the burst. The
    /// burst therefore takes only the stale and the never-answered — at most
    /// one probe per server per window, as ADR-0052 already allows for every
    /// row at start. `wall` dates the figures; `now` is the sweep's clock.
    pub(crate) fn seeded(
        servers: &[crate::server_list::ManagedServer],
        wall: std::time::SystemTime,
        now: tokio::time::Instant,
        reask: Duration,
    ) -> Self {
        let schedule = servers
            .iter()
            .filter_map(|row| {
                let age = row.figures.as_ref()?.age(wall);
                (age < reask).then(|| {
                    let at = now.checked_sub(age).unwrap_or(now);
                    (row.endpoint.clone(), PingSchedule::Pinged(at))
                })
            })
            .collect();
        Self {
            schedule,
            ..Self::default()
        }
    }
}

/// The obfuscated crypt-ping arm of the sweep (ADR-0046): aMule's
/// `CServerList::ServerStats` obfuscation branch. Disabled ⇒ the sweep fires
/// only plain `0x96` pings (the shipped behavior, unchanged). Enabled ⇒ each
/// due server is first probed with a raw crypt-ping to its obfuscation UDP port
/// (TCP + 12); a reply within `grace` proves crypt support, a timeout falls
/// back to a plain ping. **Capture-gated**: off by default until a
/// crypt-capable eserver ratifies the scheme (ADR-0046 — Lugdunum 17.15 crypt
/// support unverified).
pub(crate) struct CryptPingArm {
    /// The one obfuscation policy, the server-UDP crypt layer's master
    /// switch (ADR-0046; aMule `IsServerCryptLayerUDPEnabled` reads the same
    /// preference): any set policy arms the probe, read at every sweep tick
    /// so a live change reaches the next one.
    pub(crate) policy: crate::obfuscation_policy::SharedObfuscationPolicy,
    /// Our own wire self-facts — this arm reads only `public_ip_known()`, aMule's
    /// `theApp->GetPublicIP()` gate on the probe. Raised by the live session on a
    /// High-ID login (the ADR-0047 IDCHANGE `public_ip` projection); the probe stays
    /// plain-only while it is clear, e.g. under a LowID login.
    pub(crate) own: SharedOwnIdentity,
    /// The reply grace before a plain fallback (aMule's 20 s; its `+20` on a
    /// millisecond clock is a unit slip — rmule models the intended seconds).
    pub(crate) grace: Duration,
    /// Crypt-ping randomness (non-zero challenge + padding), injected for tests
    /// ([`os_crypt_ping_nonce`] in production).
    pub(crate) nonce: fn() -> CryptPingNonce,
}

/// The **status-ping sweep** (ADR-0052 breakdown 3):
/// aMule's `CServerList::ServerStats` loop, cite-and-rewritten, with two
/// paces. A server with no answer younger than the re-ask window — a fresh
/// import, a never-answered row, or a row whose durable figures went stale
/// while rmule was down — gets its *first contact* at one per
/// `first_contact_tick`, so an
/// imported list fills in seconds rather than at aMule's one per
/// `UDPSERVERSTATTIME`. Every later probe is a *refresh*: due once the
/// `reask` window lapses and paced at one per `tick` across the whole list
/// (aMule's 5 s), so a list that came due together never bursts twice. Each
/// server still hears at most one probe per window (plus its crypt fallback);
/// the burst spends our own uplink, not any server's tolerance. Within-window
/// servers are walked past without consuming the tick, fire-and-forget — the
/// challenge is registered with the engine's gate *before* the send, and a
/// non-answer just leaves the server capability-less until the next pass.
///
/// It walks the **managed server list** (ADR-0080), dead rows included, not
/// the swept list the global sweeps read: this is list health,
/// and every listed server has a ping, a load and a failure tally to show
/// whether or not a download ever asks it for sources. Not transplanted: the
/// failed-count dead-server *removal* (`DeadServer` eviction — rmule marks a
/// server dead and keeps pinging it, at the steady pace only, so it can come
/// back; ADR-0052's dead-server amendment), and the up-to-1-hour ping jitter (aMule's
/// `rand() % HR2S(1)` spreads a 4.5 h window that rmule does not use; the
/// steady pace already spreads the refreshes).
///
/// A row listed by host name is resolved when its ping is due (ADR-0052's
/// listed-by-name amendment) — aMule's `SendQueue` DynIP lookup — reusing an answer
/// younger than aMule's `DNS_SOLVE_TIME`; the ping goes to the address, the
/// verdict and the figures to the row. A name that gives no address is one
/// silence for that pass, judged under the same offline guard as a ping.
pub(crate) struct StatusPingSweep<T> {
    /// Where every probe leaves: the crypt-ping raw, every `0x96` through
    /// the seal rule.
    pub(crate) seal: ServerUdpSeal<T>,
    /// The managed list plus the two writes a probe makes — re-read each tick,
    /// so a server added since the last one joins the sweep and a removed one
    /// leaves it.
    pub(crate) facts: ServerFacts,
    /// The engine's `0x97` gate, where each ping registers its challenge.
    pub(crate) challenges: StatusChallenges,
    /// Entropy for plain `0x96` challenge minting ([`os_rand16`](super::status_challenge::os_rand16) in production).
    pub(crate) entropy: fn() -> u16,
    /// The first-contact pace: one never-probed server per tick.
    pub(crate) first_contact_tick: Duration,
    /// The refresh pace and the start delay (aMule `UDPSERVERSTATTIME`, 5 s):
    /// at most one refresh probe per tick across the whole list.
    pub(crate) tick: Duration,
    /// The per-server re-ask window (aMule's `UDPSERVSTATMINREASKTIME` floor,
    /// 20 min): a server probed within it is walked past.
    pub(crate) reask: Duration,
    /// The obfuscated crypt-ping arm (ADR-0046); disabled ⇒ plain-only.
    pub(crate) crypt: CryptPingArm,
    /// The **Name Resolver** a row listed by name is resolved through.
    pub(crate) resolver: SharedNameResolver,
}

impl<T: ServerUdpTransport> StatusPingSweep<T> {
    pub(crate) async fn run(self) {
        // The first probe is one steady tick after start, not at start: aMule's
        // `ServerStats` rides `DownloadQueue::Process`'s own 5 s clock, so
        // nothing is pinged — and no tally moved — before the actor has settled
        // and published the list it was handed. From there the loop wakes at
        // the first-contact pace; `ping_next` holds refreshes to the steady one.
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.tick,
            self.first_contact_tick,
        );
        // A tick that waited on a name's lookup (up to the resolver's bound)
        // is not made up for in a burst: the pace stays one probe per tick.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let listed = self.facts.listed().unwrap_or_else(|error| {
            tracing::warn!(%error, "managed server list unreadable at attach; every row is a first contact");
            Vec::new()
        });
        let mut state = SweepState::seeded(
            &listed,
            std::time::SystemTime::now(),
            tokio::time::Instant::now(),
            self.reask,
        );
        loop {
            interval.tick().await;
            self.ping_next(&mut state).await;
        }
    }

    /// One tick: walk from the cursor past ineligible servers (pinged within
    /// the re-ask window, awaiting a crypt-ping reply within its
    /// grace, or due a refresh while the steady pace has none to spend) and act
    /// on the first eligible one — a probe (crypt-ping when the arm is active,
    /// else plain), or a plain fallback for a crypt-ping the grace has timed
    /// out. A first contact or a fallback may go every tick; a refresh only
    /// once per steady `tick`. A full wrap with no eligible server is an idle
    /// tick (aMule returns once its walk comes back around).
    pub(crate) async fn ping_next(&self, state: &mut SweepState) {
        let wants_vouch = self.judge(state).await;
        let servers = match self.facts.listed() {
            Ok(servers) => servers,
            Err(error) => {
                tracing::warn!(%error, "managed server list unreadable; skipping this sweep tick");
                return;
            }
        };
        let crypt_active = self.crypt.policy.armed() && self.crypt.own.public_ip_known();
        let refresh_spendable = state
            .last_refresh
            .is_none_or(|at| at.elapsed() >= self.tick);
        let policy = self.facts.policy();
        if let Some(silent) = wants_vouch {
            match voucher(&servers, policy, &silent) {
                None => state.verdicts.unvouched(),
                Some(row) if refresh_spendable => {
                    state.last_refresh = Some(tokio::time::Instant::now());
                    match self.reached_at(row).await {
                        Some(key) => {
                            self.send_plain(&row.endpoint, key, Stake::Vouch, state)
                                .await
                        }
                        None => state.verdicts.unvouched(),
                    }
                    return;
                }
                // The steady pace has no refresh to spend this tick: the
                // vouch waits for the next one.
                Some(_) => {}
            }
        }
        for _ in 0..servers.len() {
            let row = &servers[state.cursor % servers.len()];
            let server = row.endpoint.clone();
            let stake = if policy.is_dead(row) {
                Stake::Dead
            } else {
                Stake::Live
            };
            let dead = stake == Stake::Dead;
            state.cursor = state.cursor.wrapping_add(1) % servers.len();
            match state.schedule.get(&server).copied() {
                // Pinged within the re-ask window — walk past.
                Some(PingSchedule::Pinged(at)) if at.elapsed() < self.reask => continue,
                // A crypt-ping still within its reply grace — walk past.
                Some(PingSchedule::CryptPending(at, _)) if at.elapsed() < self.crypt.grace => {
                    continue;
                }
                // A crypt-ping whose grace has elapsed. If the engine settled
                // it (challenge gone) the probe was answered: treat as a fresh
                // ping and keep walking. Otherwise it timed out — fall back to a
                // plain ping (aMule's `CryptPingReplyPending` branch).
                Some(PingSchedule::CryptPending(_, key)) => {
                    if self.challenges.crypt_outstanding(key) {
                        self.send_plain(&server, key, stake, state).await;
                        return;
                    }
                    state
                        .schedule
                        .insert(server, PingSchedule::Pinged(tokio::time::Instant::now()));
                    continue;
                }
                // The re-ask window elapsed but this tick's refresh is spent:
                // walk past, the steady pace comes back around. A dead
                // server is never a first contact: it waits for the steady
                // pace too, so a list of dead servers never bursts.
                Some(PingSchedule::Pinged(_)) if !refresh_spendable => continue,
                None if dead && !refresh_spendable => continue,
                // Never pinged (a first contact), or the re-ask window
                // elapsed (a refresh): a fresh probe.
                schedule => {
                    if schedule.is_some() || dead {
                        state.last_refresh = Some(tokio::time::Instant::now());
                    }
                    let Some(key) = self.reached_at(row).await else {
                        // A name with no address: this pass's silence.
                        state.schedule.insert(
                            server.clone(),
                            PingSchedule::Pinged(tokio::time::Instant::now()),
                        );
                        state.verdicts.unresolved(&server, stake);
                        return;
                    };
                    if crypt_active {
                        self.send_crypt_ping(&server, key, stake, state).await;
                    } else {
                        self.send_plain(&server, key, stake, state).await;
                    }
                    return;
                }
            }
        }
    }

    /// The endpoint `row` is pinged at: its own address, or — for a row
    /// listed by name — the address it resolves to, reused while fresh and
    /// asked of the Name Resolver otherwise, the answer recorded on the row
    /// either way; the port is the row's standard one, which every server-UDP
    /// port derives from. `None` for a name that gives no address.
    async fn reached_at(&self, row: &ManagedServer) -> Option<Ipv4Endpoint> {
        let server = &row.endpoint;
        let port = row.standard_endpoint().port();
        if let Some(key) = server_tcp_key(server) {
            return Some(Ipv4Endpoint::new(key.ip, port));
        }
        let ip = match self.facts.fresh_address(server) {
            Some(ip) => ip,
            None => {
                let answer = self.resolver.resolve_ipv4(server.host().to_owned()).await;
                self.facts.resolved(
                    server,
                    answer.map_or(ResolvedAddress::DoesNotResolve, ResolvedAddress::Resolved),
                );
                answer?
            }
        };
        Some(Ipv4Endpoint::new(ip, port))
    }

    /// Fire a `0x96` status ping: register the challenge with the engine's
    /// gate *before* the send, stamp the re-ask clock, note the probe for its
    /// verdict, and hand it to the seal for `key`, the address `server` is
    /// reached at.
    async fn send_plain(
        &self,
        server: &ServerEndpoint,
        key: Ipv4Endpoint,
        stake: Stake,
        state: &mut SweepState,
    ) {
        let ping = GlobServStatReq::mint((self.entropy)());
        self.challenges.expect(key, ping.challenge());
        state.schedule.insert(
            server.clone(),
            PingSchedule::Pinged(tokio::time::Instant::now()),
        );
        state
            .verdicts
            .sent(server, key, ping.challenge(), ProbeKind::Plain, stake);
        self.seal.send(key, ping.encode_packet().encode_udp()).await;
    }

    /// Fire a raw obfuscated crypt-ping to the server's obfuscation UDP port
    /// (TCP + 12): register the challenge (the reply's decrypt key *and* echo
    /// gate) *before* the send, open the grace window, note the probe, send.
    async fn send_crypt_ping(
        &self,
        server: &ServerEndpoint,
        key: Ipv4Endpoint,
        stake: Stake,
        state: &mut SweepState,
    ) {
        let nonce = (self.crypt.nonce)();
        self.challenges.expect_crypt(key, nonce.challenge);
        state.schedule.insert(
            server.clone(),
            PingSchedule::CryptPending(tokio::time::Instant::now(), key),
        );
        state
            .verdicts
            .sent(server, key, nonce.challenge, ProbeKind::Crypt, stake);
        self.seal
            .send_crypt_ping(key, encode_crypt_ping(&nonce))
            .await;
    }

    /// Settle the verdicts due now: count each silence a neighbour's answer
    /// vouches for, and say on the level whether the sweep hears anybody at
    /// all (ADR-0052, the offline guard). Returns the lone silences' servers
    /// when they await a vouching ping not yet sent.
    async fn judge(&self, state: &mut SweepState) -> Option<Vec<ServerEndpoint>> {
        let judgement = state.verdicts.judge(&self.challenges);
        for server in &judgement.counted {
            if let Err(error) = self.facts.silent(server).await {
                tracing::warn!(%error, host = %server.host(), "an unanswered status ping not tallied");
            }
        }
        if judgement.heard || !judgement.counted.is_empty() {
            self.facts.heard_from_servers(true);
        } else if judgement.dropped {
            self.facts.heard_from_servers(false);
        }
        judgement.wants_vouch
    }
}

/// Who vouches for a lone silence (ADR-0052, the offline guard): the row that
/// answered most recently by its figures, not dead and not one of the
/// `silent`. `None` when nobody can — a list of one, every other row dead,
/// or none ever answered.
fn voucher<'a>(
    servers: &'a [ManagedServer],
    policy: crate::server_list::ServerPolicy,
    silent: &[ServerEndpoint],
) -> Option<&'a ManagedServer> {
    servers
        .iter()
        .filter(|row| !policy.is_dead(row) && !silent.contains(&row.endpoint))
        .filter_map(|row| Some((row.figures.as_ref()?.answered_at, row)))
        .max_by_key(|&(answered_at, _)| answered_at)
        .map(|(_, row)| row)
}
