//! The sweep's **verdicts** (ADR-0052, "dead servers are marked, never
//! removed"): which pings went unanswered, and which of those silences count
//! against their server.
//!
//! A ping is judged once its answer is overdue. A silence counts only when a
//! ping sent near it was answered — the offline guard: when every ping around
//! a silence is silent too, the network is what failed, and nobody's tally
//! moves. Only a living server's silence says so: a dead server pinged alone
//! at the steady pace has nobody live to vouch either way. A living silence
//! alone in its window — nothing near it answered or silent — is
//! inconclusive: it waits for a vouching ping to the server that answered
//! last, whose answer makes the silence count and whose silence says the
//! network is down. A crypt-ping is never judged on its own; its plain
//! fallback is.

use std::collections::VecDeque;
use std::time::Duration;

use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};
use tokio::time::Instant;

use super::super::StatusChallenges;

/// Which probe a record is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ProbeKind {
    /// A plain `0x96`: its silence is a failure to reach the server.
    Plain,
    /// An obfuscated crypt-ping: evidence when answered, else followed by a
    /// plain ping that is judged in its place.
    Crypt,
}

/// What a probe stakes on its answer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Stake {
    /// A living server's ping: its silence is a failure, or evidence that
    /// the network is down.
    Live,
    /// The server was dead when the probe left: its unvouched silence says
    /// nothing about the network.
    Dead,
    /// A vouching ping: it decides the lone silences sent before it, and is
    /// never judged as its own server's failure.
    Vouch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Pending,
    Answered,
    Silent,
    /// A crypt-ping whose grace ran out: its fallback carries the verdict.
    Superseded,
    /// A living silence alone in its window, awaiting a vouching ping.
    Inconclusive,
}

struct Probe {
    server: ServerEndpoint,
    /// Where the probe went; `None` for a name that gave no address, which
    /// is silent from the start.
    key: Option<Ipv4Endpoint>,
    challenge: u32,
    sent_at: Instant,
    kind: ProbeKind,
    stake: Stake,
    fate: Fate,
}

/// What one pass over the ledger decided.
#[derive(Default)]
pub(super) struct Judgement {
    /// Servers whose silence counts: one failure each.
    pub(super) counted: Vec<ServerEndpoint>,
    /// A living server's silence was dropped because no ping near it was
    /// answered: the network looks down.
    pub(super) dropped: bool,
    /// A ping was answered since the last pass.
    pub(super) heard: bool,
    /// The plain probes this pass found silent, with when each left: their
    /// pings went unanswered, whatever the offline guard makes of the tally.
    pub(super) silenced: Vec<(ServerEndpoint, Instant)>,
    /// Lone silences await a vouching ping that is not yet out: the servers
    /// that went silent, none of which may vouch.
    pub(super) wants_vouch: Option<Vec<ServerEndpoint>>,
}

/// The pings sent recently enough to be judged or to vouch for another.
pub(super) struct Verdicts {
    probes: VecDeque<Probe>,
    /// How long an answer may take before its ping is silent.
    grace: Duration,
    /// How far apart two pings may be sent for one's answer to vouch that the
    /// network carried the other.
    window: Duration,
    /// When the last vouching ping went out: at most one per window.
    last_vouch: Option<Instant>,
}

impl Verdicts {
    pub(super) const fn new(grace: Duration, window: Duration) -> Self {
        Self {
            probes: VecDeque::new(),
            grace,
            window,
            last_vouch: None,
        }
    }

    /// A probe just went out to `server` with `challenge`, staking `stake`.
    pub(super) fn sent(
        &mut self,
        server: &ServerEndpoint,
        key: Ipv4Endpoint,
        challenge: u32,
        kind: ProbeKind,
        stake: Stake,
    ) {
        let sent_at = Instant::now();
        if stake == Stake::Vouch {
            self.last_vouch = Some(sent_at);
        }
        self.probes.push_back(Probe {
            server: server.clone(),
            key: Some(key),
            challenge,
            sent_at,
            kind,
            stake,
            fate: Fate::Pending,
        });
    }

    /// Nobody can vouch for the lone silences (a list of one, every other
    /// row dead, none ever answered): they are dropped quietly, neither
    /// failures nor evidence that the network is down.
    pub(super) fn unvouched(&mut self) {
        self.probes.retain(|probe| probe.fate != Fate::Inconclusive);
    }

    /// `server`'s name gave no address this pass (ADR-0052's amendment):
    /// a silence from the start, judged like an unanswered ping — it counts
    /// only when a ping near it was answered, since a network that is down
    /// fails every lookup too.
    pub(super) fn unresolved(&mut self, server: &ServerEndpoint, stake: Stake) {
        self.probes.push_back(Probe {
            server: server.clone(),
            key: None,
            challenge: 0,
            sent_at: Instant::now(),
            kind: ProbeKind::Plain,
            stake,
            fate: Fate::Silent,
        });
    }

    /// Settle what the gate and the clock can say now, then decide every
    /// silence whose neighbours have all been heard from or given up on.
    pub(super) fn judge(&mut self, challenges: &StatusChallenges) -> Judgement {
        let now = Instant::now();
        let mut judgement = Judgement::default();
        for probe in &mut self.probes {
            if probe.fate != Fate::Pending {
                continue;
            }
            let Some(key) = probe.key else {
                continue;
            };
            if !challenges.awaits(key, probe.challenge) {
                probe.fate = Fate::Answered;
                judgement.heard = true;
            } else if now.duration_since(probe.sent_at) >= self.grace {
                probe.fate = match probe.kind {
                    ProbeKind::Plain => {
                        judgement
                            .silenced
                            .push((probe.server.clone(), probe.sent_at));
                        Fate::Silent
                    }
                    ProbeKind::Crypt => Fate::Superseded,
                };
            }
        }
        let near = |a: Instant, b: Instant| a.max(b).duration_since(a.min(b)) <= self.window;
        let mut decided = Vec::new();
        let mut lone = Vec::new();
        for (at, probe) in self.probes.iter().enumerate() {
            if probe.fate != Fate::Silent || probe.stake == Stake::Vouch {
                continue;
            }
            let neighbours = || {
                self.probes
                    .iter()
                    .enumerate()
                    .filter(|&(other_at, other)| {
                        other_at != at && near(other.sent_at, probe.sent_at)
                    })
                    .map(|(_, other)| other)
            };
            if neighbours().any(|other| other.fate == Fate::Answered) {
                judgement.counted.push(probe.server.clone());
                decided.push(at);
            } else if now.duration_since(probe.sent_at) >= self.window + self.grace
                && neighbours().all(|other| other.fate != Fate::Pending)
            {
                let living_silence = |other: &Probe| {
                    other.stake == Stake::Live
                        && matches!(other.fate, Fate::Silent | Fate::Inconclusive)
                };
                match probe.stake {
                    Stake::Live if !neighbours().any(living_silence) => lone.push(at),
                    Stake::Live => {
                        judgement.dropped = true;
                        decided.push(at);
                    }
                    Stake::Dead | Stake::Vouch => decided.push(at),
                }
            }
        }
        for &at in &lone {
            self.probes[at].fate = Fate::Inconclusive;
        }
        self.decide_by_vouch(&mut judgement, &mut decided);
        decided.sort_unstable();
        decided.dedup();
        for at in decided.into_iter().rev() {
            self.probes.remove(at);
        }
        judgement.wants_vouch = self.wants_vouch(now);
        // A settled probe vouches for silences up to a window after it, and
        // those are decided a window plus a grace later still.
        let keep = self.window * 2 + self.grace * 2;
        self.probes.retain(|probe| {
            matches!(
                probe.fate,
                Fate::Pending | Fate::Silent | Fate::Inconclusive
            ) || now.duration_since(probe.sent_at) < keep
        });
        judgement
    }

    /// Settle the lone silences a vouching ping sent after them has decided:
    /// its answer makes each one its server's failure; its silence means two
    /// living servers went unheard together — the network is down, and no
    /// tally moves.
    fn decide_by_vouch(&self, judgement: &mut Judgement, decided: &mut Vec<usize>) {
        for (vouch_at, vouch) in self.probes.iter().enumerate() {
            if vouch.stake != Stake::Vouch || !matches!(vouch.fate, Fate::Answered | Fate::Silent) {
                continue;
            }
            let answered = vouch.fate == Fate::Answered;
            for (at, probe) in self.probes.iter().enumerate() {
                if probe.fate == Fate::Inconclusive && probe.sent_at <= vouch.sent_at {
                    if answered {
                        judgement.counted.push(probe.server.clone());
                    }
                    decided.push(at);
                }
            }
            if !answered {
                judgement.dropped = true;
                decided.push(vouch_at);
            }
        }
    }

    /// The silent servers of lone silences no vouch is out for, once the
    /// window since the last vouch has lapsed.
    fn wants_vouch(&self, now: Instant) -> Option<Vec<ServerEndpoint>> {
        if self
            .last_vouch
            .is_some_and(|at| now.duration_since(at) < self.window)
        {
            return None;
        }
        let silent: Vec<ServerEndpoint> = self
            .probes
            .iter()
            .filter(|probe| probe.fate == Fate::Inconclusive)
            .map(|probe| probe.server.clone())
            .collect();
        (!silent.is_empty()).then_some(silent)
    }
}
