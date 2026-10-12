//! The `natt-buddy-recruit-amule` verdict's claims: one per step of the
//! Firewalled Front's lifecycle against stock aMule — the posture, aMule's
//! own open verdicts, the walk, the `0x5A`, the dial, the held link, the
//! keepalive, the relayed callback and the dial-back it earned.
//!
//! Each step is read off the tap that saw it, aMule's log, or the target's
//! own row. A step whose precondition never happened is `blocked` and names
//! that precondition, so a run that stops early says where rather than
//! failing every claim after the first.

use super::wire::{
    BUDDY_PING, BUDDY_PONG, BUDDY_SYN, CALLBACK, CALLBACK_REQ, DIAL_BACK_SYN, FINDBUDDY_REQ,
    FINDBUDDY_RES, FWCHECK_ACK, HELLO_ANSWER, KAD_FROM_TARGET,
};
use crate::flow::nat::claims::{Claim, DriverRow, Evidence, gateways_probed_as_claimed};
use crate::flow::nat::natt::verdict::WireRow;

/// The highest client ID that is still a Low ID (`IsLowID`: below `2^24`).
const LOW_ID_LIMIT: i64 = 0x0100_0000;

/// aMule's own account of the run, off its debug logfile.
pub(super) struct AmuleLog {
    /// Its `Connected to Kad (ok)` line: two TCP firewall acks counted.
    tcp_open: Option<String>,
    /// Its UDP verdict line, read open.
    udp_open: Option<String>,
    /// `Kad TCP firewallcheck / Buddy request collision` — a `0x51` aMule
    /// dropped because it was checking the same IP (`ClientList.cpp:914`).
    collisions: usize,
    /// `Buddy client disconnected` — aMule's own record of a buddy link
    /// ending (`BaseClient.cpp:1272`).
    buddy_disconnects: usize,
}

impl AmuleLog {
    pub(super) fn read(log: &str, tcp_open: Option<String>, udp_open: Option<String>) -> Self {
        let count = |needle: &str| log.lines().filter(|line| line.contains(needle)).count();
        Self {
            tcp_open,
            udp_open,
            collisions: count("Buddy request collision"),
            buddy_disconnects: count("Buddy client disconnected"),
        }
    }

    fn open(&self) -> bool {
        self.tcp_open.is_some() && self.udp_open.is_some()
    }
}

/// The target's own row, as `natt buddy-rendezvous` wrote it.
pub(super) struct TargetRow {
    connected: bool,
    client_id: i64,
    login_failure: String,
    buddy_state: String,
    links_held: i64,
    links_lost: i64,
    dials_failed: i64,
    held_after_secs: i64,
    last_refusal: String,
    callbacks_dialed: i64,
    callbacks_dropped: i64,
    callbacks_no_buddy: i64,
    callbacks_swapped_spelling: i64,
    tcp_verdict: String,
    udp_verdict: String,
}

impl TargetRow {
    pub(super) fn read(row: &DriverRow) -> Self {
        Self {
            connected: row.flag("connected"),
            client_id: row.int("client_id"),
            login_failure: row.text("login_failure"),
            buddy_state: row.text("buddy_state"),
            links_held: row.int("buddy_links_held"),
            links_lost: row.int("buddy_links_lost"),
            dials_failed: row.int("buddy_dials_failed"),
            held_after_secs: row.int("buddy_held_after_secs"),
            last_refusal: row.text("buddy_last_recruit_refusal"),
            callbacks_dialed: row.int("relayed_callbacks_dialed"),
            callbacks_dropped: row.int("relayed_callbacks_dropped"),
            callbacks_no_buddy: row.int("relayed_callbacks_no_buddy"),
            callbacks_swapped_spelling: row.int("relayed_callbacks_swapped_spelling"),
            tcp_verdict: row.text("tcp_verdict"),
            udp_verdict: row.text("udp_verdict"),
        }
    }
}

/// What the target stands on when it recruits aMule.
pub(super) enum Posture {
    /// Logged in to the WAN's `ed2ksrv` for a server Low ID.
    ServerLowId,
    /// No server on the WAN (`--no-server`): firewalled on Kad alone. Holds
    /// the client id of every `OP_HELLO` the target sent aMule's eD2k port.
    Serverless { hello_ids: Vec<u32> },
}

/// The two gates the harness itself passed.
pub(super) struct Gates {
    /// The target logged `rmule-natt-buddy-held`.
    pub(super) held: bool,
    /// The walker logged its walk's end.
    pub(super) walked: bool,
}

fn count(wire: &[WireRow], name: &str) -> u64 {
    wire.iter()
        .find(|row| row.name == name)
        .map_or(0, |row| row.packets)
}

/// Every claim the run settles: the gateway's NAT Type Proof, then the
/// exchange.
pub(super) fn claims(
    proof: &crate::nat::NatTypeProof,
    posture: &Posture,
    amule: &AmuleLog,
    target: &TargetRow,
    gates: &Gates,
    wire: &[WireRow],
    gateway_wan: &str,
) -> Vec<Claim> {
    let mut claims = vec![gateways_probed_as_claimed([(gateway_wan, proof)])];
    claims.extend(exchange(posture, amule, target, gates, wire));
    claims
}

/// The target's posture: the id an open aMule keeps a buddy for only while
/// it reads Low (`ClientList.cpp:706-712`).
fn posture_claim(posture: &Posture, target: &TargetRow, wire: &[WireRow]) -> Claim {
    match posture {
        Posture::ServerLowId => Claim::about(
            "the-target-holds-a-server-low-id",
            target.connected && (1..LOW_ID_LIMIT).contains(&target.client_id),
            Evidence::RmuleOnly,
            format!(
                "connected = {}, client_id = {}, login failure {:?}: an open aMule keeps a \
                 buddy only while its hello reads Low (ClientList.cpp:706-712)",
                target.connected, target.client_id, target.login_failure
            ),
        ),
        Posture::Serverless { hello_ids } => {
            const NAME: &str = "the-target-presents-the-kad-firewalled-id-1";
            if hello_ids.is_empty() && count(wire, BUDDY_SYN) == 0 {
                return Claim::blocked(NAME, "the target never dialed aMule, so sent it no hello");
            }
            Claim::about(
                NAME,
                !target.connected && !hello_ids.is_empty() && hello_ids.iter().all(|id| *id == 1),
                Evidence::Captured,
                format!(
                    "connected = {}; aMule's tap: the target's OP_HELLOs named {hello_ids:?} \
                     over {} dials. A serverless, Kad-firewalled node presents 1 \
                     (amule.cpp:2051-2053), a Low ID aMule keeps as a buddy; a 0 reads as \
                     the dialer's address (BaseClient.cpp:678), a High ID it drops",
                    target.connected,
                    count(wire, BUDDY_SYN)
                ),
            )
        }
    }
}

/// The exchange's claims, in the order the front's lifecycle runs them.
fn exchange(
    posture: &Posture,
    amule: &AmuleLog,
    target: &TargetRow,
    gates: &Gates,
    wire: &[WireRow],
) -> Vec<Claim> {
    let n = |name| count(wire, name);
    let (req, res) = (n(FINDBUDDY_REQ), n(FINDBUDDY_RES));
    let (ping, pong) = (n(BUDDY_PING), n(BUDDY_PONG));
    let (callback_req, callback) = (n(CALLBACK_REQ), n(CALLBACK));
    vec![
        posture_claim(posture, target, wire),
        Claim::about(
            "the-amule-read-kad-tcp-open",
            amule.tcp_open.is_some(),
            Evidence::Captured,
            format!("aMule's own line: {:?}", amule.tcp_open),
        ),
        Claim::about(
            "the-amule-udp-verdict-read-open",
            amule.udp_open.is_some(),
            Evidence::Captured,
            format!("aMule's own line: {:?}", amule.udp_open),
        ),
        Claim::about(
            "the-target-walked-to-amule-with-0x51",
            req > 0,
            Evidence::RmuleOnly,
            format!(
                "aMule's tap: {req} 0x51 of {} Kad datagrams from the target; the target's \
                 verdicts at its window's end: tcp {:?}, udp {:?}; last recruit refusal {:?}",
                n(KAD_FROM_TARGET),
                target.tcp_verdict,
                target.udp_verdict,
                target.last_refusal
            ),
        ),
        answered(amule, req, res),
        if res == 0 {
            Claim::blocked(
                "the-target-dialed-amule-and-amule-answered-its-hello",
                "no 0x5A left aMule, so there was no buddy to dial",
            )
        } else {
            Claim::about(
                "the-target-dialed-amule-and-amule-answered-its-hello",
                n(BUDDY_SYN) > 0 && n(HELLO_ANSWER) > 0,
                Evidence::Captured,
                format!(
                    "aMule's tap: {} SYN to its eD2k port from the target, {} OP_HELLOANSWER \
                     back; {} OP_KAD_FWTCPCHECK_ACK on the same road (a firewall-check \
                     dial-back, not the buddy link); {} buddy dials failed",
                    n(BUDDY_SYN),
                    n(HELLO_ANSWER),
                    n(FWCHECK_ACK),
                    target.dials_failed
                ),
            )
        },
        if res == 0 {
            Claim::blocked(
                "the-target-held-the-link-through-its-window",
                "no 0x5A left aMule, so there was no link to hold",
            )
        } else {
            Claim::about(
                "the-target-held-the-link-through-its-window",
                target.links_held >= 1 && target.links_lost == 0 && target.buddy_state == "Held",
                Evidence::RmuleOnly,
                format!(
                    "links held {}, lost {}, state {:?} at the window's end, held {} s after \
                     start; aMule logged `Buddy client disconnected` x{}",
                    target.links_held,
                    target.links_lost,
                    target.buddy_state,
                    target.held_after_secs,
                    amule.buddy_disconnects
                ),
            )
        },
        if gates.held {
            Claim::about(
                "the-target-pinged-its-buddy-0x9f",
                ping > 0,
                Evidence::RmuleOnly,
                format!("aMule's tap: {ping} OP_BUDDYPING from the target"),
            )
        } else {
            Claim::blocked(
                "the-target-pinged-its-buddy-0x9f",
                "the target never read Held, so no keepalive was due",
            )
        },
        if ping == 0 {
            Claim::blocked(
                "amule-ponged-0xa0-on-the-buddy-link",
                "no OP_BUDDYPING reached aMule",
            )
        } else {
            Claim::about(
                "amule-ponged-0xa0-on-the-buddy-link",
                pong > 0,
                Evidence::Captured,
                format!(
                    "aMule's tap: {pong} OP_BUDDYPONG to {ping} pings; aMule pongs only \
                     GetBuddy(), and no ping inside 13 min of the client's creation or its \
                     last pong (ClientTCPSocket.cpp:1669-1673, updownclient.h:488-489)"
                ),
            )
        },
        if gates.held {
            Claim::about(
                "the-walker-sent-0x52-to-amule",
                callback_req > 0,
                Evidence::RmuleOnly,
                format!(
                    "aMule's tap: {callback_req} KADEMLIA_CALLBACK_REQ from the walker; walk \
                     ended = {}",
                    gates.walked
                ),
            )
        } else {
            Claim::blocked(
                "the-walker-sent-0x52-to-amule",
                "the target never read Held, so no callback was walked",
            )
        },
        if callback_req == 0 {
            Claim::blocked(
                "amule-relayed-the-callback-as-0x99",
                "no 0x52 reached aMule",
            )
        } else {
            Claim::about(
                "amule-relayed-the-callback-as-0x99",
                callback > 0,
                Evidence::Captured,
                format!(
                    "aMule's tap: {callback} OP_CALLBACK onto the link for {callback_req} 0x52"
                ),
            )
        },
        if callback == 0 {
            Claim::blocked(
                "the-target-dialed-the-requester-back",
                "no OP_CALLBACK reached the target",
            )
        } else {
            Claim::about(
                "the-target-dialed-the-requester-back",
                n(DIAL_BACK_SYN) > 0 && target.callbacks_dialed >= 1,
                Evidence::RmuleOnly,
                format!(
                    "gateway WAN: {} SYN to the walker's port; the front dialed {} ({} only \
                     under the other TAG_BUDDYHASH spelling), dropped {} ({} for want of a held \
                     buddy)",
                    n(DIAL_BACK_SYN),
                    target.callbacks_dialed,
                    target.callbacks_swapped_spelling,
                    target.callbacks_dropped,
                    target.callbacks_no_buddy
                ),
            )
        },
    ]
}

/// aMule's answer to the recruit — blocked, not absent, when its own gate
/// (`KademliaUDPListener.cpp:1430`: open on both verdicts, and verified) was
/// never met, because then its silence is the gate's and not a refusal.
fn answered(amule: &AmuleLog, req: u64, res: u64) -> Claim {
    const NAME: &str = "amule-answered-the-recruit-with-0x5a";
    if req == 0 {
        return Claim::blocked(
            NAME,
            "no 0x51 reached aMule, so there was nothing to answer",
        );
    }
    if !amule.open() {
        return Claim::blocked(
            NAME,
            format!(
                "aMule answers a 0x51 only open on both verdicts (KademliaUDPListener.cpp:1430) \
                 and read tcp {:?}, udp {:?}; {req} recruits went unanswered",
                amule.tcp_open, amule.udp_open
            ),
        );
    }
    Claim::about(
        NAME,
        res > 0,
        Evidence::Captured,
        format!(
            "aMule's tap: {res} 0x5A for {req} 0x51; aMule logged {} buddy-request collisions",
            amule.collisions
        ),
    )
}

#[cfg(test)]
mod tests;
