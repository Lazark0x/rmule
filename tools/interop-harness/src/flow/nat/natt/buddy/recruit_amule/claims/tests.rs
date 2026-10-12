//! How a run's observations score: which step a stalled run blames, and why
//! a silence aMule's own gate explains is `blocked` rather than `absent`.

use super::*;
use crate::flow::nat::claims::label;

/// The target row a run that reached every step writes.
const HELD_ROW: &str = r#"
connected = true
client_id = 4242
login_failure = ""
buddy_state = "Held"
buddy_links_held = 1
buddy_links_lost = 0
buddy_dials_failed = 0
buddy_held_after_secs = 431
buddy_last_recruit_refusal = ""
relayed_callbacks_dialed = 1
relayed_callbacks_dropped = 0
relayed_callbacks_no_buddy = 0
relayed_callbacks_swapped_spelling = 0
tcp_verdict = "firewalled"
udp_verdict = "firewalled"
"#;

fn target(text: &str) -> TargetRow {
    TargetRow::read(&DriverRow::parse(text).expect("a row"))
}

fn open_amule() -> AmuleLog {
    AmuleLog::read(
        "",
        Some("amule.cpp(1915): Connected to Kad (ok)".to_owned()),
        Some("New Kad Firewallstate (UDP): Open, using intern port".to_owned()),
    )
}

fn wire(counts: &[(&str, u64)]) -> Vec<WireRow> {
    counts
        .iter()
        .map(|(name, packets)| WireRow {
            name: (*name).to_owned(),
            bpf: String::new(),
            packets: *packets,
        })
        .collect()
}

/// Every row a run that reached every step counts at least once.
fn every_step() -> Vec<WireRow> {
    wire(&[
        (KAD_FROM_TARGET, 9),
        (FINDBUDDY_REQ, 1),
        (FINDBUDDY_RES, 1),
        (BUDDY_SYN, 1),
        (HELLO_ANSWER, 1),
        (BUDDY_PING, 1),
        (BUDDY_PONG, 1),
        (CALLBACK_REQ, 1),
        (CALLBACK, 1),
        (DIAL_BACK_SYN, 1),
    ])
}

fn outcome<'a>(claims: &'a [Claim], name: &str) -> &'a str {
    claims
        .iter()
        .find(|claim| claim.name == name)
        .unwrap_or_else(|| panic!("no claim {name}"))
        .outcome
}

const LOW_ID: Posture = Posture::ServerLowId;

const BOTH_GATES: Gates = Gates {
    held: true,
    walked: true,
};

#[test]
fn a_run_that_reaches_every_step_passes() {
    let claims = exchange(
        &LOW_ID,
        &open_amule(),
        &target(HELD_ROW),
        &BOTH_GATES,
        &every_step(),
    );
    assert_eq!(label(&claims).0, "PASS", "{claims:#?}");
}

/// A recruit aMule left unanswered while it never read itself open is its
/// gate's silence: `blocked`, naming the gate — and the open verdict that
/// never came is the claim that fails the run.
#[test]
fn an_unanswered_recruit_to_an_amule_that_never_read_open_is_blocked_on_its_gate() {
    let never_open = AmuleLog::read(
        "",
        None,
        Some("New Kad Firewallstate (UDP): Open".to_owned()),
    );
    let claims = exchange(
        &LOW_ID,
        &never_open,
        &target(HELD_ROW),
        &Gates {
            held: false,
            walked: false,
        },
        &wire(&[(KAD_FROM_TARGET, 9), (FINDBUDDY_REQ, 2)]),
    );
    assert_eq!(outcome(&claims, "the-amule-read-kad-tcp-open"), "absent");
    assert_eq!(
        outcome(&claims, "amule-answered-the-recruit-with-0x5a"),
        "blocked"
    );
    assert_eq!(
        outcome(&claims, "the-target-held-the-link-through-its-window"),
        "blocked"
    );
}

/// The same silence from an aMule that read open on both verdicts is a
/// refusal the bench measured: `absent`, and the run fails.
#[test]
fn an_unanswered_recruit_to_an_open_amule_fails_the_run() {
    let claims = exchange(
        &LOW_ID,
        &open_amule(),
        &target(HELD_ROW),
        &Gates {
            held: false,
            walked: false,
        },
        &wire(&[(KAD_FROM_TARGET, 9), (FINDBUDDY_REQ, 2)]),
    );
    assert_eq!(
        outcome(&claims, "amule-answered-the-recruit-with-0x5a"),
        "absent"
    );
    assert_eq!(label(&claims).0, "FAIL");
}

/// aMule accepted and the link came up, then went: the hold fails, and the
/// keepalive and callback steps it gates are blocked on it rather than
/// failed one by one.
#[test]
fn a_link_lost_inside_the_window_fails_the_hold_and_blocks_what_rode_it() {
    let lost = HELD_ROW
        .replace("buddy_links_lost = 0", "buddy_links_lost = 1")
        .replace("buddy_state = \"Held\"", "buddy_state = \"None\"");
    let claims = exchange(
        &LOW_ID,
        &open_amule(),
        &target(&lost),
        &Gates {
            held: true,
            walked: true,
        },
        &wire(&[
            (FINDBUDDY_REQ, 1),
            (FINDBUDDY_RES, 1),
            (BUDDY_SYN, 1),
            (HELLO_ANSWER, 1),
        ]),
    );
    assert_eq!(
        outcome(&claims, "the-target-held-the-link-through-its-window"),
        "absent"
    );
    assert_eq!(
        outcome(&claims, "amule-ponged-0xa0-on-the-buddy-link"),
        "blocked"
    );
    assert_eq!(
        outcome(&claims, "amule-relayed-the-callback-as-0x99"),
        "blocked"
    );
}

/// A relayed `0x99` the front never dialed back is the last step failing:
/// the SYN on the gateway's WAN and the front's own count must agree.
#[test]
fn a_relay_the_front_did_not_act_on_fails_the_dial_back() {
    let undialed = HELD_ROW.replace(
        "relayed_callbacks_dialed = 1",
        "relayed_callbacks_dialed = 0",
    );
    let mut rows = every_step();
    rows.retain(|row| row.name != DIAL_BACK_SYN);
    let claims = exchange(
        &LOW_ID,
        &open_amule(),
        &target(&undialed),
        &BOTH_GATES,
        &rows,
    );
    assert_eq!(
        outcome(&claims, "the-target-dialed-the-requester-back"),
        "absent"
    );
}

/// A hello carrying no id is not a Low ID: aMule reads it as the dialer's
/// address and drops the buddy.
#[test]
fn a_target_with_no_server_id_does_not_hold_the_low_id_posture() {
    let serverless = HELD_ROW
        .replace("connected = true", "connected = false")
        .replace("client_id = 4242", "client_id = 0");
    let claims = exchange(
        &LOW_ID,
        &open_amule(),
        &target(&serverless),
        &BOTH_GATES,
        &every_step(),
    );
    assert_eq!(
        outcome(&claims, "the-target-holds-a-server-low-id"),
        "absent"
    );
}

/// The target's row with no server on the WAN: never connected.
fn serverless_row() -> String {
    HELD_ROW
        .replace("connected = true", "connected = false")
        .replace("client_id = 4242", "client_id = 0")
}

/// With no server on the WAN, every hello aMule received naming `1` is the
/// posture aMule keeps a buddy for, and a run that reached every step passes.
#[test]
fn a_serverless_run_whose_hellos_name_one_passes() {
    let claims = exchange(
        &Posture::Serverless {
            hello_ids: vec![1, 1],
        },
        &open_amule(),
        &target(&serverless_row()),
        &BOTH_GATES,
        &every_step(),
    );
    assert_eq!(label(&claims).0, "PASS", "{claims:#?}");
}

/// A serverless hello naming `0` reads as the dialer's address, a High ID an
/// open aMule drops as a buddy: the posture fails the run.
#[test]
fn a_serverless_hello_naming_zero_fails_the_posture() {
    let claims = exchange(
        &Posture::Serverless { hello_ids: vec![0] },
        &open_amule(),
        &target(&serverless_row()),
        &BOTH_GATES,
        &every_step(),
    );
    assert_eq!(
        outcome(&claims, "the-target-presents-the-kad-firewalled-id-1"),
        "absent"
    );
    assert_eq!(label(&claims).0, "FAIL");
}

/// A target that never dialed aMule sent it no hello: the posture is blocked
/// on the dial, not failed.
#[test]
fn a_serverless_target_that_never_dialed_blocks_the_posture() {
    let claims = exchange(
        &Posture::Serverless {
            hello_ids: Vec::new(),
        },
        &open_amule(),
        &target(&serverless_row()),
        &Gates {
            held: false,
            walked: false,
        },
        &wire(&[(KAD_FROM_TARGET, 9), (FINDBUDDY_REQ, 1)]),
    );
    assert_eq!(
        outcome(&claims, "the-target-presents-the-kad-firewalled-id-1"),
        "blocked"
    );
}
