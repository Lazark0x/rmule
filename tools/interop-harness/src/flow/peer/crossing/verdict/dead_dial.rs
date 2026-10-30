//! The dead-dial legs' claims: rmule's dial-back carried the slot, went dead
//! at the far end, and the waiter's own link took its standing; and, on the
//! identifying leg, a key the dial never proved was bound once, off that link.

use std::fs;
use std::path::Path;

use super::{Link, OP_PUBLICKEY, Rows};
use crate::flow::nat::claims::{Claim, Evidence};
use crate::flow::pcap::TcpCapture;

/// One `clients.met` record's length, and the offsets inside it of the key's
/// size and of the key (`rmule_core::clients_met`).
const CREDIT_RECORD_LEN: usize = 119;
const CREDIT_KEY_SIZE_AT: usize = 38;
const CREDIT_KEY_AT: usize = 39;

/// The secure-ident keys `clients.met` under `dir` holds.
fn bound_keys(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(bytes) = fs::read(dir.join("clients.met")) else {
        return Vec::new();
    };
    bytes
        .get(5..)
        .unwrap_or_default()
        .chunks_exact(CREDIT_RECORD_LEN)
        .map(|record| {
            let size = usize::from(record[CREDIT_KEY_SIZE_AT]);
            record[CREDIT_KEY_AT..CREDIT_KEY_AT + size].to_vec()
        })
        .filter(|key| !key.is_empty())
        .collect()
}

/// The key the waiter sent on `link`, from its `OP_PUBLICKEY`.
fn key_sent_on(capture: &TcpCapture, link: &Link) -> Option<Vec<u8>> {
    capture
        .streams
        .iter()
        .filter(|stream| {
            stream.source.to_string() == link.peer_end
                && stream.destination.to_string() == link.rmule_end
        })
        .flat_map(|stream| stream.ed2k_frames())
        .find(|frame| frame.protocol == 0xC5 && frame.opcode == OP_PUBLICKEY)
        .and_then(|frame| {
            let size = usize::from(*frame.payload().first()?);
            frame.payload().get(1..1 + size).map(<[u8]>::to_vec)
        })
}

/// The claims both legs share.
pub(super) fn dead_dial_claims(rows: &Rows, dial: Option<&Link>, own: Option<&Link>) -> Vec<Claim> {
    let logged = |record: &str, text: &str| {
        rows.records
            .iter()
            .any(|line| line.starts_with(record) && line.contains(text))
    };
    let silent = logged("serve.dead_dial_let_go", "sign=silent");
    let to_own =
        own.is_some_and(|link| logged("serve.waiter_relinked", &format!("to={}", link.peer_end)));
    vec![
        Claim::about(
            "the-dial-carried-the-slot-first",
            dial.is_some_and(|link| link.first_grant > 0.0),
            Evidence::Captured,
            format!(
                "OP_ACCEPTUPLOADREQ on the dial: {}; OP_SENDINGPART: {}",
                dial.map_or(0, |link| link.grants_from_rmule),
                dial.map_or(0, |link| link.parts_from_rmule)
            ),
        ),
        Claim::about(
            "rmule-read-the-dial-dead-by-its-silence",
            silent,
            Evidence::Captured,
            format!("serve.dead_dial_let_go sign=silent logged: {silent}"),
        ),
        Claim::about(
            "the-standing-moved-to-the-waiters-own-link",
            to_own,
            Evidence::Captured,
            format!("serve.waiter_relinked to the waiter's own link logged: {to_own}"),
        ),
        Claim::about(
            "rmule-closed-the-dial",
            dial.is_some_and(|link| link.closed_by == "rmule"),
            Evidence::Captured,
            format!(
                "the dial closed by: {}",
                dial.map_or("nobody", |link| link.closed_by.as_str())
            ),
        ),
        Claim::about(
            "blocks-flowed-on-the-waiters-own-link",
            own.is_some_and(|link| link.first_grant > 0.0 && link.parts_from_rmule > 0),
            Evidence::Captured,
            format!(
                "OP_ACCEPTUPLOADREQ on it: {}; OP_SENDINGPART: {}",
                own.map_or(0, |link| link.grants_from_rmule),
                own.map_or(0, |link| link.parts_from_rmule)
            ),
        ),
    ]
}

/// The identifying leg's further claims.
pub(super) fn identity_claims(
    capture: &TcpCapture,
    log: &str,
    data_dir: &Path,
    dial: Option<&Link>,
    own: Option<&Link>,
) -> Vec<Claim> {
    let keys = bound_keys(data_dir);
    let proved = own.and_then(|link| key_sent_on(capture, link));
    let held = proved
        .as_ref()
        .is_some_and(|key| keys.iter().any(|bound| bound == key));
    let mismatches = log
        .lines()
        .filter(|line| line.starts_with("identity.secured_mismatch"))
        .count();
    vec![
        Claim::about(
            "the-dial-went-with-its-verification-unfinished",
            dial.is_some_and(|link| link.proofs_from_peer == 0),
            Evidence::Captured,
            format!(
                "on the dial: rmule's OP_SECIDENTSTATE {}, the waiter's OP_SIGNATURE {}",
                dial.map_or(0, |link| link.sui_asks_from_rmule),
                dial.map_or(0, |link| link.proofs_from_peer)
            ),
        ),
        Claim::about(
            "the-waiter-proved-its-key-on-its-own-link",
            own.is_some_and(|link| link.proofs_from_peer > 0),
            Evidence::Captured,
            format!(
                "the waiter's OP_SIGNATURE on its own link: {}",
                own.map_or(0, |link| link.proofs_from_peer)
            ),
        ),
        Claim::about(
            "clients-met-holds-the-waiters-key",
            held,
            Evidence::Captured,
            format!(
                "keys in clients.met: {}; the key the waiter sent on its own link among them: {held}",
                keys.len()
            ),
        ),
        Claim::about(
            "no-mismatch-was-raised",
            mismatches == 0,
            Evidence::Captured,
            format!("identity.secured_mismatch records: {mismatches}"),
        ),
    ]
}
