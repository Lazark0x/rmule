//! `ipv6-extsx-emit`'s holds-nothing leg: a third requester queued on
//! rmule that says, in its name ask, it holds no part of the file — so rmule's
//! needed-part filter must leave it out of the answer emule-qt draws, beside
//! the dual-stack source of unknown parts it keeps (ADR-0055 §Serving).

use anyhow::{Context, Result};

use super::{HOLD_SECS, dual_stack_record};
use crate::flow::bench::Bench;
use crate::flow::nat::dialect::BODY_PEER_TCP_PORT;
use crate::flow::nat::dialect::bench::{
    HOST_DRIVER, HOST_QUEUED_DUAL_STACK, HOST_QUEUED_HOLDS_NONE, Ipv6DialectOptions, Stage, out,
    start_detached_driver,
};
use crate::flow::nat::dialect::ext_sx::SLOT_MARKER;
use crate::flow::nat::dialect::verdict::{Claim, DriverRow, Evidence};

/// The holds-nothing requester's user hash.
const HOLDS_NONE_USER_HASH: &str = "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e";

/// The holds-nothing requester's container role.
const HOLDS_NONE_ROLE: &str = "v6none";

/// Queue the holds-nothing requester on rmule: over IPv4, its own
/// address as a High ID, no IPv6 named, and rmule's own extended-requests v1
/// claim, so its name ask says it holds no part of the file. Returns its
/// container and whether rmule granted or queued it.
pub(super) fn start_holds_nothing_requester(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(String, bool)> {
    let v4: std::net::Ipv4Addr = stage
        .v4(HOST_QUEUED_HOLDS_NONE)
        .parse()
        .context("the holds-nothing requester's IPv4")?;
    let hold = [
        "ipv6".to_owned(),
        "hold-slot".to_owned(),
        "--peer".to_owned(),
        format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(HOST_DRIVER)),
        "--file".to_owned(),
        stage
            .shared
            .as_ref()
            .context("rmule shares a file")?
            .link
            .clone(),
        "--client-id".to_owned(),
        u32::from_le_bytes(v4.octets()).to_string(),
        "--user-hash".to_owned(),
        HOLDS_NONE_USER_HASH.to_owned(),
        "--capture".to_owned(),
        out("extsx-none-capture"),
        "--out".to_owned(),
        out("extsx-none.toml"),
        "--hold-secs".to_owned(),
        HOLD_SECS.to_string(),
    ];
    start_detached_driver(
        bench,
        options,
        stage,
        HOLDS_NONE_ROLE,
        HOST_QUEUED_HOLDS_NONE,
        &hold,
        SLOT_MARKER,
    )
}

pub(super) fn holds_nothing_queued_claim(stage: &Stage, none: &DriverRow) -> Claim {
    let none_v4 = stage.v4(HOST_QUEUED_HOLDS_NONE);
    Claim::about(
        "a-requester-holding-no-part-holds-a-place-on-rmule",
        !none.text("slot").is_empty(),
        Evidence::RmuleOnly,
        format!(
            "the requester reached rmule over IPv4 from {none_v4} with that address as its High \
             ID, claimed extended-requests v1 so its name ask carried an all-zero part status, \
             and rmule answered its OP_STARTUPLOADREQ with slot={:?}; failure={:?}",
            none.text("slot"),
            none.text("failure"),
        ),
    )
}

/// The holds-nothing leg's claims: rmule queued the requester, and its
/// answer to emule-qt carries the pooled sources of unknown parts but not the
/// one that said it holds nothing — the needed-part filter reading emule-qt's
/// own status.
pub(super) fn holds_nothing_claims(
    stage: &Stage,
    none: &DriverRow,
    answer: Option<&[u8]>,
) -> Result<Vec<Claim>> {
    let none_v4: std::net::Ipv4Addr = stage
        .v4(HOST_QUEUED_HOLDS_NONE)
        .parse()
        .context("the holds-nothing requester's IPv4")?;
    let dual_v4: std::net::Ipv4Addr = stage
        .v4(HOST_QUEUED_DUAL_STACK)
        .parse()
        .context("the dual-stack requester's IPv4")?;
    let dual_v6: std::net::Ipv6Addr = stage
        .v6(HOST_QUEUED_DUAL_STACK)
        .parse()
        .context("the dual-stack requester's IPv6")?;
    let kept = answer.and_then(|frame| dual_stack_record(frame, dual_v4, dual_v6));
    let left_out = answer.map(|frame| !names_source(frame, none_v4, HOLDS_NONE_USER_HASH));
    Ok(vec![
        holds_nothing_queued_claim(stage, none),
        Claim::about(
            "rmule-left-the-holds-nothing-source-out-of-emuleqts-answer",
            kept.is_some() && left_out == Some(true),
            Evidence::RmuleOnly,
            format!(
                "rmule's OP_ANSWERSOURCES2 to emule-qt (`extsx-answer.bin`, {} bytes) keeps the \
                 dual-stack source of unknown parts ({kept:?}) and names the holds-nothing \
                 source {none_v4}:{BODY_PEER_TCP_PORT} (id or user hash) {}: its all-zero \
                 status offers no part emule-qt's fresh download lacks. rmule answers every \
                 pooled source to an asker whose status it could not read (ADR-0055), so \
                 the absence is emule-qt's own name-ask status applied",
                answer.map_or(0, <[u8]>::len),
                match left_out {
                    Some(true) => "nowhere",
                    Some(false) => "IN THE ANSWER",
                    None => "— no answer lifted",
                },
            ),
        ),
    ])
}

/// Whether `frame` carries a source record for the High ID `v4` at the body
/// port, or the user hash `user_hash_hex` anywhere (a record's
/// `CT_EMULE_USERHASH` / v2+ hash field).
fn names_source(frame: &[u8], v4: std::net::Ipv4Addr, user_hash_hex: &str) -> bool {
    let mut head = v4.octets().to_vec();
    head.extend_from_slice(&BODY_PEER_TCP_PORT.to_le_bytes());
    let hash: Vec<u8> = (0..user_hash_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(user_hash_hex.get(i..i + 2)?, 16).ok())
        .collect();
    let contains = |needle: &[u8]| frame.windows(needle.len()).any(|window| window == needle);
    contains(&head) || contains(&hash)
}

#[cfg(test)]
mod tests {
    use super::{HOLDS_NONE_USER_HASH, names_source};

    /// The holds-nothing source is named by its High-ID record head or by its
    /// user hash, and a frame carrying neither leaves it out.
    #[test]
    fn a_source_is_named_by_its_record_head_or_its_user_hash() {
        let v4: std::net::Ipv4Addr = "45.55.200.9".parse().unwrap();
        let mut frame = vec![0xc5, 0, 0, 0, 0, 0x84, 0x01];
        frame.extend_from_slice(&[0x11; 16]);
        frame.extend_from_slice(&[0x01, 0x00, 45, 55, 200, 8, 0x36, 0x12, 0x01, 0x81, 0xbc]);
        frame.extend_from_slice(&[0x5d; 16]);
        assert!(!names_source(&frame, v4, HOLDS_NONE_USER_HASH));

        let mut by_head = frame.clone();
        by_head.extend_from_slice(&[45, 55, 200, 9, 0x36, 0x12]);
        assert!(names_source(&by_head, v4, HOLDS_NONE_USER_HASH));
        let mut by_hash = frame;
        by_hash.extend_from_slice(&[0x6e; 16]);
        assert!(names_source(&by_hash, v4, HOLDS_NONE_USER_HASH));
    }
}
