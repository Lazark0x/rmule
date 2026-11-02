//! The session-cap leg's claims: rmule's uploader rule read from its tap. A
//! holder past 10 MiB with someone waiting is told `OP_OUTOFPARTREQS`, ranked
//! `OP_QUEUERANKING` on the same link (`UploadQueue.cpp:576-583`,
//! `UploadClient.cpp:643-660`), and the waiter takes the slot.

use std::net::{IpAddr, Ipv4Addr};

use super::{Link, OP_SENDINGPART};
use crate::flow::nat::claims::{Claim, Evidence};
use crate::flow::pcap::{Ed2kFrame, TcpCapture};

const OP_OUTOFPARTREQS: u8 = 0x57;
const OP_QUEUERANKING: u8 = 0x60;
/// aMule's session bound (`UploadQueue.cpp:581`): strictly more than this
/// many bytes.
const SESSION_BYTES: u64 = 10_485_760;
/// How close behind the `0x57` its rank must follow: one write in stock.
const RANK_AFTER_KICK_SECS: f64 = 5.0;
/// How far the waiter's grant may lead the `0x57` on the wire: the slot moves
/// once, and each link drains its own lanes, so the holder's tail can finish
/// after the waiter's accept left.
const GRANT_LEADS_KICK_SECS: f64 = 1.0;

/// rmule's frames to `holder`, in wire order.
fn frames_to(capture: &TcpCapture, rmule: Ipv4Addr, holder: Ipv4Addr) -> Vec<Ed2kFrame> {
    let mut frames: Vec<Ed2kFrame> = capture
        .streams
        .iter()
        .filter(|stream| {
            stream.source.ip() == IpAddr::V4(rmule) && stream.destination.ip() == IpAddr::V4(holder)
        })
        .flat_map(|stream| stream.ed2k_frames())
        .collect();
    frames.sort_by(|a, b| a.at.total_cmp(&b.at));
    frames
}

/// The leg's claims over rmule's tap: `links` are rmule's links with W.
pub(super) fn claims(
    capture: &TcpCapture,
    rmule: Ipv4Addr,
    holder: Option<Ipv4Addr>,
    links: &[Link],
) -> Vec<Claim> {
    let frames = holder.map_or_else(Vec::new, |holder| frames_to(capture, rmule, holder));
    claims_over(&frames, links)
}

fn claims_over(frames: &[Ed2kFrame], links: &[Link]) -> Vec<Claim> {
    let kick = frames.iter().find(|frame| frame.opcode == OP_OUTOFPARTREQS);
    let kick_at = kick.map(|frame| frame.at);
    let sent: u64 = frames
        .iter()
        .filter(|frame| frame.opcode == OP_SENDINGPART && kick_at.is_none_or(|at| frame.at <= at))
        .map(|frame| frame.bytes.len() as u64)
        .sum();
    let rank = frames
        .iter()
        .find(|frame| frame.opcode == OP_QUEUERANKING && kick_at.is_some_and(|at| frame.at >= at));
    let rank_after = kick_at.zip(rank.map(|frame| frame.at)).map(|(k, r)| r - k);
    let granted = links
        .iter()
        .filter(|link| kick_at.is_some_and(|at| link.first_grant >= at - GRANT_LEADS_KICK_SECS))
        .min_by(|a, b| a.first_grant.total_cmp(&b.first_grant));
    vec![
        Claim::about(
            "the-holder-was-told-past-ten-mib",
            kick.is_some() && sent > SESSION_BYTES,
            Evidence::Captured,
            format!("OP_OUTOFPARTREQS after {sent} bytes of OP_SENDINGPART: {kick_at:?}"),
        ),
        Claim::about(
            "a-rank-followed-on-that-link",
            rank_after.is_some_and(|secs| secs <= RANK_AFTER_KICK_SECS),
            Evidence::Captured,
            format!("OP_QUEUERANKING seconds past the kick: {rank_after:?}"),
        ),
        Claim::about(
            "the-waiter-took-the-slot",
            granted.is_some(),
            Evidence::Captured,
            format!(
                "first OP_ACCEPTUPLOADREQ to W at the kick: {:?}",
                granted.map(|link| link.first_grant)
            ),
        ),
        Claim::about(
            "the-waiter-took-parts-on-it",
            granted.is_some_and(|link| link.parts_from_rmule > 0),
            Evidence::Captured,
            format!(
                "OP_SENDINGPART frames on that link: {}",
                granted.map_or(0, |link| link.parts_from_rmule)
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(at: f64, opcode: u8, len: usize) -> Ed2kFrame {
        Ed2kFrame {
            at,
            source: "172.20.0.2:4663".parse().unwrap(),
            destination: "172.20.0.3:4662".parse().unwrap(),
            protocol: 0xE3,
            opcode,
            bytes: vec![0; len],
        }
    }

    fn passed(claims: &[Claim], name: &str) -> bool {
        claims
            .iter()
            .any(|claim| claim.name == name && claim.outcome == "held")
    }

    /// A kick short of the session does not read as the rule.
    #[test]
    fn a_kick_short_of_ten_mib_is_not_the_rule() {
        let claims = claims_over(
            &[
                frame(1.0, OP_SENDINGPART, 1024),
                frame(2.0, OP_OUTOFPARTREQS, 0),
                frame(2.1, OP_QUEUERANKING, 2),
            ],
            &[],
        );
        assert!(!passed(&claims, "the-holder-was-told-past-ten-mib"));
        assert!(passed(&claims, "a-rank-followed-on-that-link"));
    }

    /// Past the session the kick reads, and a rank before it does not count.
    #[test]
    fn the_kick_past_the_session_with_its_rank() {
        let claims = claims_over(
            &[
                frame(0.5, OP_QUEUERANKING, 2),
                frame(1.0, OP_SENDINGPART, 10_485_761),
                frame(2.0, OP_OUTOFPARTREQS, 0),
            ],
            &[],
        );
        assert!(passed(&claims, "the-holder-was-told-past-ten-mib"));
        assert!(!passed(&claims, "a-rank-followed-on-that-link"));
    }

    /// The holder's tail drains on its own link, so the waiter's accept can
    /// leave first: the slot still moved at the kick. A grant long before it
    /// is another turn.
    #[test]
    fn a_grant_leading_the_holders_kick_on_the_wire_is_the_slot_moving() {
        let frames = [
            frame(1.0, OP_SENDINGPART, 10_485_761),
            frame(2.0, OP_OUTOFPARTREQS, 0),
        ];
        let granted = |first_grant| Link {
            first_grant,
            parts_from_rmule: 180,
            ..Link::default()
        };
        let led = claims_over(&frames, &[granted(1.96)]);
        assert!(passed(&led, "the-waiter-took-the-slot"));
        assert!(passed(&led, "the-waiter-took-parts-on-it"));
        let earlier = claims_over(&frames, &[granted(0.5)]);
        assert!(!passed(&earlier, "the-waiter-took-the-slot"));
    }
}
