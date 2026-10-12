//! The NAT-traversal claims read against hand-built rows: a **Documented Absence**
//! must fail when its own run observed the thing it names.

use super::{GatewayProof, caps_utp_wire_claims, punch_claims, punch_wire_claims};
use crate::flow::nat::claims::{Claim, DriverRow};
use crate::flow::nat::natt::NattFlow;
use crate::flow::nat::natt::verdict::WireRow;
use crate::nat::{NatType, NatTypeProof, PinnedPortReach};

fn wire(rows: &[(&str, u64)]) -> Vec<WireRow> {
    rows.iter()
        .map(|(name, packets)| WireRow {
            name: (*name).to_owned(),
            bpf: String::new(),
            packets: *packets,
        })
        .collect()
}

fn named<'a>(claims: &'a [Claim], name: &str) -> &'a Claim {
    claims
        .iter()
        .find(|claim| claim.name == name)
        .unwrap_or_else(|| panic!("{name} missing from {claims:?}"))
}

fn symmetric_gateway(wan: &str) -> GatewayProof {
    GatewayProof {
        wan: wan.to_owned(),
        proof: NatTypeProof::new(
            NatType::Symmetric,
            "address-and-port-dependent",
            "address-and-port-dependent",
            PinnedPortReach {
                port: 4672,
                reachable: true,
            },
        ),
        punch_mappings: 3,
        unreplied: 3,
    }
}

fn punch_row(dialed: i64, accepted: i64) -> DriverRow {
    DriverRow::parse(&format!(
        "connected = true\nlow_id = true\ntunnels_dialed = {dialed}\n\
         tunnels_accepted = {accepted}\nrouted = \"server_punch\"\n"
    ))
    .expect("a hand-built row parses")
}

fn symmetric_tunnel_claim(rows: &[DriverRow]) -> Claim {
    let proofs = [
        symmetric_gateway("198.18.0.2"),
        symmetric_gateway("198.18.0.3"),
    ];
    let driven = punch_claims(
        NattFlow::ServerPunchSymmetric,
        rows,
        &proofs,
        "198.18.0.10",
        "",
        0,
        Vec::new(),
    );
    named(&driven.claims, "no-tunnel-rose-behind-symmetric-gateways").clone()
}

/// `natt-server-punch-symmetric`'s negative: a Tunnel on either peer is the
/// thing the claim says did not happen, so it must fail the row rather than
/// sit beside it as `held`.
#[test]
fn a_tunnel_behind_symmetric_gateways_fails_the_negative() {
    let silent = [punch_row(0, 0), punch_row(0, 0)];
    assert_eq!(symmetric_tunnel_claim(&silent).outcome, "held");

    let rose = [punch_row(1, 0), punch_row(0, 1)];
    assert_eq!(symmetric_tunnel_claim(&rose).outcome, "absent");

    // A row that never reported its count is not a zero.
    let unreported = [
        punch_row(0, 0),
        DriverRow::parse("connected = true\n").expect("parses"),
    ];
    assert_eq!(symmetric_tunnel_claim(&unreported).outcome, "absent");
}

/// `natt-server-punch-symmetric`'s counterparty-zero: a `0xB2` arriving
/// at either client's LAN is the punch working, which the negative must
/// not publish as its absence.
#[test]
fn a_transport_frame_that_arrived_fails_the_symmetric_negative() {
    let rows = |arrived| {
        wire(&[
            ("natt-transport-lan-out-requester", 4),
            ("natt-transport-lan-in-requester", arrived),
            ("natt-transport-lan-out-responder", 4),
            ("natt-transport-lan-in-responder", 0),
        ])
    };
    let name = "no-transport-frame-arrived-at-either-peer";
    let quiet = punch_wire_claims(NattFlow::ServerPunchSymmetric, &rows(0));
    assert_eq!(named(&quiet, name).outcome, "held");
    let answered = punch_wire_claims(NattFlow::ServerPunchSymmetric, &rows(2));
    assert_eq!(named(&answered, name).outcome, "absent");
    // No arrival row cut at all is a count the run never took.
    let uncut = punch_wire_claims(NattFlow::ServerPunchSymmetric, &[]);
    assert_eq!(named(&uncut, name).outcome, "absent");
}

/// `natt-caps-utp`: a CAPS-ACK counted on kno's own attachment contradicts the absence.
#[test]
fn a_caps_ack_on_the_wire_fails_its_absence() {
    let name = "no-caps-ack-crossed-the-wire";
    let silent = caps_utp_wire_claims(&wire(&[("caps-ack-in", 0)]));
    assert_eq!(named(&silent, name).outcome, "held");
    let answered = caps_utp_wire_claims(&wire(&[("caps-ack-in", 1)]));
    assert_eq!(named(&answered, name).outcome, "absent");
}

/// ADR-0045's tiers on the server rows: rmule's own `0x60` and `0x9F`
/// counted arriving carry no server byte, and the `0x61` only ed2ksrv emits
/// is `single-oracle`, as its promoted fixture's meta classes it. Tagging
/// all three `captured` is what let ADR-0092 class these rows "captured".
#[test]
fn the_server_rows_carry_the_tier_their_bytes_earn() {
    use crate::flow::nat::claims::Evidence;
    let claims = punch_wire_claims(NattFlow::ServerPunchCone, &[]);
    for (name, tier) in [
        (
            "the-server-received-one-holepunch-request",
            Evidence::RmuleOnly,
        ),
        (
            "the-keepalive-reached-the-server-udp-port",
            Evidence::RmuleOnly,
        ),
        ("the-server-introduced-both-peers", Evidence::SingleOracle),
    ] {
        assert_eq!(named(&claims, name).evidence, tier, "{name}");
    }
}
