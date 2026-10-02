//! What the buddy rendezvous claims, and out of which measurement.
//!
//! The split is the one every NAT-traversal row keeps: a **Driver Row** is rmule's
//! own account of its own surfaces and is read to locate the exchange, while
//! the **Wire Rows** counted off the three attachments are what the exchange
//! actually put on a wire. All three bodies are rmule, so every claim here is
//! `rmule-only` (ADR-0045's 2026-09-16 amendment) and scored *exercised*
//! against a proven NAT — never captured.

use crate::flow::nat::claims::{
    Body, Claim, DriverRow, Evidence, gateways_probed_as_claimed, measured_total,
};
use crate::flow::nat::natt::NattFlow;
use crate::flow::nat::natt::bench::Driven;
use crate::flow::nat::natt::legs::GatewayProof;
use crate::flow::nat::natt::verdict::{WireRow, packets};

/// The standing note a reader needs before any number below means anything.
const NOTE: &str = "ADR-0091 rung 1 through its SECOND Rendezvous coordinator. Three rmule \
     bodies: an open buddy on the fake-public WAN, a firewalled target behind its own \
     gateway that recruits that buddy over a live Kad FINDBUDDY walk from a Seeded \
     Bootstrap, and a firewalled requester behind its own gateway that embeds an \
     OP_RENDEZVOUS in an OP_REASKCALLBACKUDP addressed to the buddy. NO eD2k server \
     stands on this WAN — the buddy is the coordinator — so the bodies' logins cannot \
     complete and `connected` reads false by design; what each body needs from \
     StartServing is the bind. The requester is handed the target's User Hash and its \
     buddy's contact out of band and reaches it with the shipped CoreCommand::ReachPeer: \
     this row measures the rendezvous, and natt-buddy-transfer-cone measures the same \
     path reached by a download from a Kad row.";

/// The standing note for the transfer row, where nothing is
/// handed to the requester but the link.
const TRANSFER_NOTE: &str = "ADR-0091 rung 1 through the buddy coordinator, driven by a real \
     DOWNLOAD. The buddy topology of natt-buddy-rendezvous-cone plus a placed \
     mesh member at the file's own Kad key (a storer refuses a non-LAN publish outside \
     SEARCHTOLERANCE of its ID). The target shares the Synthetic File once its buddy is \
     held, so its source publish is the firewalled type-3 row naming that buddy with \
     rmule's connect options (uTP NAT-T) in TAG_ENCRYPTION. The requester is handed the \
     ed2k link and NOTHING about the target: its download asks Kad for sources, and the \
     row the mesh serves is the only channel that names the target, its User Hash and its \
     buddy. NO eD2k server stands on this WAN, so both downloaders are Low-ID and the \
     candidate's only road is the punch.";

/// What a transfer row moved, for the claims that compare against it.
pub(super) struct Transferred<'a> {
    /// The link's ED2K hash, upper-case hex.
    pub(super) file_hash: &'a str,
    /// The file's size in bytes.
    pub(super) size: u64,
}

/// The claims the driver rows settle, in the order a reader needs them.
///
/// `rows` is `[requester, target, buddy]`; `proofs` is the two gatewayed
/// bodies' NAT Type Proofs in the same order as the peers.
pub(super) fn driven(
    flow: NattFlow,
    rows: &[DriverRow],
    proofs: &[GatewayProof],
    bodies: Vec<Body>,
    transferred: Option<Transferred<'_>>,
) -> Driven {
    let negative = flow == NattFlow::BuddyRendezvousSymmetric;
    let (requester, target, buddy) = (&rows[0], &rows[1], &rows[2]);
    let tunnels = measured_total(
        rows.iter()
            .flat_map(|row| [row.int("tunnels_dialed"), row.int("tunnels_accepted")]),
    );

    let mut claims = vec![
        // The **NAT Type Proof**'s pinned-port leg first, exactly as the punch
        // rows state it: a gateway that cannot forward the port every punch is
        // aimed at makes every later count meaningless, and RFC 5780 cannot
        // see that rule at all.
        Claim::about(
            "each-lan-reached-the-wan-on-the-pinned-port",
            proofs.iter().all(|gateway| {
                gateway.proof.pinned_port_reachable && gateway.proof.pinned_port != 0
            }),
            Evidence::RmuleOnly,
            proofs
                .iter()
                .map(|gateway| {
                    let proof = &gateway.proof;
                    format!(
                        "{}: one datagram to the Pinned-Port Sink at port {} {}; \
                         RFC 4787 axes observed {}/{} against a {} claim (agrees = {})",
                        gateway.wan,
                        proof.pinned_port,
                        if proof.pinned_port_reachable {
                            "arrived"
                        } else {
                            "never arrived"
                        },
                        proof.observed_mapping,
                        proof.observed_filtering,
                        proof.nat_type.knob(),
                        proof.agrees,
                    )
                })
                .collect::<Vec<_>>()
                .join(" | "),
        ),
        // The proof's RFC 4787 half: a gateway that built another NAT type
        // puts this row behind a NAT it does not name.
        gateways_probed_as_claimed(
            proofs
                .iter()
                .map(|gateway| (gateway.wan.as_str(), &gateway.proof)),
        ),
        // The topology's own precondition: every body's listener came up, so a
        // buddy link has an accept surface and a hello has a port to name.
        Claim::about(
            "every-body-bound-its-serve-listener-without-a-server",
            rows.iter().all(|row| row.flag("serving")),
            Evidence::RmuleOnly,
            format!(
                "requester serving = {}, target = {}, buddy = {}; none of the three \
                 completed a login ({:?} / {:?} / {:?}), which is the point — the bind is \
                 taken on the actor before any login is awaited (the bind-before-login contract), and \
                 the buddy link rides the listener the bind produced",
                requester.flag("serving"),
                target.flag("serving"),
                buddy.flag("serving"),
                requester.text("login_failure"),
                target.text("login_failure"),
                buddy.text("login_failure"),
            ),
        ),
        // The **self-proof**, driver half. The wire half is below.
        Claim::about(
            "the-firewalled-target-holds-a-buddy-it-recruited-live",
            target.text("buddy_state") == "Held" && target.int("buddy_links_held") >= 1,
            Evidence::RmuleOnly,
            format!(
                "buddy_state = {:?} after {} s, {} links held and {} lost; last recruit \
                 refusal {:?}. The slot is filled only by a `0x5A` whose echoed buddy-ID \
                 inverts to this node's own Kad ID ({}), so a stray answer cannot fill it. \
                 The walk ran over a Seeded Bootstrap of {} placed contacts.",
                target.text("buddy_state"),
                target.int("buddy_held_after_secs"),
                target.int("buddy_links_held"),
                target.int("buddy_links_lost"),
                target.text("buddy_last_recruit_refusal"),
                target.text("kad_id"),
                target.int("seeded_contacts"),
            ),
        ),
        Claim::about(
            "the-requester-routed-through-the-buddy-coordinator",
            requester.text("routed").contains("NatTraversal")
                && requester.int("attempts_buddy") >= 1
                && requester.int("attempts_server") == 0,
            Evidence::RmuleOnly,
            format!(
                "The requester routed {}; {} Traversal Attempts opened with a buddy \
                 coordinator and {} with a server one; {} rendezvous emitted. The route \
                 tree reached the buddy rung because this body has no session at all, so \
                 `on_our_server` is honestly false and the server coordinator cannot apply.",
                requester.text("routed"),
                requester.int("attempts_buddy"),
                requester.int("attempts_server"),
                requester.int("rendezvous_emitted"),
            ),
        ),
        Claim::about(
            "the-buddy-relayed-the-rendezvous-onto-the-held-link",
            buddy.int("relays_forwarded") >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} rendezvous forwarded as a serving buddy, {} refused. Relay admission \
                 is buddy relations only (ADR-0091 correction 7): the claimed buddy-ID is \
                 verified against the registered slot on both opcodes, which is the \
                 tightening ADR-0061 records over aMule's own `JOHNTODO`.",
                buddy.int("relays_forwarded"),
                buddy.int("relays_refused"),
            ),
        ),
        Claim::about(
            "the-target-acted-on-the-relayed-rendezvous",
            target.int("acting_punches") >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} relayed rendezvous acted on (burst asked for, Responder expectation \
                 armed), {} refused, last refusal {:?}",
                target.int("acting_punches"),
                target.int("acting_refusals"),
                target.text("acting_last_refusal"),
            ),
        ),
    ];

    if negative {
        claims.push(Claim::absence(
            "no-tunnel-rose-behind-symmetric-gateways",
            tunnels,
            format!(
                "{tunnels} tunnels across all three bodies; the requester spent its budget \
                 on {} dials ({} in its last attempt) and the target on {}. {} endpoint \
                 hints were refused (last {:?}). The negative is qualified in the same run \
                 by both gateways' NAT Type Proof, the reflector probe beside their claim, \
                 the conntrack dump showing the outbound mapping existed, and the \
                 counterparty's own zero on the wire below (ADR-0045 as amended).",
                requester.int("dials"),
                requester.text("last_attempt_dials"),
                target.int("dials"),
                requester.int("hint_refusals"),
                requester.text("last_hint_refusal"),
            ),
        ));
        claims.push(Claim::about(
            "the-outbound-punch-mapping-exists-in-each-gateways-conntrack",
            proofs.iter().all(|gateway| gateway.punch_mappings > 0),
            Evidence::RmuleOnly,
            proofs
                .iter()
                .map(|gateway| {
                    format!(
                        "{}: {} conntrack mappings from the client's pinned port toward the \
                         other gateway, {} of them [UNREPLIED]",
                        gateway.wan, gateway.punch_mappings, gateway.unreplied,
                    )
                })
                .collect::<Vec<_>>()
                .join(" | "),
        ));
    } else {
        claims.push(Claim::about(
            "a-tunnel-rose-between-the-two-firewalled-peers",
            tunnels >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} dialed + {} accepted on the requester, {} + {} on the target; {} \
                 openers sent by the requester ({} in its last attempt), {} by the target; \
                 last transport {:?}. The requester dials because it is the side that \
                 asked (ADR-0091).",
                requester.int("tunnels_dialed"),
                requester.int("tunnels_accepted"),
                target.int("tunnels_dialed"),
                target.int("tunnels_accepted"),
                requester.int("dials"),
                requester.text("last_attempt_dials"),
                target.int("dials"),
                requester.text("last_tunnel_transport"),
            ),
        ));
    }

    if let Some(file) = transferred.as_ref() {
        claims.extend(transfer_claims(requester, target, file));
    }

    Driven {
        claims,
        bodies,
        wire: Vec::new(),
        note: if transferred.is_some() {
            TRANSFER_NOTE
        } else {
            NOTE
        }
        .to_owned(),
        tunnel_rose: None,
    }
}

/// The transfer row's own claims: the row went out naming the
/// buddy, the download reached the buddy coordinator from it alone, claimed
/// the Tunnel, and the bytes arrived intact.
fn transfer_claims(
    requester: &DriverRow,
    target: &DriverRow,
    file: &Transferred<'_>,
) -> Vec<Claim> {
    vec![
        Claim::about(
            "the-target-published-its-file-through-the-held-buddy",
            target.flag("published") && target.text("buddy_state") == "Held",
            Evidence::RmuleOnly,
            format!(
                "published = {}, buddy_state = {:?}. The file is shared only once the slot \
                 reads Held, so the publish it triggers is the firewalled type-3 row \
                 naming the buddy, with the uTP NAT-T bit in TAG_ENCRYPTION.",
                target.flag("published"),
                target.text("buddy_state"),
            ),
        ),
        Claim::about(
            "the-download-found-the-buddy-coordinator-from-a-kad-row-alone",
            requester.flag("download_started")
                && requester.text("routed").contains("NatTraversal")
                && requester.int("download_fallbacks") >= 1
                && requester.int("download_fallbacks_unclaimable") == 0,
            Evidence::RmuleOnly,
            format!(
                "download_started = {}, routed {}, {} falls to NAT traversal ({} \
                 unclaimable), {} Traversal Attempts with a buddy coordinator. Nothing \
                 named the target to this body: the buddy, its endpoint and the User Hash \
                 the claim is keyed by all came off the Kad row.",
                requester.flag("download_started"),
                requester.text("routed"),
                requester.int("download_fallbacks"),
                requester.int("download_fallbacks_unclaimable"),
                requester.int("attempts_buddy"),
            ),
        ),
        Claim::about(
            "the-download-adopted-the-tunnel-the-buddy-coordinated",
            requester.int("download_adoptions") >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} adoptions; the claim is keyed by the row's User Hash and the peer's own \
                 hello confirms it (ADR-0091)",
                requester.int("download_adoptions"),
            ),
        ),
        Claim::about(
            "the-file-completed-byte-equal-over-the-buddy-path",
            requester.flag("download_completed")
                && requester
                    .text("output_ed2k_hash")
                    .eq_ignore_ascii_case(file.file_hash),
            Evidence::RmuleOnly,
            format!(
                "completed = {}, {} bytes out of {}, ED2K hash {} against the link's {}{}",
                requester.flag("download_completed"),
                requester.int("output_bytes"),
                file.size,
                requester.text("output_ed2k_hash"),
                file.file_hash,
                if requester.text("download_failure").is_empty() {
                    String::new()
                } else {
                    format!("; failure: {}", requester.text("download_failure"))
                },
            ),
        ),
    ]
}

/// The claims only the pcaps can settle — the self-proof's wire half, the
/// rendezvous chain, and the coordinator this row did *not* use.
pub(crate) fn wire_claims(flow: NattFlow, wire: &[WireRow]) -> Vec<Claim> {
    let negative = flow == NattFlow::BuddyRendezvousSymmetric;
    let recruit_in = packets(wire, "findbuddy-recruit-in");
    let accept_out = packets(wire, "findbuddy-accept-out");
    let recruit_from_target = packets(wire, "findbuddy-recruit-from-target");
    let link_syn = packets(wire, "buddy-link-syn-in");
    let rendezvous_in = packets(wire, "rendezvous-in");
    let relay_out = packets(wire, "relayed-reask-callback-out");
    let hint_out = packets(wire, "endpoint-hint-out");
    let hint_to_requester = packets(wire, "endpoint-hint-lan-in-requester");
    let server_punch = packets(wire, "server-holepunch-request-anywhere");
    let burst_requester = packets(wire, "holepunch-lan-out-from-requester");
    let burst_target = packets(wire, "holepunch-lan-out-from-target");
    let punch_at_requester = packets(wire, "holepunch-lan-in-requester");
    let transport_requester = packets(wire, "natt-transport-lan-out-requester");
    let transport_target = packets(wire, "natt-transport-lan-out-target");
    let arrived_requester = packets(wire, "natt-transport-lan-in-requester");
    let arrived_target = packets(wire, "natt-transport-lan-in-target");

    let mut claims = vec![
        // The self-proof's decisive half: the recruit is counted arriving on
        // the *intended* buddy's own wire, sourced at the target's gateway,
        // and answered.
        Claim::about(
            "the-recruit-landed-on-the-intended-buddy",
            recruit_in >= 1 && accept_out >= 1 && recruit_from_target >= 1 && link_syn >= 1,
            Evidence::RmuleOnly,
            format!(
                "{recruit_in} `0x51` KADEMLIA_FINDBUDDY_REQ arrived on the buddy's own \
                 attachment and {accept_out} `0x5A` went back; {recruit_from_target} of \
                 those recruits left the target's own gateway; {link_syn} buddy-link TCP \
                 SYNs arrived at the buddy's peer port. The walk had two routing-only mesh \
                 members to converge on instead and did not: the buddy's Kad ID is the \
                 target's inverted, which is the walk's own target, so it sits at distance \
                 zero from `~targetID`.",
            ),
        ),
        // The coordinator this row did not use, stated rather than assumed.
        Claim::absence(
            "no-server-coordinator-was-asked",
            server_punch,
            format!(
                "{server_punch} `OP_LOWID_HOLEPUNCH_REQUEST` (`0x60`) frames anywhere on \
                 the tapped wires. No eD2k server stands on this WAN, so ADR-0091's \
                 preferred coordinator cannot apply and the buddy rung is reached on its \
                 own merits rather than as a fall-through.",
            ),
        ),
        Claim::about(
            "the-rendezvous-reached-the-buddy-and-was-relayed",
            rendezvous_in >= 1 && relay_out >= 1,
            Evidence::RmuleOnly,
            format!(
                "{rendezvous_in} `0x94` OP_REASKCALLBACKUDP carrying an embedded \
                 OP_RENDEZVOUS arrived at the buddy; {relay_out} `0x9A` \
                 OP_REASKCALLBACKTCP left it over the held buddy link.",
            ),
        ),
        Claim::about(
            "the-buddy-answered-with-the-targets-observed-endpoint",
            hint_out >= 1,
            Evidence::RmuleOnly,
            format!(
                "{hint_out} `0xAA` OP_NATT_ENDPOINT_HINT left the buddy, \
                 {hint_to_requester} reached the requester's own LAN. The hint is the \
                 *buddy's* answer, not the target's (ADR-0091), and it \
                 names the mapping the buddy observed on the `0x51` — which is the mapping \
                 a punch must reach, because Kad and client-UDP ride one socket \
                 (ADR-0057).",
            ),
        ),
        // Departures stay the burst's evidence: a burst the
        // front cancelled never left, so no arrival tap can stand in for it.
        // Run `1790169196` read 0 off the requester's LAN, 0 off its
        // gateway's WAN and none sourced at it on the target's taps, while
        // its log shows the hold (762 µs) cut short by the Tunnel entering
        // the serve pipeline 565 µs after it began — ADR-0091's hold cancellation,
        // not a tap that slipped. What the requester owes is therefore its
        // burst *or* the dial through the target's punch that pre-empted it.
        Claim::about(
            "each-side-burst-or-dialed-through-the-others-punch",
            burst_target >= 1
                && (burst_requester >= 1 || (punch_at_requester >= 1 && arrived_target >= 1)),
            Evidence::RmuleOnly,
            format!(
                "{burst_target} `0xA1` OP_HOLEPUNCH left the target's LAN and \
                 {burst_requester} the requester's; {punch_at_requester} reached the \
                 requester's LAN and {arrived_target} `0xB2` frames reached the target. The \
                 target bursts when the relayed rendezvous reaches it. The requester holds \
                 its burst for half the hint's round trip, and a Tunnel it dials into the \
                 target's burst inside that hold ends the attempt and takes the hold with it \
                 (ADR-0091), so its zero is the shipped path exactly when the \
                 target's burst reached it and its dial crossed.",
            ),
        ),
    ];
    if negative {
        // **Counterparty-zero, read on both sides of each gateway.** A `0xB2`
        // that left the LAN and never crossed the WAN would be a bench fault; a
        // `0xB2` that crossed the WAN and never arrived is the NAT type doing
        // its job. Only the second is the negative this row publishes, so the
        // outbound half is asserted as a *condition* beside the absence.
        claims.push(Claim::absence(
            "no-transport-frame-arrived-at-either-body",
            measured_total([arrived_requester, arrived_target]),
            format!(
                "{transport_requester} `0xB2` frames left the requester's LAN and \
                 {transport_target} the target's; {arrived_requester} arrived at the \
                 requester and {arrived_target} at the target. The openers were fired and \
                 translated; nothing answered, which behind an address-and-port-dependent \
                 mapping is the expected outcome and not a silence the bench caused.",
            ),
        ));
        claims.push(Claim::about(
            "the-openers-left-the-lan-behind-symmetric-gateways",
            transport_requester >= 1,
            Evidence::RmuleOnly,
            format!(
                "{transport_requester} `0xB2` openers left the requester's LAN — without \
                 them the zero above would be a dial that was never made rather than a \
                 mapping that defeated it.",
            ),
        ));
    } else {
        claims.push(Claim::about(
            "transport-frames-crossed-the-punched-path-both-ways",
            // Arrivals, not departures: a frame that arrived at
            // the far body crossed the punched path by definition, while a
            // frame that left a LAN did not, and reading departures makes the
            // claim depend on whichever tap is least likely to miss a short
            // burst. Run `1790082950` read `FAIL` on `transport_target = 0`
            // while the target's own `tunnels_accepted = 1` and the
            // requester's LAN tap held 2 `0xB2` datagrams arriving from the
            // target's gateway in a 2 ms window its own tap slipped.
            arrived_requester >= 1 && arrived_target >= 1,
            Evidence::RmuleOnly,
            format!(
                "{arrived_requester} `0xB2` frames arrived at the requester and \
                 {arrived_target} at the target — the uTP Tunnel riding the pinhole the \
                 two bursts opened. {transport_requester} left the requester's LAN and \
                 {transport_target} the target's, kept as context rather than the gate.",
            ),
        ));
    }
    claims
}

#[cfg(test)]
mod tests {
    use super::wire_claims;
    use crate::flow::nat::natt::NattFlow;
    use crate::flow::nat::natt::verdict::WireRow;

    fn transport_wire(
        out_requester: u64,
        in_requester: u64,
        out_target: u64,
        in_target: u64,
    ) -> Vec<WireRow> {
        let row = |name: &str, packets: u64| WireRow {
            name: name.to_owned(),
            bpf: String::new(),
            packets,
        };
        vec![
            row("natt-transport-lan-out-requester", out_requester),
            row("natt-transport-lan-in-requester", in_requester),
            row("natt-transport-lan-out-target", out_target),
            row("natt-transport-lan-in-target", in_target),
        ]
    }

    fn burst_claim(flow: NattFlow, counts: [(&str, u64); 4]) -> crate::flow::nat::claims::Claim {
        let wire: Vec<WireRow> = counts
            .iter()
            .map(|(name, packets)| WireRow {
                name: (*name).to_owned(),
                bpf: String::new(),
                packets: *packets,
            })
            .collect();
        wire_claims(flow, &wire)
            .into_iter()
            .find(|claim| claim.name == "each-side-burst-or-dialed-through-the-others-punch")
            .expect("every buddy row pushes the burst claim")
    }

    /// Run `1790169196`: the Tunnel the requester dialed into the
    /// target's six arriving `0xA1` rose inside its 762 µs hold, so its own
    /// burst was cancelled and none left — the shipped path, not a gap.
    #[test]
    fn a_hold_the_tunnel_pre_empted_reads_held() {
        let claim = burst_claim(
            NattFlow::BuddyTransferCone,
            [
                ("holepunch-lan-out-from-requester", 0),
                ("holepunch-lan-out-from-target", 36),
                ("holepunch-lan-in-requester", 6),
                ("natt-transport-lan-in-target", 119),
            ],
        );
        assert_eq!(claim.outcome, "held");
    }

    /// Run `1790106612`'s shape behind symmetric gateways: nothing the target
    /// fired reaches the requester, so only the requester's own burst can
    /// satisfy it — a requester that stayed silent there still reads absent.
    #[test]
    fn a_silent_requester_the_target_never_reached_reads_absent() {
        let counts = |requester_out| {
            [
                ("holepunch-lan-out-from-requester", requester_out),
                ("holepunch-lan-out-from-target", 68),
                ("holepunch-lan-in-requester", 0),
                ("natt-transport-lan-in-target", 0),
            ]
        };
        let flow = NattFlow::BuddyRendezvousSymmetric;
        assert_eq!(burst_claim(flow, counts(458)).outcome, "held");
        assert_eq!(burst_claim(flow, counts(0)).outcome, "absent");
    }

    fn transport_claim(wire: &[WireRow]) -> crate::flow::nat::claims::Claim {
        wire_claims(NattFlow::BuddyRendezvousCone, wire)
            .into_iter()
            .find(|claim| claim.name == "transport-frames-crossed-the-punched-path-both-ways")
            .expect("the positive row always pushes this claim")
    }

    /// Run `1790082950`: the target's LAN tap missed a 2 ms `0xB2` burst, so
    /// its departure count read 0 while frames plainly arrived on both taps
    /// Departures alone used to fail this row; arrivals don't.
    #[test]
    fn fail_run_departures_reads_held_on_arrivals() {
        let wire = transport_wire(3, 2, 0, 3);
        let claim = transport_claim(&wire);
        assert_eq!(claim.outcome, "held");
        assert!(
            claim
                .note
                .contains("2 `0xB2` frames arrived at the requester")
        );
        assert!(claim.note.contains("3 at the target"));
        assert!(
            claim
                .note
                .contains("3 left the requester's LAN and 0 the target's")
        );
    }

    /// Run `1790083846`: departures already satisfied the old gate (3/1) and
    /// arrivals (2/3) satisfy the new one too — the fix changes nothing for a
    /// run whose taps caught everything.
    #[test]
    fn pass_run_stays_held_on_arrivals() {
        let wire = transport_wire(3, 2, 1, 3);
        let claim = transport_claim(&wire);
        assert_eq!(claim.outcome, "held");
    }

    fn named(wire: &[WireRow], name: &str) -> crate::flow::nat::claims::Claim {
        wire_claims(NattFlow::BuddyRendezvousSymmetric, wire)
            .into_iter()
            .find(|claim| claim.name == name)
            .unwrap_or_else(|| panic!("the symmetric row always pushes {name}"))
    }

    /// `natt-buddy-rendezvous-symmetric`'s counterparty-zero: a `0xB2`
    /// that arrived at either body is the punch working, so the
    /// negative's absence must fail on it.
    #[test]
    fn an_arrival_behind_symmetric_gateways_fails_the_negative() {
        let name = "no-transport-frame-arrived-at-either-body";
        assert_eq!(named(&transport_wire(5, 0, 5, 0), name).outcome, "held");
        assert_eq!(named(&transport_wire(5, 0, 5, 1), name).outcome, "absent");
        assert_eq!(named(&transport_wire(5, 2, 5, 0), name).outcome, "absent");
    }

    /// The coordinator the buddy rows did not use is a count, not a given: a
    /// `0x60` anywhere on the taps contradicts it, and so does no tap at all.
    #[test]
    fn a_server_holepunch_request_fails_the_no_server_absence() {
        let name = "no-server-coordinator-was-asked";
        let wire = |count| {
            vec![WireRow {
                name: "server-holepunch-request-anywhere".to_owned(),
                bpf: String::new(),
                packets: count,
            }]
        };
        assert_eq!(named(&wire(0), name).outcome, "held");
        assert_eq!(named(&wire(1), name).outcome, "absent");
        assert_eq!(named(&[], name).outcome, "absent");
    }

    /// One arrival tap reading zero still fails the row — the fix reads
    /// arrivals instead of departures, not "either counter clears the gate".
    #[test]
    fn no_arrival_at_the_target_still_reads_absent() {
        let wire = transport_wire(3, 2, 1, 0);
        let claim = transport_claim(&wire);
        assert_eq!(claim.outcome, "absent");
    }
}
