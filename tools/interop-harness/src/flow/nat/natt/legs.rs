//! What each NAT-traversal flow drives, and the claims it draws from the answer.
//!
//! The pattern is the IPv6-dialect flows': a **Driver Row** is rmule's own account and is read
//! only to *locate* the counterparty's statement; the evidence is the retained
//! datagram the row points at and the **Wire Row** counted off the tap. Nothing
//! rmule reports about itself settles a `captured` claim.
//!
//! `natt-caps-utp` carries one correction to ADR-0092's own row, measured
//! rather than read off the fork's source alone — see [`caps_utp`].

use anyhow::Result;

use crate::flow::bench::Bench;
use crate::flow::nat::claims::{
    Claim, DriverRow, Evidence, gateways_probed_as_claimed, measured_total,
};
use crate::flow::nat::natt::bench::{
    Driven, HOST_AMULE_KNO, NattOptions, Stage, WireRowRequest, body_log, container_name, out,
    run_driver,
};
use crate::flow::nat::natt::verdict::{WireRow, packets};
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT, NattFlow};

/// rmule's own user hash in every NAT-traversal leg. Fixed so a counterparty's KEY
/// frame, CAPS answer or obfuscated datagram is keyed on a value the verdict
/// can name.
const RMULE_USER_HASH: &str = "42424242424242424242424242424242";

/// The `0xB2` frame types the wire rows are cut on (ADR-0091's envelope).
const FRAME_UTP: u8 = 0x00;
const FRAME_CAPS: u8 = 0x02;
const FRAME_CAPS_ACK: u8 = 0x03;
const FRAME_KEY: u8 = 0xFF;

/// Drive the flow and return what it produced.
///
/// # Errors
/// If a driver container cannot run or its row cannot be read.
pub(crate) fn drive(bench: &mut Bench, options: &NattOptions<'_>, stage: &Stage) -> Result<Driven> {
    match options.flow {
        NattFlow::CapsUtp => caps_utp(bench, options, stage),
        // The gateway-bearing rows stand their own topology up and never reach
        // this shared-WAN path; `bench::drive` dispatches them before a stage
        // exists at all.
        NattFlow::ServerPunchCone
        | NattFlow::ServerPunchSymmetric
        | NattFlow::ServerPunchOneSymmetric
        | NattFlow::TunnelTransfer
        | NattFlow::BuddyRendezvousCone
        | NattFlow::BuddyRendezvousRestricted
        | NattFlow::BuddyRendezvousSymmetric
        | NattFlow::BuddyTransferCone
        | NattFlow::UdpSelfCheckCone
        | NattFlow::UdpSelfCheckRemapped
        | NattFlow::UdpSelfCheckAmule => {
            anyhow::bail!("{} drives its own topology", options.flow.name())
        }
    }
}

/// The claims a flow can only settle once its **Wire Rows** are counted.
pub(crate) fn wire_claims(flow: NattFlow, wire: &[WireRow]) -> Vec<Claim> {
    match flow {
        NattFlow::CapsUtp => caps_utp_wire_claims(wire),
        NattFlow::ServerPunchCone
        | NattFlow::ServerPunchSymmetric
        | NattFlow::ServerPunchOneSymmetric
        | NattFlow::TunnelTransfer => punch_wire_claims(flow, wire),
        NattFlow::BuddyRendezvousCone
        | NattFlow::BuddyRendezvousRestricted
        | NattFlow::BuddyRendezvousSymmetric
        | NattFlow::BuddyTransferCone => super::buddy::wire_claims(flow, wire),
        // Its claims are the driven ones: the evidence is the storer's own
        // capture, decoded, rather than a BPF count.
        NattFlow::UdpSelfCheckCone
        | NattFlow::UdpSelfCheckRemapped
        | NattFlow::UdpSelfCheckAmule => Vec::new(),
    }
}

/// **`natt-caps-utp`** — the dialect's three opening frames against kno's
/// aMule at its Fork Pin.
///
/// ADR-0092's row reads "CAPS/CAPS-ACK, KEY frame, uTP SYN answered", and
/// **two thirds of that have no counterparty at this pin** — a finding about
/// the body rather than about rmule. kno's fork answers no capability frame at
/// all: `ClientUDPSocket.cpp`'s `0xB2` demux takes `OP_NATT_FRAME_CAPS` and
/// `OP_NATT_FRAME_CAPS_ACK` to one drop branch (*"nothing to negotiate"*) and
/// `OP_NATT_FRAME_KEY` to another (*"no NAT traversal in this build"*). So the
/// CAPS and KEY halves are **Documented Absences** and the uTP half is the
/// captured row — the predicted shape: kno's uTP *answers* and never
/// initiates.
///
/// What makes each absence a measurement rather than a silence the bench caused
/// is the **Wire Row** on the counterparty's own attachment: the probe is
/// counted arriving, and the answer counted at zero. The fork's log cannot
/// corroborate either — its drop lines compile out of a `Release` build — so
/// the claims quote the wire.
fn caps_utp(bench: &mut Bench, options: &NattOptions<'_>, stage: &Stage) -> Result<Driven> {
    let kno_v4 = stage.v4(HOST_AMULE_KNO).to_owned();
    let driver_v4 = stage.v4(super::bench::HOST_DRIVER).to_owned();

    // The counterparty's user hash is an operand, not a guess: a CAPS probe
    // naming a fabricated recipient is refused by every conforming reader, so
    // it is read off the body's own hello answer first.
    let hello = hello_leg(bench, options, stage, &kno_v4)?;
    let peer_hash = hello.text("peer_user_hash");
    if peer_hash.len() != 32 {
        anyhow::bail!(
            "the hello leg did not recover kno's user hash (got {peer_hash:?}); \
             a CAPS probe cannot be addressed without it"
        );
    }

    run_driver(
        bench,
        options,
        stage,
        "caps-utp",
        &[
            "natt".to_owned(),
            "caps-utp".to_owned(),
            "--peer".to_owned(),
            format!("{kno_v4}:{BODY_CLIENT_UDP_PORT}"),
            "--peer-user-hash".to_owned(),
            peer_hash.clone(),
            "--user-hash".to_owned(),
            RMULE_USER_HASH.to_owned(),
            "--observed-address".to_owned(),
            driver_v4.clone(),
            "--bind-port".to_owned(),
            BODY_CLIENT_UDP_PORT.to_string(),
            "--capture".to_owned(),
            out("caps-utp-capture"),
            "--out".to_owned(),
            out("caps-utp.toml"),
        ],
    )?;
    let row = DriverRow::read(&stage.leg_dir.join("caps-utp.toml"))?;

    // kno's `0xB2` demux narrates both drops — *in a debug build*.
    // `AddDebugLogLineN` expands to nothing without `__DEBUG__` (`Logger.h:462`)
    // and the image is built `-DCMAKE_BUILD_TYPE=Release`, so the lines cannot
    // be on this body's log and their absence says nothing about the drop. The
    // scan stays because a debug-built pin would carry them; what the claims
    // quote instead is the wire, which is where the silence actually is.
    let kno_log = body_log(
        bench,
        stage,
        &container_name(options.layout, "nattkno")?,
        "amule-kno",
    )?;
    let no_debug_lines = "its own drop lines are `AddDebugLogLineN`, which expands to nothing \
         outside a `__DEBUG__` build (Logger.h:462) and the image builds Release — \
         so the log cannot carry them and the wire is what shows the silence";
    let caps_line = quoted(&kno_log, "Ignoring NAT-T capability frame", no_debug_lines);
    let key_line = quoted(&kno_log, "Ignoring NAT-T key frame", no_debug_lines);

    let claims = vec![
        Claim::about(
            "amule-kno-claims-natt-in-its-hello",
            hello.flag("mod_misc_present") && hello.int("mod_misc_word") & 0x0002 != 0,
            Evidence::Captured,
            format!(
                "its OP_HELLOANSWER carried CT_MOD_MISCOPTIONS = {:#06x}; \
                 bit 1 MODMISC_NAT_TRAVERSAL {}, bit 4 MODMISC_NAT_TRAVERSAL_QUIC {}",
                hello.int("mod_misc_word"),
                if hello.int("mod_misc_word") & 0x0002 != 0 {
                    "set"
                } else {
                    "clear"
                },
                if hello.int("mod_misc_word") & 0x0010 != 0 {
                    "set"
                } else {
                    "clear"
                },
            ),
        ),
        Claim::about(
            "a-utp-tunnel-rose-over-the-advertised-client-udp-bind",
            row.flag("tunnel_open"),
            Evidence::SingleOracle,
            format!(
                "librqbit-utp completed a handshake with {} in {}s; \
                 {} inbound 0xB2/0x00 frames, first from {}. \
                 Single-oracle: kno's fork is the only pinned body carrying uTP under 0xB2.",
                row.text("peer"),
                row.int("dial_seconds"),
                row.int("utp_frames_in"),
                row.text("utp_answer_from"),
            ),
        ),
        Claim::about(
            "the-utp-answer-left-the-port-the-hello-named",
            row.text("utp_answer_from") == format!("{kno_v4}:{BODY_CLIENT_UDP_PORT}"),
            Evidence::SingleOracle,
            format!(
                "answered from {}, the client-UDP bind its CT_EMULE_UDPPORTS names \
                 (ADR-0057's unified socket)",
                row.text("utp_answer_from")
            ),
        ),
        Claim::absence(
            "amule-kno-negotiates-no-caps-at-this-pin",
            row.int("caps_ack_frames"),
            format!(
                "the probe went out ({} bytes) and drew {} CAPS-ACK. kno's own log: {}. \
                 Its 0xB2 demux takes OP_NATT_FRAME_CAPS and _CAPS_ACK to one branch \
                 (\"nothing to negotiate\", ClientUDPSocket.cpp), so ADR-0092's \
                 CAPS/CAPS-ACK claim has no counterparty at this Fork Pin.",
                row.int("caps_probe_bytes"),
                row.int("caps_ack_frames"),
                caps_line,
            ),
        ),
        Claim::absence(
            "amule-kno-adopts-no-key-frame-at-this-pin",
            row.int("key_frames_in"),
            format!(
                "{} inbound KEY frames. kno's own log: {}. It reads the frame and \
                 discards it, so rmule's transport frames toward it stay plaintext — \
                 which is what the wire rows below count.",
                row.int("key_frames_in"),
                key_line,
            ),
        ),
    ];

    let wire = vec![
        wire_row("caps-probe-out", &kno_v4, true, FRAME_CAPS),
        wire_row("caps-ack-in", &kno_v4, false, FRAME_CAPS_ACK),
        wire_row("key-frame-out", &kno_v4, true, FRAME_KEY),
        wire_row("utp-out", &kno_v4, true, FRAME_UTP),
        wire_row("utp-in", &kno_v4, false, FRAME_UTP),
    ];

    Ok(Driven {
        claims,
        bodies: Vec::new(),
        wire,
        note: format!(
            "ADR-0092's `natt-caps-utp` row names three claims and kno's aMule \
             `ab483654` can serve one of them. Its `0xB2` demux ignores both capability \
             frames and the KEY frame by design and says so in its own log, so the \
             CAPS/CAPS-ACK and KEY halves are Documented Absences with the \
             counterparty's line attached, and the uTP half is the captured row. \
             rmule's side ran on {driver_v4} with the crypt armed, so the KEY frame \
             the send path arms on an opening packet is on the wire and counted."
        ),
        tunnel_rose: None,
    })
}

/// The wire half of `natt-caps-utp`: which `0xB2` frame types crossed, in which
/// direction, off the counterparty's own attachment.
fn caps_utp_wire_claims(wire: &[WireRow]) -> Vec<Claim> {
    vec![
        Claim::about(
            "the-caps-probe-reached-the-counterparty",
            packets(wire, "caps-probe-out") >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} 0xB2/0x02 datagrams on its own attachment — the silence above is \
                 measured against a probe that demonstrably arrived",
                packets(wire, "caps-probe-out")
            ),
        ),
        Claim::about(
            "the-key-frame-rode-the-opening-packet",
            packets(wire, "key-frame-out") >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} 0xB2/0xFF datagrams toward the counterparty. rmule-only: the KEY \
                 frame is rmule's own emission and no counterparty byte can prove it.",
                packets(wire, "key-frame-out")
            ),
        ),
        Claim::about(
            "the-counterparty-answered-the-utp-syn",
            packets(wire, "utp-in") >= 1 && packets(wire, "utp-out") >= 1,
            Evidence::SingleOracle,
            format!(
                "{} 0xB2/0x00 datagrams out, {} back — the handshake in both directions, \
                 off kno's own attachment",
                packets(wire, "utp-out"),
                packets(wire, "utp-in"),
            ),
        ),
        Claim::absence(
            "no-caps-ack-crossed-the-wire",
            packets(wire, "caps-ack-in"),
            format!(
                "{} 0xB2/0x03 datagrams from the counterparty: the absence is the pcap's, \
                 not the driver's socket's",
                packets(wire, "caps-ack-in")
            ),
        ),
    ]
}

/// The counterparty's own line for `needle`, quoted, or `fallback` when this
/// build cannot have written one. Never an invented sentence: a claim that said
/// "the counterparty logged nothing" would read as a measurement when the line
/// was compiled out.
fn quoted(log: &str, needle: &str, fallback: &str) -> String {
    log.lines().find(|line| line.contains(needle)).map_or_else(
        || fallback.to_owned(),
        |line| format!("\"{}\"", line.trim()),
    )
}

/// One `0xB2` **Wire Row** in one direction, cut on the frame-type byte.
///
/// The tap runs in the counterparty's own namespace, so `dst host <body>` is
/// rmule's emission and `src host <body>` is the counterparty's.
fn wire_row(name: &str, body: &str, toward_body: bool, frame_type: u8) -> WireRowRequest {
    let direction = if toward_body { "dst" } else { "src" };
    WireRowRequest {
        name: name.to_owned(),
        bpf: format!(
            "udp and {direction} host {body} and udp[8] = 0xb2 and udp[9] = {frame_type:#04x}"
        )
        .into(),
    }
}

/// One `ipv6 hello` leg against a body over IPv4, returning its row.
///
/// Reused rather than reimplemented: the hello is not what these flows measure,
/// it is how they learn the counterparty's user hash and its `0xAA` claim word,
/// and a second hello driver would be a second reading of the same block.
fn hello_leg(
    bench: &Bench,
    options: &NattOptions<'_>,
    stage: &Stage,
    body_v4: &str,
) -> Result<DriverRow> {
    run_driver(
        bench,
        options,
        stage,
        "hello",
        &[
            "ipv6".to_owned(),
            "hello".to_owned(),
            "--peer".to_owned(),
            format!("{body_v4}:{BODY_PEER_TCP_PORT}"),
            "--user-hash".to_owned(),
            RMULE_USER_HASH.to_owned(),
            "--advertise-udp-ports".to_owned(),
            format!("{BODY_CLIENT_UDP_PORT}:{BODY_CLIENT_UDP_PORT}"),
            "--capture".to_owned(),
            out("hello-capture"),
            "--out".to_owned(),
            out("hello.toml"),
        ],
    )?;
    DriverRow::read(&stage.leg_dir.join("hello.toml"))
}

/// One peer's gateway as evidence: its **NAT Type Proof** and what its own
/// conntrack table says about the punch's outbound half.
///
/// The conntrack counts are here rather than left in the dump because ADR-0045
/// names "the outbound conntrack entry" as one of the four things a punch-failure
/// row needs, and a claim that cited a *file* would be satisfied by an empty one.
pub(crate) struct GatewayProof {
    /// The gateway's fake-public WAN address.
    pub(crate) wan: String,
    /// Its claim, the probe's observation, and the pinned-port leg.
    pub(crate) proof: crate::nat::NatTypeProof,
    /// Mappings leaving the client's pinned port toward the *other* peer's
    /// gateway — the burst and the opener, as the kernel recorded them.
    pub(crate) punch_mappings: usize,
    /// How many of those never saw a packet back.
    pub(crate) unreplied: usize,
}

/// **`natt-server-punch-{cone,symmetric}`** — what two rmule peers introduced
/// by an `ed2ksrv` did, from the two driver rows.
///
/// Every claim here is **`rmule-only`** (ADR-0045's 2026-09-16 amendment):
/// both ends of the punch are rmule, so the surface is scored *exercised*
/// against a proven NAT rather than captured. The server rows are the wire
/// half, below: its `0x61` out is its own bytes (`single-oracle`), while the
/// `0x60` and `0x9F` it receives are rmule's (`rmule-only`).
pub(crate) fn punch_claims(
    flow: NattFlow,
    rows: &[DriverRow],
    proofs: &[GatewayProof],
    server_v4: &str,
    file_hash: &str,
    expected_size: u64,
    bodies: Vec<crate::flow::nat::claims::Body>,
) -> Driven {
    let transfer = flow == NattFlow::TunnelTransfer;
    // "Negative" is the one axis these three rows differ on, and it is the
    // symmetric row alone: the cone row and the transfer row both expect a
    // Tunnel. Deriving it from `== ServerPunchCone` left the transfer row
    // carrying the symmetric row's claims (run `1790034522`).
    let negative = flow == NattFlow::ServerPunchSymmetric;
    let cone = !negative;
    let gateways: Vec<&str> = proofs.iter().map(|proof| proof.wan.as_str()).collect();
    let (requester, responder) = (&rows[0], &rows[1]);
    let both_low_id = rows
        .iter()
        .all(|row| row.flag("connected") && row.flag("low_id"));
    let tunnels = measured_total(
        rows.iter()
            .flat_map(|row| [row.int("tunnels_dialed"), row.int("tunnels_accepted")]),
    );

    let mut claims = vec![
        // The **NAT Type Proof**'s pinned-port leg, before anything about the
        // punch. A gateway that cannot forward the port every punch is aimed at
        // makes every later count meaningless, and the RFC 5780 tests cannot
        // see that rule at all — the zero it once produced cost two debugging
        // sessions, so the flow now states it first and by name.
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
        Claim::about(
            "both-peers-earned-a-low-id-behind-their-own-gateway",
            both_low_id,
            // Read off rmule's own driver rows; no capture of the server's
            // id assignment backs it.
            Evidence::RmuleOnly,
            format!(
                "the server assigned {} and {}; a gateway that forwards no TCP is what \
                 makes the pair Low-ID↔Low-ID, which is the rung this row exists for",
                requester.int("client_id"),
                responder.int("client_id"),
            ),
        ),
        Claim::about(
            "the-requester-routed-through-the-server-coordinator",
            requester.text("routed").contains("ServerPunch"),
            Evidence::RmuleOnly,
            format!(
                "ReachPeer for {} routed {}; {} server punches emitted, {} refused ({})",
                requester.int("target_id"),
                requester.text("routed"),
                requester.int("server_punches"),
                requester.int("server_refusals"),
                requester.text("last_refusal"),
            ),
        ),
    ];
    // The one-symmetric row is one draw of a probabilistic pairing: a run
    // without a Tunnel is not a failure, only a Tunnel that disagrees with
    // the two port sets is (its prediction claims, `punch::prediction`).
    if flow == NattFlow::ServerPunchOneSymmetric {
        // Neither the positive's Tunnel claim nor the negative's kit: this
        // row's per-run claims are `punch::prediction`'s.
    } else if cone {
        claims.push(Claim::about(
            "a-tunnel-rose-between-the-two-firewalled-peers",
            tunnels >= 1,
            Evidence::RmuleOnly,
            // The dial counts are what separate "the coordination never
            // reached the transport" from "openers left and nothing answered".
            // Without them a zero here reads as the first, which is how one
            // run sent a whole session looking for a defect in `crates/`
            // while an `ST_SYN` was on the requester's own LAN tap.
            format!(
                "{} dialed + {} accepted on the requester, {} + {} on the responder; \
                 {} openers sent by the requester ({} in its last attempt), {} by the \
                 responder; last transport {:?}",
                requester.int("tunnels_dialed"),
                requester.int("tunnels_accepted"),
                responder.int("tunnels_dialed"),
                responder.int("tunnels_accepted"),
                requester.int("dials"),
                requester.text("last_attempt_dials"),
                responder.int("dials"),
                requester.text("last_tunnel_transport"),
            ),
        ));
    } else {
        claims.push(Claim::absence(
            "no-tunnel-rose-behind-symmetric-gateways",
            tunnels,
            format!(
                "{tunnels} tunnels across both peers; the requester spent its budget on {} \
                 dials ({} in its last attempt) and the responder on {}. The negative is \
                 qualified in the same run by both gateways' NAT Type Proof, the reflector \
                 probe beside their claim, the conntrack dump showing the outbound mapping \
                 existed, and the counterparty's own zero below (ADR-0045 as amended).",
                requester.int("dials"),
                requester.text("last_attempt_dials"),
                responder.int("dials"),
            ),
        ));
        // ADR-0045's third element, by name rather than by the presence of a
        // file: the outbound mapping a symmetric gateway *did* open. Without
        // it, "no tunnel rose" is indistinguishable from a punch that never
        // left the LAN.
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
    }
    if transfer {
        // The rung's whole point, in three claims: the download *chose* NAT-T
        // on its own clock, it *claimed* the Tunnel the punch raised, and the
        // bytes that came out the far end are the bytes that went in.
        claims.push(Claim::about(
            "the-low-id-downloader-admitted-its-low-id-candidate",
            requester.flag("download_started") && requester.text("download_failure").is_empty(),
            Evidence::RmuleOnly,
            format!(
                "download_started = {}, failure {:?}. The admission rule is `a callback, \
                 or a coordinator` (`LowIdRoad::of`): this downloader is \
                 itself Low-ID, so no callback can be relayed to it and the candidate is \
                 admitted on the other half alone — it is on the server both peers are \
                 logged into, which is the coordinator that can introduce them.",
                requester.flag("download_started"),
                requester.text("download_failure"),
            ),
        ));
        claims.push(Claim::about(
            "the-download-fell-to-nat-t-on-its-own-clock",
            requester.int("download_fallbacks") >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} falls to NAT traversal, {} of them unclaimable; {} candidates admitted \
                 no coordinator. The fall is the download brain's own decision — nothing in \
                 this flow asks for a punch — and for a LowID↔LowID pair it is taken on \
                 admission, with no callback to spend twelve seconds of silence on.",
                requester.int("download_fallbacks"),
                requester.int("download_fallbacks_unclaimable"),
                requester.int("download_adoptions_no_coordinator"),
            ),
        ));
        claims.push(Claim::about(
            "the-download-adopted-the-tunnel-the-punch-raised",
            requester.int("download_adoptions") >= 1,
            Evidence::RmuleOnly,
            format!(
                "{} adoptions, {} refused, {} claims retired; the claim is keyed by the \
                 target's User Hash and the peer's own hello is what confirms it \
                 (ADR-0091)",
                requester.int("download_adoptions"),
                requester.int("download_adoptions_refused"),
                requester.int("download_claims_retired"),
            ),
        ));
        claims.push(Claim::about(
            "the-file-completed-byte-equal-over-the-punched-path",
            requester.flag("download_completed")
                && requester
                    .text("output_ed2k_hash")
                    .eq_ignore_ascii_case(file_hash),
            Evidence::RmuleOnly,
            format!(
                "completed = {}, {} bytes out of {expected_size}, ED2K hash {} against the \
                 link's {file_hash}{}",
                requester.flag("download_completed"),
                requester.int("output_bytes"),
                requester.text("output_ed2k_hash"),
                if requester.text("download_failure").is_empty() {
                    String::new()
                } else {
                    format!("; failure: {}", requester.text("download_failure"))
                },
            ),
        ));
    }

    Driven {
        claims,
        bodies,
        // The punch topology counts its own rows across three taps before it
        // returns, so nothing is left for the shared bench path to count.
        wire: Vec::new(),
        note: format!(
            "Both ends of the punch are rmule, so every row above is `rmule-only` and is \
             scored exercised rather than captured; the counterparty bytes are the \
             ed2ksrv's own, off its attachment at {server_v4}. One gateway per peer \
             ({}), because ed2k-server `{}` keys `observed_udp_ports` by IPv4 address \
             alone and two NAT-T clients behind one NAT overwrite each other's observed port.",
            gateways.join(", "),
            crate::flow::ed2ksrv::pin_text(),
        ),
        tunnel_rose: None,
    }
}

/// Sum every **Wire Row** whose name begins with `prefix` — the per-peer rows
/// a two-peer topology cuts twice under one question — or `-1` when no row
/// carries that prefix, so a count the run never cut cannot read as a zero.
fn sum_rows(wire: &[WireRow], prefix: &str) -> i64 {
    let mut rows = wire
        .iter()
        .filter(|row| row.name.starts_with(prefix))
        .map(|row| i64::try_from(row.packets).unwrap_or(i64::MAX))
        .peekable();
    if rows.peek().is_none() {
        return -1;
    }
    measured_total(rows)
}

/// The server's tap: rmule's `0x60` in, the server's own `0x61` to both
/// peers, and the keepalive cadence that makes an observed port fresh enough
/// to introduce.
fn punch_wire_claims(flow: NattFlow, wire: &[WireRow]) -> Vec<Claim> {
    let cone = flow != NattFlow::ServerPunchSymmetric;
    let punches: i64 = sum_rows(wire, "holepunch-datagrams-from-");
    let mut claims = vec![
        Claim::about(
            "the-server-received-one-holepunch-request",
            packets(wire, "holepunch-request-in") >= 1,
            // rmule's own `0x60`, counted arriving: no server byte in it.
            Evidence::RmuleOnly,
            format!(
                "{} `0x60` frames on the coordinator's own session, against {} `0x62` refusals",
                packets(wire, "holepunch-request-in"),
                packets(wire, "holepunch-fail-out"),
            ),
        ),
        Claim::about(
            "the-server-introduced-both-peers",
            packets(wire, "holepunch-info-out") >= 2,
            // The server's own bytes, but only ed2ksrv emits `0x61`: the
            // promoted fixture's meta classes it `single-oracle`.
            Evidence::SingleOracle,
            format!(
                "{} `0x61` frames out — one per side, which is what makes both ends punch \
                 at once (ADR-0091: no relay round trip exists to halve)",
                packets(wire, "holepunch-info-out"),
            ),
        ),
        Claim::about(
            "the-keepalive-reached-the-server-udp-port",
            packets(wire, "natt-keepalive-in") >= 1,
            // rmule's own `0x9F`, counted arriving: no server byte in it.
            Evidence::RmuleOnly,
            format!(
                "{} `0x9F` datagrams; the server trusts an observed port for 600 s, so the \
                 cadence is a correctness invariant rather than a tuning",
                packets(wire, "natt-keepalive-in"),
            ),
        ),
    ];
    // The same `0xA1` burst as the LAN taps saw it, before translation. Two
    // numbers rather than one because they answer different questions: the WAN
    // count says what left the gateway, the LAN count says what the node fired.
    // Run `1790028867` had 38 on the LAN and 13 on the WAN and nobody looked.
    let lan_punches: i64 = sum_rows(wire, "holepunch-lan-out-from-");
    let lan_transport_out: i64 = sum_rows(wire, "natt-transport-lan-out-");
    let lan_transport_in: i64 = sum_rows(wire, "natt-transport-lan-in-");
    let wan_transport: i64 = sum_rows(wire, "natt-transport-from-");
    claims.push(if cone {
        Claim::about(
            "both-peers-burst-at-the-endpoint-the-server-named",
            punches >= 1,
            Evidence::RmuleOnly,
            format!(
                "{punches} `0xA1` datagrams left the two gateways, against {lan_punches} \
                 fired on the two LAN segments — a WAN count far below the LAN one is a \
                 gateway eating the burst, which is what the first server-coordinated punch's zero turned out to be"
            ),
        )
    } else {
        Claim::about(
            "the-punch-was-attempted-and-the-mapping-existed",
            punches >= 1 && lan_punches >= 1,
            Evidence::RmuleOnly,
            format!(
                "{punches} `0xA1` datagrams left the two gateways ({lan_punches} fired on \
                 the two LANs) — the outbound half of the negative, without which a zero \
                 would be a punch that was never fired",
            ),
        )
    });
    if !cone {
        // **Counterparty-zero, read on both taps.** A `0xB2` that left the LAN
        // and never crossed the WAN would be a bench fault; a `0xB2` that
        // crossed the WAN and never came back is the NAT type doing its job.
        // Only the second is the negative this row publishes.
        claims.push(Claim::absence(
            "no-transport-frame-arrived-at-either-peer",
            lan_transport_in,
            format!(
                "{lan_transport_out} `0xB2` frames left the two LAN segments and \
                 {wan_transport} crossed the two WAN attachments, and \
                 {lan_transport_in} arrived at either client. The openers were fired \
                 and translated; nothing answered, which behind an \
                 address-and-port-dependent mapping is the expected outcome and not a \
                 silence the bench caused.",
            ),
        ));
        claims.push(Claim::about(
            "the-openers-left-the-lan-behind-symmetric-gateways",
            lan_transport_out >= 1,
            Evidence::RmuleOnly,
            format!(
                "{lan_transport_out} `0xB2` frames on the two LAN taps. A zero here would \
                 make the row above a statement about rmule's dialer rather than about \
                 the NAT type, so it is asserted separately.",
            ),
        ));
    }
    claims
}

#[cfg(test)]
mod tests;
