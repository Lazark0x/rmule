//! The verdict each port-mapping flow writes, and the rule that judges it.
//!
//! Every judgement below reads the **gateway's** own record first and rmule's
//! row second. That order is the ADR-0045 posture, not style: "rmule says it is
//! mapped" is a claim about rmime's own state, and only the router's lease table
//! and log can say whether the port is actually forwarded.
//!
//! ADR-0092's fourth `portmap-highid` assertion — the Kad verdict flips open —
//! is the one no router can settle on its own, so it is judged on the **Kad
//! helpers'** own bytes: their `0x58` answers, their connect-backs to the
//! mapped port, and the `OP_KAD_FWTCPCHECK_ACK` they delivered on those links.

use std::fs;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::artifacts::RunLayout;
use crate::flow::nat::claims::GATEWAYS_PROBED_AS_CLAIMED;
use crate::flow::nat::portmap::gateway::GatewayRecord;
use crate::flow::nat::portmap::helper::KadHelperWire;
use crate::flow::nat::portmap::link_local::PcpSources;
use crate::flow::nat::portmap::row::DriverRow;
use crate::flow::nat::portmap::{DRIVER_LAN_ADDRESS, PEER_TCP_PORT, PortMapFlow, UDP_PORT};
use crate::flow::taps::TapRow;
use crate::nat::NatTypeProof;

/// The flow's verdict file.
#[derive(Debug, Serialize)]
pub(crate) struct PortMapVerdict {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    /// `PASS`, `OBSERVED`, `SKIPPED` or `FAIL`.
    pub(crate) verdict: &'static str,
    /// What the label means for this run, in one sentence per claim.
    pub(crate) detail: String,
    /// Present only on a skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skip_reason: Option<String>,
    /// The **NAT Type Proof** for the gateway this run used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nat_type: Option<NatTypeProof>,
    /// The fake-public WAN and the masquerade-free LAN the run used.
    pub(crate) wan_subnet: String,
    pub(crate) lan_subnet: String,
    /// The v6 `/64`s, when the flow used them.
    pub(crate) wan_subnet_v6: String,
    pub(crate) lan_subnet_v6: String,
    /// Which protocol the driver was forced onto.
    pub(crate) protocol: &'static str,
    /// The `(protocol, port)` pairs a second container claimed first.
    pub(crate) preclaimed: Vec<String>,
    /// The **Per-Attachment Taps** on the gateway's two sides.
    #[serde(rename = "tap")]
    pub(crate) taps: Vec<TapRow>,
    /// The bench capabilities the doctor measured.
    #[serde(rename = "capability")]
    pub(crate) capabilities: Vec<crate::bench_doctor::Capability>,
    /// What the gateway itself recorded.
    pub(crate) gateway: GatewayRecord,
    /// What rmule reported about itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rmule: Option<DriverRow>,
    /// What the **Kad helpers** did, counted off the WAN tap — present only for
    /// the flow that stands them up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kad_wire: Option<KadHelperWire>,
    /// Every PCP request's source against its header, off the LAN tap —
    /// present only for the link-local variant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pcp_sources: Option<PcpSources>,
    /// The per-claim results, so a reader sees which half held.
    pub(crate) claim: Vec<Claim>,
}

/// One assertion the flow makes, and how it came out.
#[derive(Debug, Serialize)]
pub(crate) struct Claim {
    /// The claim's stable name.
    pub(crate) name: &'static str,
    /// `held`, `absent`, or `blocked` — an assertion that could not be driven at
    /// all, with the reason in `note`.
    pub(crate) outcome: &'static str,
    /// What was actually observed, quoting the gateway where it spoke.
    pub(crate) note: String,
}

impl Claim {
    fn held(name: &'static str, note: impl Into<String>) -> Self {
        Self {
            name,
            outcome: "held",
            note: note.into(),
        }
    }

    fn absent(name: &'static str, note: impl Into<String>) -> Self {
        Self {
            name,
            outcome: "absent",
            note: note.into(),
        }
    }

    pub(super) fn blocked(name: &'static str, note: impl Into<String>) -> Self {
        Self {
            name,
            outcome: "blocked",
            note: note.into(),
        }
    }

    /// `held` when `condition`, else `absent`.
    pub(super) fn about(name: &'static str, condition: bool, note: impl Into<String>) -> Self {
        if condition {
            Self::held(name, note)
        } else {
            Self::absent(name, note)
        }
    }
}

/// Judge one flow from the gateway's record and rmule's row.
///
/// The label is the weakest claim: every claim `held` is `PASS`, a `blocked`
/// claim with no `absent` one is `OBSERVED` (the flow measured everything it
/// could and named what it could not), and any `absent` claim is `FAIL` —
/// something the bench *can* drive did not happen.
pub(crate) fn judge(
    flow: PortMapFlow,
    proof: &NatTypeProof,
    gateway: &GatewayRecord,
    rmule: &DriverRow,
    kad_wire: Option<&KadHelperWire>,
    sources: Option<&PcpSources>,
) -> (&'static str, String, Vec<Claim>) {
    let mut claims = vec![gateway_claim(proof)];
    claims.extend(match flow {
        PortMapFlow::HighId | PortMapFlow::NatPmp => high_id_claims(flow, gateway, rmule, kad_wire),
        PortMapFlow::Mismatch => mismatch_claims(gateway, rmule),
        PortMapFlow::Moved => super::moved::claims(gateway, rmule),
        PortMapFlow::Ipv6Pinhole | PortMapFlow::Ipv6PinholeLinkLocal => {
            pinhole_claims(gateway, rmule)
        }
    });
    if flow == PortMapFlow::Ipv6PinholeLinkLocal {
        claims.extend(sources.map_or_else(
            || {
                vec![Claim::absent(
                    "every-pcp-request-left-from-the-known-ipv6",
                    "no PCP request was lifted off the LAN tap",
                )]
            },
            |sources| sources.claims(gateway),
        ));
    }
    let absent = claims
        .iter()
        .filter(|claim| claim.outcome == "absent")
        .count();
    let blocked = claims
        .iter()
        .filter(|claim| claim.outcome == "blocked")
        .count();
    let verdict = if absent > 0 {
        "FAIL"
    } else if blocked > 0 {
        "OBSERVED"
    } else {
        "PASS"
    };
    let detail = format!(
        "{} claims: {} held, {blocked} blocked (undriveable, named in `claim`), {absent} absent.",
        claims.len(),
        claims.len() - blocked - absent,
    );
    (verdict, detail, claims)
}

/// A post-exit table as a note prints it.
fn after_table(table: Option<&String>) -> String {
    table.map_or_else(
        || "unread".to_owned(),
        |table| format!("<{}>", table.trim()),
    )
}

/// `release-on-exit-empties-the-gateway-table`, `blocked` when a post-exit
/// table could not be read: an unread table is not an emptied one.
fn release_claim(gateway: &GatewayRecord) -> Claim {
    const NAME: &str = "release-on-exit-empties-the-gateway-table";
    let note = format!(
        "after the driver exited the gateway's tables read v4={} v6={}, and it logged {} \
         DeletePortMapping / {} PCP or NAT-PMP removals",
        after_table(gateway.table_v4_after.as_ref()),
        after_table(gateway.table_v6_after.as_ref()),
        gateway.delete_port_mapping,
        gateway.pcp_removed,
    );
    gateway.released().map_or_else(
        || Claim::blocked(NAME, note.clone()),
        |released| Claim::about(NAME, released, note.clone()),
    )
}

/// `the-shifted-grants-end-on-exit` (`portmap-mismatch`): UPnP keys a mapping
/// by its external port, so the release at quit must name the ports the
/// gateway granted, not the ones rmule asked for — those name the second
/// host's rows. Held when no row for rmule survives the exit and both
/// pre-claim rows do; `blocked` on an unread table.
fn shifted_release_claim(gateway: &GatewayRecord) -> Claim {
    const NAME: &str = "the-shifted-grants-end-on-exit";
    let note = format!(
        "after the driver exited the gateway's IPv4 table read {} and it logged {} \
         DeletePortMapping",
        after_table(gateway.table_v4_after.as_ref()),
        gateway.delete_port_mapping,
    );
    match gateway.rows_v4_after() {
        None => Claim::blocked(NAME, note),
        Some(rows) => {
            let ours = rows
                .iter()
                .filter(|row| row.internal_address == DRIVER_LAN_ADDRESS)
                .count();
            let preclaimed = rows
                .iter()
                .filter(|row| row.description.contains("preclaim"))
                .count();
            Claim::about(NAME, ours == 0 && preclaimed == 2, note)
        }
    }
}

/// `the-pinhole-is-withdrawn-on-exit`, `blocked` on an unread table.
fn pinhole_withdrawn_claim(gateway: &GatewayRecord) -> Claim {
    const NAME: &str = "the-pinhole-is-withdrawn-on-exit";
    let note = format!(
        "after the driver exited the pinhole table read {} and the gateway logged {} removals",
        after_table(gateway.table_v6_after.as_ref()),
        gateway.pcp_removed,
    );
    match &gateway.table_v6_after {
        Some(table) => Claim::about(NAME, table.trim().is_empty(), note),
        None => Claim::blocked(NAME, note),
    }
}

/// The gateway's **NAT Type Proof**, judged rather than only recorded: a
/// miniupnpd gateway that probed as another NAT type than it claims ran these
/// rows behind a NAT the verdict does not name.
fn gateway_claim(proof: &NatTypeProof) -> Claim {
    Claim::about(
        GATEWAYS_PROBED_AS_CLAIMED,
        proof.agrees,
        format!(
            "claimed {} ({}/{}), observed {}/{}, agrees = {}",
            proof.nat_type.knob(),
            proof.claimed_mapping,
            proof.claimed_filtering,
            proof.observed_mapping,
            proof.observed_filtering,
            proof.agrees,
        ),
    )
}

/// `portmap-highid`: ADR-0092's four assertions, one claim each.
fn high_id_claims(
    flow: PortMapFlow,
    gateway: &GatewayRecord,
    rmule: &DriverRow,
    kad_wire: Option<&KadHelperWire>,
) -> Vec<Claim> {
    let tcp_exact = gateway.holds_exact(DRIVER_LAN_ADDRESS, PEER_TCP_PORT);
    // The gateway's log of each MAP, renewals included: SOAP actions for
    // UPnP, request lines for NAT-PMP.
    let (requests, action) = if flow == PortMapFlow::NatPmp {
        (gateway.natpmp_requests, "NAT-PMP mapping requests")
    } else {
        (gateway.add_port_mapping, "AddPortMapping actions")
    };
    let tcp_line = gateway
        .leases
        .iter()
        .find(|lease| lease.internal_port == PEER_TCP_PORT)
        .map_or_else(|| "(no row)".to_owned(), |lease| lease.line.clone());
    let rows_mapped = !rmule.mappings.is_empty()
        && rmule
            .mappings
            .iter()
            .all(|mapping| mapping.status == "mapped" && mapping.exact);
    // The assertion is about the **endpoint**, not the tier that holds it.
    //
    // Measured: once the ADR-0058 self-check is armed, the helpers'
    // `0x58` answers state rmule's observed external address at the `kad-check`
    // tier, which *outranks* `mapping-grant` on ADR-0084's per-family address
    // ladder. So the row legitimately reads `kad-check` on a run with Kad
    // helpers and `mapping-grant` on one without, while naming the same
    // endpoint both times — two independent sources agreeing is the ladder
    // working, and pinning the tier would have made that read as a failure.
    // Comparing against the grant is also the stronger check: an Interface- or
    // Server-tier address would name a different endpoint, and this catches that
    // whatever tier label it arrived under.
    let tcp_advertised = rmule.address("tcp", "v4").is_some_and(|address| {
        address.verdict == "known"
            && rmule
                .mapping("tcp", "v4")
                .is_some_and(|row| row.external == address.endpoint)
    });

    vec![
        Claim::about(
            "gateway-table-holds-the-exact-port",
            tcp_exact,
            format!("the gateway's own lease table reads `{tcp_line}`"),
        ),
        Claim::about(
            "every-row-mapped-on-its-own-port",
            rows_mapped && rmule.every_row_exact,
            format!(
                "{} desired rows, every_row_exact = {}; statuses {}",
                rmule.desired_mappings,
                rmule.every_row_exact,
                rmule
                    .mappings
                    .iter()
                    .map(|mapping| format!(
                        "{}/{}={}@{}",
                        mapping.role, mapping.family, mapping.status, mapping.external_port
                    ))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ),
        Claim::about(
            "one-renewal-in-the-gateways-own-record",
            gateway.max_renewals() >= 1 && requests > gateway.leases.len() as u64,
            format!(
                "the gateway's table advanced an expiry {}x and it logged {requests} {action} \
                 for {} mappings; rmule counted {} renewals",
                gateway.max_renewals(),
                gateway.leases.len(),
                rmule.total_renewals,
            ),
        ),
        Claim::about(
            "the-granted-endpoint-is-what-gets-advertised",
            tcp_advertised,
            format!(
                "Address Learning holds TCP v4 as {}, against a granted external endpoint of {}",
                rmule.address("tcp", "v4").map_or_else(
                    || "(no row)".to_owned(),
                    |address| format!(
                        "{} at the {} tier ({})",
                        address.endpoint, address.tier, address.verdict
                    )
                ),
                rmule
                    .mapping("tcp", "v4")
                    .map_or("(no row)", |row| row.external.as_str()),
            ),
        ),
        release_claim(gateway),
        kad_flip_claim(rmule, kad_wire),
    ]
}

/// `portmap-mismatch`: the shifted grant, graded per role.
fn mismatch_claims(gateway: &GatewayRecord, rmule: &DriverRow) -> Vec<Claim> {
    let preclaimed: Vec<&_> = gateway
        .leases
        .iter()
        .filter(|lease| lease.description.contains("preclaim"))
        .collect();
    let tcp = rmule.mapping("tcp", "v4");
    let udp = rmule.mapping("udp", "v4");
    let tcp_degraded = tcp.is_some_and(|row| row.status == "degraded" && !row.exact);
    // "Never advertised" is a statement about the **port**, not about the tier.
    //
    // Measured (ADR-0092): ADR-0084's store runs a per-family ADDRESS
    // ladder and a per-role PORT ladder. `adopt` refuses a mismatched TCP grant
    // before it ever reaches the store, so the shifted port is never learned —
    // but the UDP grant in the same trial does feed it, and the address it
    // carries is the whole family's, so the TCP row legitimately reads
    // `<gateway external address>:<bound port>` at the `mapping-grant` tier.
    // That is exactly the outcome the eD2k hello needs: the port advertised is
    // the one the listener bound, and the shifted one is nowhere.
    let tcp_learned_port = tcp_advertised_port(rmule);
    let tcp_not_advertised = tcp.is_some_and(|row| {
        tcp_learned_port != Some(row.external_port) && tcp_learned_port == Some(row.internal_port)
    });
    let udp_shifted_mapped =
        udp.is_some_and(|row| row.status == "mapped" && !row.exact && row.external_port != 0);
    let udp_advertised_shifted = udp.is_some_and(|row| {
        rmule.address("udp", "v4").is_some_and(|address| {
            address.tier == "mapping-grant"
                && address
                    .endpoint
                    .ends_with(&format!(":{}", row.external_port))
        })
    });

    vec![
        Claim::about(
            "a-second-host-held-the-ports-first",
            preclaimed.len() == 2,
            format!(
                "the gateway's table held {} pre-claim rows: {}",
                preclaimed.len(),
                preclaimed
                    .iter()
                    .map(|lease| lease.line.clone())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
        ),
        Claim::about(
            "the-gateway-shifted-the-grant",
            gateway
                .external_for(DRIVER_LAN_ADDRESS, PEER_TCP_PORT)
                .is_some_and(|port| port != PEER_TCP_PORT)
                && gateway
                    .external_for(DRIVER_LAN_ADDRESS, UDP_PORT)
                    .is_some_and(|port| port != UDP_PORT),
            format!(
                "the gateway granted rmule TCP {} -> {:?} and UDP {} -> {:?}, logging {} \
                 AddPortMapping and {} AddAnyPortMapping actions; its rows for rmule are {}",
                PEER_TCP_PORT,
                gateway.external_for(DRIVER_LAN_ADDRESS, PEER_TCP_PORT),
                UDP_PORT,
                gateway.external_for(DRIVER_LAN_ADDRESS, UDP_PORT),
                gateway.add_port_mapping,
                gateway.add_any_port_mapping,
                gateway
                    .leases
                    .iter()
                    .filter(|lease| lease.internal_address == DRIVER_LAN_ADDRESS)
                    .map(|lease| lease.line.clone())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
        ),
        Claim::about(
            "the-tcp-row-reads-degraded",
            tcp_degraded,
            format!(
                "TCP v4 {}",
                tcp.map_or_else(
                    || "(no row)".to_owned(),
                    |row| format!(
                        "status={} external_port={} exact={} (bound {})",
                        row.status, row.external_port, row.exact, row.internal_port
                    )
                )
            ),
        ),
        Claim::about(
            "the-degraded-tcp-grant-is-never-advertised",
            tcp_not_advertised,
            format!(
                "Address Learning holds TCP v4 as {} — the port it would advertise is {:?}, the \
                 port the listener bound is {:?}, and the shifted port the gateway granted is \
                 {:?}. The tier reads `mapping-grant` because ADR-0084's ADDRESS ladder is \
                 per-family and the UDP grant in the same trial carried it; the mismatched \
                 TCP grant itself never reached the store.",
                rmule.address("tcp", "v4").map_or_else(
                    || "(no row)".to_owned(),
                    |address| format!(
                        "{} at the {} tier ({})",
                        address.endpoint, address.tier, address.verdict
                    )
                ),
                tcp_learned_port,
                tcp.map(|row| row.internal_port),
                tcp.map(|row| row.external_port),
            ),
        ),
        Claim::about(
            "a-shifted-udp-grant-is-mapped-and-carried",
            udp_shifted_mapped && udp_advertised_shifted,
            format!(
                "UDP v4 {} and Address Learning holds {}",
                udp.map_or_else(
                    || "(no row)".to_owned(),
                    |row| format!(
                        "status={} external_port={} (bound {})",
                        row.status, row.external_port, row.internal_port
                    )
                ),
                rmule
                    .address("udp", "v4")
                    .map_or_else(|| "(no row)".to_owned(), |address| address.endpoint.clone()),
            ),
        ),
        Claim::about(
            "no-reachability-recheck-was-earned",
            !rmule.every_row_exact && !rmule.kad_recheck_observed,
            format!(
                "every_row_exact = {} (so the install graded Mismatched, not Exact, and the \
                 mapper's recheck guard did not fire) and kad_recheck_observed = {}",
                rmule.every_row_exact, rmule.kad_recheck_observed,
            ),
        ),
        shifted_release_claim(gateway),
    ]
}

/// ADR-0092's fourth `portmap-highid` assertion, and the only one a router
/// cannot settle by itself: the mapping made rmule genuinely dialable, so the
/// Kad verdict it holds about itself must stop reading firewalled.
///
/// Judged counterparty-first (ADR-0045). The helpers' `0x58` answers say they
/// accepted rmule's checks; their connect-backs say the redirect carried a dial
/// from the outside world to rmule's listener; their `OP_KAD_FWTCPCHECK_ACK`s
/// say they completed the proof over the link they opened. rmule's own
/// `kad_firewall` is read last, and the *timing* is part of the claim: the flip
/// has to land at or after the grant, or it was never the grant that caused it.
///
/// The legacy `0x59` count is a control. A helper that judged rmule a pre-v7
/// node would ack over UDP instead, which would carry the verdict open with the
/// `0xA8` path never running — a green row for the wrong reason.
fn kad_flip_claim(rmule: &DriverRow, kad_wire: Option<&KadHelperWire>) -> Claim {
    let Some(wire) = kad_wire else {
        return Claim::blocked(
            "kad-verdict-flips-open",
            "no Kad helpers stood on the WAN, so no connect-back could be earned",
        );
    };
    let granted_at = rmule
        .mapping("tcp", "v4")
        .map_or(-1.0, |row| row.first_granted_secs);
    let flipped_after_the_grant = rmule.kad_firewall == "open"
        && granted_at >= 0.0
        && rmule.kad_first_open_secs >= granted_at;
    let held = wire.tcp_acks >= ACKS_FOR_OPEN
        && wire.legacy_acks == 0
        && rmule.kad_recheck_observed
        && flipped_after_the_grant;
    Claim::about(
        "kad-verdict-flips-open",
        held,
        format!(
            "the helpers answered {} of rmule's {} firewall checks, dialed the mapped port back \
             {} times and delivered {} OP_KAD_FWTCPCHECK_ACK on those links ({} legacy 0x59 — the \
             control); rmule held {} Kad contacts, saw its verdict pass through Checking = {}, \
             read \"{}\" at the end, and first read open at {:.1}s against a TCP grant at {:.1}s",
            wire.responses_in,
            wire.checks_out,
            wire.connect_backs,
            wire.tcp_acks,
            wire.legacy_acks,
            rmule.kad_contacts,
            rmule.kad_recheck_observed,
            rmule.kad_firewall,
            rmule.kad_first_open_secs,
            granted_at,
        ),
    )
}

/// Connect-back acks the ADR-0058 TCP verdict reads open on
/// (`Reachability::TCP_ACKS_FOR_OPEN`). Named here because the claim asserts the
/// *counterparty* delivered that many, which is the half rmule cannot fake.
const ACKS_FOR_OPEN: u64 = 2;

/// The port **Address Learning** would put on the eD2k hello for the TCP
/// listener, parsed off the rendered endpoint (`1.2.3.4:4662` or
/// `[3fff:ed2:2::4]:4662` — the port is always after the last colon).
fn tcp_advertised_port(rmule: &DriverRow) -> Option<u16> {
    rmule
        .address("tcp", "v4")
        .filter(|address| address.verdict == "known")
        .and_then(|address| address.endpoint.rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
}

/// `portmap-ipv6-pinhole`: a PCP MAP on the `3fff` address.
fn pinhole_claims(gateway: &GatewayRecord, rmule: &DriverRow) -> Vec<Claim> {
    let v6_rows = rmule.family_rows("v6");
    let v6_mapped = !v6_rows.is_empty()
        && v6_rows
            .iter()
            .all(|row| row.status == "mapped" && row.method == "pcp");
    let pinhole_rows: Vec<&_> = gateway
        .leases
        .iter()
        .filter(|lease| lease.family == "v6")
        .collect();
    let on_the_plan = pinhole_rows
        .iter()
        .all(|lease| lease.internal_address.starts_with("3fff:"));

    vec![
        Claim::about(
            "the-desired-set-grew-a-v6-row",
            !v6_rows.is_empty(),
            format!(
                "{} of {} desired rows are v6: {}",
                v6_rows.len(),
                rmule.desired_mappings,
                v6_rows
                    .iter()
                    .map(|row| format!("{}:{}", row.role, row.internal_port))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ),
        Claim::about(
            "the-gateway-opened-a-pinhole-on-the-3fff-address",
            !pinhole_rows.is_empty() && on_the_plan,
            format!(
                "the gateway's own IPv6 pinhole table (lease_file6) reads: {}; it logged {} \
                 `PCP MAP: added mapping` lines",
                pinhole_rows
                    .iter()
                    .map(|lease| lease.line.clone())
                    .collect::<Vec<_>>()
                    .join(" | "),
                gateway.pcp_added,
            ),
        ),
        Claim::about(
            "rmule-graded-the-pinhole-usable",
            v6_mapped,
            format!(
                "the v6 rows read {}",
                v6_rows
                    .iter()
                    .map(|row| format!(
                        "{}={}@{} via {} (lease {}s){}",
                        row.role,
                        row.status,
                        row.external,
                        row.method,
                        row.lease_secs,
                        if row.last_error.is_empty() {
                            String::new()
                        } else {
                            format!(" err={}", row.last_error)
                        }
                    ))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ),
        Claim::about(
            "the-v6-endpoint-is-known",
            rmule
                .address("tcp", "v6")
                .is_some_and(|address| address.verdict == "known"),
            format!(
                "the v6 half of the Desired Mapping Set is gated on a Known IPv6, so the driver \
                 states one outright (ADR-0084's Override tier, the one source exempt from the \
                 corroboration filter) rather than letting the gate ride on whatever the live \
                 interface enumeration found in the container — which is why the tier below \
                 reads `override` and not `mapping-grant`: an operator's statement outranks a \
                 grant. Address Learning holds TCP v6 as {}",
                rmule.address("tcp", "v6").map_or_else(
                    || "(no row)".to_owned(),
                    |address| format!(
                        "{} at the {} tier ({})",
                        address.endpoint, address.tier, address.verdict
                    )
                )
            ),
        ),
        pinhole_withdrawn_claim(gateway),
    ]
}

/// Write the verdict beside the flow's other artifacts.
///
/// # Errors
/// If it cannot be serialised or written.
pub(crate) fn write(layout: &RunLayout, verdict: &PortMapVerdict) -> Result<()> {
    fs::create_dir_all(layout.nat_dir())?;
    let text = toml::to_string_pretty(verdict).context("serialize the port-mapping verdict")?;
    let path = layout.root().join(format!("{}-verdict.toml", verdict.flow));
    println!(
        "{} verdict={} — {}",
        verdict.flow, verdict.verdict, verdict.detail
    );
    for claim in &verdict.claim {
        println!("  {} {} — {}", claim.outcome, claim.name, claim.note);
    }
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{gateway_claim, pinhole_withdrawn_claim, release_claim, shifted_release_claim};
    use crate::flow::nat::portmap::gateway::GatewayRecord;

    /// A post-exit table that could not be read used to read as emptied, so
    /// the release claims held on a failed `cat`; they are `blocked` now.
    #[test]
    fn an_unread_post_exit_table_proves_no_release() {
        let unread = GatewayRecord::default();
        assert_eq!(release_claim(&unread).outcome, "blocked");
        assert_eq!(pinhole_withdrawn_claim(&unread).outcome, "blocked");

        let emptied = GatewayRecord {
            table_v4_after: Some(String::new()),
            table_v6_after: Some("\n".to_owned()),
            ..GatewayRecord::default()
        };
        assert_eq!(release_claim(&emptied).outcome, "held");
        assert_eq!(pinhole_withdrawn_claim(&emptied).outcome, "held");

        let kept = GatewayRecord {
            table_v4_after: Some(String::new()),
            table_v6_after: Some("row".to_owned()),
            ..GatewayRecord::default()
        };
        assert_eq!(release_claim(&kept).outcome, "absent");
        assert_eq!(pinhole_withdrawn_claim(&kept).outcome, "absent");
    }
    use crate::nat::{NatType, NatTypeProof, PinnedPortReach};

    /// A shifted grant ends only when the release names the granted port: a
    /// delete by the asked-for port leaves rmule's row and, on a gateway that
    /// did not check the caller, would take the second host's.
    #[test]
    fn a_shifted_grant_ends_on_its_granted_port() {
        let after = |table: &str| GatewayRecord {
            table_v4_after: Some(table.to_owned()),
            ..GatewayRecord::default()
        };
        let preclaims = "TCP:4662:10.77.0.5:4662:1:preclaim\nUDP:4672:10.77.0.5:4672:1:preclaim\n";
        assert_eq!(shifted_release_claim(&after(preclaims)).outcome, "held");
        let kept = format!("{preclaims}TCP:57641:10.77.0.4:4662:1:rmule\n");
        assert_eq!(shifted_release_claim(&after(&kept)).outcome, "absent");
        let taken = "UDP:4672:10.77.0.5:4672:1:preclaim\n";
        assert_eq!(shifted_release_claim(&after(taken)).outcome, "absent");
        assert_eq!(
            shifted_release_claim(&GatewayRecord::default()).outcome,
            "blocked"
        );
    }

    /// The proof used to land only in the TOML; a gateway that probed as
    /// another type now fails the portmap row it stands under.
    #[test]
    fn a_gateway_probed_as_another_type_fails_its_row() {
        let (mapping, filtering) = NatType::PortRestricted.claim();
        let agreeing = NatTypeProof::new(
            NatType::PortRestricted,
            mapping.as_str(),
            filtering.as_str(),
            PinnedPortReach::not_probed(),
        );
        assert_eq!(gateway_claim(&agreeing).outcome, "held");
        let symmetric = NatTypeProof::new(
            NatType::PortRestricted,
            "address-and-port-dependent",
            filtering.as_str(),
            PinnedPortReach::not_probed(),
        );
        assert_eq!(gateway_claim(&symmetric).outcome, "absent");
    }
}
