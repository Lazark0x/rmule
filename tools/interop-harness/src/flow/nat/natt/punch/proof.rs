//! The **NAT Type Proof**'s observation half: the WAN reflector with its
//! **Pinned-Port Sink**, the probe run from inside each peer's own LAN, and the
//! `nat-type.toml` the two produce.
//!
//! It runs before any driver does. A gateway that cannot forward the pinned
//! port at all was the whole cause of an early all-zero punch, and it costs seconds to find here
//! against three minutes of silent zero later.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::natt::bench::NattOptions;
use crate::flow::nat::{NAT_CLIENT_UDP_PORT, NATPROBE_PRIMARY_PORT, NATPROBE_SECONDARY_PORT};
use crate::nat::{NatType, NatTypeProof, PinnedPortReach};

use super::Peer;

/// The RFC 5780 **Reflector Probe**'s server half on the WAN, carrying a
/// **Pinned-Port Sink** beside its own two ports.
pub(in crate::flow::nat::natt) fn run_reflector(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    wan: &str,
    primary: &str,
    secondary: &str,
    suffix: &str,
    timeout: Duration,
) -> Result<()> {
    let reflector = format!("rmule-interop-nattprobe-{suffix}");
    bench.start_extra(
        &reflector,
        RunContainer::new(options.natprobe_image)
            .detach()
            .name(&reflector)
            .network(wan)
            .ip(primary)
            .cap_add("NET_ADMIN")
            .env("NATPROBE_PRIMARY_ADDR", primary)
            .env("NATPROBE_SECONDARY_ADDR", secondary)
            .env("NATPROBE_PRIMARY_PORT", NATPROBE_PRIMARY_PORT.to_string())
            .env(
                "NATPROBE_SECONDARY_PORT",
                NATPROBE_SECONDARY_PORT.to_string(),
            )
            .env("NATPROBE_PINNED_PORT", NAT_CLIENT_UDP_PORT.to_string()),
        "run the natprobe reflector",
    )?;
    wait_for_container_log(&bench.docker, &reflector, "rmule-natprobe-ready", timeout).map(drop)
}

/// Probe one peer's gateway from inside that peer's own LAN, and write the
/// `nat-type.toml` half of its **NAT Type Proof** beside the dumps.
///
/// The probe container takes the **client's own LAN address and pinned local
/// port**, exactly as `natgw-selfproof` does, and runs before the driver takes
/// them. It has to: `full-cone-pinned` is endpoint-independent **for the pinned
/// port only** (ADR-0092 names it so), and `NatType::claim()` states that
/// pinned-port behaviour — so a prober on any other port reads
/// address-and-port-dependent filtering and the proof would record
/// `agrees = false` about a gateway that is behaving exactly as specified.
/// Measured that way in run `1790033093` before this posture was fixed.
///
/// The pinned port is exercised twice over, and the two are different
/// questions: as a **source**, which is what makes the filtering reading the
/// pinned one; and as a **destination**, which is the axis the hairpinning rule
/// behind that early all-zero punch was keyed on.
pub(in crate::flow::nat::natt) fn probe_peer_lan(
    bench: &Bench,
    options: &NattOptions<'_>,
    peer: &Peer,
    nat_type: NatType,
    reflector: (&str, &str),
) -> Result<NatTypeProof> {
    let output = bench
        .docker
        .run_container(
            RunContainer::new(options.rmule_tools_image)
                .remove_after_exit()
                .network(&peer.network)
                .ip(peer.lan.client)
                .cap_add("NET_ADMIN")
                .volume(&peer.dir, "/out")
                .env("RMULE_DEFAULT_ROUTE_VIA", peer.lan.gateway)
                .arg("nat")
                .arg("probe")
                .arg("--reflector-primary")
                .arg(reflector.0)
                .arg("--reflector-secondary")
                .arg(reflector.1)
                .arg("--reflector-primary-port")
                .arg(NATPROBE_PRIMARY_PORT.to_string())
                .arg("--reflector-secondary-port")
                .arg(NATPROBE_SECONDARY_PORT.to_string())
                .arg("--pinned-port")
                .arg(NAT_CLIENT_UDP_PORT.to_string())
                .arg("--local-port")
                .arg(NAT_CLIENT_UDP_PORT.to_string())
                .arg("--timeout-ms")
                .arg("1500")
                .arg("--attempts")
                .arg("3")
                .arg("--out")
                .arg("/out/nat-probe.toml"),
        )
        .to_command()
        .output()
        .context("run the reflector probe")?;
    fs::write(peer.dir.join("probe.stdout.log"), &output.stdout)?;
    fs::write(peer.dir.join("probe.stderr.log"), &output.stderr)?;
    if !output.status.success() {
        bail!(
            "the reflector probe exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let path = peer.dir.join("nat-probe.toml");
    let row: ProbeRow = toml::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("parse the reflector probe's row")?;
    let proof = NatTypeProof::new(
        nat_type,
        row.mapping_behaviour,
        row.filtering_behaviour,
        PinnedPortReach {
            port: row.pinned_port,
            reachable: row.pinned_port_reachable,
        },
    );
    let text = toml::to_string_pretty(&proof).context("serialize nat-type.toml")?;
    let proof_path = peer.dir.join("nat-type.toml");
    fs::write(&proof_path, text).with_context(|| format!("write {}", proof_path.display()))?;
    println!(
        "natt peer={} nat_type={} observed={}/{} agrees={} pinned_port={} reachable={}",
        peer.name,
        nat_type.knob(),
        proof.observed_mapping,
        proof.observed_filtering,
        proof.agrees,
        proof.pinned_port,
        proof.pinned_port_reachable,
    );
    Ok(proof)
}

/// The fields the flow reads back out of the probe's own row.
#[derive(serde::Deserialize)]
pub(super) struct ProbeRow {
    mapping_behaviour: String,
    filtering_behaviour: String,
    #[serde(default)]
    pinned_port: u16,
    #[serde(default)]
    pinned_port_reachable: bool,
}
