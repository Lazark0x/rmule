//! `portmap-moved`: a UPnP grant whose external port moves at renewal.
//!
//! miniupnpd re-grants the same external port on every renewal, so a moved
//! port has to be staged. Once the gateway's table shows rmule's exact TCP
//! row, a second LAN host deletes it and claims that external port for
//! itself, the way a neighbour takes a port the gateway lost (a reboot, an
//! expiry). rmule's next renewal then meets `ConflictInMappingEntry` (718)
//! and falls back to `AddAnyPortMapping`, and the grant comes back on another
//! port. The gateway runs with `secure_mode=no` (`-S0`), the only mode in
//! which one LAN host may delete another's mapping; in it, a
//! `DeletePortMapping` is obeyed whoever sends it.
//!
//! The claims, all on the gateway's own lease table: the second host held
//! the port after rmule's grant; rmule's TCP row came back on another
//! external port; rmule's own row names that port; after the driver exited no
//! row of rmule's survives (the release named the moved port); and the
//! second host's row on the old port survives too — rmule withdrew only what
//! it held.

use anyhow::{Context, Result, bail};

use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::nat::NAT_LAN_GATEWAY;
use crate::flow::nat::portmap::gateway::GatewayRecord;
use crate::flow::nat::portmap::row::DriverRow;
use crate::flow::nat::portmap::verdict::Claim;
use crate::flow::nat::portmap::{DRIVER_LAN_ADDRESS, PEER_TCP_PORT, PRECLAIM_LAN_ADDRESS};

/// The description the second host's row carries.
const NEIGHBOUR: &str = "preclaim";

/// Delete rmule's TCP mapping on [`PEER_TCP_PORT`] from the second LAN host
/// and claim that external port for it.
///
/// # Errors
/// If the container cannot run or `upnpc` fails either step.
pub(crate) fn take_the_port(bench: &Bench, image: &str, lan_network: &str) -> Result<()> {
    let script = format!(
        "ip route replace default via {NAT_LAN_GATEWAY} && \
         upnpc -d {PEER_TCP_PORT} TCP && \
         upnpc -e {NEIGHBOUR} -a {PRECLAIM_LAN_ADDRESS} {PEER_TCP_PORT} {PEER_TCP_PORT} TCP 600"
    );
    let output = bench
        .docker
        .run_container(
            RunContainer::new(image)
                .remove_after_exit()
                .network(lan_network)
                .ip(PRECLAIM_LAN_ADDRESS)
                .cap_add("NET_ADMIN")
                .entrypoint("sh")
                .arg("-c")
                .arg(script),
        )
        .to_command()
        .output()
        .context("run the port take-over")?;
    println!(
        "portmap take-over TCP:{PEER_TCP_PORT} -> {}",
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .last()
            .unwrap_or("(no output)")
    );
    if !output.status.success() {
        bail!(
            "taking TCP:{PEER_TCP_PORT} over failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// The claims of `portmap-moved`.
pub(crate) fn claims(gateway: &GatewayRecord, rmule: &DriverRow) -> Vec<Claim> {
    let rows = |address: &str| -> Vec<String> {
        gateway
            .leases
            .iter()
            .filter(|lease| lease.protocol == "TCP" && lease.internal_address == address)
            .map(|lease| lease.line.clone())
            .collect()
    };
    let granted_exact = gateway.holds_exact(DRIVER_LAN_ADDRESS, PEER_TCP_PORT);
    let neighbour = gateway.leases.iter().any(|lease| {
        lease.protocol == "TCP"
            && lease.external_port == PEER_TCP_PORT
            && lease.internal_address == PRECLAIM_LAN_ADDRESS
    });
    let moved = gateway
        .leases
        .iter()
        .find(|lease| {
            lease.protocol == "TCP"
                && lease.internal_address == DRIVER_LAN_ADDRESS
                && lease.internal_port == PEER_TCP_PORT
                && lease.external_port != PEER_TCP_PORT
        })
        .map(|lease| lease.external_port);
    let tcp = rmule.mapping("tcp", "v4");
    let after = gateway.rows_v4_after();
    let after_note = after.as_ref().map_or_else(
        || "unread".to_owned(),
        |rows| {
            rows.iter()
                .map(|row| row.line.clone())
                .collect::<Vec<_>>()
                .join(" | ")
        },
    );
    let ours_after = after.as_ref().map(|rows| {
        rows.iter()
            .any(|row| row.internal_address == DRIVER_LAN_ADDRESS)
    });
    let neighbour_after = after.as_ref().map(|rows| {
        rows.iter().any(|row| {
            row.protocol == "TCP"
                && row.external_port == PEER_TCP_PORT
                && row.internal_address == PRECLAIM_LAN_ADDRESS
        })
    });
    let after_claim = |name: &'static str, read: Option<bool>, note: String| {
        read.map_or_else(
            || Claim::blocked(name, note.clone()),
            |held| Claim::about(name, held, note.clone()),
        )
    };
    vec![
        Claim::about(
            "a-second-host-took-the-port-after-the-grant",
            granted_exact && neighbour,
            format!(
                "the gateway's TCP rows for rmule: {}; for the second host: {}",
                rows(DRIVER_LAN_ADDRESS).join(" | "),
                rows(PRECLAIM_LAN_ADDRESS).join(" | ")
            ),
        ),
        Claim::about(
            "the-renewal-moved-the-grant",
            moved.is_some(),
            format!(
                "rmule's TCP {PEER_TCP_PORT} came back on external port {moved:?}; the gateway \
                 logged {} AddPortMapping, {} AddAnyPortMapping and {} conflicts",
                gateway.add_port_mapping, gateway.add_any_port_mapping, gateway.conflicts
            ),
        ),
        Claim::about(
            "rmule-holds-the-moved-port",
            tcp.is_some_and(|row| moved == Some(row.external_port)),
            format!(
                "TCP v4 {}",
                tcp.map_or_else(
                    || "(no row)".to_owned(),
                    |row| format!(
                        "status={} external_port={} exact={}",
                        row.status, row.external_port, row.exact
                    )
                )
            ),
        ),
        after_claim(
            "the-release-names-the-moved-port",
            ours_after.map(|ours| !ours),
            format!(
                "after the driver exited the gateway's IPv4 table read <{after_note}>, and it \
                 logged {} DeletePortMapping",
                gateway.delete_port_mapping
            ),
        ),
        after_claim(
            "the-second-hosts-port-outlives-rmule",
            neighbour_after,
            format!("after the driver exited the gateway's IPv4 table read <{after_note}>"),
        ),
    ]
}
