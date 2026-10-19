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
//! it held. Two more read who asked what: on the gateway's log, every
//! `DeletePortMapping` rmule sent follows its own `GetSpecificPortMappingEntry`
//! for that port (UPnP's delete names no internal client, so only the
//! entry's answer says whose mapping it is); and rmule's Run Log carries
//! `port_mapping.release_kept` for the port the second host holds.

use anyhow::{Context, Result, bail};

use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::nat::NAT_LAN_GATEWAY;
use crate::flow::nat::portmap::gateway::{GatewayRecord, SoapRequest};
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

/// The Run Log record of a release the gateway kept.
const RELEASE_KEPT: &str = "port_mapping.release_kept";

/// rmule's `GetSpecificPortMappingEntry` asks, and the `DeletePortMapping`s
/// it sent with no ask for the same port and protocol before them.
fn unchecked_deletes(soap: &[SoapRequest]) -> (Vec<&SoapRequest>, Vec<&SoapRequest>) {
    let ours: Vec<&SoapRequest> = soap
        .iter()
        .filter(|request| request.client == DRIVER_LAN_ADDRESS)
        .collect();
    let asks: Vec<&SoapRequest> = ours
        .iter()
        .copied()
        .filter(|request| request.action == "GetSpecificPortMappingEntry")
        .collect();
    let unchecked = ours
        .iter()
        .enumerate()
        .filter(|(_, request)| request.action == "DeletePortMapping")
        .filter(|(index, delete)| {
            ours[..*index].iter().all(|earlier| {
                earlier.action != "GetSpecificPortMappingEntry"
                    || earlier.port().is_none()
                    || earlier.port() != delete.port()
            })
        })
        .map(|(_, delete)| *delete)
        .collect();
    (asks, unchecked)
}

/// The claims of `portmap-moved`; `driver_log` is rmule's own output.
pub(crate) fn claims(gateway: &GatewayRecord, rmule: &DriverRow, driver_log: &str) -> Vec<Claim> {
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
    let (asks, unchecked) = unchecked_deletes(&gateway.soap);
    let kept: Vec<&str> = driver_log
        .lines()
        .filter_map(|line| line.split_once(RELEASE_KEPT).map(|(_, rest)| rest.trim()))
        .collect();
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
        Claim::about(
            "rmule-asked-whose-mapping-it-was-before-each-delete",
            !asks.is_empty() && unchecked.is_empty(),
            format!(
                "rmule's GetSpecificPortMappingEntry answers: <{}>; its DeletePortMapping with \
                 no ask for that port before it: <{}>",
                details(&asks),
                details(&unchecked)
            ),
        ),
        Claim::about(
            "the-run-log-says-the-second-hosts-port-was-left-alone",
            kept.iter()
                .any(|line| line.contains(&format!("external_port={PEER_TCP_PORT} "))),
            format!("rmule's {RELEASE_KEPT} records: <{}>", kept.join(" | ")),
        ),
    ]
}

/// Each request's detail line, or its action where the daemon wrote none.
fn details(requests: &[&SoapRequest]) -> String {
    requests
        .iter()
        .map(|request| {
            request
                .detail
                .clone()
                .unwrap_or_else(|| request.action.clone())
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::{SoapRequest, unchecked_deletes};

    fn request(client: &str, action: &str, detail: &str) -> SoapRequest {
        SoapRequest {
            client: client.to_owned(),
            action: action.to_owned(),
            detail: Some(format!("{action}: {detail}")),
        }
    }

    /// Run `1792392425`: the second host checked 4662, rmule deleted it
    /// unchecked. A check rmule sent for the port before its delete clears it.
    #[test]
    fn a_delete_counts_as_checked_only_after_rmules_own_ask_for_its_port() {
        let neighbours_check = request(
            "10.77.0.5",
            "GetSpecificPortMappingEntry",
            "rhost='' 4662 TCP found => 10.77.0.5:4662 desc='preclaim' duration=600",
        );
        let delete = |port| {
            request(
                "10.77.0.4",
                "DeletePortMapping",
                &format!("external port: {port}, protocol: TCP"),
            )
        };
        let blind = [neighbours_check.clone(), delete(4662)];
        let (asks, unchecked) = unchecked_deletes(&blind);
        assert!(asks.is_empty());
        assert_eq!(unchecked.len(), 1);
        let ours = request(
            "10.77.0.4",
            "GetSpecificPortMappingEntry",
            "rhost='' 53906 TCP found => 10.77.0.4:4662 desc='rmule' duration=120",
        );
        let checked = [neighbours_check, ours, delete(53906)];
        let (asks, unchecked) = unchecked_deletes(&checked);
        assert_eq!(asks.len(), 1);
        assert!(unchecked.is_empty());
        let other_port = [checked[1].clone(), delete(4662)];
        assert_eq!(unchecked_deletes(&other_port).1.len(), 1);
    }
}
