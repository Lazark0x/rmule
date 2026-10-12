//! The stimulus the Low-ID callback re-ask flow queues at the sharer: a bare
//! peer that reaches the Low-ID sharer directly, is queued behind the
//! holders and states no part status, so aMule lists it as a source to name
//! to rmule.

use std::ffi::OsString;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use super::SHARER_IP;
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;

/// The stimulus's static address.
const STIMULUS_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 34);
/// The stimulus's User Hash: the sharer keys its clients by hash.
const STIMULUS_USER_HASH: &str = "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d";
/// The sharer's TCP port, the aMule image's default.
const SHARER_TCP_PORT: u16 = 4662;
/// What `ipv6 hold-slot` prints once the sharer queued or served it.
const HOLD_SLOT_MARKER: &str = "rmule-ipv6-hold-slot-open";
/// Where the stimulus's capture, row and log go, under the flow's root.
pub(super) const STIMULUS_DIR: &str = "stimulus";

/// Queue the stimulus at the sharer, holding the link for `hold_secs`: one
/// ACCEPT ahead of the sharer's inbound DROP for the stimulus's address, then
/// `ipv6 hold-slot` claiming extended-requests 0, until it prints that it is
/// queued.
pub(super) fn queue_the_stimulus(
    bench: &mut Bench,
    image: &str,
    sharer: &str,
    name: &str,
    root: &Path,
    link: &str,
    hold_secs: u64,
) -> Result<()> {
    let stimulus_ip = STIMULUS_IP.to_string();
    let port = SHARER_TCP_PORT.to_string();
    run_checked(
        bench.docker.exec(
            sharer.to_owned(),
            [
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-s",
                &stimulus_ip,
                "-p",
                "tcp",
                "--dport",
                &port,
                "-j",
                "ACCEPT",
            ]
            .map(OsString::from),
        ),
        "let the stimulus reach the sharer",
    )?;
    let dir = root.join(STIMULUS_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let peer = format!("{SHARER_IP}:{SHARER_TCP_PORT}");
    let hold = hold_secs.to_string();
    let container = [
        "ipv6",
        "hold-slot",
        "--peer",
        &peer,
        "--file",
        link,
        "--user-hash",
        STIMULUS_USER_HASH,
        "--extended-requests",
        "0",
        "--capture",
        "/out/capture",
        "--out",
        "/out/hold-slot.toml",
        "--hold-secs",
        &hold,
    ]
    .iter()
    .fold(
        RunContainer::new(image.to_owned())
            .detach()
            .name(name)
            .network(bench.names.network_name.clone())
            .ip(stimulus_ip.clone())
            .volume(&dir, "/out"),
        |container, arg| container.arg(*arg),
    );
    bench.start_extra(name, container, "run the stimulus")?;
    wait_for_container_log(
        &bench.docker,
        name,
        HOLD_SLOT_MARKER,
        Duration::from_secs(hold_secs),
    )?;
    Ok(())
}
