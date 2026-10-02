//! The `rmule-tools` process each peer runs, and the **Synthetic File** the
//! transfer row moves between them.
//!
//! One place decides what a peer is *for* this run: the punch rows give both
//! peers the same command and let the target file the harness drops tell them
//! apart, while the transfer row gives them different halves because one of
//! them is downloading and the other is the file's only source.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::nat::natt::bench::NattOptions;
use crate::flow::nat::natt::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT};
use crate::flow::nat::synthetic::SyntheticFile;

use super::{ED2KSRV_TCP_PORT, Peer, TARGET_TIMEOUT_SECS, WINDOW_SECS};

/// How many times a driver start is retried when the LAN address is still
/// held, and how long between attempts.
///
/// The probe container ran at the same address a moment ago, and `docker run
/// --rm` returns when the container *exits* while the daemon frees its IPAM
/// lease a beat later. That is a bench race, not a measurement, so it is
/// retried rather than left to fail a whole flow.
const DRIVER_START_ATTEMPTS: usize = 5;
const DRIVER_START_BACKOFF: Duration = Duration::from_secs(2);

pub(super) fn start_driver(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    peer: &Peer,
    plan: &TransferPlan<'_>,
    server_v4: &str,
    extra: &[String],
) -> Result<()> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut container = RunContainer::new(options.rmule_tools_image)
            .detach()
            .name(&peer.driver)
            .network(&peer.network)
            .ip(peer.lan.client)
            .cap_add("NET_ADMIN")
            .env("RMULE_DEFAULT_ROUTE_VIA", peer.lan.gateway)
            // The NAT-T front traces every silent drop at debug — an
            // unexpected `0xA1`, a refused hint, an introduction the front did
            // not take. A punch that does not land is diagnosed from those
            // lines and nowhere else, so the two modules are raised and the
            // rest of the node left at `info`.
            .env(
                "RMULE_LOG",
                "info,rmule_core::natt=debug,rmule_net::natt=debug",
            )
            .volume(&peer.dir, "/out");
        if let Some(share) = plan.share {
            container = container.volume(share, SHARED_FILE_IN_CONTAINER);
        }
        for arg in driver_args(peer, plan, server_v4)
            .into_iter()
            .chain(extra.iter().cloned())
        {
            container = container.arg(arg);
        }
        match bench.start_extra(&peer.driver, container, "run the rmule NAT-T peer") {
            Ok(()) => return Ok(()),
            Err(error) if attempt < DRIVER_START_ATTEMPTS => {
                eprintln!(
                    "natt: peer {} could not take {} on attempt {attempt} ({error}); retrying",
                    peer.name, peer.lan.client,
                );
                std::thread::sleep(DRIVER_START_BACKOFF);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Where the **Synthetic File** is mounted inside the sharing peer.
const SHARED_FILE_IN_CONTAINER: &str = "/out/shared.bin";

/// The driver command one peer runs, per flow and per role.
pub(super) fn driver_args(peer: &Peer, plan: &TransferPlan<'_>, server_v4: &str) -> Vec<String> {
    let common = |subcommand: &str| {
        vec![
            "natt".to_owned(),
            subcommand.to_owned(),
            "--server".to_owned(),
            format!("{server_v4}:{ED2KSRV_TCP_PORT}"),
            "--listen".to_owned(),
            format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
            "--udp-port".to_owned(),
            BODY_CLIENT_UDP_PORT.to_string(),
            "--user-hash".to_owned(),
            peer.user_hash.to_owned(),
            "--identity-out".to_owned(),
            "/out/identity.toml".to_owned(),
            "--window".to_owned(),
            WINDOW_SECS.to_string(),
        ]
    };
    match plan.link {
        // The punch rows: both peers run the same command and only the target
        // file the harness drops tells them apart.
        None => {
            let mut args = common("server-punch");
            args.extend([
                "--share".to_owned(),
                "/etc/hostname".to_owned(),
                "--target-file".to_owned(),
                "/out/target.toml".to_owned(),
                "--target-timeout".to_owned(),
                TARGET_TIMEOUT_SECS.to_string(),
                "--out".to_owned(),
                "/out/punch.toml".to_owned(),
            ]);
            args
        }
        // The transfer row: the two peers run different halves, because one of
        // them is downloading and the other is the file's only source.
        Some(link) => {
            let mut args = common("tunnel-transfer");
            if plan.share.is_some() {
                args.extend([
                    "--role".to_owned(),
                    "target".to_owned(),
                    "--share".to_owned(),
                    SHARED_FILE_IN_CONTAINER.to_owned(),
                ]);
            } else {
                args.extend([
                    "--role".to_owned(),
                    "requester".to_owned(),
                    "--file".to_owned(),
                    link.to_owned(),
                    "--download-out".to_owned(),
                    "/out/downloaded.bin".to_owned(),
                    "--source-file".to_owned(),
                    "/out/source.toml".to_owned(),
                    "--source-timeout".to_owned(),
                    TARGET_TIMEOUT_SECS.to_string(),
                ]);
            }
            args.extend(["--out".to_owned(), "/out/punch.toml".to_owned()]);
            args
        }
    }
}

/// What one peer is asked to do this run: nothing extra for the punch rows, or
/// one half of the transfer.
pub(super) struct TransferPlan<'a> {
    /// The ed2k link both halves name, or `None` for a punch row.
    pub(super) link: Option<&'a str>,
    /// The **Synthetic File** to mount, for the sharing half only.
    pub(super) share: Option<&'a Path>,
}

/// How big the transferred file is: two parts, so the transfer is not one
/// block and the part loop, the hash check and the slot all actually run —
/// and small enough that a punched path moves it inside one window.
const TRANSFER_FILE_BYTES: u64 = 9_728_000 * 2 + 4096;

/// Write the **Synthetic File** the transfer row moves and compute its link.
pub(in crate::flow::nat::natt) fn synthetic_file(dir: &Path) -> Result<SyntheticFile> {
    crate::flow::nat::synthetic::write_hashed(dir, TRANSFER_FILE_BYTES)
}
