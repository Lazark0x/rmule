//! The dead-dial legs: the waiter holds its slot on rmule's dial-back, its
//! end of that link goes with no close reaching rmule, and it comes back on
//! its own link (ADR-0107 invariant 7). Holds inside the waiter's namespace
//! do it, the way a NAT that dropped its mapping would: nothing crosses the
//! link either way, and its socket at the waiter ends with no close reaching
//! rmule. rmule's tap reads everything rmule wrote, its close of the dial
//! included.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;

use super::verdict::{self, Marks};
use super::{AMULE_PEER_TCP_PORT, amulecmd, cancel_download, iptables_on};
use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::gate::wait_for_container_log;

/// The waiter's download cap: slow enough that the dial is still carrying
/// blocks when its far end goes, a 32 MiB file at this rate taking 17 min.
pub(super) const WAITER_KIB: u32 = 32;
/// Past rmule's reading of a dial as silent: aMule's 40 s socket timeout
/// (`ClientTCPSocket.cpp:201-229`), rmule's last write a second behind the
/// hold. The same 40 s then ends a drained slot at rmule's next sweep (run
/// `1793401559`: 50.4 s past that write), so the waiter comes back at once.
const SILENCE_SECS: u64 = 41;
/// Grace for the blocks to start on the dial before its far end goes.
const FLOWING_SECS: u64 = 3;
/// How long past the waiter's `Add` the flow waits for rmule's let-go.
const LET_GO_BOUND: Duration = Duration::from_secs(30);
/// aMule's `OP_SIGNATURE` as it opens: `0xC5`, the length of a 384-bit RSA
/// signature's frame, the opcode, the signature's length.
const SIGNATURE_FRAME_HEAD: &str = "|c5 32 00 00 00 86 30|";

/// The rule holding the waiter's `OP_SIGNATURE` on the dial back: rmule's
/// challenge stays unanswered, and TCP's order holds whatever follows it.
pub(super) fn proof_hold(rmule: Ipv4Addr) -> Vec<String> {
    let rmule = rmule.to_string();
    [
        "-p",
        "tcp",
        "-d",
        rmule.as_str(),
        "--sport",
        &AMULE_PEER_TCP_PORT.to_string(),
        "-m",
        "string",
        "--algo",
        "bm",
        "--hex-string",
        SIGNATURE_FRAME_HEAD,
        "-j",
        "DROP",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Wait for the waiter's slot on the dial, drop the dial at the waiter's end,
/// wait out rmule's silence, and bring the waiter back on its own link.
pub(super) fn drop_then_come_back(
    bench: &Bench,
    image: &str,
    (rmule_name, rmule): (&str, Ipv4Addr),
    waiter: &str,
    (wait_link, add_back): (&str, &str),
    timeout: Duration,
    marks: &mut Marks,
) -> Result<()> {
    let granted =
        wait_for_container_log(&bench.docker, rmule_name, "road=dialed_back", timeout).is_ok();
    println!("peer_crossing slot_on_the_dial={granted}");
    std::thread::sleep(Duration::from_secs(FLOWING_SECS));

    let rmule = rmule.to_string();
    let port = AMULE_PEER_TCP_PORT.to_string();
    let incoming = ["-p", "tcp", "-s", &rmule, "--dport", &port, "-j", "DROP"]
        .map(str::to_owned)
        .to_vec();
    let outgoing = ["-p", "tcp", "-d", &rmule, "--sport", &port, "-j", "DROP"]
        .map(str::to_owned)
        .to_vec();
    for (chain, rule) in [("INPUT", &incoming), ("OUTPUT", &outgoing)] {
        run_checked(
            bench
                .docker
                .run_container(iptables_on(chain, image, waiter, "-A", rule)),
            "drop the dial at the waiter's end",
        )?;
    }
    let dropped_at = verdict::unix_now();
    marks.lifted_at.push(dropped_at);
    println!("peer_crossing dial_dropped at={dropped_at:.3}");
    std::thread::sleep(Duration::from_secs(SILENCE_SECS));

    // The waiter forgets the client while it holds the socket, then the
    // socket goes, so the client goes with it: reset any earlier, it stays as
    // a source-less client its `Add` never reaches (run `1793402133`).
    cancel_download(bench, waiter, wait_link)?;
    run_checked(
        bench.docker.run_container(
            RunContainer::new(image.to_owned())
                .remove_after_exit()
                .network(format!("container:{waiter}"))
                .cap_add("NET_ADMIN")
                .entrypoint("ss")
                .arg("-K")
                .arg("dst")
                .arg(rmule.as_str())
                .arg("sport")
                .arg("=")
                .arg(format!(":{port}")),
        ),
        "end the waiter's socket on the dial",
    )?;
    marks.returned_at = Some(verdict::unix_now());
    amulecmd(bench, waiter, add_back, "the waiter adds it again")?;
    let let_go = wait_for_container_log(
        &bench.docker,
        rmule_name,
        "serve.dead_dial_let_go",
        LET_GO_BOUND,
    )
    .is_ok();
    println!("peer_crossing dead_dial_let_go={let_go}");
    Ok(())
}
