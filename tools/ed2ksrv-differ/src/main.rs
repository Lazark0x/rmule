//! Differential decoding harness: `andrey23127/ed2k-server`'s parser as a bug
//! oracle for rmule's server-facing wire code.
//!
//! # Why a second parser is worth a heavy dependency
//!
//! rmule scores itself against aMule 2.3.3 and Lugdunum 17.15. Both are tolerant
//! — they accepted two malformed rmule emissions without a murmur, and both
//! defects were found only because a *third*, stricter implementation dropped
//! the frames in silence:
//!
//! * rmule minted crypt-pings 4..=19 bytes long; this server's UDP pre-flight
//!   drops anything under 10 before the arm that would answer it.
//! * the crypt-ping challenge leads little-endian, so its low byte is the first
//!   wire byte — the `0xE3` protocol-marker slot. One challenge in 256 was read
//!   as a malformed plain frame.
//!
//! Both were invisible on the wire: a dropped datagram is indistinguishable from
//! a server that never implemented the exchange. Answer rate went 4/17 → 20/20
//! once both were closed. A second implementation's *acceptance boundary* is the
//! instrument that finds this class, and until now it was being read by hand.
//!
//! # What this is not
//!
//! Not a gate. The exit code is 0 whatever it finds, unless
//! `--fail-on-unattributed` is passed. Three implementations of this protocol
//! genuinely differ; the oracle has six filed bugs of its own; and ADR-0045's
//! amendment makes its verdicts admissible **only while it stays unpatched and
//! pinned at `eacf7f1`**. So a divergence is a pointer, and adjudicating it
//! against aMule 2.3.3 is a human's job.
//!
//! # Running it
//!
//! ```text
//! cargo run --manifest-path tools/ed2ksrv-differ/Cargo.toml
//! cargo run --manifest-path tools/ed2ksrv-differ/Cargo.toml -- --fail-on-unattributed
//! ```
//!
//! The crate is outside the rmule workspace on purpose: the oracle drags ~180
//! transitive crates and a C-compiled jemalloc, none of which should land in the
//! build every other rmule crate pays for.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod known;
mod report;
mod tcp;
mod udp;

fn main() -> std::process::ExitCode {
    let strict = std::env::args().any(|a| a == "--fail-on-unattributed");

    let mut report = report::Report::new(known::REGISTRY);
    tcp::run(&mut report);
    udp::run(&mut report);

    print!("{}", report.render());

    if strict && report.has_unattributed() {
        eprintln!("--fail-on-unattributed: at least one divergence has no registered cause.");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
