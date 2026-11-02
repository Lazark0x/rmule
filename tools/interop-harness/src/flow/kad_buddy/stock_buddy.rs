//! Flow M with a **stock buddy** (`kad-core-buddy --stock-buddy`): the
//! firewalled stock aMule's buddy is an open stock aMule, and rmule is an
//! ordinary far node plus the downloader. It is the one topology where
//! nothing repairs rmule's reading of `TAG_BUDDYHASH`.
//!
//! # The open aMule
//!
//! It answers a `0x51` only while it reads itself open and verified on both
//! verdicts (`KademliaUDPListener.cpp:1430`), so it gets what
//! `natt-buddy-recruit-amule`'s open aMule gets, from stock helpers:
//!
//! - two contacts that can dial it in its routing zone, rmule and the first
//!   helper: the two `OP_KAD_FWTCPCHECK_ACK`s `CPrefs::GetFirewalled` needs
//!   (`Prefs.cpp:161`), and the two slots the one-`/24` bin admits
//!   (`RoutingBin.cpp:91`);
//! - two helpers its zone does not hold, which only rmule's answers can name.
//!   rmule keeps two contacts of a `/24` per bucket, so a placed member could
//!   take a helper's place: its far Kad ID, [`STOCK_BUDDY_RMULE_KAD_ID`], gives
//!   each helper a bucket of its own.
//!
//! The firewalled node starts once both verdict lines are in the stock
//! buddy's log. Its own UDP port is dropped, as with any helpers in flow M, so
//! the same helpers read it firewalled.
//!
//! # The road
//!
//! aMule's relay checks nothing: `ProcessCallbackRequest`
//! (`KademliaUDPListener.cpp:1489-1518`) writes the `0x99` from the `0x52`
//! verbatim, and the firewalled node drops one that does not name it
//! (`ClientTCPSocket.cpp:1636-1641`). So rmule's first `0x52`, the eMule
//! layout, is relayed and dies in silence. The second reads the row byte for
//! byte, and the leg's last claim asks for its dial-back. Run `1793423850` did
//! not get one: the fallback left after the road's 30 s, and the buddy takes
//! one `KADEMLIA_CALLBACK_REQ` a minute per IP (`PacketTracking.cpp:158-160`).
//! The node's **Callback Pace** now holds it past that minute.
//!
//! A `0x94` is stricter: `OP_REASKCALLBACKUDP` is relayed only under the
//! buddy's own bytes (`ClientUDPSocket.cpp:151`), so it needs the reading
//! `adopt` flipped to.

use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::docker::Docker;
use crate::flow::bench::run_checked;
use crate::flow::identity::hex_lower;
use crate::flow::kad_buddy::callback::{DOWNLOADER_PCAP, Judged};
use crate::flow::kad_buddy::core::KAD_CORE_BUDDY_RMULE_KAD_ID;
use crate::flow::pcap::{tcp4_syns, udp4_datagrams};
use crate::flow::wire_filter::{OP_EMULEPROT, WireFilter, lift_ed2k_frames};
use crate::verdict::Verdict;

/// Stock helpers the stock buddy's world needs: its second TCP tester and
/// two fresh UDP helpers.
pub(crate) const STOCK_BUDDY_HELPERS: usize = 3;
/// The stock buddy's host on the `/24`, past the planned Kad nodes. Its third
/// party takes the hosts after it.
pub(crate) const STOCK_BUDDY_HOST: u8 = 201;
/// Its Kad UDP port, past the helpers' and short of the members'.
pub(crate) const STOCK_BUDDY_KAD_PORT_OFFSET: u16 = 15;
/// rmule's Kad ID beside a stock buddy: far from the walk's target, and
/// each helper's distance from it opens a different bucket.
pub(crate) const STOCK_BUDDY_RMULE_KAD_ID: [u8; 16] = [
    0x73, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
];

/// How long the stock buddy's two verdicts may take: the
/// `natt-buddy-recruit-amule` budget.
const OPEN_BUDGET: Duration = Duration::from_secs(420);
const TCP_OPEN_LINE: &str = "Connected to Kad (ok)";
const UDP_OPEN_LINE: &str = "New Kad Firewallstate (UDP): Open";
/// The Callback Pace's 65 s between two `0x52` to one IP, with the tap's
/// slack: stock's window is strictly more than 60 s.
const CALLBACK_SPACING_SECS: std::ops::RangeInclusive<f64> = 64.0..=69.0;
/// `PacketTracking.cpp:222`, for the opcode the Callback Pace spaces.
const FLOOD_LINE: &str = "Request flood detected for opcode 0x52";
/// How soon aMule dials after the `0x99` that names it.
const DIAL_BACK_SECS: f64 = 5.0;

/// `0xE4 0x52`, then the buddy check the `0x52` and `0x99` both carry.
const REQ_CHECK_AT: usize = 2;
/// A frame's protocol, length and opcode, then the same check.
const RELAY_CHECK_AT: usize = 6;
const OP_KAD_CALLBACK_REQ: u8 = 0x52;
const OP_KADEMLIAUDP: u8 = 0xE4;

/// Wait for the stock buddy's own two verdict lines.
///
/// # Errors
/// If its log cannot be read or a line stays out of the budget: the walk
/// has no answer, so the run stops at staging.
pub(crate) fn await_open(docker: &Docker, container: &str) -> Result<()> {
    let deadline = Instant::now() + OPEN_BUDGET;
    loop {
        let log = run_checked(
            docker.exec(
                container.to_owned(),
                [
                    std::ffi::OsString::from("sh"),
                    std::ffi::OsString::from("-c"),
                    std::ffi::OsString::from("cat /root/.aMule/logfile 2>/dev/null || true"),
                ],
            ),
            "read the stock buddy's logfile",
        )?;
        let (tcp, udp) = (log.contains(TCP_OPEN_LINE), log.contains(UDP_OPEN_LINE));
        if tcp && udp {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "the stock buddy stayed out of the walk: tcp open {tcp}, udp open {udp} after \
                 {} s",
                OPEN_BUDGET.as_secs()
            );
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// `id` with every 32-bit word's bytes reversed: the row's other reading.
fn other_layout(id: [u8; 16]) -> [u8; 16] {
    let mut out = id;
    out.chunks_exact_mut(4).for_each(<[u8]>::reverse);
    out
}

/// What the taps saw of the road, in capture time.
struct Road<'a> {
    /// `0x52`s leaving the downloader: when, and the check they carry.
    requests: &'a [(f64, [u8; 16])],
    /// `0x99`s the stock buddy wrote: when, and the check they carry.
    relays: &'a [(f64, [u8; 16])],
    /// The firewalled node's SYNs onto the downloader.
    dials: &'a [f64],
    /// `Request flood detected` lines the stock buddy logged for `0x52`.
    floods: usize,
}

impl Road<'_> {
    /// The named claims, keyed on the Kad ID the row's source takes as its
    /// buddy's. An empty road holds none of them.
    fn claims(&self, buddy_id: [u8; 16]) -> [(&'static str, bool); 6] {
        let primary = self.requests.first();
        let fallback = self.requests.get(1);
        let silent = match (primary, fallback) {
            (Some((sent, _)), Some((retried, _))) => {
                !self.dials.iter().any(|at| at >= sent && at < retried)
            }
            _ => false,
        };
        let dialed = fallback.is_some_and(|(at, _)| {
            self.dials
                .iter()
                .any(|dial| *dial >= *at && dial - at <= DIAL_BACK_SECS)
        });
        [
            (
                "the-first-0x52-reads-the-emule-layout",
                primary.is_some_and(|(_, check)| *check == other_layout(buddy_id)),
            ),
            (
                "the-stock-buddy-relayed-it-unchanged-and-the-source-stayed-silent",
                silent && self.relays.first().map(|(_, check)| check) == primary.map(|(_, c)| c),
            ),
            (
                "the-fallback-0x52-left-past-the-stock-window",
                primary
                    .zip(fallback)
                    .is_some_and(|((sent, _), (retried, _))| {
                        CALLBACK_SPACING_SECS.contains(&(retried - sent))
                    }),
            ),
            (
                "the-fallback-0x52-reads-the-row-byte-for-byte",
                fallback.is_some_and(|(_, check)| *check == buddy_id),
            ),
            (
                "the-stock-buddy-relayed-the-fallback-past-its-flood-guard",
                self.floods == 0
                    && fallback.is_some_and(|(retried, _)| {
                        self.relays
                            .iter()
                            .any(|(at, check)| at >= retried && *check == buddy_id)
                    }),
            ),
            ("the-source-dialed-back-on-the-fallback", dialed),
        ]
    }
}

/// Score the stock road off the downloader's tap and the buddy's, and write
/// `kad-stock-buddy-verdict.toml`.
///
/// # Errors
/// If a tap cannot be read, or a claim does not hold: the failing claims are
/// the error.
pub(crate) fn judge(judged: &Judged<'_>, downloader_dir: &Path, downloader_v4: &str) -> Result<()> {
    let pcap = downloader_dir.join(DOWNLOADER_PCAP);
    let downloader: Ipv4Addr = downloader_v4.parse().context("the downloader's address")?;
    let buddy: Ipv4Addr = judged.rmule_ip.parse().context("the buddy's address")?;
    let amule: Ipv4Addr = judged.amule_ip.parse().context("aMule's address")?;
    let check =
        |bytes: &[u8], at: usize| -> Option<[u8; 16]> { bytes.get(at..at + 16)?.try_into().ok() };

    let requests: Vec<(f64, [u8; 16])> = udp4_datagrams(&pcap)?
        .iter()
        .filter(|datagram| {
            *datagram.source.ip() == downloader
                && *datagram.destination.ip() == buddy
                && datagram
                    .payload
                    .starts_with(&[OP_KADEMLIAUDP, OP_KAD_CALLBACK_REQ])
        })
        .filter_map(|datagram| Some((datagram.at, check(&datagram.payload, REQ_CHECK_AT)?)))
        .collect();
    let dials: Vec<f64> = tcp4_syns(&pcap)?
        .into_iter()
        .filter_map(|(at, from)| (from == amule).then_some(at))
        .collect();
    let relays: Vec<(f64, [u8; 16])> = lift_ed2k_frames(
        judged.docker,
        judged.buddy_tap,
        judged.buddy_pcap,
        &WireFilter::ed2k(
            format!("src host {buddy} and dst host {amule}"),
            &[OP_EMULEPROT],
            0x99,
        ),
        "stock-buddy-relays-0x99.pcap",
    )?
    .into_iter()
    .filter_map(|frame| Some((frame.at, check(&frame.bytes, RELAY_CHECK_AT)?)))
    .collect();

    let log = judged
        .layout
        .kad_node_logs_dir("stock-buddy")
        .join("amule-logfile.log");
    let floods = fs::read_to_string(&log)
        .with_context(|| format!("read {}", log.display()))?
        .matches(FLOOD_LINE)
        .count();

    let claims = Road {
        requests: &requests,
        relays: &relays,
        dials: &dials,
        floods,
    }
    .claims(KAD_CORE_BUDDY_RMULE_KAD_ID);
    let pass = claims.iter().all(|(_, holds)| *holds);

    let mut out = format!(
        "# kad-core-buddy --stock-buddy: rmule's reading of a stock row through a stock relay.\n\
         verdict = \"{}\"\n",
        if pass { Verdict::Pass } else { Verdict::Fail }
    );
    for (key, seen) in [("request_0x52", &requests), ("relay_0x99", &relays)] {
        for (index, (at, check)) in seen.iter().enumerate() {
            writeln!(out, "{key}_{index} = \"{at:.3} {}\"", hex_lower(check))?;
        }
    }
    for (index, at) in dials.iter().enumerate() {
        writeln!(out, "dial_back_syn_{index} = {at:.3}")?;
    }
    writeln!(out, "flood_lines_0x52 = {floods}")?;
    // A later road's first `0x52`, the row's held reading after `adopt`.
    writeln!(
        out,
        "next_road_0x52 = \"{}\"",
        requests
            .get(2)
            .map(|(_, check)| hex_lower(check))
            .unwrap_or_default()
    )?;
    out.push_str("\n[claims]\n");
    for (name, holds) in &claims {
        writeln!(out, "\"{name}\" = {holds}")?;
    }
    let path = judged.layout.kad_dir().join("kad-stock-buddy-verdict.toml");
    crate::verdict::write(&path, &out)?;
    println!("kad-stock-buddy verdict={}", pass);
    if !pass {
        let failing: Vec<&str> = claims
            .iter()
            .filter_map(|(name, holds)| (!holds).then_some(*name))
            .collect();
        bail!("kad-stock-buddy: claims not held: {}", failing.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 16] = KAD_CORE_BUDDY_RMULE_KAD_ID;

    fn held(claims: &[(&'static str, bool)]) -> Vec<&'static str> {
        claims
            .iter()
            .filter_map(|(name, holds)| holds.then_some(*name))
            .collect()
    }

    #[test]
    fn the_silent_primary_and_the_answered_fallback_hold_every_claim() {
        let claims = Road {
            requests: &[(100.0, other_layout(ID)), (165.1, ID)],
            relays: &[(100.0, other_layout(ID)), (165.1, ID)],
            dials: &[165.2],
            floods: 0,
        }
        .claims(ID);
        assert_eq!(held(&claims).len(), claims.len());
    }

    /// A dial-back before the fallback left means the relay or the source
    /// took the eMule layout, which is the claim the leg exists to refute.
    #[test]
    fn a_dial_back_on_the_primary_breaks_the_silence() {
        let claims = Road {
            requests: &[(100.0, other_layout(ID)), (165.1, ID)],
            relays: &[(100.0, other_layout(ID)), (165.1, ID)],
            dials: &[100.5, 165.2],
            floods: 0,
        }
        .claims(ID);
        assert!(!held(&claims).contains(&claims[1].0));
    }

    #[test]
    fn a_fallback_inside_the_stock_window_breaks_the_spacing_claim() {
        let claims = Road {
            requests: &[(100.0, other_layout(ID)), (130.1, ID)],
            relays: &[(100.0, other_layout(ID))],
            dials: &[130.2],
            floods: 1,
        }
        .claims(ID);
        assert!(!held(&claims).contains(&claims[2].0));
    }

    /// The relay's own count of the drop: run `1793423850`'s failure.
    #[test]
    fn a_flood_line_at_the_relay_breaks_the_relay_claim() {
        let claims = Road {
            requests: &[(100.0, other_layout(ID)), (165.1, ID)],
            relays: &[(100.0, other_layout(ID)), (165.1, ID)],
            dials: &[165.2],
            floods: 1,
        }
        .claims(ID);
        assert!(!held(&claims).contains(&claims[4].0));
    }

    #[test]
    fn a_fallback_the_relay_never_wrote_breaks_the_relay_claim() {
        let claims = Road {
            requests: &[(100.0, other_layout(ID)), (165.1, ID)],
            relays: &[(100.0, other_layout(ID))],
            dials: &[165.2],
            floods: 0,
        }
        .claims(ID);
        assert!(!held(&claims).contains(&claims[4].0));
    }
}
