//! The **Pinned-Pair Reach** leg's client half: one translated client aiming
//! datagrams at *another translated client*'s gateway, at the pinned port.
//!
//! The **Reflector Probe** beside it cannot ask this question. Its sixth test
//! addresses a **Pinned-Port Sink** on the reflector — an untranslated host on
//! the WAN — so it proves the LAN reaches the WAN on that port and stops there.
//! What a punch actually does is aim the pinned port at a host that is *itself*
//! behind a gateway pinning the same port, and that pairing has its own failure
//! mode: the far gateway may already hold conntrack state for `us:4672 ->
//! them:4672` — state it acquired by accepting our own opener locally — and the
//! mapping their client then needs collides with it.
//!
//! **The stagger is the measurement, not a convenience.** The `first` role
//! sends while the far side is still silent, which is exactly the unsolicited
//! datagram that poisons; the `second` role holds `--lead-ms` before its own
//! first send. Two clients bursting simultaneously would reproduce the defect
//! only when the scheduler happened to order them that way, and a proof that
//! passes on a coin flip is not one.
//!
//! **Stimulus, never evidence** (ADR-0045). Both ends are the harness's own
//! driver; what is being measured is the bench's gateways.

use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};

/// The datagram both roles send. A magic prefix rather than an empty payload:
/// the local port is the client's real eD2k/Kad port and a bench bridge carries
/// other traffic, so a reach must be counted on this driver's own bytes.
const MAGIC: &str = "RMULE-PEERREACH/1";

/// Which side of the pair this driver is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PeerReachRole {
    /// Sends immediately, while the far client is still silent — the
    /// unsolicited opener the far gateway must discard without remembering.
    First,
    /// Holds `--lead-ms`, so its own gateway has taken the first side's
    /// datagrams before it makes a mapping of its own.
    Second,
}

impl PeerReachRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Second => "second",
        }
    }
}

/// `rmule-tools nat peer-reach` — one side of the pinned-port pair.
#[derive(Debug, Args)]
pub(crate) struct NatPeerReachArgs {
    /// Which side of the pair to be.
    #[arg(long, value_enum)]
    pub(crate) role: PeerReachRole,
    /// The far client's gateway WAN address.
    #[arg(long)]
    pub(crate) peer: Ipv4Addr,
    /// The far gateway's pinned port — the destination every datagram carries.
    #[arg(long, default_value_t = 4672)]
    pub(crate) peer_port: u16,
    /// The local UDP port, which must be the port our own gateway pins: the
    /// SNAT rule that collides is keyed on this source port.
    #[arg(long, default_value_t = 4672)]
    pub(crate) local_port: u16,
    /// How long the `second` role waits before its first send. It has to absorb
    /// the two containers' start skew as well as carry the stagger the leg
    /// needs, so it is set in seconds' worth of milliseconds, not tens.
    #[arg(long, default_value_t = 4000)]
    pub(crate) lead_ms: u64,
    /// The gap between sends.
    #[arg(long, default_value_t = 250)]
    pub(crate) interval_ms: u64,
    /// How long to keep sending and listening. It must outlast `--lead-ms` by
    /// enough for the far side to answer once it starts.
    #[arg(long, default_value_t = 12_000)]
    pub(crate) window_ms: u64,
    /// Where to write the `peer-reach.toml` row.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

/// What one side observed.
#[derive(Debug, PartialEq, Eq)]
struct Reach {
    sent: u32,
    received: u32,
    /// When the first of the far side's datagrams arrived, measured from this
    /// driver's own start. It separates the two filtering behaviours on sight:
    /// under Endpoint-Independent Filtering the `second` role hears the `first`
    /// before it has sent anything at all, under Address-Dependent Filtering it
    /// hears nothing until after its own first send.
    first_received_after_ms: Option<u64>,
}

impl Reach {
    fn reached(&self) -> bool {
        self.received > 0
    }
}

/// Run one side of the pair and write its row.
///
/// # Errors
/// If the local port cannot be bound or the row cannot be written. **Receiving
/// nothing is not an error**: behind two symmetric gateways it is the leg's
/// expected outcome, and a driver that exited non-zero on it would turn the
/// negative into a bench failure.
pub(crate) fn run_nat_peer_reach(args: NatPeerReachArgs) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.local_port))
        .with_context(|| format!("bind the local pinned port {}", args.local_port))?;
    // Short, because the loop alternates sending and draining: the read timeout
    // is the drain's granularity, never the leg's patience.
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .context("set the peer-reach read timeout")?;
    let peer = SocketAddr::from((args.peer, args.peer_port));
    let reach = exchange(&socket, peer, &args)?;

    println!(
        "nat-peer-reach role={} peer={peer} sent={} received={} reached={} first_after_ms={}",
        args.role.as_str(),
        reach.sent,
        reach.received,
        reach.reached(),
        reach
            .first_received_after_ms
            .map_or_else(|| "-".to_owned(), |at| at.to_string()),
    );
    let row = render_row(&args, peer, &reach);
    print!("{row}");
    if let Some(path) = &args.out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(path, &row).with_context(|| format!("write {}", path.display()))?;
        println!("nat-peer-reach row written to {}", path.display());
    }
    Ok(())
}

/// Send on the cadence the role dictates and drain what arrives, until the
/// window is spent.
fn exchange(socket: &UdpSocket, peer: SocketAddr, args: &NatPeerReachArgs) -> Result<Reach> {
    let start = Instant::now();
    let window = Duration::from_millis(args.window_ms);
    let interval = Duration::from_millis(args.interval_ms);
    let lead = match args.role {
        PeerReachRole::First => Duration::ZERO,
        PeerReachRole::Second => Duration::from_millis(args.lead_ms),
    };
    let payload = format!("{MAGIC} {}\n", args.role.as_str());

    let mut reach = Reach {
        sent: 0,
        received: 0,
        first_received_after_ms: None,
    };
    let mut next_send = start + lead;
    while start.elapsed() < window {
        if Instant::now() >= next_send {
            match socket.send_to(payload.as_bytes(), peer) {
                Ok(_) => reach.sent += 1,
                // A gateway that answered ICMP unreachable surfaces here on the
                // next send. It is an observation about the bench and must not
                // end the window.
                Err(error) => eprintln!("nat-peer-reach: send to {peer} failed: {error}"),
            }
            next_send += interval;
        }
        drain(socket, peer, start, &mut reach)?;
    }
    Ok(reach)
}

/// Read whatever is waiting, counting only this driver's own datagrams from the
/// far gateway's address.
fn drain(socket: &UdpSocket, peer: SocketAddr, start: Instant, reach: &mut Reach) -> Result<()> {
    let mut buffer = [0_u8; 2048];
    loop {
        let (read, source) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error).context("receive on the pinned port"),
        };
        if source.ip() != peer.ip() || !buffer[..read].starts_with(MAGIC.as_bytes()) {
            continue;
        }
        reach.received += 1;
        reach
            .first_received_after_ms
            .get_or_insert_with(|| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
    }
}

/// The `peer-reach.toml` row. Hand-rendered for the reason the probe's is:
/// rmule-tools carries no TOML dependency.
fn render_row(args: &NatPeerReachArgs, peer: SocketAddr, reach: &Reach) -> String {
    let mut row = String::new();
    let _ = writeln!(row, "probe = \"pinned-port-pair\"");
    let _ = writeln!(row, "role = \"{}\"", args.role.as_str());
    let _ = writeln!(row, "local_port = {}", args.local_port);
    let _ = writeln!(row, "peer = \"{peer}\"");
    let _ = writeln!(
        row,
        "lead_ms = {}",
        match args.role {
            PeerReachRole::First => 0,
            PeerReachRole::Second => args.lead_ms,
        }
    );
    let _ = writeln!(row, "sent = {}", reach.sent);
    let _ = writeln!(row, "received = {}", reach.received);
    let _ = writeln!(row, "reached = {}", reach.reached());
    // `-1` is the spelling for "nothing ever arrived", so a reader cannot mis-read
    // a missing field as an instant answer.
    let _ = writeln!(
        row,
        "first_received_after_ms = {}",
        reach
            .first_received_after_ms
            .map_or_else(|| "-1".to_owned(), |at| at.to_string()),
    );
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(role: PeerReachRole) -> NatPeerReachArgs {
        NatPeerReachArgs {
            role,
            peer: Ipv4Addr::new(45, 55, 200, 4),
            peer_port: 4672,
            local_port: 4672,
            lead_ms: 4000,
            interval_ms: 250,
            window_ms: 12_000,
            out: None,
        }
    }

    /// The row is read by the harness, and two of its fields are traps. A side
    /// that heard nothing must say so twice over — a reader must not be able to
    /// mistake an absent timestamp for an instant answer — and the stagger the
    /// leg depends on must be recorded as it was *applied*, which for the
    /// `first` role is zero whatever the operand said.
    #[test]
    fn the_row_states_the_absence_and_the_stagger_as_applied() {
        let silent = render_row(
            &args(PeerReachRole::Second),
            SocketAddr::from(([45, 55, 200, 4], 4672)),
            &Reach {
                sent: 32,
                received: 0,
                first_received_after_ms: None,
            },
        );
        assert!(silent.contains("reached = false"), "{silent}");
        assert!(silent.contains("first_received_after_ms = -1"), "{silent}");
        assert!(silent.contains("lead_ms = 4000"), "{silent}");

        let opener = render_row(
            &args(PeerReachRole::First),
            SocketAddr::from(([45, 55, 200, 4], 4672)),
            &Reach {
                sent: 48,
                received: 22,
                first_received_after_ms: Some(4102),
            },
        );
        assert!(opener.contains("lead_ms = 0"), "{opener}");
        assert!(opener.contains("reached = true"), "{opener}");
        assert!(
            opener.contains("first_received_after_ms = 4102"),
            "{opener}"
        );
    }
}
