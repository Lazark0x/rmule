//! `rmule-tools natt caps-utp` — the NAT-T `natt-caps-utp` driver (ADR-0092):
//! put the dialect's three opening frames on a counterparty's client-UDP socket
//! and record what it does with each.
//!
//! Three questions, in the order ADR-0091's negotiation asks them:
//!
//! 1. **CAPS** (`0xB2 0x02`) — a probe naming the counterparty's own user hash,
//!    which is the only form it may answer at all. The answer, a CAPS-ACK, is
//!    the counterparty's capability statement; its *silence* is a measurement
//!    too, and the dialect's own rule for a silent peer is the 1500 ms
//!    legacy-uTP fallback rather than a failure.
//! 2. **KEY** (`0xB2 0xFF`) — armed by the send path itself on the first
//!    opening transport payload, so it is never emitted by hand here: what the
//!    driver does is arm the crypt (`--observed-address`) so the production
//!    rule fires, and the WAN tap counts the frame.
//! 3. **uTP `ST_SYN`** (`0xB2 0x00`) — a real dial through the production
//!    [`UtpEngine`](rmule_net::natt::UtpEngine). A handshake that completes is
//!    the counterparty answering the SYN; there is no other way for
//!    `connect` to return.
//!
//! The counterparty's hash is an *operand*, not a guess: the flow reads it off
//! that body's own `OP_HELLOANSWER` (the `ipv6 hello` driver's
//! `peer_user_hash`) and passes it in. A CAPS probe naming a fabricated
//! recipient is refused by every conforming reader — rmule's own demux answers
//! `CapsNotOurs` — so a fabricated one would measure the fabrication.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Args;
use rmule_net::ed2k::ClientUdpSocket;
use rmule_net::family::FamilySelection;
use rmule_net::natt::{
    ClientUdpNattSink, NattCrypt, NattDemux, NattIdentity, NattOwnHash, NattSender, TunnelRegistry,
};
use rmule_peer::natt::{
    CapsFrame, HelloNattClaim, NattConnectOptions, NattFrame, NattFrameType, NattTransport,
};
use rmule_primitives::{FileHash, UserHash};
use tokio::io::AsyncWriteExt;

use crate::capture::{hex_lower, write_new};
use crate::driver_row::Row;
use crate::natt::{Arrivals, DriverIdentity, Seen};
use crate::operand::{parse_hex16, parse_user_hash};

#[derive(Debug, Args)]
pub(crate) struct NattCapsUtpArgs {
    /// The counterparty's client-UDP socket, `a.b.c.d:port`.
    #[arg(long)]
    peer: String,
    /// The counterparty's 16-byte user hash as hex — the recipient a CAPS
    /// probe must name. Read off its own hello by the flow, never invented.
    #[arg(long)]
    peer_user_hash: String,
    /// Our own user hash: the CAPS sender and the KEY frame's whole body.
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Our own address as the counterparty observes it. Supplying it arms the
    /// NAT-T crypt, which is what makes the send path emit a **Key Frame** on
    /// the opening uTP packet; omitted, every frame goes plaintext and the KEY
    /// row is a measured zero rather than an absence nobody caused.
    #[arg(long)]
    observed_address: Option<IpAddr>,
    /// Bind the client-UDP socket to this port. A NAT-T exchange must leave the
    /// one advertised bind — the pinhole a punch opened belongs to it — so the
    /// bench pins it rather than drawing an ephemeral one.
    #[arg(long, default_value_t = 4672)]
    bind_port: u16,
    /// Claim QUIC (`0x40`) in the probe's connect-options byte as well as uTP.
    /// Off by default, which is what a build with `local.quic == false` says
    /// (ADR-0091); the `natt-quic-handshake` flow turns it on to ask the
    /// counterparty what *it* would answer.
    #[arg(long)]
    claim_quic: bool,
    /// Seconds to wait for a CAPS-ACK before recording its absence. The
    /// dialect's own legacy window is 1500 ms; the default is far longer so a
    /// slow container cannot be mistaken for a silent one.
    #[arg(long, default_value_t = 10)]
    caps_wait: u64,
    /// uTP dial budget, seconds.
    #[arg(long, default_value_t = 30)]
    dial_timeout: u64,
    /// Hold a risen tunnel open this long before closing it, so the tap records
    /// the path in both directions.
    #[arg(long, default_value_t = 3)]
    hold_secs: u64,
    /// Where every inbound NAT-T datagram is retained, raw and in arrival order.
    #[arg(long)]
    capture: PathBuf,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
}

/// Drive the three frames and write the row.
///
/// # Errors
/// If an operand will not parse, the socket cannot be bound, the engines will
/// not start, or the row cannot be written. **A silent counterparty is a row,
/// never an error** — that is the measurement the flow exists to take.
pub(crate) async fn run_caps_utp(args: NattCapsUtpArgs) -> Result<()> {
    let peer: SocketAddr = args
        .peer
        .parse()
        .with_context(|| format!("parse peer socket {}", args.peer))?;
    let peer = rmule_net::family::endpoint_of(peer);
    let peer_hash = UserHash::from_bytes(parse_hex16("--peer-user-hash", &args.peer_user_hash)?);
    let our_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    std::fs::create_dir_all(&args.capture)
        .with_context(|| format!("create {}", args.capture.display()))?;

    let identity = Arc::new(DriverIdentity {
        user_hash: our_hash,
        observed_address: args.observed_address,
    });
    let socket = Arc::new(
        ClientUdpSocket::bind_with(args.bind_port, FamilySelection::v4_only())
            .await
            .with_context(|| format!("bind the client-UDP socket on {}", args.bind_port))?,
    );
    let local_claim = HelloNattClaim {
        utp: true,
        quic: args.claim_quic,
    };
    let sender = Arc::new(NattSender::new(
        ClientUdpNattSink(Arc::clone(&socket)),
        Some(Box::new(DriverIdentity {
            user_hash: our_hash,
            observed_address: args.observed_address,
        })),
    ));
    let demux = Arc::new(
        NattDemux::start(
            NattIdentity { local: local_claim },
            Arc::clone(&identity) as Arc<dyn NattOwnHash>,
            Arc::clone(&sender),
            Arc::new(Mutex::new(TunnelRegistry::new())),
        )
        .context("start the NAT-T demux and its engines")?,
    );

    let arrivals = Arrivals::default();
    spawn_pump(Arc::clone(&socket), Arc::clone(&demux), arrivals.clone());

    // 1. The CAPS probe. Its recipient is the counterparty's own hash, which
    //    is the only form any conforming reader will answer; its crypt bits
    //    are the ones the driver's CAPS answers state.
    let probe = NattFrame::Caps(CapsFrame {
        connect_options: NattConnectOptions::advertise(
            identity.crypt_options(),
            true,
            args.claim_quic,
        ),
        sender: our_hash,
        expected_recipient: peer_hash,
        file_hash: FileHash::from_bytes([0; FileHash::BYTE_LEN]),
    });
    let probe_bytes = probe.encode();
    sender
        .send_frame(peer, &probe)
        .await
        .context("send the CAPS probe")?;
    demux.probe_sent(peer, HelloNattClaim::default(), Instant::now());
    println!(
        "natt-caps-utp CAPS probe sent to {peer} ({} bytes)",
        probe_bytes.len()
    );
    tokio::time::sleep(Duration::from_secs(args.caps_wait)).await;
    let caps_ack = arrivals.first_frame(NattFrameType::CapsAck.as_byte());

    // 2. + 3. The dial. The KEY frame is the send path's own, armed by the
    //    opening `ST_SYN`; a handshake that completes is the counterparty
    //    having answered that SYN, and there is no other way to get one.
    let dial_started = Instant::now();
    let dial = tokio::time::timeout(
        Duration::from_secs(args.dial_timeout),
        demux.utp().connect(peer),
    )
    .await;
    let dial_secs = dial_started.elapsed().as_secs_f64();
    let mut tunnel_open = false;
    let mut tunnel_transport = String::new();
    let mut dial_failure = String::new();
    match dial {
        Ok(Ok(mut tunnel)) => {
            tunnel_open = true;
            tunnel_transport = format!("{:?}", tunnel.transport());
            println!("natt-caps-utp uTP tunnel up to {peer} after {dial_secs:.2}s");
            tokio::time::sleep(Duration::from_secs(args.hold_secs)).await;
            // Closed rather than dropped: the peer's own accept path treats a
            // half-open stream as a live client and would hold it for its
            // whole connection timeout.
            let _ = tunnel.shutdown().await;
        }
        Ok(Err(error)) => dial_failure = error.to_string(),
        Err(_) => dial_failure = format!("no handshake within {}s", args.dial_timeout),
    }

    let seen = arrivals.snapshot();
    retain(&args.capture, &seen)?;
    let verdict_transport = demux.verdict(peer, HelloNattClaim::default(), Instant::now());

    let mut row = Row::new(
        "rmule-tools natt caps-utp — the dialect's three opening frames against one\n\
         counterparty (ADR-0091/ADR-0092). Everything rmule emitted is Stimulus;\n\
         the retained inbound datagrams beside this row are the counterparty's own bytes.",
    );
    row.str("peer", &peer.to_string())
        .str("peer_user_hash", &args.peer_user_hash)
        .bool("claimed_quic", args.claim_quic)
        .int("bind_port", i64::from(socket.local_port()))
        .bool("crypt_armed", args.observed_address.is_some())
        .int("caps_probe_bytes", as_i64(probe_bytes.len()))
        .str("caps_probe_hex", &hex_lower(&probe_bytes))
        .bool("caps_ack_received", caps_ack.is_some())
        .str(
            "caps_ack_hex",
            &caps_ack
                .as_ref()
                .map(|seen| hex_lower(&seen.bytes))
                .unwrap_or_default(),
        )
        .int(
            "caps_ack_frames",
            as_i64(arrivals.count_frames(NattFrameType::CapsAck.as_byte())),
        )
        .int(
            "caps_frames_in",
            as_i64(arrivals.count_frames(NattFrameType::Caps.as_byte())),
        )
        .int(
            "key_frames_in",
            as_i64(arrivals.count_frames(NattFrameType::Key.as_byte())),
        )
        .int(
            "utp_frames_in",
            as_i64(arrivals.count_frames(NattFrameType::Utp.as_byte())),
        )
        .int(
            "quic_frames_in",
            as_i64(arrivals.count_frames(NattFrameType::Quic.as_byte())),
        )
        .int("datagrams_in", as_i64(seen.len()))
        // Which socket answered, not merely that something did: a uTP answer
        // from a port other than the one the counterparty's hello named would
        // mean the transport does not ride the advertised bind.
        .str(
            "utp_answer_from",
            &arrivals
                .first_frame(NattFrameType::Utp.as_byte())
                .map(|seen| seen.from.to_string())
                .unwrap_or_default(),
        )
        .bool("tunnel_open", tunnel_open)
        .str("tunnel_transport", &tunnel_transport)
        .str("dial_failure", &dial_failure)
        .int("dial_seconds", dial_secs.round() as i64)
        .str("negotiated_transport", &describe(verdict_transport));
    println!(
        "natt-caps-utp caps_ack={} utp_in={} tunnel={tunnel_open}",
        caps_ack.is_some(),
        arrivals.count_frames(NattFrameType::Utp.as_byte()),
    );
    crate::driver_row::write_row(&args.out, row)
}

/// Drain the socket into the demux, retaining every datagram on the way.
///
/// The pump is the only reader of the socket, so it — not the demux — is where
/// a datagram becomes evidence: the demux consumes a frame and answers it,
/// while the row needs the bytes exactly as they arrived.
fn spawn_pump(
    socket: Arc<ClientUdpSocket>,
    demux: Arc<NattDemux<ClientUdpNattSink>>,
    arrivals: Arrivals,
) {
    tokio::spawn(async move {
        loop {
            let Ok((datagram, from)) = socket.recv().await else {
                return;
            };
            arrivals.push(Seen {
                from,
                bytes: datagram.clone(),
            });
            if datagram.first() == Some(&rmule_peer::natt::NATT_PROTOCOL) {
                demux.on_datagram(from, &datagram, Instant::now()).await;
            }
        }
    });
}

/// Retain every inbound datagram, raw and numbered in arrival order, so a
/// fixture can be promoted byte-for-byte from the run dir.
fn retain(dir: &std::path::Path, seen: &[Seen]) -> Result<()> {
    for (index, datagram) in seen.iter().enumerate() {
        let kind = datagram
            .natt_frame_type()
            .map_or_else(|| "other".to_owned(), |byte| format!("b2-{byte:02x}"));
        let path = dir.join(format!("{index:03}-{kind}.bin"));
        write_new(&path, &datagram.bytes)?;
    }
    Ok(())
}

/// The negotiation's verdict as a row value.
fn describe(verdict: rmule_peer::natt::TransportVerdict) -> String {
    match verdict {
        rmule_peer::natt::TransportVerdict::Ready(NattTransport::Utp) => "utp".to_owned(),
        rmule_peer::natt::TransportVerdict::Ready(NattTransport::Quic) => "quic".to_owned(),
        rmule_peer::natt::TransportVerdict::AwaitingCaps => "awaiting-caps".to_owned(),
        rmule_peer::natt::TransportVerdict::Unsupported => "unsupported".to_owned(),
    }
}

/// A count as a row integer; `-1` for the impossible overflow rather than a
/// silent truncation.
fn as_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(-1)
}
