//! `ed2k sentinel-stimulus`: an rmule-authored eD2k server that hands a
//! **Sentinel Source**-bearing list (ADR-0085) to whatever logs in, and writes
//! down what that counterparty then did.
//!
//! This exists because the legacy-safety question — does a stock aMule
//! 2.3.3 desync on a source list whose records keep their fixed stride, one of
//! whose ids is `0xFFFFFFFF`, with sixteen-byte address blocks appended past
//! the declared count? — cannot be asked of the pinned `ed2ksrv`, which is
//! v4-only and has no config surface for emitting such a row.
//! The encoder now writes the spec's layout instead — the
//! sixteen bytes inline, as the sentinel record's last field — so a run of this
//! command asks a different question than run `1789576224` answered.
//! rmule owns the encoders, so rmule emits the stimulus and the
//! counterparty's reaction is the evidence — the same posture as the Kad
//! Stimulus Node and the Registrant.
//!
//! **Everything this command emits is Stimulus and is never evidence** (ADR-0045),
//! however correct the bytes are. What counts is in the journal's `received`
//! and `sink_dial` tables: the counterparty's own frames, and the address+port
//! it dialled — which is the counterparty naming, in its own TCP SYN, the
//! source record it decoded.
//!
//! The wire it speaks is the minimum that keeps a client engaged: a banner, an
//! `OP_IDCHANGE` granting the client its own address as a High ID, the status
//! counts, then the scripted `OP_FOUNDSOURCES` (`0x42`) list and the packed
//! `OP_GLOBFOUNDSOURCES` (`0x9B`) datagram.

mod journal;
mod session;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Args;
use rmule_ed2k::{FoundSources, Opcode};
use rmule_primitives::{FileHash, Ipv4Endpoint, Ipv6Endpoint, Packet, PacketProtocol, PeerSource};
use tokio::net::{TcpListener, UdpSocket};

use crate::operand::parse_hex16;

use self::journal::Journal;
use self::session::{Stimulus, bind_sinks, run_sink, serve_session, serve_udp};

/// Printed once every listener is bound — the harness's **Readiness Gate**.
const READY_MARKER: &str = "rmule-sentinel-stimulus-ready";

/// The eD2k convention this stimulus keeps: a server's UDP face sits four above
/// its TCP port, which is what a client's `port - 4` mapping assumes.
const SERVER_UDP_PORT_OFFSET: u16 = 4;

/// `rmule-tools ed2k sentinel-stimulus` — run the scripted server.
#[derive(Debug, Args)]
pub(crate) struct SentinelStimulusArgs {
    /// Where the eD2k server face listens, `ip:port`.
    #[arg(long, default_value = "0.0.0.0:4661")]
    listen: SocketAddr,
    /// The server-UDP port; defaults to the listen port + 4.
    #[arg(long)]
    udp_port: Option<u16>,
    /// One scripted `OP_FOUNDSOURCES` list, as `<file-hash-hex>=<record>[,<record>…]`.
    /// A record is `a.b.c.d:port` (a plain IPv4 record) or `[v6]:port` (a
    /// **Sentinel Source**: a `0xFFFFFFFF` id whose address rides the tail).
    /// Repeat the flag for several lists. Record order is flag order.
    #[arg(long = "record")]
    records: Vec<String>,
    /// One body of the packed `OP_GLOBFOUNDSOURCES` datagram, same syntax as
    /// `--record`. Repeat the flag to pack several files into ONE datagram, in
    /// flag order — which is the shape whose legacy safety the sentinel tail
    /// puts in question.
    #[arg(long = "packed")]
    packed: Vec<String>,
    /// Bodies of a SECOND packed datagram, emitted right after the first. Its
    /// whole purpose is to be the control: give it the same shape with no
    /// Sentinel Source, and a counterparty that reads its second body but not
    /// the first datagram's names the sentinel tail as the difference. Without
    /// it, "the second body was lost" cannot be attributed to anything.
    #[arg(long = "packed-control")]
    packed_control: Vec<String>,
    /// A TCP port to hold open as a **Source Sink**, so a dial at a decoded
    /// record lands somewhere that records it. Repeat per distinct port.
    #[arg(long = "sink")]
    sinks: Vec<u16>,
    /// The counterparty UDP port the packed datagram is pushed at, used only
    /// until the counterparty speaks from its own server-UDP socket — that
    /// endpoint then wins, and a datagram sent in answer to a query always goes
    /// back to the query's own source port.
    #[arg(long, default_value_t = 4665)]
    peer_udp_port: u16,
    /// A path whose appearance releases the scripted emission, so the harness
    /// fires it once every counterparty is staged rather than on a stopwatch.
    #[arg(long)]
    emit_trigger_file: Option<PathBuf>,
    /// Backstop: emit this many seconds after a login even if the trigger file
    /// never appears, so a missing trigger degrades to a late emission rather
    /// than to silence.
    #[arg(long, default_value_t = 120)]
    emit_after_secs: u64,
    /// Stop this many seconds after the scripted emission fires, so the run
    /// ends on the counterparty's observation window rather than on the hard
    /// cap. The harness reads the journal out of the exited container.
    #[arg(long, default_value_t = 45)]
    stop_after_emit_secs: u64,
    /// Hard cap: run at most this many seconds whatever happens, then write the
    /// journal and exit 0.
    #[arg(long, default_value_t = 180)]
    max_seconds: u64,
    /// Directory the journal (`stimulus.toml`) is written to.
    #[arg(long)]
    out: PathBuf,
}

/// The scripted emissions, built once before anything is bound so a malformed
/// spec fails before a counterparty is engaged.
#[derive(Debug)]
pub(crate) struct Plan {
    /// `(label, whole TCP frame)` per `--record` list, in flag order.
    pub(crate) tcp_frames: Vec<(String, Vec<u8>)>,
    /// `(label, whole datagram)` per packed `OP_GLOBFOUNDSOURCES` emission, in
    /// emission order: the sentinel-bearing one, then its control.
    pub(crate) packed_datagrams: Vec<(String, Vec<u8>)>,
}

impl Plan {
    /// Build the plan from the record specs.
    ///
    /// # Errors
    /// If a spec is malformed, names a bad hash, or exceeds the `u8` record
    /// count the wire carries.
    fn build(records: &[String], packed: &[String], control: &[String]) -> Result<Self> {
        let mut tcp_frames = Vec::with_capacity(records.len());
        for (index, spec) in records.iter().enumerate() {
            let list = parse_list(spec)?;
            tcp_frames.push((
                format!("found-sources-{index}"),
                list.encode_packet().encode(),
            ));
        }
        let mut packed_datagrams = Vec::new();
        for (label, specs) in [
            ("glob-found-sources-packed", packed),
            ("glob-found-sources-control", control),
        ] {
            let datagram = packed_datagram(specs)?;
            if !datagram.is_empty() {
                packed_datagrams.push((label.to_owned(), datagram));
            }
        }
        Ok(Self {
            tcp_frames,
            packed_datagrams,
        })
    }
}

/// One datagram packing every spec's body in flag order. The same body as the
/// TCP `0x42`, under the UDP opcode: a datagram may pack several, each carrying
/// its own `[0xE3][0x9B]` header (`docs/reference/notes/server-udp.md`).
fn packed_datagram(specs: &[String]) -> Result<Vec<u8>> {
    let mut datagram = Vec::new();
    for spec in specs {
        let list = parse_list(spec)?;
        let packet = Packet::new(
            PacketProtocol::Edonkey,
            Opcode::GlobFoundSources.as_u8(),
            list.encode_packet().payload().to_vec(),
        );
        datagram.extend_from_slice(&packet.encode_udp());
    }
    Ok(datagram)
}

/// Parse one `<file-hash-hex>=<record>[,<record>…]` spec into the list it names.
fn parse_list(spec: &str) -> Result<FoundSources> {
    let (hash_hex, records) = spec
        .split_once('=')
        .with_context(|| format!("source list spec {spec} is not <file-hash-hex>=<record>[,…]"))?;
    let file_hash = FileHash::from_bytes(parse_hex16("file-hash", hash_hex)?);
    let mut sources = Vec::new();
    for record in records.split(',') {
        sources.push(parse_record(record.trim())?);
    }
    if sources.is_empty() {
        bail!("source list spec {spec} names no records");
    }
    FoundSources::new(file_hash, sources)
        .with_context(|| format!("build the source list for {spec}"))
}

/// One record: an IPv4 socket address is a plain record, an IPv6 one is a
/// **Sentinel Source** whose sixteen address bytes ride the list's tail.
fn parse_record(record: &str) -> Result<PeerSource> {
    let address: SocketAddr = record
        .parse()
        .with_context(|| format!("parse source record {record} as ip:port"))?;
    Ok(match address {
        SocketAddr::V4(v4) => PeerSource::HighId(Ipv4Endpoint::new(*v4.ip(), v4.port())),
        SocketAddr::V6(v6) => PeerSource::Ipv6(Ipv6Endpoint::new(*v6.ip(), v6.port())),
    })
}

/// Run the stimulus until `--max-seconds`, then write the journal.
///
/// # Errors
/// If a spec is malformed, a listener cannot be bound, or the journal cannot be
/// written. A counterparty that never connects is **not** an error — the empty
/// journal is the observation.
pub(crate) async fn sentinel_stimulus(args: SentinelStimulusArgs) -> Result<()> {
    let plan = Plan::build(&args.records, &args.packed, &args.packed_control)?;
    let udp_port = args
        .udp_port
        .unwrap_or_else(|| args.listen.port().saturating_add(SERVER_UDP_PORT_OFFSET));
    let bind_ip: IpAddr = args.listen.ip();
    let udp_addr = SocketAddr::new(bind_ip, udp_port);

    let tcp = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind the eD2k server face on {}", args.listen))?;
    let udp = UdpSocket::bind(udp_addr)
        .await
        .with_context(|| format!("bind the server-UDP face on {udp_addr}"))?;
    let sinks = bind_sinks(bind_ip, &args.sinks)
        .await
        .context("bind the source sinks")?;

    let journal = Journal::new(
        args.listen.to_string(),
        udp_addr.to_string(),
        args.sinks.iter().map(u16::to_string).collect(),
    );
    let stimulus = Arc::new(Stimulus {
        plan,
        journal,
        udp,
        peer_udp_port: args.peer_udp_port,
        heard_udp: Mutex::new(None),
        emit_trigger_file: args.emit_trigger_file.clone(),
        emit_after: Duration::from_secs(args.emit_after_secs),
        emitted_at: Mutex::new(None),
    });

    for sink in sinks {
        let held = Arc::clone(&stimulus);
        tokio::spawn(async move { run_sink(held, sink).await });
    }
    let udp_held = Arc::clone(&stimulus);
    tokio::spawn(async move { serve_udp(udp_held).await });

    println!(
        "{READY_MARKER} listen={} udp={udp_addr} sinks={:?} lists={} packed_bytes={}",
        args.listen,
        args.sinks,
        stimulus.plan.tcp_frames.len(),
        stimulus
            .plan
            .packed_datagrams
            .iter()
            .map(|(_, datagram)| datagram.len())
            .sum::<usize>()
    );

    let accept = async {
        loop {
            let Ok((stream, peer)) = tcp.accept().await else {
                continue;
            };
            let held = Arc::clone(&stimulus);
            tokio::spawn(async move { serve_session(held, stream, peer).await });
        }
    };
    // Two ends to the run: the observation window that opens when the scripted
    // emission fires, and the hard cap for a run where it never does.
    let done = wait_out_the_window(
        Arc::clone(&stimulus),
        Duration::from_secs(args.stop_after_emit_secs),
        Instant::now() + Duration::from_secs(args.max_seconds),
    );
    tokio::select! {
        () = accept => {},
        () = done => {},
    }
    stimulus.journal.write(&args.out)
}

/// Hold until the counterparty's observation window closes (`window` after the
/// scripted emission fired) or `cap` passes, whichever comes first.
async fn wait_out_the_window(stimulus: Arc<Stimulus>, window: Duration, cap: Instant) {
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if stimulus
            .emitted_elapsed()
            .is_some_and(|elapsed| elapsed >= window)
        {
            return;
        }
        if Instant::now() >= cap {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    /// The one wire shape the whole flow rests on: the sentinel id in the
    /// middle, its address inline as its record's last field (emule-qt
    /// `ipv6-spec.md` §4.4), the record after it behind those sixteen bytes.
    #[test]
    fn a_sentinel_bearing_list_carries_the_address_inline() {
        let plan = Plan::build(
            &["51".repeat(16) + "=203.0.113.50:5001,[3fff:1::2]:5002,203.0.113.60:5003"],
            &[],
            &[],
        )
        .expect("the spec parses");
        let frame = &plan.tcp_frames[0].1;
        let (packet, consumed) = Packet::decode(frame).expect("the frame decodes");
        assert_eq!(consumed, frame.len());
        assert_eq!(packet.opcode(), 0x42);
        let payload = packet.payload();
        assert_eq!(payload[..16], [0x51; 16], "file hash");
        assert_eq!(payload[16], 3, "declared record count");
        let records = &payload[17..];
        assert_eq!(&records[..6], &[203, 0, 113, 50, 0x89, 0x13]);
        assert_eq!(&records[6..12], &[0xFF, 0xFF, 0xFF, 0xFF, 0x8A, 0x13]);
        assert_eq!(
            &records[12..28],
            &Ipv6Addr::new(0x3fff, 1, 0, 0, 0, 0, 0, 2).octets(),
            "the sentinel's address is inline, before the next record",
        );
        assert_eq!(&records[28..34], &[203, 0, 113, 60, 0x8B, 0x13]);
        assert_eq!(payload.len(), 16 + 1 + 18 + 16);
    }

    /// The packed datagram carries one `[0xE3][0x9B]`-headed packet per file,
    /// in flag order — so the sentinel tail of the first sits exactly where the
    /// second packet's header begins.
    #[test]
    fn the_packed_datagram_heads_every_body_and_puts_the_tail_before_the_next() {
        let plan = Plan::build(
            &[],
            &[
                "11".repeat(16) + "=203.0.113.70:5004,[3fff:1::3]:5005",
                "22".repeat(16) + "=203.0.113.80:5006",
            ],
            &["33".repeat(16) + "=203.0.113.90:5007"],
        )
        .expect("the specs parse");
        assert_eq!(
            plan.packed_datagrams.len(),
            2,
            "the control rides as its own datagram",
        );
        let datagram = &plan.packed_datagrams[0].1;
        assert_eq!(&datagram[..2], &[0xE3, 0x9B]);
        // First body: hash + count + two records, one carrying its 16 address bytes.
        let first_len = 2 + 16 + 1 + 12 + 16;
        assert_eq!(&datagram[first_len..first_len + 2], &[0xE3, 0x9B]);
        assert_eq!(datagram.len(), first_len + 2 + 16 + 1 + 6);
    }

    #[test]
    fn a_spec_without_a_hash_separator_is_rejected_before_anything_binds() {
        let error = Plan::build(&["203.0.113.50:5001".to_owned()], &[], &[]).unwrap_err();
        assert!(
            format!("{error:#}").contains("<file-hash-hex>="),
            "{error:#}"
        );
    }
}
