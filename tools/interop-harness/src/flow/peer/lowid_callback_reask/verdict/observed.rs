//! What a run's two taps and two logs hold, read once into [`Observed`]:
//! every reassembled eD2k frame, the directions that did not open as plain
//! eD2k, rmule's SYNs, the datagrams between rmule and the sharer, and the
//! two stdout logs, and how a single queue-rank frame reads. Scoring them
//! is `super::claims`.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};

use super::{Addresses, RMULE_PCAP, ROOT_DIR, SERVER_PCAP};
use crate::flow::pcap::{
    Ed2kFrame, TcpOpen, TcpStream, Udp4Datagram, records, tcp_capture, udp4_datagrams,
};
use crate::flow::wire_filter::{OP_EDONKEYPROT, OP_EMULEPROT};

/// What the two taps and the two logs hold, read once.
pub(crate) struct Observed {
    /// Every eD2k frame of every TCP direction the server tap reassembled.
    pub(crate) server_frames: Vec<Ed2kFrame>,
    /// Every eD2k frame of every TCP direction the rmule tap reassembled.
    pub(crate) rmule_frames: Vec<Ed2kFrame>,
    /// The directions that did not open as plain eD2k, as `source > destination`.
    pub(crate) obfuscated: Vec<(SocketAddr, SocketAddr)>,
    /// Every SYN without ACK on the rmule tap.
    pub(crate) rmule_opens: Vec<TcpOpen>,
    /// Every UDP datagram between rmule's address and the sharer's.
    pub(crate) reask_datagrams: Vec<Udp4Datagram>,
    /// The sharer's stdout: its `amulecmd Status`.
    pub(crate) sharer_log: String,
    /// rmule's stdout: its run-log records.
    pub(crate) rmule_log: String,
}

/// Read the taps and logs under `run_dir`.
pub(super) fn observe(run_dir: &Path, addresses: &Addresses) -> Result<Observed> {
    let root = run_dir.join(ROOT_DIR);
    let server = tcp_capture(&records(&root.join(SERVER_PCAP))?)?;
    let rmule_pcap = root.join(RMULE_PCAP);
    let rmule = tcp_capture(&records(&rmule_pcap)?)?;
    let frames = |streams: &[TcpStream]| -> Vec<Ed2kFrame> {
        streams.iter().flat_map(TcpStream::ed2k_frames).collect()
    };
    let obfuscated = server
        .streams
        .iter()
        .chain(&rmule.streams)
        .filter(|stream| !stream.opens_plain())
        .map(|stream| (stream.source, stream.destination))
        .collect();
    let between = |a: Ipv4Addr, b: Ipv4Addr| {
        (a, b) == (addresses.rmule, addresses.sharer)
            || (a, b) == (addresses.sharer, addresses.rmule)
    };
    let reask_datagrams = udp4_datagrams(&rmule_pcap)?
        .into_iter()
        .filter(|datagram| between(*datagram.source.ip(), *datagram.destination.ip()))
        .collect();
    let log = |relative: &str| {
        let path = run_dir.join(relative);
        fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))
    };
    Ok(Observed {
        server_frames: frames(&server.streams),
        rmule_frames: frames(&rmule.streams),
        obfuscated,
        rmule_opens: rmule.opens,
        reask_datagrams,
        sharer_log: log("logs/amule/sharer.stdout.log")?,
        rmule_log: log("rmule/stdout.log")?,
    })
}

/// `OP_QUEUERANKING` (eMule extension, `u16` rank).
const OP_QUEUERANKING: u8 = 0x60;
/// `OP_QUEUERANK` (eDonkey, `u32` rank).
const OP_QUEUERANK: u8 = 0x5C;

/// The first little-endian `u32` of a frame's payload.
pub(super) fn u32_at_start(frame: &Ed2kFrame) -> Option<u32> {
    let bytes = frame.payload().get(..4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The rank a queue-rank frame names: `OP_QUEUERANKING`'s `u16` or
/// `OP_QUEUERANK`'s `u32`.
pub(super) fn rank_of(frame: &Ed2kFrame) -> Option<u32> {
    match (frame.protocol, frame.opcode) {
        (OP_EMULEPROT, OP_QUEUERANKING) => {
            let bytes = frame.payload().get(..2)?;
            Some(u32::from(u16::from_le_bytes([bytes[0], bytes[1]])))
        }
        (OP_EDONKEYPROT, OP_QUEUERANK) => u32_at_start(frame),
        _ => None,
    }
}

/// Whether `addr` is an IPv4 endpoint at `ip`.
pub(super) fn is_v4(addr: SocketAddr, ip: Ipv4Addr) -> bool {
    matches!(addr, SocketAddr::V4(v4) if *v4.ip() == ip)
}
