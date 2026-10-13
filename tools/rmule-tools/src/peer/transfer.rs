//! The `peer transfer capture` command: run a real part transfer against a
//! live peer — hello, file request, slot, part data — and record each leg,
//! optionally following it with a source exchange on the same session.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, Connection as PeerConnection};
use rmule_peer::{
    ConnectionEvent, PartBitmap, PeerCommand, PeerEvent, PeerHandshakeContext, RequesterCommand,
    RequesterEvent,
};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kLink, Ed2kText, UserHash};

use crate::cli::{CaptureModeArg, ObfuscationArg};
use crate::operand::{parse_peer_endpoint, parse_user_hash};
use crate::peer::source_exchange::source_exchange_capture;

#[derive(Debug, Args)]
pub(crate) struct PeerTransferCaptureArgs {
    /// Peer endpoint as `ipv4:port`.
    #[arg(long)]
    peer: String,
    /// ED2K file link (`ed2k://|file|<name>|<size>|<hash>|...|/`).
    #[arg(long)]
    file: String,
    /// Output directory for capture artifacts.
    #[arg(long)]
    pub(super) output_dir: std::path::PathBuf,
    /// Capture mode (defaults to `protocol-only` per ADR-0024).
    #[arg(long, value_enum, default_value_t = CaptureModeArg::ProtocolOnly)]
    mode: CaptureModeArg,
    /// Maximum seconds to run before forcing terminal shutdown.
    #[arg(long, default_value_t = 120)]
    pub(super) max_seconds: u64,
    /// After capture, slice the inbound stream into per-packet fixture
    /// files. Deferred; flag accepted for forward compatibility.
    #[arg(long)]
    slice: bool,
    /// Local user hash as upper-case hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Local nickname tag.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// Local TCP port advertised in hello.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// Protocol version tag.
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Connect timeout (seconds).
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Hello-response timeout (seconds).
    #[arg(long, default_value_t = 15)]
    hello_timeout: u64,
    /// Run Secure User Identification (ADR-0041) with a fresh keypair and
    /// fail unless the peer's identity verifies. The exchange rides the
    /// capture artifacts — the SUI golden-vector source.
    #[arg(long)]
    secure_ident: bool,
    /// Protocol-obfuscation policy for the dial (ADR-0042). When set, rmule
    /// initiates an RC4-obfuscated connection; `--obfuscation-target-hash` must
    /// supply the peer's User Hash (the key basis). A completing exchange through
    /// the crypt layer is the obfuscation interop proof.
    #[arg(long, value_enum)]
    obfuscation: Option<ObfuscationArg>,
    /// The target peer's User Hash as upper-case hex (32 chars), keying the peer
    /// obfuscation handshake. Required with `--obfuscation`.
    #[arg(long)]
    obfuscation_target_hash: Option<String>,
    /// Source-exchange capture (ADR-0053 / ADR-0055): after the
    /// hello + file probe, send `OP_REQUESTSOURCES` and hold the connection to
    /// receive the peer's `OP_ANSWERSOURCES`. With enough sources known for the
    /// file the answer arrives zlib-packed (>354 bytes) — the packed-inflate
    /// golden. The answer frame is extracted to `sx_answer_raw.bin` in the
    /// output dir. Skips the part-download flow.
    #[arg(long)]
    request_sources: bool,
    /// Diagnostic/capture-only source-exchange nibble to advertise in the hello
    /// (ADR-0055 "consume 0x82 v3" toggle). aMule answers a plain
    /// `OP_REQUESTSOURCES` at the *requester's* nibble and cross-checks against
    /// its own advertised nibble (3), so `--sx-nibble 3` is what makes aMule's
    /// packed reply land at v3 geometry and reconcile on decode. Omit for
    /// rmule's honest v1 advert.
    #[arg(long)]
    sx_nibble: Option<u8>,
    /// Multipacket capture (ADR-0054 emit): open
    /// the file negotiation with `RequesterCommand::RequestFile` — the live
    /// download runner's connect-time shape — so a MultiPacket-advertising
    /// aMule receives one `OP_MULTIPACKET_EXT` (`0xA4`) bundle and answers its
    /// composed `OP_MULTIPACKETANSWER` (`0x93`), the forward-direction capture
    /// target. The rest of the flow (probe upgrade → one-part pull) is
    /// unchanged.
    #[arg(long)]
    pub(super) multipacket: bool,
    /// A byte range `<start>-<end>` (end exclusive) to ask for in place of the
    /// first part; repeat for several. Each goes as its own `OP_REQUESTPARTS`
    /// once the one before has arrived whole or `--range-wait-secs` passed
    /// with it unanswered; after the last the link is held to
    /// `--max-seconds`, so a run shows whether the peer closes it.
    #[arg(long = "range", value_parser = parse_range)]
    ranges: Vec<(u64, u64)>,
    /// How long a `--range` waits for its bytes before the next one goes.
    #[arg(long, default_value_t = 10)]
    range_wait_secs: u64,
}

/// One `--range`: `<start>-<end>`, decimal byte offsets, `start < end`.
fn parse_range(text: &str) -> std::result::Result<(u64, u64), String> {
    let (start, end) = text
        .split_once('-')
        .ok_or_else(|| format!("{text}: want <start>-<end>"))?;
    let start: u64 = start.parse().map_err(|_| format!("{text}: bad start"))?;
    let end: u64 = end.parse().map_err(|_| format!("{text}: bad end"))?;
    if start >= end {
        return Err(format!("{text}: the end must lie past the start"));
    }
    Ok((start, end))
}

pub(crate) async fn transfer_capture(args: PeerTransferCaptureArgs) -> Result<()> {
    let peer = parse_peer_endpoint(&args.peer)?;
    let link =
        Ed2kLink::parse(&args.file).with_context(|| format!("parse ed2k link {}", args.file))?;
    let file = match link {
        Ed2kLink::File(f) => f,
        _ => anyhow::bail!("--file must be an ed2k file link, got {}", args.file),
    };
    let user_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let identity = ClientIdentity::new(
        user_hash,
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        args.protocol_version,
    );
    let ctx = PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(0x10000001),
        ed2k_client_id: ClientId::from_u32(0x10000001),
        public_ip: None,
        connected_server: None,
    };
    // A fresh keypair per run (ADR-0041): the capture needs a real exchange,
    // not a persisted identity, and a throwaway key keeps the artifacts free
    // of any durable secret.
    let secure_ident_key = args
        .secure_ident
        .then(rmule_primitives::SecureIdentKey::generate)
        .transpose()
        .context("generate SUI keypair")?
        .map(std::sync::Arc::new);
    // Obfuscation dial (ADR-0042): the policy plus the target's User Hash the
    // peer key derives from. A completing exchange through the crypt layer is the
    // interop proof that rmule's obfuscation is aMule-compatible.
    let obfuscation = args
        .obfuscation
        .map(|arg| rmule_net::peer::ObfuscationConfig { policy: arg.into() });
    let obfuscation_target = match &args.obfuscation_target_hash {
        Some(hex) => Some(UserHash::from_bytes(parse_user_hash(hex)?)),
        None => None,
    };
    if obfuscation.is_some() && obfuscation_target.is_none() {
        anyhow::bail!("--obfuscation requires --obfuscation-target-hash (the peer's User Hash)");
    }
    let options = PeerConnectOptions {
        capture_dir: Some(args.output_dir.clone()),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        hello_timeout: Duration::from_secs(args.hello_timeout),
        capture_mode: args.mode.into(),
        secure_ident: secure_ident_key.map(|key| rmule_peer::SecureIdentConfig {
            key,
            challenge: mint_challenge(),
        }),
        obfuscation,
        // The operator naming the peer's hash vouches that it supports crypt:
        // the dial then meets that stance with `--obfuscation` by the
        // outbound rule (ADR-0049).
        peer_crypt: rmule_primitives::PeerCrypt::new(
            rmule_primitives::CryptStance::new(obfuscation_target.is_some(), false, false),
            obfuscation_target,
        ),
        source_exchange_capture_override: args.sx_nibble,
        ..Default::default()
    };
    if args.request_sources {
        return source_exchange_capture(args, peer, ctx, options, file).await;
    }
    let mut conn = PeerConnection::connect(peer, ctx, options).await?;

    let first_part = (
        0,
        std::cmp::min(file.size, rmule_primitives::ED2K_PART_SIZE),
    );
    let mut asks = Asks::new(if args.ranges.is_empty() {
        vec![first_part]
    } else {
        args.ranges.clone()
    });
    // Without `--range` the first part is awaited to `--max-seconds`, as
    // before: only an asked-for range is given up on.
    let range_wait = (!args.ranges.is_empty()).then(|| Duration::from_secs(args.range_wait_secs));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.max_seconds);
    let mut sent_probe = false;
    let mut sent_release = false;
    let mut identity_verified = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                println!("max_seconds reached, shutting down");
                break;
            }
            () = asks.lapse(range_wait) => {
                if let Some((start, end, received)) = asks.give_up() {
                    println!(
                        "transfer range_unanswered range={start}-{end} received={received} waited_secs={} at_unix_ms={}",
                        args.range_wait_secs,
                        unix_ms()
                    );
                }
                send_next(&mut conn, &file, &mut asks).await?;
            }
            event = conn.next_event() => match event {
                Some(event @ PeerEvent::Connection(ConnectionEvent::IdentityVerified { .. })) => {
                    identity_verified = true;
                    println!("{event}");
                }
                Some(event @ PeerEvent::Connection(ConnectionEvent::Identified { .. })) => {
                    println!("{event}");
                    if !sent_probe {
                        if args.multipacket {
                            // The live runner's connect-time shape: the
                            // session folds name + status + SX asks into one
                            // 0xA4/0x92 bundle when the peer advertised
                            // MultiPacket, else the same standalone packets.
                            let _ = conn.send(PeerCommand::Requester(RequesterCommand::RequestFile {
                                file_hash: file.file_hash,
                                file_size: file.size,
                                own_status: PartBitmap::downloader_empty(file.size),
                                want_sources: true,
                                want_aich_root: false,
                            })).await;
                        } else {
                            // Issue the full flow: probe then request.
                            let _ = conn
                                .send(PeerCommand::Requester(RequesterCommand::ProbeFile {
                                    file_hash: file.file_hash,
                                    file_size: file.size,
                                    own_status: PartBitmap::downloader_empty(file.size),
                                }))
                                .await;
                        }
                        sent_probe = true;
                    }
                }
                Some(PeerEvent::Requester(RequesterEvent::FileProbed { status, .. })) => {
                    println!("file_probed: {status:?}");
                    if !asks.started() {
                        send_next(&mut conn, &file, &mut asks).await?;
                    }
                }
                Some(event @ PeerEvent::Requester(RequesterEvent::PartReceived { .. })) => {
                    if let PeerEvent::Requester(RequesterEvent::PartReceived { offset, bytes, .. }) = &event
                        && let Some((start, end)) = asks.receive(*offset, bytes.len() as u64)
                    {
                        println!("transfer range_answered range={start}-{end} at_unix_ms={}", unix_ms());
                        send_next(&mut conn, &file, &mut asks).await?;
                    }
                    println!("{event}");
                    // The slot is held across block requests (ADR-0025,
                    // amended); as the completion authority, release it once
                    // every requested range has arrived, mirroring the core
                    // worker.
                    if !sent_release && asks.all_answered() {
                        let _ = conn
                            .send(PeerCommand::Requester(RequesterCommand::ReleaseSlot {
                                file_hash: file.file_hash,
                            }))
                            .await;
                        sent_release = true;
                    }
                }
                Some(PeerEvent::Requester(RequesterEvent::SlotReleased { reason, .. })) => {
                    println!("slot_released: {reason:?}");
                    break;
                }
                Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                    println!("disconnected: {reason:?}");
                    break;
                }
                Some(event) => println!("{event}"),
                None => break,
            }
        }
    }
    let _ = conn.shutdown().await;
    if args.slice {
        eprintln!(
            "warning: --slice is accepted but per-packet fixture slicing for transfer captures \
             is deferred to a follow-up slice"
        );
    }
    if args.secure_ident && !identity_verified {
        anyhow::bail!(
            "secure user identification did not complete: no IdentityVerified from the peer"
        );
    }
    Ok(())
}

/// Send the next `--range`, when one is left, and say so.
async fn send_next(
    conn: &mut PeerConnection,
    file: &rmule_primitives::Ed2kFileLink,
    asks: &mut Asks,
) -> Result<()> {
    let Some((start, end)) = asks.next() else {
        return Ok(());
    };
    let ranges = rmule_peer::PartRanges::new([(start, end), (0, 0), (0, 0)])
        .with_context(|| format!("range {start}-{end}"))?;
    let _ = conn
        .send(PeerCommand::Requester(RequesterCommand::RequestParts {
            file_hash: file.file_hash,
            file_size: file.size,
            ranges,
        }))
        .await;
    println!(
        "transfer range_requested range={start}-{end} at_unix_ms={}",
        unix_ms()
    );
    Ok(())
}

/// The ranges a run asks for, one at a time, and how much of the one in
/// flight has arrived.
struct Asks {
    left: std::collections::VecDeque<(u64, u64)>,
    current: Option<Current>,
    answered: usize,
    total: usize,
}

/// The range in flight: since when, and its bytes so far.
struct Current {
    range: (u64, u64),
    since: tokio::time::Instant,
    received: u64,
}

impl Asks {
    fn new(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            total: ranges.len(),
            left: ranges.into(),
            current: None,
            answered: 0,
        }
    }

    /// Whether the first range has gone.
    fn started(&self) -> bool {
        self.current.is_some() || self.left.len() < self.total
    }

    /// Take the next range as the one in flight.
    fn next(&mut self) -> Option<(u64, u64)> {
        let range = self.left.pop_front()?;
        self.current = Some(Current {
            range,
            since: tokio::time::Instant::now(),
            received: 0,
        });
        Some(range)
    }

    /// Count a block of `len` bytes at `offset` against the range in
    /// flight, when it falls inside it; the range's bounds once it has
    /// arrived whole.
    fn receive(&mut self, offset: u64, len: u64) -> Option<(u64, u64)> {
        let current = self.current.as_mut()?;
        let (start, end) = current.range;
        if offset < start || offset >= end {
            return None;
        }
        current.received = current.received.saturating_add(len);
        (current.received >= end - start).then(|| {
            self.current = None;
            self.answered += 1;
            (start, end)
        })
    }

    /// Whether every range has arrived whole.
    fn all_answered(&self) -> bool {
        self.answered == self.total
    }

    /// Resolves once the range in flight has waited `wait`; never while
    /// none is, or with no `wait`.
    async fn lapse(&self, wait: Option<Duration>) {
        match (&self.current, wait) {
            (Some(current), Some(wait)) => tokio::time::sleep_until(current.since + wait).await,
            _ => std::future::pending().await,
        }
    }

    /// Give up on the range in flight: its bounds and the bytes it got.
    fn give_up(&mut self) -> Option<(u64, u64, u64)> {
        let current = self.current.take()?;
        Some((current.range.0, current.range.1, current.received))
    }
}

/// The wall clock in Unix milliseconds.
fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

/// A fresh random SUI Challenge (ADR-0041 anti-replay) for one capture run.
fn mint_challenge() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("OS entropy for SUI challenge");
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Asks, parse_range};

    /// A range reads as decimal offsets, end exclusive, and an empty or
    /// backward one is refused before anything is sent.
    #[test]
    fn a_range_is_two_offsets_its_end_past_its_start() {
        assert_eq!(parse_range("9723904-9732096"), Ok((9_723_904, 9_732_096)));
        assert!(parse_range("10-10").is_err());
        assert!(parse_range("12-10").is_err());
        assert!(parse_range("12").is_err());
    }

    /// Blocks count only against the range in flight: a late block of a
    /// range given up on is not taken for the next one's.
    #[tokio::test]
    async fn a_late_block_of_a_given_up_range_counts_for_nothing() {
        let mut asks = Asks::new(vec![(100, 200), (0, 50)]);
        assert_eq!(asks.next(), Some((100, 200)));
        assert_eq!(asks.give_up(), Some((100, 200, 0)));
        assert_eq!(asks.next(), Some((0, 50)));
        assert_eq!(asks.receive(100, 100), None);
        assert_eq!(asks.receive(0, 50), Some((0, 50)));
        assert!(!asks.all_answered(), "the first range never arrived");
    }
}
