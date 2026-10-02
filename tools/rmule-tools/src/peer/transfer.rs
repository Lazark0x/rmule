//! The `peer transfer capture` command: run a real part transfer against a
//! live peer — hello, file request, slot, part data — and record each leg,
//! optionally following it with a source exchange on the same session.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, Connection as PeerConnection};
use rmule_peer::{PartBitmap, PeerCommand, PeerEvent, PeerHandshakeContext};
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
    /// the file negotiation with `PeerCommand::RequestFile` — the live
    /// download runner's connect-time shape — so a MultiPacket-advertising
    /// aMule receives one `OP_MULTIPACKET_EXT` (`0xA4`) bundle and answers its
    /// composed `OP_MULTIPACKETANSWER` (`0x93`), the forward-direction capture
    /// target. The rest of the flow (probe upgrade → one-part pull) is
    /// unchanged.
    #[arg(long)]
    pub(super) multipacket: bool,
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

    let requested_len = std::cmp::min(file.size, rmule_primitives::ED2K_PART_SIZE);
    let ranges = rmule_peer::PartRanges::new([(0, requested_len), (0, 0), (0, 0)])
        .context("first part range")?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.max_seconds);
    let mut sent_probe = false;
    let mut sent_request = false;
    let mut received: u64 = 0;
    let mut sent_release = false;
    let mut identity_verified = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                println!("max_seconds reached, shutting down");
                break;
            }
            event = conn.next_event() => match event {
                Some(event @ PeerEvent::PeerIdentityVerified { .. }) => {
                    identity_verified = true;
                    println!("{event}");
                }
                Some(event @ PeerEvent::PeerIdentified { .. }) => {
                    println!("{event}");
                    if !sent_probe {
                        if args.multipacket {
                            // The live runner's connect-time shape: the
                            // session folds name + status + SX asks into one
                            // 0xA4/0x92 bundle when the peer advertised
                            // MultiPacket, else the same standalone packets.
                            let _ = conn.send(PeerCommand::RequestFile {
                                file_hash: file.file_hash,
                                file_size: file.size,
                                own_status: PartBitmap::downloader_empty(file.size),
                                want_sources: true,
                                want_aich_root: false,
                            }).await;
                        } else {
                            // Issue the full flow: probe then request.
                            let _ = conn
                                .send(PeerCommand::ProbeFile {
                                    file_hash: file.file_hash,
                                    file_size: file.size,
                                    own_status: PartBitmap::downloader_empty(file.size),
                                })
                                .await;
                        }
                        sent_probe = true;
                    }
                }
                Some(PeerEvent::FileProbed { status, .. }) => {
                    println!("file_probed: {status:?}");
                    if !sent_request {
                        let _ = conn.send(PeerCommand::RequestParts {
                            file_hash: file.file_hash,
                            file_size: file.size,
                            ranges,
                        }).await;
                        sent_request = true;
                    }
                }
                Some(event @ PeerEvent::PartReceived { .. }) => {
                    if let PeerEvent::PartReceived { bytes, .. } = &event {
                        received = received.saturating_add(bytes.len() as u64);
                    }
                    println!("{event}");
                    // The slot is held across block requests (ADR-0025,
                    // amended); as the completion authority, release it once
                    // the whole requested range has arrived, mirroring the
                    // core worker.
                    if !sent_release && received >= requested_len {
                        let _ = conn
                            .send(PeerCommand::ReleaseSlot {
                                file_hash: file.file_hash,
                            })
                            .await;
                        sent_release = true;
                    }
                }
                Some(PeerEvent::SlotReleased { reason, .. }) => {
                    println!("slot_released: {reason:?}");
                    break;
                }
                Some(PeerEvent::Disconnected { reason }) => {
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
            "secure user identification did not complete: no PeerIdentityVerified from the peer"
        );
    }
    Ok(())
}

/// A fresh random SUI Challenge (ADR-0041 anti-replay) for one capture run.
fn mint_challenge() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("OS entropy for SUI challenge");
    u32::from_le_bytes(bytes)
}
