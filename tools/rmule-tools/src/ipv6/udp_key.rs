//! `rmule-tools ipv6 udp-key` — put one **obfuscated** `OP_REASKFILEPING`
//! (`0x90`) on a counterparty's client-UDP socket over the family its endpoint
//! names, and record whether the answer comes back keyed the same way.
//!
//! The whole question is the key *layout*, and the layout is chosen by the
//! address width on each side (ADR-0087): outbound, the receiver's user hash
//! plus **our own** address in the family the datagram leaves by; inbound,
//! **our** user hash plus the datagram's source address. So the flow proves the
//! 35-byte form both ways with one exchange — the counterparty could not have
//! parsed our datagram with any other derivation, and we could not have read
//! its reply with any other.
//!
//! The stimulus is the unshared-hash branch, which every implementation answers
//! unconditionally with an empty-body `OP_FILENOTFOUND` (`0x92`) before it looks
//! the sender up. A plaintext control datagram rides in the same run so a silent
//! obfuscated leg can be told apart from a socket that answers nothing at all.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, DatagramNonce, DatagramSenderAddress, FileHash, UserHash,
    decrypt_datagram_client, ed2k_key_material, encrypt_datagram_client,
};

use crate::capture::{hex_lower, write_new};
use crate::driver_row::Row;
use crate::operand::{parse_hex16, parse_user_hash};

/// The peer-UDP protocol byte every plaintext client datagram opens with.
const PEER_UDP_PROTOCOL: u8 = 0xC5;

#[derive(Debug, Args)]
pub(crate) struct Ipv6UdpKeyArgs {
    /// The counterparty's client-UDP socket, `a.b.c.d:port` or `[addr]:port`.
    #[arg(long)]
    peer: String,
    /// The counterparty's 16-byte user hash as hex — the *receiver's* hash,
    /// which the outbound key is derived from. A flow reads it off that body's
    /// own hello rather than configuring it.
    #[arg(long)]
    peer_user_hash: String,
    /// Our own user hash; the reply is keyed on it.
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Our own address **as the counterparty will see it** — the sender input
    /// of the outbound key, and what picks the 23- or 35-byte layout.
    #[arg(long)]
    our_address: IpAddr,
    /// A file hash the counterparty does not share: the unconditional `0x92`
    /// branch.
    #[arg(long, default_value = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")]
    missing_hash: String,
    /// Also send one plaintext `0x90` as a control, so an unanswered obfuscated
    /// leg is distinguishable from a socket that answers nothing.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    plaintext_control: bool,
    /// Where the raw datagrams are retained.
    #[arg(long)]
    capture: PathBuf,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
    /// Bind the probe socket to this local port rather than an ephemeral one.
    /// A counterparty attributes an inbound reask to the client it holds by the
    /// `CT_EMULE_UDPPORTS` that client advertised, so the datagram has to leave
    /// from the port the hello named or it arrives from a stranger.
    #[arg(long, default_value_t = 0)]
    bind_port: u16,
    /// Per-reply budget, seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

/// What the exchange measured.
#[derive(Debug)]
struct UdpKeyRow {
    /// The socket addressed.
    peer: String,
    /// `v4` or `v6` — the family the datagrams travelled in.
    family: &'static str,
    /// The address our outbound key mixed in.
    our_address: String,
    /// How many bytes that key was `MD5`'d over: 23 for IPv4, 35 for IPv6.
    outbound_key_material_bytes: usize,
    /// How many bytes the *reply's* key is derived over — the same width, from
    /// the other end's address.
    inbound_key_material_bytes: usize,
    /// The obfuscated datagram's own length on the wire.
    sent_bytes: usize,
    /// Whether anything at all came back to the obfuscated datagram.
    obfuscated_reply_received: bool,
    /// Whether that reply's first byte was a plaintext protocol byte — which
    /// would mean the counterparty answered in the clear.
    obfuscated_reply_was_plaintext: bool,
    /// Whether our own 35-/23-byte derivation recovered the payload.
    obfuscated_reply_decrypted: bool,
    /// The recovered opcode (`0x92` for file-not-found), or `-1`.
    obfuscated_reply_opcode: i16,
    /// The recovered payload, hex.
    obfuscated_reply_payload: String,
    /// The reply exactly as it arrived, hex — the evidence.
    obfuscated_reply_raw: String,
    /// Where that raw datagram was retained.
    obfuscated_reply_file: String,
    /// Whether the plaintext control was sent, and whether it was answered —
    /// the control that tells a silent crypt leg from a silent socket.
    plaintext_control_sent: bool,
    plaintext_control_answered: bool,
    plaintext_control_raw: String,
}

/// Fire the two datagrams and write the row.
///
/// # Errors
/// If an operand will not parse, the socket cannot be bound, or the row cannot
/// be written. A counterparty that stays silent is a row, not an error.
pub(crate) async fn run_udp_key(args: Ipv6UdpKeyArgs) -> Result<()> {
    let peer: SocketAddr = args
        .peer
        .parse()
        .with_context(|| format!("parse peer socket {}", args.peer))?;
    let peer_hash = UserHash::from_bytes(parse_hex16("--peer-user-hash", &args.peer_user_hash)?);
    let our_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let missing = FileHash::from_bytes(parse_hex16("--missing-hash", &args.missing_hash)?);
    std::fs::create_dir_all(&args.capture)
        .with_context(|| format!("create {}", args.capture.display()))?;

    let bind: SocketAddr = if peer.is_ipv6() {
        format!("[::]:{}", args.bind_port).parse()?
    } else {
        format!("0.0.0.0:{}", args.bind_port).parse()?
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    let window = Duration::from_secs(args.timeout);

    let ping = rmule_peer::ReaskFilePing {
        file_hash: missing,
        part_status: None,
        complete_sources: None,
    }
    .encode_udp();

    let sender = DatagramSenderAddress::from_ip(args.our_address);
    let nonce = os_nonce();
    let obfuscated = encrypt_datagram_client(
        &ping,
        &ClientEncryptKey::Ed2k {
            user_hash: &peer_hash,
            sender,
        },
        &nonce,
    );

    let mut row = UdpKeyRow {
        peer: peer.to_string(),
        family: if peer.is_ipv6() { "v6" } else { "v4" },
        our_address: args.our_address.to_string(),
        outbound_key_material_bytes: ed2k_key_material(&peer_hash, sender, nonce.random_key).len(),
        inbound_key_material_bytes: ed2k_key_material(
            &our_hash,
            DatagramSenderAddress::from_ip(peer.ip()),
            0,
        )
        .len(),
        sent_bytes: obfuscated.len(),
        obfuscated_reply_received: false,
        obfuscated_reply_was_plaintext: false,
        obfuscated_reply_decrypted: false,
        obfuscated_reply_opcode: -1,
        obfuscated_reply_payload: String::new(),
        obfuscated_reply_raw: String::new(),
        obfuscated_reply_file: String::new(),
        plaintext_control_sent: args.plaintext_control,
        plaintext_control_answered: false,
        plaintext_control_raw: String::new(),
    };

    socket
        .send_to(&obfuscated, peer)
        .await
        .context("send the obfuscated OP_REASKFILEPING")?;
    println!(
        "ipv6-udp-key sent obfuscated 0x90 to {peer} ({} bytes, key material {} bytes)",
        obfuscated.len(),
        row.outbound_key_material_bytes
    );

    if let Some(reply) = receive(&socket, peer, window).await? {
        row.obfuscated_reply_received = true;
        row.obfuscated_reply_raw = hex_lower(&reply);
        let path = args.capture.join("obfuscated_reply.bin");
        write_new(&path, &reply)?;
        row.obfuscated_reply_file = path.display().to_string();
        if reply.first() == Some(&PEER_UDP_PROTOCOL) {
            row.obfuscated_reply_was_plaintext = true;
            row.obfuscated_reply_opcode = i16::from(reply.get(1).copied().unwrap_or_default());
        } else if let Some(decrypted) = decrypt_datagram_client(
            &reply,
            &ClientDecryptKeys {
                user_hash: Some(&our_hash),
                sender: DatagramSenderAddress::from_ip(peer.ip()),
                ..Default::default()
            },
        ) {
            row.obfuscated_reply_decrypted = true;
            row.obfuscated_reply_payload = hex_lower(&decrypted.payload);
            row.obfuscated_reply_opcode =
                i16::from(decrypted.payload.get(1).copied().unwrap_or_default());
            let path = args.capture.join("obfuscated_reply_payload.bin");
            write_new(&path, &decrypted.payload)?;
        }
    }

    if args.plaintext_control {
        socket
            .send_to(&ping, peer)
            .await
            .context("send the plaintext control OP_REASKFILEPING")?;
        if let Some(reply) = receive(&socket, peer, window).await? {
            row.plaintext_control_answered = true;
            row.plaintext_control_raw = hex_lower(&reply);
            let path = args.capture.join("plaintext_control_reply.bin");
            write_new(&path, &reply)?;
        }
    }

    println!(
        "ipv6-udp-key family={} decrypted={} opcode={} control_answered={}",
        row.family,
        row.obfuscated_reply_decrypted,
        row.obfuscated_reply_opcode,
        row.plaintext_control_answered
    );
    let mut out = Row::new(
        "rmule-tools ipv6 udp-key — one obfuscated OP_REASKFILEPING and what came\n\
         back (ADR-0087). The key material width IS the measurement; the retained\n\
         reply datagram beside this row is the counterparty's own bytes.",
    );
    out.str("peer", &row.peer)
        .str("family", row.family)
        .str("our_address", &row.our_address)
        .int(
            "outbound_key_material_bytes",
            i64::try_from(row.outbound_key_material_bytes).unwrap_or(-1),
        )
        .int(
            "inbound_key_material_bytes",
            i64::try_from(row.inbound_key_material_bytes).unwrap_or(-1),
        )
        .int("sent_bytes", i64::try_from(row.sent_bytes).unwrap_or(-1))
        .bool("obfuscated_reply_received", row.obfuscated_reply_received)
        .bool(
            "obfuscated_reply_was_plaintext",
            row.obfuscated_reply_was_plaintext,
        )
        .bool("obfuscated_reply_decrypted", row.obfuscated_reply_decrypted)
        .int(
            "obfuscated_reply_opcode",
            i64::from(row.obfuscated_reply_opcode),
        )
        .str("obfuscated_reply_payload", &row.obfuscated_reply_payload)
        .str("obfuscated_reply_raw", &row.obfuscated_reply_raw)
        .str("obfuscated_reply_file", &row.obfuscated_reply_file)
        .bool("plaintext_control_sent", row.plaintext_control_sent)
        .bool("plaintext_control_answered", row.plaintext_control_answered)
        .str("plaintext_control_raw", &row.plaintext_control_raw);
    crate::driver_row::write_row(&args.out, out)
}

/// The first datagram back from `peer` inside `window`, or `None`.
async fn receive(
    socket: &tokio::net::UdpSocket,
    peer: SocketAddr,
    window: Duration,
) -> Result<Option<Vec<u8>>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut buf = [0u8; 4096];
    loop {
        let received = tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            received = socket.recv_from(&mut buf) => received.context("recv a reply")?,
        };
        let (len, from) = received;
        if from.ip() != peer.ip() {
            println!("ipv6-udp-key ignored a datagram from {from}");
            continue;
        }
        return Ok(Some(buf[..len].to_vec()));
    }
}

/// OS-entropy nonce, padding-free — aMule disables UDP padding outright, so a
/// datagram with padding would decode but would not be byte-shaped like one of
/// theirs.
fn os_nonce() -> DatagramNonce {
    let mut raw = [0u8; 3];
    getrandom::fill(&mut raw).expect("OS entropy for the client-UDP crypt nonce");
    DatagramNonce {
        marker_byte: raw[0],
        random_key: u16::from_le_bytes([raw[1], raw[2]]),
        padding: Vec::new(),
    }
}
