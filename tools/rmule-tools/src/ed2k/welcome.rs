//! The `ed2k server welcome` capture: log in to a live server, record both
//! directions of the welcome dialogue to disk, and slice the recorded stream
//! into the per-packet fixtures a promotion needs.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_ed2k::{Ed2kCommand, Ed2kEvent, Opcode};
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, Packet, UserHash};

use crate::capture::{hex_lower, write_new};
use crate::ed2k::inspect::packet_short_name;
use crate::operand::parse_user_hash;

#[derive(Debug, Args)]
pub(crate) struct LiveCaptureArgs {
    /// Server endpoint as `host:port` (e.g. `192.0.2.10:4661` or
    /// `[2001:db8::1]:4661`).
    endpoint: String,
    /// Output directory for capture artifacts
    /// (`s2c.bin` / `c2s.bin` / `meta.toml` / `events.toml`).
    #[arg(long)]
    out: PathBuf,
    /// Client nickname tag value.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// 16-byte user hash as upper-case hex (32 chars). Default is a
    /// fixed stable value so re-running against the same server yields
    /// reproducible login bytes.
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Local TCP port advertised in the login packet.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// CT_VERSION value (eDonkey protocol version constant).
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Connect timeout, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Login-response timeout, seconds.
    #[arg(long, default_value_t = 15)]
    login_timeout: u64,
    /// Maximum seconds to keep the session open after login before
    /// initiating a clean shutdown (so capture artifacts flush). `0`
    /// means "run until the server closes" (legacy behavior).
    #[arg(long, default_value_t = 0)]
    max_seconds: u64,
    /// After login, issue the session's `RequestServerList` command
    /// (`OP_GETSERVERLIST 0x14`) so the capture also holds the server's
    /// `OP_SERVERLIST 0x32` / `OP_SERVERIDENT 0x41` answers.
    #[arg(long, default_value_t = false)]
    request_server_list: bool,
    /// After login, ask the server to relay a callback to this LowID
    /// (`OP_CALLBACKREQUEST 0x1C`). A LowID the server never allocated is the
    /// deterministic way to draw `OP_CALLBACK_FAIL 0x36`; a live one draws the
    /// relay instead, and the target sees `OP_CALLBACKREQUESTED 0x35`.
    ///
    /// **Bench precondition:** the requester must hold a High ID or a server
    /// drops the `0x1C` in silence (no `0x36` either) — check the printed
    /// `login_accepted client_id=`, and make sure something answers this
    /// client's advertised `--tcp-port` so the server's ID check passes.
    #[arg(long)]
    callback_low_id: Option<u32>,
}

#[derive(Debug, Args)]
pub(crate) struct SliceCaptureArgs {
    /// Capture directory containing `s2c.bin`.
    dir: PathBuf,
}

pub(crate) async fn welcome_live(args: LiveCaptureArgs) -> Result<()> {
    let server_endpoint = rmule_primitives::ServerEndpoint::parse_host_port(&args.endpoint)
        .with_context(|| format!("parse endpoint {}", args.endpoint))?;
    let user_hash_bytes = parse_user_hash(&args.user_hash)?;
    let identity = ClientIdentity::new(
        UserHash::from_bytes(user_hash_bytes),
        Ed2kText::from_utf8(args.nickname),
        args.tcp_port,
        args.protocol_version,
    );
    let capture_dir = args.out.clone();
    let options = ConnectOptions {
        capture_dir: Some(args.out),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        login_timeout: Duration::from_secs(args.login_timeout),
        obfuscation: None,
        obfuscated_port: None,
        advertised_ipv6: None,
        udp_ports: None,
    };

    let mut conn = Connection::connect_with_options(server_endpoint, identity, options).await?;
    let deadline = (args.max_seconds > 0)
        .then(|| tokio::time::Instant::now() + Duration::from_secs(args.max_seconds));
    let mut server_list_requested = false;
    let mut callback_requested = false;
    loop {
        let event = match deadline {
            Some(deadline) => tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    println!("max_seconds reached, shutting down");
                    break;
                }
                event = conn.next_event() => event,
            },
            None => conn.next_event().await,
        };
        let Some(event) = event else {
            break;
        };
        println!("{event}");
        if args.request_server_list
            && !server_list_requested
            && matches!(event, Ed2kEvent::LoginAccepted { .. })
        {
            server_list_requested = true;
            match conn.send(Ed2kCommand::RequestServerList).await {
                Ok(()) => println!("sent RequestServerList (OP_GETSERVERLIST 0x14)"),
                Err(error) => eprintln!("send RequestServerList: {error}"),
            }
        }
        if let Some(low_id) = args.callback_low_id
            && !callback_requested
            && matches!(event, Ed2kEvent::LoginAccepted { .. })
        {
            callback_requested = true;
            let command = Ed2kCommand::RequestCallback {
                low_id: ClientId::from_u32(low_id),
            };
            match conn.send(command).await {
                Ok(()) => {
                    println!("sent RequestCallback (OP_CALLBACKREQUEST 0x1C) low_id={low_id}")
                }
                Err(error) => eprintln!("send RequestCallback: {error}"),
            }
        }
        // The only answer a requester ever receives is the fail: on success the
        // server relays `OP_CALLBACKREQUESTED 0x35` to the *target*, and we see
        // nothing until that target dials us back. Silence is therefore the
        // success shape — and also what a Low-ID requester gets, which is why
        // the flag's docs make High ID a precondition.
        if callback_requested && matches!(event, Ed2kEvent::CallbackFailed) {
            println!("callback_reply: opcode=0x36 OP_CALLBACK_FAIL");
        }
        if matches!(event, Ed2kEvent::Disconnected { .. }) {
            break;
        }
    }
    if let Err(error) = conn.shutdown().await {
        eprintln!("shutdown: {error}");
    }
    if callback_requested {
        report_callback_reply(&capture_dir)?;
    }
    Ok(())
}

/// Lift the server's answer to our `0x1C` out of the finished capture's
/// `s2c.bin` and stand it up as its own fixture file: the last
/// `OP_CALLBACK_FAIL 0x36` frame, printed as hex and written beside the
/// capture (`callback_reply_0x36.bin`). Last wins — a later answer supersedes
/// an earlier one within the session. The bytes come from the counterparty's
/// own stream; the runner never re-encodes the answer it reports (ADR-0045
/// point 2). No such frame means the server stayed silent, which is itself the
/// observation to record: either the relay succeeded (the `0x35` went to the
/// *target*, never to us) or the `0x1C` was dropped unanswered.
fn report_callback_reply(dir: &Path) -> Result<()> {
    let s2c_path = dir.join("s2c.bin");
    let bytes = std::fs::read(&s2c_path).with_context(|| format!("read {}", s2c_path.display()))?;
    let mut answer: Option<Vec<u8>> = None;
    let mut offset = 0usize;
    while offset < bytes.len() {
        // An undecodable tail (a frame the server was still writing at
        // shutdown) ends the walk; `welcome slice` keeps it as raw evidence.
        let Ok((packet, consumed)) = Packet::decode(&bytes[offset..]) else {
            break;
        };
        if packet.opcode() == Opcode::CallbackFail.as_u8() {
            answer = Some(bytes[offset..offset + consumed].to_vec());
        }
        offset += consumed;
    }
    let Some(frame) = answer else {
        println!("callback_reply: none (no OP_CALLBACK_FAIL 0x36 in the capture)");
        return Ok(());
    };
    println!("callback_reply: opcode=0x36 OP_CALLBACK_FAIL");
    println!("callback_reply_bytes: {}", hex_lower(&frame));
    write_new(&dir.join(CALLBACK_REPLY_FIXTURE), &frame)?;
    println!(
        "callback_reply_file: {CALLBACK_REPLY_FIXTURE} ({} bytes)",
        frame.len()
    );
    Ok(())
}

/// Fixture file the requester's `OP_CALLBACK_FAIL 0x36` frame is written to.
const CALLBACK_REPLY_FIXTURE: &str = "callback_reply_0x36.bin";

pub(crate) fn welcome_slice(args: SliceCaptureArgs) -> Result<()> {
    slice_capture(&args.dir)
}

pub(crate) fn slice_capture(dir: &Path) -> Result<()> {
    let s2c_path = dir.join("s2c.bin");
    let bytes = std::fs::read(&s2c_path).with_context(|| format!("read {}", s2c_path.display()))?;
    let mut offset = 0usize;
    let mut index = 0u32;
    while offset < bytes.len() {
        match Packet::decode(&bytes[offset..]) {
            Ok((packet, consumed)) => {
                let frame_bytes = bytes[offset..offset + consumed].to_vec();
                let name = packet_short_name(&packet);
                let filename = format!("{:02}_{}.bin", index + 1, name);
                let out = dir.join(&filename);
                std::fs::write(&out, &frame_bytes)
                    .with_context(|| format!("write {}", out.display()))?;
                println!("{filename}");
                offset += consumed;
                index += 1;
            }
            Err(err) => {
                // Only genuinely unsupported protocol bytes reach this branch
                // (e.g. a future Kad frame surfacing in an eD2k capture):
                // packed `0xD4` server frames are decoded and inflated by
                // `ServerPacket::decode`. Preserve the tail as raw evidence
                // rather than failing the whole slice.
                let tail_path = dir.join(format!("{:02}_undecoded_tail.bin", index + 1));
                std::fs::write(&tail_path, &bytes[offset..])
                    .with_context(|| format!("write {}", tail_path.display()))?;
                eprintln!(
                    "slice stopped at offset {offset}: {err}; remaining {} byte(s) saved to {}",
                    bytes.len() - offset,
                    tail_path.file_name().unwrap().to_string_lossy()
                );
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_ed2k::{CallbackFailed, IdChange};

    /// The `0x36` fixture must be the server's own frame, sliced out of a
    /// multi-frame `s2c.bin` at the right boundary — a stream walk, never a
    /// re-encode (ADR-0045 point 2). A real capture always opens with other
    /// traffic, so taking the first frame or mis-summing the walk both yield a
    /// wrong fixture that would only surface at promotion time, after the
    /// bench sitting is over.
    #[test]
    fn the_callback_fixture_is_the_0x36_frame_sliced_out_of_the_capture_stream() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id_change = IdChange {
            client_id: ClientId::from_u32(0x0100_007F),
            tcp_flags: None,
            standard_tcp_port: None,
            public_ip: None,
            obfuscation_tcp_port: None,
            trailing: Vec::new(),
        }
        .encode_packet()
        .encode();
        let fail = CallbackFailed.encode_packet().encode();
        let mut s2c = id_change;
        s2c.extend_from_slice(&fail);
        std::fs::write(dir.path().join("s2c.bin"), &s2c).expect("write s2c.bin");

        report_callback_reply(dir.path()).expect("walk the capture");

        assert_eq!(
            std::fs::read(dir.path().join(CALLBACK_REPLY_FIXTURE)).expect("fixture written"),
            fail
        );
    }
}
