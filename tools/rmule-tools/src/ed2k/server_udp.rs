//! The server's UDP face: the `0x96`/`0x97` status-ping exchange in both its
//! plain and obfuscated spellings, the port offsets the listener is found on,
//! and the reply classification the probe and the capture command both report.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use rmule_ed2k::{GlobServStatReq, GlobServStatRes, crypt_ping_challenge, crypt_ping_padding_len};
use rmule_primitives::{ServerCryptDirection, decrypt_datagram_server};

/// eD2k server UDP port offsets from the TCP port (mirrors rmule-core
/// `adapters.rs`): the plain `0x96` status ping rides TCP+4, the obfuscated
/// crypt-ping rides TCP+12. The probe tries TCP+4 then the same-as-TCP port
/// (some servers — e.g. Lugdunum with `ports=N` — bind their UDP listener on
/// the TCP port itself), so a valid `0x97` is found wherever the server answers.
pub(super) const SERVER_UDP_PLAIN_OFFSET: u16 = 4;
pub(super) const SERVER_UDP_CRYPT_OFFSET: u16 = 12;

/// What a status ping (plain `0x96` or crypt-ping) reply resolved to.
pub(super) enum StatusReply {
    /// No datagram arrived within the timeout.
    NoReply,
    /// A datagram arrived but was not a challenge-matching `0x97` (wrong
    /// opcode, malformed, undecryptable, or an anti-spoof challenge mismatch).
    NotStatus(String),
    /// A valid `0x97` whose challenge echoed our ping.
    Ok(GlobServStatRes),
}

/// One status-ping leg's result: how the reply classified, plus the bytes
/// `--out` promotes to a fixture. Decoding is lossy (a `0x97` projects to
/// capability fields), so the datagrams are carried alongside rather than
/// re-derived from the decode.
pub(super) struct PingOutcome {
    pub(super) reply: StatusReply,
    /// The datagram exactly as it came off the wire — ciphertext on the crypt
    /// leg. `None` only when nothing arrived.
    pub(super) raw: Option<Vec<u8>>,
    /// The crypt leg's decrypted payload. `None` on the plain leg, and on a
    /// crypt reply that arrived in the clear — there `raw` already is the
    /// plaintext.
    pub(super) plain: Option<Vec<u8>>,
}

impl PingOutcome {
    /// The ping drew no datagram within the timeout.
    const fn silent() -> Self {
        Self {
            reply: StatusReply::NoReply,
            raw: None,
            plain: None,
        }
    }
}

pub(super) async fn plain_status_ping(
    ip: Ipv4Addr,
    port: u16,
    dur: Duration,
) -> Result<PingOutcome> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("bind status-ping socket")?;
    let request = GlobServStatReq::mint(os_rand16());
    let challenge = request.challenge();
    let datagram = request.encode_packet().encode_udp();
    socket
        .send_to(&datagram, (ip, port))
        .await
        .context("send status ping")?;
    let Some(reply) = recv_datagram(&socket, dur).await? else {
        return Ok(PingOutcome::silent());
    };
    Ok(PingOutcome {
        reply: decode_status_reply(&reply, challenge),
        raw: Some(reply),
        plain: None,
    })
}

/// Send a raw crypt-ping (`[challenge u32 LE][6..=14 padding]`, unencrypted)
/// and decrypt the `0x97` reply under the challenge (ADR-0046 layout).
pub(super) async fn crypt_status_ping(
    ip: Ipv4Addr,
    port: u16,
    dur: Duration,
) -> Result<PingOutcome> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("bind crypt-ping socket")?;
    let (challenge, datagram) = mint_crypt_ping();
    socket
        .send_to(&datagram, (ip, port))
        .await
        .context("send crypt-ping")?;
    let Some(reply) = recv_datagram(&socket, dur).await? else {
        return Ok(PingOutcome::silent());
    };
    // The reply is RC4-encrypted with the challenge as the base key.
    match decrypt_datagram_server(&reply, challenge, ServerCryptDirection::FromServer) {
        Some(plaintext) => Ok(PingOutcome {
            reply: decode_status_reply(&plaintext, challenge),
            raw: Some(reply),
            plain: Some(plaintext),
        }),
        // A non-crypt server may answer the raw ping in the clear (or ignore it):
        // try a plaintext decode before declaring it undecryptable.
        None => {
            let decoded = match GlobServStatRes::decode_udp(&reply) {
                Ok(res) if res.challenge() == challenge => StatusReply::Ok(res),
                _ => StatusReply::NotStatus("reply did not decrypt under challenge".to_owned()),
            };
            Ok(PingOutcome {
                reply: decoded,
                raw: Some(reply),
                plain: None,
            })
        }
    }
}

/// Decode a `0x97` datagram and gate it on the anti-spoof challenge echo.
fn decode_status_reply(datagram: &[u8], challenge: u32) -> StatusReply {
    match GlobServStatRes::decode_udp(datagram) {
        Ok(res) if res.challenge() == challenge => StatusReply::Ok(res),
        Ok(res) => StatusReply::NotStatus(format!(
            "challenge mismatch (got 0x{:08X}, sent 0x{challenge:08X})",
            res.challenge()
        )),
        Err(error) => StatusReply::NotStatus(format!("not a 0x97 ({error})")),
    }
}

/// Receive one datagram within `dur`, or `None` on timeout.
pub(super) async fn recv_datagram(
    socket: &tokio::net::UdpSocket,
    dur: Duration,
) -> Result<Option<Vec<u8>>> {
    let mut buffer = vec![0u8; 4096];
    match tokio::time::timeout(dur, socket.recv_from(&mut buffer)).await {
        Ok(Ok((len, _from))) => {
            buffer.truncate(len);
            Ok(Some(buffer))
        }
        Ok(Err(error)) => Err(error).context("receive status reply"),
        Err(_timeout) => Ok(None),
    }
}

/// Mint one raw crypt-ping: a non-zero 32-bit challenge (the reply's echo gate
/// and RC4 base key) then the padding [`crypt_ping_padding_len`] admits —
/// byte-for-byte what rmule-core's `os_crypt_ping_nonce` emits in production,
/// which is the point: the probe solicits the reply that ratifies *that*
/// emitter, so the two must not drift.
fn mint_crypt_ping() -> (u32, Vec<u8>) {
    let mut seed = [0u8; 5];
    getrandom::fill(&mut seed).expect("OS entropy for crypt-ping");
    let challenge = crypt_ping_challenge(u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]));
    let mut padding = vec![0u8; crypt_ping_padding_len(seed[4])];
    getrandom::fill(&mut padding).expect("OS entropy for crypt-ping padding");
    let mut datagram = challenge.to_le_bytes().to_vec();
    datagram.extend_from_slice(&padding);
    (challenge, datagram)
}

/// OS-entropy low half for a plain status-ping challenge.
pub(super) fn os_rand16() -> u16 {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).expect("OS entropy for status-ping challenge");
    u16::from_le_bytes(bytes)
}

/// Resolve `host:port` to the first IPv4 address (for the raw UDP offset sends).
pub(super) async fn resolve_server_ipv4(endpoint: &str) -> Result<Ipv4Addr> {
    tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("resolve {endpoint}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
        .with_context(|| format!("no IPv4 address for {endpoint}"))
}
