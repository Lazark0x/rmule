//! The `ed2k server crypt-pong` command: learn a server's UDP key from its plain
//! `0x97` advert, seal a `0x96` under that key to the obfuscation port it
//! advertised, and write both answers.
//!
//! The crypt ping is keyed on our own challenge; this is the other keying, the
//! one every later server datagram rides (ADR-0046). Only the server's reply
//! bytes are written, so they can be promoted to a fixture (ADR-0045).

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmule_ed2k::{GlobServStatReq, GlobServStatRes};
use rmule_primitives::{
    DatagramNonce, ServerCryptDirection, ServerEndpoint, decrypt_datagram_server,
    encrypt_datagram_server,
};

use crate::capture::write_new;
use crate::ed2k::server_udp::{
    SERVER_UDP_PLAIN_OFFSET, os_rand16, recv_datagram, resolve_server_ipv4,
};

/// The plain advert, as the server sent it.
pub(crate) const PLAIN_REPLY: &str = "status_res_0x97_plain.bin";
/// The sealed answer, as the server sent it.
pub(crate) const SEALED_REPLY: &str = "status_res_0x97_crypt.bin";

/// Run the exchange against `args.endpoint` and write what came back.
///
/// # Errors
/// If the endpoint will not resolve, a socket fails, or a reply cannot be
/// written. A server that stays silent, or whose advert names no key, is
/// reported on stdout and ends the run with an error: nothing was captured.
pub(crate) async fn server_crypt_pong(args: crate::cli::ServerCryptPongArgs) -> Result<()> {
    let endpoint = ServerEndpoint::parse_host_port(&args.endpoint)
        .with_context(|| format!("parse endpoint {}", args.endpoint))?;
    let ip = resolve_server_ipv4(&args.endpoint).await?;
    let plain_port = endpoint
        .port()
        .checked_add(SERVER_UDP_PLAIN_OFFSET)
        .context("server UDP port (TCP+4) overflows")?;
    let timeout = Duration::from_secs(args.timeout);
    std::fs::create_dir_all(&args.out).with_context(|| format!("create {}", args.out.display()))?;
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("bind the status socket")?;

    let ping = GlobServStatReq::mint(os_rand16());
    socket
        .send_to(&ping.encode_packet().encode_udp(), (ip, plain_port))
        .await
        .context("send the plain 0x96")?;
    let Some(advert) = recv_datagram(&socket, timeout).await? else {
        bail!("no answer to the plain 0x96");
    };
    write_new(&args.out.join(PLAIN_REPLY), &advert)?;
    let advert = GlobServStatRes::decode_udp(&advert).context("decode the plain 0x97")?;
    let (Some(key), Some(sealed_port)) = (advert.server_udp_key(), advert.obfuscation_udp_port())
    else {
        bail!("the plain 0x97 names no UDP key and obfuscation port");
    };
    println!("crypt-pong advert key={key:#010x} obfuscation_udp_port={sealed_port}");

    let ping = GlobServStatReq::mint(os_rand16());
    let sealed = encrypt_datagram_server(
        &ping.encode_packet().encode_udp(),
        key,
        ServerCryptDirection::ToServer,
        &DatagramNonce {
            marker_byte: u8::try_from(os_rand16() & 0xFF).unwrap_or(0x5A),
            random_key: os_rand16(),
            padding: Vec::new(),
        },
    );
    socket
        .send_to(&sealed, (ip, sealed_port))
        .await
        .context("send the sealed 0x96")?;
    let Some(pong) = recv_datagram(&socket, timeout).await? else {
        bail!("no answer to the sealed 0x96 on port {sealed_port}");
    };
    write_new(&args.out.join(SEALED_REPLY), &pong)?;
    let opened = decrypt_datagram_server(&pong, key, ServerCryptDirection::FromServer)
        .context("the answer does not open under the advertised key")?;
    let status = GlobServStatRes::decode_udp(&opened).context("decode the opened 0x97")?;
    println!(
        "crypt-pong answered=true challenge_ok={}",
        status.challenge() == ping.challenge()
    );
    Ok(())
}
