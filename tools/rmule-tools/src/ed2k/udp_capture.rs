//! The `ed2k server udp-capture` command: put one hand-built request on a live
//! server's UDP port and write whatever datagram comes back, so a reply opcode
//! with no fixture yet can be promoted from a genuine counterparty.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use rmule_ed2k::{
    GlobSearchReq, GlobSearchVariant, GlobServStatReq, GlobServStatRes, SearchRequest,
    ServerDescReq,
};
use rmule_primitives::{Ed2kText, KeywordQuery, ServerEndpoint};

use crate::capture::write_new;
use crate::ed2k::server_udp::{
    SERVER_UDP_PLAIN_OFFSET, os_rand16, recv_datagram, resolve_server_ipv4,
};

/// Send a plain `OP_GLOBSERVSTATREQ` (`0x96`) and await the `0x97` reply.
/// Drive the server-UDP status → description → global-search chain against a
/// live server and write each raw counterparty reply to `out`:
/// `status_res_0x97.bin`, `desc_res_0xA3.bin`, and `search_res_0x99_<n>.bin`.
/// Only the server's own reply bytes are written — the evidence (ADR-0045).
pub(crate) async fn server_udp_capture(args: crate::cli::ServerUdpCaptureArgs) -> Result<()> {
    let endpoint = ServerEndpoint::parse_host_port(&args.endpoint)
        .with_context(|| format!("parse endpoint {}", args.endpoint))?;
    let ip = resolve_server_ipv4(&args.endpoint).await?;
    let udp_port = endpoint
        .port()
        .checked_add(SERVER_UDP_PLAIN_OFFSET)
        .context("server UDP port (TCP+4) overflows")?;
    let dur = Duration::from_secs(args.timeout);
    std::fs::create_dir_all(&args.out).with_context(|| format!("create {}", args.out.display()))?;
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("bind capture socket")?;

    // 1. Status ping (0x96 → 0x97): proves the server answers UDP and gates the
    //    challenge echo. Its reply is the leg-A control alongside the goldens.
    let status = GlobServStatReq::mint(os_rand16());
    let status_challenge = status.challenge();
    socket
        .send_to(&status.encode_packet().encode_udp(), (ip, udp_port))
        .await
        .context("send 0x96")?;
    match recv_datagram(&socket, dur).await? {
        Some(reply) => {
            write_new(&args.out.join("status_res_0x97.bin"), &reply)?;
            match GlobServStatRes::decode_udp(&reply) {
                Ok(res) => println!(
                    "status_0x97 answered=true challenge_ok={}",
                    res.challenge() == status_challenge
                ),
                Err(e) => println!("status_0x97 undecodable: {e}"),
            }
        }
        None => println!("status_0x97 answered=false (no reply)"),
    }

    // 2. Description request (0xA2 → 0xA3): the graceful desc reply (name /
    //    description / version), challenge high-word pinned to INV_SERV_DESC_LEN.
    let desc = ServerDescReq::mint(os_rand16());
    socket
        .send_to(&desc.encode_packet().encode_udp(), (ip, udp_port))
        .await
        .context("send 0xA2")?;
    match recv_datagram(&socket, dur).await? {
        Some(reply) => {
            write_new(&args.out.join("desc_res_0xA3.bin"), &reply)?;
            println!("desc_0xA3 answered=true len={}", reply.len());
        }
        None => println!("desc_0xA3 answered=false (no reply)"),
    }

    // 3. Global search (0x98 → 0x99): the multi-result packing golden. Baseline
    //    variant (no UDP-flags gate needed for the capture). Drain every 0x99
    //    the server sends within the window — a packed answer may span datagrams.
    let query = KeywordQuery::new(Ed2kText::from_utf8(&args.query))
        .with_context(|| format!("build query {:?}", args.query))?;
    let search = GlobSearchReq::new(SearchRequest::from_query(query));
    socket
        .send_to(
            &search
                .encode_packet(GlobSearchVariant::Baseline)
                .encode_udp(),
            (ip, udp_port),
        )
        .await
        .context("send 0x98")?;
    let mut count = 0;
    while let Some(reply) = recv_datagram(&socket, dur).await? {
        write_new(
            &args.out.join(format!("search_res_0x99_{count}.bin")),
            &reply,
        )?;
        println!(
            "search_0x99[{count}] len={} first_op=0x{:02X}",
            reply.len(),
            reply.get(1).copied().unwrap_or(0)
        );
        count += 1;
        if count >= 8 {
            break;
        }
    }
    println!("search_0x99 datagrams={count}");
    Ok(())
}
