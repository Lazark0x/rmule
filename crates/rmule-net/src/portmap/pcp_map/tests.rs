//! The IPv6 PCP `MAP` codec against two real gateways' bytes, and the
//! transport's source pin on loopback.
//!
//! Vectors are UDP payloads copied verbatim: the bench's miniupnpd 2.3.10
//! (bench run 1790023348, `nat/portmap-ipv6-pinhole/tap-lan.pcap`,
//! run `1790023348`, the `portmap-ipv6-pinhole` PASS ADR-0092 cites) and a
//! FRITZ!Box (emule-qt `tests/tst_PortMapWire.cpp` `kFritzPcpMapV6`, `73fff71`).

use std::time::Duration;

use super::super::udp::LADDER;
use super::*;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

const HOST: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 2, 0, 0, 0, 0, 4);

/// 22:42:41.353200, `[3fff:ed2:2::4]:59161 → [3fff:ed2:2::2]:5351`.
const BENCH_MAP_TCP_4662: &str = "020100000000000c3fff0ed20002000000000000000000042d8d6ac49374337eeacf2d72060000001236123600000000000000000000000000000000";
/// 22:42:41.355847, its answer.
const BENCH_GRANT_TCP_4662: &str = "02810000000000780000808b0000000000000000000000002d8d6ac49374337eeacf2d7206000000123612363fff0ed2000200000000000000000004";
/// FRITZ!Box: 120 s pinhole on TCP 42391.
const FRITZ_GRANT_TCP_42391: &str = "0281000000000078005501a70000000000000000000000008a205cdcf2b28f80daa4706906000000a597a5972a0d334415db320004e6a98b052a8c8d";

fn bench_map() -> MapRequest {
    MapRequest {
        client: HOST,
        nonce: [0x2d8d_6ac4, 0x9374_337e, 0xeacf_2d72],
        protocol: 6,
        internal_port: 4662,
        suggested_external_port: 4662,
        lifetime: 12,
    }
}

#[test]
fn a_map_request_encodes_to_the_bytes_miniupnpd_granted() {
    assert_eq!(bench_map().encode().to_vec(), hex(BENCH_MAP_TCP_4662));
}

#[test]
fn a_captured_grant_decodes_to_its_lease_epoch_and_pinhole() {
    // miniupnpd clamps the 12 s ask to 120 s (ADR-0092 finding 3), and a
    // pinhole's external endpoint is our own address and port.
    assert_eq!(
        bench_map().decode(&hex(BENCH_GRANT_TCP_4662)),
        MapReply::Granted(MapGrant {
            lifetime: 120,
            epoch: 0x808b,
            external_port: 4662,
            external_address: HOST,
        })
    );
    let fritz = MapRequest {
        client: "2a0d:3344:15db:3200:4e6:a98b:52a:8c8d"
            .parse()
            .expect("literal"),
        nonce: [0x8a20_5cdc, 0xf2b2_8f80, 0xdaa4_7069],
        protocol: 6,
        internal_port: 42391,
        suggested_external_port: 42391,
        lifetime: 3600,
    };
    assert_eq!(
        fritz.decode(&hex(FRITZ_GRANT_TCP_42391)),
        MapReply::Granted(MapGrant {
            lifetime: 120,
            epoch: 0x0055_01a7,
            external_port: 42391,
            external_address: fritz.client,
        })
    );
}

#[test]
fn an_answer_to_another_mapping_is_not_ours() {
    // §11.3: the nonce, protocol and internal port identify the mapping. The
    // bench's UDP 4672 request shared a gateway with this one; its grant must
    // not satisfy the TCP 4662 wait.
    let other = "02810000000000780000808b000000000000000000000000c1d89cc03d1dcd1d5f3de7c511000000124012403fff0ed2000200000000000000000004";
    assert_eq!(bench_map().decode(&hex(other)), MapReply::Foreign);
    // A request echoed back (R bit clear) is not an answer either.
    assert_eq!(
        bench_map().decode(&hex(BENCH_MAP_TCP_4662)),
        MapReply::Foreign
    );
}

#[test]
fn a_refusal_carries_its_code_and_hold_off_even_header_only() {
    // The captured grant with its result byte set to ADDRESS_MISMATCH (12)
    // — the answer an unpinned request from a link-local source earns — and
    // the same header alone, which §7.2 allows for a request the server
    // could not parse.
    let mut refused = hex(BENCH_GRANT_TCP_4662);
    refused[3] = 12;
    assert_eq!(
        bench_map().decode(&refused),
        MapReply::Refused {
            code: 12,
            lifetime: 120
        }
    );
    assert_eq!(
        bench_map().decode(&refused[..HEADER_LEN]),
        MapReply::Refused {
            code: 12,
            lifetime: 120
        }
    );
    assert_eq!(
        crate::portmap::MappingRefusal::from_pcp_code(12),
        crate::portmap::MappingRefusal::AddressMismatch
    );
    // A NAT-PMP-only box answers with version 0 (emule-qt's FRITZ!Box
    // capture shows the mirror case: a PCP box naming version 2).
    assert_eq!(
        bench_map().decode(&[0x00, 0x81, 0x00, 0x01]),
        MapReply::UnsupportedVersion(0)
    );
}

/// The transport end to end: the request leaves *from the address it names*
/// — the §8.2 check a real server runs — survives a foreign datagram, and
/// the answer is read. A gateway on `::1` stands in for the router.
#[tokio::test]
async fn the_request_leaves_from_the_address_its_header_names() {
    // `::1` is the precondition, not the subject: a host with no IPv6 stack
    // (`EAFNOSUPPORT`) has no gateway to stand in for, so it skips, as the
    // family tests do, rather than failing.
    let server = match UdpSocket::bind("[::1]:0").await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("skipped: this host cannot bind [::1] ({error})");
            return;
        }
    };
    let SocketAddr::V6(server_address) = server.local_addr().expect("addr") else {
        unreachable!("bound v6");
    };
    let request = MapRequest {
        client: Ipv6Addr::LOCALHOST,
        ..bench_map()
    };
    let gateway = tokio::spawn(async move {
        let mut buffer = [0_u8; MAX_DATAGRAM];
        let (length, from) = server.recv_from(&mut buffer).await.expect("request");
        let header_client = Ipv6Addr::from(<[u8; 16]>::try_from(&buffer[8..24]).expect("16"));
        let mut answer = hex(BENCH_GRANT_TCP_4662);
        answer[44..60].copy_from_slice(&header_client.octets());
        if from.ip() != IpAddr::V6(header_client) {
            answer[3] = 12;
        }
        let foreign = hex(
            "02810000000000780000808b000000000000000000000000c1d89cc03d1dcd1d5f3de7c511000000124012403fff0ed2000200000000000000000004",
        );
        server.send_to(&foreign, from).await.expect("foreign");
        server.send_to(&answer, from).await.expect("answer");
        length
    });
    let reply = exchange(server_address, &request, LADDER)
        .await
        .expect("answered");
    assert_eq!(gateway.await.expect("gateway"), MAP_LEN);
    assert_eq!(
        reply,
        MapReply::Granted(MapGrant {
            lifetime: 120,
            epoch: 0x808b,
            external_port: 4662,
            external_address: Ipv6Addr::LOCALHOST,
        })
    );
}

#[tokio::test]
async fn a_client_address_this_host_does_not_hold_fails_at_the_bind() {
    // The pin is the bind: an address that is not ours must not quietly
    // leave from another source.
    let request = MapRequest {
        client: "2001:db8::dead".parse().expect("literal"),
        ..bench_map()
    };
    let server = SocketAddrV6::new(Ipv6Addr::LOCALHOST, PCP_SERVER_PORT, 0, 0);
    assert!(matches!(
        exchange(server, &request, LADDER).await,
        Err(MappingError::Transport { .. })
    ));
}

/// The pinned exchange runs the backend's one `LADDER`, send for send: the
/// schedule the hand-rolled loop had (250 ms doubling to a 4 s cap, four
/// sends), and whatever a retune makes it.
#[test]
fn the_pinned_exchange_waits_on_the_shared_ladder() {
    let ms = Duration::from_millis;
    assert_eq!(
        ladder_waits(LADDER).collect::<Vec<_>>(),
        vec![ms(250), ms(500), ms(1000), ms(2000)]
    );
    let retuned = TimeoutConfig {
        initial_timeout: ms(20),
        max_retries: 2,
        max_retry_timeout: Some(ms(30)),
    };
    assert_eq!(
        ladder_waits(retuned).collect::<Vec<_>>(),
        vec![ms(20), ms(30), ms(30)]
    );
}
