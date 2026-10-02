//! Endpoints on the wire and in configuration: the four-octets-then-LE-port
//! encoding of an `Ipv4Endpoint`, and what a `ServerEndpoint` accepts as a host.

use std::net::Ipv4Addr;

use rmule_primitives::{Ipv4Endpoint, ServerEndpoint};

#[test]
fn ipv4_endpoint_encodes_octets_then_le_port() {
    let endpoint = Ipv4Endpoint::new(Ipv4Addr::new(192, 168, 0, 1), 4661);
    assert_eq!(endpoint.encode(), [0xc0, 0xa8, 0x00, 0x01, 0x35, 0x12]);
}

#[test]
fn ipv4_endpoint_round_trips_wire_bytes() {
    let bytes = [0x7f, 0x00, 0x00, 0x01, 0xa1, 0x0f];
    let endpoint = Ipv4Endpoint::decode(&bytes);
    assert_eq!(endpoint.ip, Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(endpoint.port, 4001);
    assert_eq!(endpoint.encode(), bytes);
}

#[test]
fn server_endpoint_lowercases_dns_host_but_preserves_ip_literal() {
    let dns = ServerEndpoint::new("Example.Invalid", 4661).unwrap();
    assert_eq!(dns.host(), "example.invalid");

    let ipv4 = ServerEndpoint::new("192.168.0.1", 4661).unwrap();
    assert_eq!(ipv4.host(), "192.168.0.1");
}

#[test]
fn server_endpoint_rejects_blank_or_padded_host() {
    assert!(ServerEndpoint::new("", 4661).is_err());
    assert!(ServerEndpoint::new(" example.invalid", 4661).is_err());
}

#[test]
fn parse_host_port_splits_ipv4_and_hostname_inputs() {
    let v4 = ServerEndpoint::parse_host_port("192.168.0.1:4661").unwrap();
    assert_eq!(v4.host(), "192.168.0.1");
    assert_eq!(v4.port(), 4661);

    let dns = ServerEndpoint::parse_host_port("Example.Invalid:4661").unwrap();
    assert_eq!(dns.host(), "example.invalid");
    assert_eq!(dns.port(), 4661);
}

#[test]
fn parse_host_port_handles_bracketed_ipv6_via_socketaddr() {
    // `rsplit_once(':')` alone would mangle this (splitting on the last
    // colon of the address); the `SocketAddr::from_str` fast path keeps
    // the host intact.
    let v6 = ServerEndpoint::parse_host_port("[::1]:4661").unwrap();
    assert_eq!(v6.host(), "::1");
    assert_eq!(v6.port(), 4661);
}

#[test]
fn parse_host_port_rejects_empty_host_zero_port_and_missing_port() {
    assert!(ServerEndpoint::parse_host_port(":4661").is_err());
    assert!(ServerEndpoint::parse_host_port("host:0").is_err());
    assert!(ServerEndpoint::parse_host_port("host-no-port").is_err());
}
