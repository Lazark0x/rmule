# Wire IPv4 endpoints are a type of their own, apart from host-or-IP server endpoints

## Context

The eD2k wire carries server and peer endpoints as raw addresses plus ports, never as
DNS names: an `OP_SERVERLIST` entry is six bytes of IPv4 address and port. A server
endpoint from an `ed2k://|server|...|/` link or a server list can instead name a DNS
host. Holding both shapes in one host-string type forces a wire decoder to stringify
addresses, and lets an encoder fail at run time on a DNS host, even though the wire
invariant is total.

A source-lookup reply is a third shape. Its records carry a client ID and a TCP port,
and the client ID is an IPv4 address only for a High ID; a Low ID is an opaque number
that a callback must broker.

## Decision

`rmule-primitives` keeps three distinct types:

- **`Ipv4Endpoint { ip: Ipv4Addr, port: u16 }`** (`endpoint.rs`) is a decoded wire
  field: always a literal address, always round-trips. Wire payloads such as
  `OP_SERVERLIST` entries use it.
- **`ServerEndpoint`** (`identity.rs`) keeps the host-or-IP shape for links, server
  lists and configuration. Host names are lower-cased; IP literals are kept verbatim.
- **`PeerSource`** (`source.rs`) models a source record: `HighId(Ipv4Endpoint)`,
  `LowId { id, port }`, or `Ipv6(Ipv6Endpoint)` behind the IPv6 sentinel id
  (ADR-0085). Source-lookup replies decode to `PeerSource`, never straight to an
  `Ipv4Endpoint`, so LowID callback semantics survive decoding.

DNS resolution is an explicit step owned by whoever dials, in the runtime crate
`rmule-net`; it is never an implicit string parse inside an encoder.

## Consequences

- The wire invariant is expressed in the type system, and a whole class of run-time
  encode failures cannot occur.
- Moving from a configured server to a dialable address is a visible resolution step
  with its own errors.
- Whether a source is dialable follows from its `PeerSource` variant, never from a
  separate flag.
