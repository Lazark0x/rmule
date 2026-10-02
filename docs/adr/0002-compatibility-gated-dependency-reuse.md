# Reuse general crates freely; accept protocol-specific crates only on compatibility evidence

## Context

The Rust ecosystem covers most of the general infrastructure rmule needs: async
runtime, buffers, tracing, serialization, storage, hashing, checksums, compression
and crypto. It also offers crates for protocols that look close to eMule's, such as
libp2p Kademlia, that differ from eMule Kad on the wire. A crate that implements a
related but different protocol breaks interoperability with aMule and eMule in ways
that are easy to miss until a live peer rejects us.

## Decision

rmule reuses existing crates for general infrastructure and generic primitives in
preference to writing its own. A crate that implements eMule-family protocol
behaviour (Kad, peer-to-peer, file-sharing, or an eMule hash) is accepted only once
tests or fixtures show that its behaviour matches eMule-compatible clients, and it is
wrapped behind rmule's own types (ADR-0012 is the worked case for the `ed2k` hash
crate).

## Consequences

- Choosing a dependency includes a compatibility note, not just API fit.
- Similar protocols are never assumed compatible; libp2p Kademlia is not eMule Kad.
- Protocol fixtures and conformance tests sit close to the crates that rely on them.

## Considered options

- **Adapt any close Rust crate, even one for a related but different protocol.**
  Rejected: it trades interoperability for speed and hides the mismatch.
- **Implement all eMule-specific behaviour in-house and reuse only generic
  infrastructure.** Rejected: it rewrites well-tested code, such as MD4 hashing,
  when a fixture can prove the existing crate correct.
