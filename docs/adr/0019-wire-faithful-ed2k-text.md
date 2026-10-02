# eD2k text is kept as its original bytes in an `Ed2kText` primitive

## Context

eD2k packets and tags carry strings that, in the wild, are often not valid UTF-8:
legacy MOTD banners, Windows-1252 server descriptions, mojibake file names in search
results. Modelling them as Rust `String` forces a decoder either to reject the packet
on invalid UTF-8, disconnecting from servers aMule talks to and breaking ADR-0003, or
to decode lossily with U+FFFD replacement, destroying the original bytes, the
byte-exact round trip, and any later codepage recovery. The wire is bytes, not text.

## Decision

`Ed2kText` (`crates/rmule-primitives/src/text.rs`) owns the original bytes losslessly.
Its constructors are asymmetric by direction: `Ed2kText::from_utf8` for text rmule
authors, which is UTF-8 by construction, and `Ed2kText::from_bytes` for text a
counterparty sent, with no validation and no substitution. Its accessors are
`as_bytes()` for the wire round trip, `try_as_str()` for callers that need strict
UTF-8, and `to_display_string()` plus a lossy `Display` impl for rendering only.

Every eD2k text value that crosses the wire is an `Ed2kText`: `TagValue::String`,
server message text, the `ServerIdentity` name and description, and file names decoded
from eD2k links.

## Consequences

- Byte-level fixtures round-trip exactly, whatever encoding the counterparty used.
- A caller that needs strict UTF-8 opts in explicitly at the projection boundary and
  handles the error.
- Display text is never written back to the wire, because it is not the original
  bytes.
- Per-server codepage hints can be added later without touching the decoders.
