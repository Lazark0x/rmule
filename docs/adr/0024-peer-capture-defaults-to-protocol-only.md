# Peer capture defaults to ProtocolOnly

## Context

Capture is a first-class option on every connection (ADR-0022). For handshake
traffic a peer capture is a few hundred bytes per direction, but `OP_SENDINGPART`
carries file content: a 100 MB download would produce a ~100 MB `inbound.bin`.
Full capture by default turns a debugging aid into a disk bomb, and fixture
extraction never wants payload bytes — copyrighted or merely large — in the
repository.

## Decision

The peer `ConnectOptions` in `rmule-net` carries `capture_mode: CaptureMode`, with
`ProtocolOnly` as the default and `Full` as the opt-in.

- Under `ProtocolOnly`, every frame is recorded byte for byte except the data of
  `OP_SENDINGPART` and `OP_SENDINGPART_I64`. Their header, opcode, file hash and
  start/end offsets stay; the data is replaced by `ELISION_MARKER`
  (`RMULE-ELIDED-PART-PAYLOAD`) followed by padding, so replay tooling recognises
  an elided region.
- `meta.toml` records `capture_mode` and the elided byte count per direction
  (`bytes_elided_inbound`, `bytes_elided_outbound`), so replay tools never guess.
- `events.toml` is the same in both modes.
- `Full` keeps payload bytes verbatim. `rmule-tools peer transfer capture --mode
  full` exposes it for one-off byte-faithful validation.

## Consequences

- Captures of real downloads stay small, and fixtures cut from them hold exactly
  what the repository checks in: headers, opcodes, length fields and non-bulk
  payloads.
- Elision needs both whole streams, so the peer capture format buffers them and
  writes the elided result at finalize.
- Elision covers the two uncompressed part opcodes only; compressed part frames are
  recorded as they arrive.
- Another bulk-data surface can add its own elision rule on the same
  `CaptureMode` switch.
