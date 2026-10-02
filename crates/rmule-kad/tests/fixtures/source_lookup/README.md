# Kad Source Lookup Fixtures

These fixtures support the Kad dependency spike only. They are not a complete Kad corpus.

## Promotion Rules

- Handwritten fixtures are allowed only after packet layout is cited in `docs/reference/notes/kad-packet-framing.md` and `docs/reference/notes/kad-source-lookup.md`.
- Captured fixtures must record the capture command, local Kad identity, bootstrap node, target file identity, and whether UDP obfuscation/encryption wrapped the inner Kad bytes.
- GPL-derived byte sequences are forbidden unless they are actual runtime captures or independent handwritten examples based on documented packet layout.
- Each binary fixture must have adjacent metadata describing expected decoded request/result facts.
- Fixtures must distinguish direct-connectable High ID sources from Low ID, firewalled, buddy, and callback-mediated rows.
- Unsupported result rows are preserved as expected diagnostics and must not silently become `PeerSource`.

## First Fixture Target

The first accepted transcript should include:

- one plain `KADEMLIA2_SEARCH_SOURCE_REQ` (`0xE4`, `0x34`);
- one plain `KADEMLIA2_SEARCH_RES` (`0xE4`, `0x3B`);
- one direct-connectable High ID row;
- one unsupported row if available, to prove diagnostics.

If packet evidence is incomplete, create `minimal.toml` with `status = "blocked"` and list the exact missing evidence instead of inventing bytes.

## Promoted Captured Fixtures

Captured fixtures live under `captured/` and are **promoted manually** from a
retained interop run — never auto-generated. The full pcap stays in
`.scratch/interop-runs/` and is not committed; only the minimal datagrams and
metadata are checked in:

```text
captured/private-amule-kad-source-lookup-YYYYMMDD/
  request_0x34.bin
  result_0x3b_high_id.bin
  metadata.toml
  routing_request_0x21_*.bin        # Phase 2 only, if promoted
  routing_result_0x29_*.bin         # Phase 2 only, if promoted
```

`metadata.toml` must separate protocol facts from provenance facts and at
minimum set `provenance = "captured"`, `public_kad_used = false`,
`request.protocol = "0xE4"`, `request.opcode = "0x34"`, `result.protocol =
"0xE4"`, `result.opcode = "0x3B"`, list `[[nodes]]` including the `requester`
and `publisher` roles, and record an observed `kad_id` for the promoted
endpoints. `captured_source_lookup_fixture.rs` enforces these on every promoted
directory.

No captured fixture is promoted yet. Reliable private Kad bootstrap is still an
open problem (see `docs/reference/notes/kad-source-lookup.md`), so the gate
stays blocked and `minimal.toml` remains authoritative.
