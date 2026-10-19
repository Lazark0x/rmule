# AICH block-level recovery with a trusted-set root

## Context

A part assembled from several peers is verified once, by its MD4 part hash
(ADR-0029). On failure, MD4 cannot say which block was bad, so the only safe move
without more information is to retire every contributor and refetch the part — which
collaterally retires honest peers.

AICH is eMule's optional SHA-1 hash tree over 180 KiB (`EMBLOCKSIZE`) blocks. With a
trusted master root, a part's recovery data localises the corrupt block and so names
the peer that sent it. But the AICH master root has no anchor in the ED2K file hash:
unlike the MD4 part hash set, whose hashes re-hash to the file hash (so one peer's set
can be accepted once proven, `VerificationAuthority::PeerHashSet`), a single peer's
root proves nothing. A peer could send a bad root with matching bad recovery data and
defeat the recovery.

A first-class peer also answers AICH requests; advertising AICH without serving it
would be a dishonest capability (ADR-0047).

## Decision

AICH is a block-level recovery layer beside MD4, implemented in both directions.

- **Layering.** `AichHashSet` in `rmule-primitives` is the SHA-1 sibling of
  `PartHashSet`: built from bytes into a master root plus per-block hashes, it verifies a
  part's blocks against a trusted root and parses and serialises per-part recovery data.
  SHA-1 comes from the `sha1` crate wrapped behind rmule types, as the MD4 crate is
  (ADR-0012). `rmule-peer` owns only the client-to-client envelopes under `OP_EMULEPROT`
  (`0xC5`): `OP_AICHREQUEST` (`0x9B`), `OP_AICHANSWER` (`0x9C`), `OP_AICHFILEHASHANS`
  (`0x9D`) and `OP_AICHFILEHASHREQ` (`0x9E`), passing recovery data as opaque bytes.
  `rmule-core` composes recovery and answers the serve side.
- **Root authority: link `h=`, then a trusted-set vote, then none.** A single peer's
  root is never trusted. Without `h=`, core collects root proposals from connected peers
  (`0x9E` → `0x9D`) and commits one only when at least `MIN_UNIQUE_IPS_TO_TRUST` (10)
  distinct voters propose it and it holds at least `MIN_PERCENTAGE_TO_TRUST` (92 %) of
  all voters, as aMule's `SHAHashSet.cpp` does. A voter is an IPv4 address masked as
  aMule masks it (`dwIP &= 0x00F0FFFF`), so one subnet cannot stuff the vote, or an IPv6
  proposer's `/64`. With no trusted root, AICH recovery is unavailable and a
  failed part takes the retire-all path of ADR-0029. AICH is never a new failure mode.
- **AICH changes only the failure path.** MD4 still defines "verified". When a part fails
  MD4 and a trusted root exists, core requests the part's recovery data
  (`0x9B` → `0x9C`), hashes each block, and finds the corrupt ones. `PartAssembly` records
  every worker that wrote a byte into each block's cell (ADR-0117); repair drops only the
  corrupt cells from the part's **Arrived Ranges**, retires the workers that wrote into
  them, and distrusts a corrupt cell's sole writer. The dropped blocks are handed again to
  the next workers with room, and the part re-verifies by MD4.
- **Bad AICH input is a skip, not an error.** A malformed `0x9C`, a master-hash echo that
  does not match, or recovery data that does not chain to the trusted root falls back to
  retire-all, and the peer session stays open.
- **Serving is lazy.** The serve side builds a shared file's `AichHashSet` from the file's
  bytes on the first `0x9B` or `0x9E` for it, caches it, and drops it when the file is
  unshared. It answers recovery data (`0x9C`) and the master root (`0x9D`) from the cache.
- **Honest advertisement.** The `MiscOptions1` AICH-version field (bits `[29..32)`) is lit
  because rmule builds, verifies and serves AICH (ADR-0047).

## Consequences

- With a trusted root, a corrupt part costs one peer — the poisoner — instead of every
  contributor.
- Repair refetches exactly the corrupt blocks. A cell holding two workers' bytes — a
  duplicate, a freed lost block, an off-grid ask — retires both writers and distrusts
  neither. The in-memory, per-session lifetime of assembly is unchanged.
- The serve-side cache holds one tree per shared file a peer asked about, about 20 bytes
  per 180 KiB block; nothing bounds it but the share set.
- AICH trees are not persisted (there is no `known2.met` equivalent); a restart rebuilds
  them on demand. AICH over UDP and eMule's `AICH_VERIFIED` / `AICH_HASHSETCOMPLETE`
  propagation states are not implemented.

## Considered options

- **Receive-only AICH.** Rejected: rmule would advertise a capability it does not serve,
  and the tree is computable on demand from a shared file's bytes, so serving needs no new
  durable state.
- **Trusting a single peer's root.** Rejected: with no anchor in the file hash, one peer
  can feed a bad root with matching bad recovery data.
- **Localising and refetching the bad block without retiring its sender.** Rejected: it
  converges but leaves the poisoner free to serve the same bad block again.
- **Building and holding every shared file's tree up front.** Rejected: a tree is roughly
  a hundred times the size of the MD4 part hash set; building on request bounds the cost to
  files peers ask about.
- **Persisting trees, as eMule's `known2.met` does.** Not adopted: a file-format and schema
  effort that changes no wire behaviour.
