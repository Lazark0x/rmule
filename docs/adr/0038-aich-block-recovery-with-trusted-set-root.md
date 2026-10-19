# AICH block-level recovery with a trusted-set root

## Context

A part assembled from several peers is verified once, by its MD4 part hash
(ADR-0029). On failure, MD4 cannot say which block was bad. Without more information
the part is fetched again, and only a refetch can say which writer sent the bad bytes
(ADR-0117 §1).

AICH is eMule's optional SHA-1 hash tree over 180 KiB (`EMBLOCKSIZE`) blocks. With a
trusted master root, a part's recovery data localises the corrupt block and so names
the peer that sent it. But the AICH master root has no anchor in the ED2K file hash:
unlike the MD4 part hash set, whose hashes re-hash to the file hash (so one peer's set
can be accepted once proven, `VerificationAuthority::PeerHashSet`), a single peer's
root proves nothing. A peer could send a bad root with matching bad recovery data and
defeat the recovery.

Kad offers a second witness. A storer at Kad v9 or later answers a keyword search with
`TAG_KADAICHHASHRESULT` (`0x37`), a `BSOB` of `<count>{<popularity><AICH root>}`: each root
the file's publishers reported to it in `TAG_KADAICHHASHPUB`, with how many of them did
(eMule 0.70b `kademlia/kademlia/Entry.cpp:680-710`). It writes the tag for every searcher,
whatever the searcher's Kad version, so rmule at v8 receives it from eMule storers today.
eMule reads it from storers at v9 or later only (`Search.cpp:1127-1146`) and takes a lone
root that at least a third of the publishers reported as if it were a link's `h=`
(`SearchList.cpp:785-803`). Both counts are the storer's own word.

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
- **Root authority: link `h=`, then a qualified Kad root, then the peer vote, then
  none.** A single peer's root is never trusted. Without `h=`, core collects root proposals from connected peers
  (`0x9E` → `0x9D`) and commits one only when at least `MIN_UNIQUE_IPS_TO_TRUST` (10)
  distinct voters propose it and it holds at least `MIN_PERCENTAGE_TO_TRUST` (92 %) of
  all voters, as aMule's `SHAHashSet.cpp` does. A voter is an IPv4 address masked as
  aMule masks it (`dwIP &= 0x00F0FFFF`), so one subnet cannot stuff the vote, or an IPv6
  proposer's `/64`. With no trusted root, AICH recovery is unavailable and a
  failed part takes the rootless path of ADR-0117 §1, which attributes its corrupt cells
  across a refetch. AICH is never a new failure mode.
- **A qualified Kad root.** rmule keeps `TAG_KADAICHHASHRESULT` from a storer its search walk
  knows at Kad v9 or later, as eMule does, and ignores it from any other. A pair of popularity
  0 is skipped, as eMule and aMule 3.1.0 skip it (`AICHHashList.cpp:149-177`), and bytes past
  the count are ignored; a `BSOB` too short for its count drops the pairs, never the result
  (ADR-0053). The pairs ride the keyword result beside the publisher count from
  `TAG_PUBLISHINFO`. A result's root is **qualified** only when the result carries exactly one
  root, reported by at least a third of the publishers and by at least
  `MIN_UNIQUE_IPS_TO_TRUST` (10) of them. The third is eMule's rule; the floor is the vote's,
  because the counts are one storer's word, and a forged root with recovery data built to match
  it would blame honest cells (ADR-0117). Two roots, or one under either bar, qualify nothing.
- **The result the operator starts from decides.** A search row keeps the first qualified
  root a report of it carried: the Kad node surfaces one storer's row per file and search
  (ADR-0062), and a server answer folded into the row carries none. Several results of one
  file may carry different roots, from different storers in different searches; the download
  takes the root of the one it was started from. The root rides the start command beside the
  link, never inside it: a copied link carries no `h=` from Kad, which would lift the root above
  the vote for whoever pastes it.
- **A Kad root stays open to the vote.** A download started from a result with a qualified
  root trusts it from the start and still asks its peers for theirs, as a rootless download
  does. When the vote commits the same root, nothing changes. When it commits a different one,
  the download trusts neither for its life, takes the rootless path of ADR-0117 §1, and the
  Run Log records the contest (`download.kad_aich_root_contested`). A link's `h=` closes the
  vote; a Kad root does not.
- **The record keeps the Kad root.** The download's durable row holds its Kad root and, once
  the vote contests it, the contest, so a resumed run starts from the same authority. A
  link's `h=` is already in the row's canonical link; the vote's root is not kept.
- **AICH changes only the failure path.** MD4 still defines "verified". When a part fails
  MD4 and a trusted root exists, core requests the part's recovery data
  (`0x9B` → `0x9C`), hashes each block, and finds the corrupt ones. `PartAssembly` records
  every worker that wrote a byte into each block's cell (ADR-0117); repair drops only the
  corrupt cells from the part's **Arrived Ranges**, retires the workers that wrote into
  them, and distrusts a corrupt cell's sole writer. The dropped blocks are handed again to
  the next workers with room, and the part re-verifies by MD4.
- **Bad AICH input is a skip, not an error.** A malformed `0x9C`, a master-hash echo that
  does not match, or recovery data that does not chain to the trusted root falls back to
  the rootless path, and the peer session stays open. So does recovery data naming no
  corrupt block, and an ask whose worker ends before it answers. While the ask is out the
  part is verifying, so none of its blocks is handed.
- **Serving is lazy.** The serve side builds a shared file's `AichHashSet` from the file's
  bytes on the first `0x9B` or `0x9E` for it, caches it, and drops it when the file is
  unshared. It answers recovery data (`0x9C`) and the master root (`0x9D`) from the cache.
- **Honest advertisement.** The `MiscOptions1` AICH-version field (bits `[29..32)`) is lit
  because rmule builds, verifies and serves AICH (ADR-0047).

## Consequences

- With a trusted root, a corrupt part costs one peer — the poisoner — at once, and only
  its corrupt cells are fetched again; without one, the whole part is, before the
  poisoner can be named (ADR-0117 §1).
- Repair refetches exactly the corrupt blocks. A cell holding two workers' bytes — a
  duplicate, a freed lost block, an off-grid ask — retires both writers and distrusts
  neither. The in-memory, per-session lifetime of assembly is unchanged.
- The serve-side cache holds one tree per shared file a peer asked about, about 20 bytes
  per 180 KiB block; nothing bounds it but the share set.
- The Kad leg is source-derived until a bench settles it: a v9 storer holding a keyword entry
  that 10 or more publishers reported with one AICH root, and rmule's download from that result
  taking the root. aMule 2.3.3 is Kad v8, and aMule 3.1.0 and kno write
  `TAG_KADAICHHASHRESULT` only when built with their non-default `ENABLE_KAD_PROTOCOL_10`
  (`Constants.h:47-57`); emule-qt runs Kad v10, writes the tag (`KadEntry.cpp:504-527`) and
  publishes its roots to v9 storers (`KadSearch.cpp:143-186`), so the bench stages it with an
  emule-qt storer and ten emule-qt publishers sharing one file.
- eMule computes its third in integer arithmetic, `publishers / popularity <= 3`
  (`SearchList.cpp:797`), as aMule 3.1.0 does, which admits a root from just over a quarter of
  the publishers. rmule's `3 × popularity >= publishers` is the third it names: a root from 6 of
  20 publishers passes eMule's test and fails rmule's.
- AICH trees are not persisted (there is no `known2.met` equivalent); a restart rebuilds
  them on demand. AICH over UDP and eMule's `AICH_VERIFIED` / `AICH_HASHSETCOMPLETE`
  propagation states are not implemented.

## Considered options

- **Receive-only AICH.** Rejected: rmule would advertise a capability it does not serve,
  and the tree is computable on demand from a shared file's bytes, so serving needs no new
  durable state.
- **Trusting a single peer's root.** Rejected: with no anchor in the file hash, one peer
  can feed a bad root with matching bad recovery data.
- **Taking a qualified Kad root as a link's `h=`, as eMule does.** Rejected: the counts are
  one storer's word, and `h=` closes the vote, so a forged root would never be contested.
- **Dropping the Kad roots, as the tag-list step-past first did.** Rejected: eMule storers
  send them to rmule today, and a root ten publishers agree on enables recovery before ten
  peers have answered the vote.
- **Taking the most popular of several Kad roots.** Rejected: competing roots mean a
  publisher lies, and the popularity is a count the storer reports, so whoever lies can set it.
- **Letting a contesting vote replace the Kad root.** Rejected: two witnesses disagree and
  neither is anchored in the file hash; the rootless path costs a refetch, never a wrong blame.
- **Localising and refetching the bad block without retiring its sender.** Rejected: it
  converges but leaves the poisoner free to serve the same bad block again.
- **Building and holding every shared file's tree up front.** Rejected: a tree is roughly
  a hundred times the size of the MD4 part hash set; building on request bounds the cost to
  files peers ask about.
- **Persisting trees, as eMule's `known2.met` does.** Not adopted: a file-format and schema
  effort that changes no wire behaviour.
