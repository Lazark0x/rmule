# Source exchange is symmetric, feeds the live candidate pool and propagates only verified contacts

## Context

Peers downloading or uploading a file know other sources for it. eMule's source exchange
lets a peer ask for them: `OP_REQUESTSOURCES` (`0x81`) answered by `OP_ANSWERSOURCES`
(`0x82`), and the SX2 pair `OP_REQUESTSOURCES2` (`0x83`) / `OP_ANSWERSOURCES2` (`0x84`).
It is the eMule-native way to refresh a download's sources: free, because the peers are
already connected, and it rescues a download whose server lookup returned too few usable
sources.

aMule's serve gate answers only requesters that advertise source exchange
([ClientTCPSocket.cpp#L1453](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1453)),
so a client has to advertise it to receive answers. Advertising it while never serving
takes from the exchange without giving back.

Wire facts that shape the decision:

- An entry is `<id4><port2><srvIP4><srvPort2>`, plus `<hash16>` from version 2 and
  `<crypt1>` (bits 0/1/2 = supports/requests/requires) from version 4; from version 3 the
  ID is in hybrid byte order.
- aMule 2.3.3's serve path checks a standalone `0x83` for `size != 16`, so it disconnects
  every standalone 19-byte SX2 request
  ([ClientTCPSocket.cpp#L1455](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientTCPSocket.cpp#L1455));
  eMule checks 19. It is masked in the wild because SX2 requests ride inside multipackets,
  and aMule itself asks SX2 standalone only toward a peer without MultiPacket.
- aMule's uploader answers an ask only from an asker whose part status it holds at the
  file's part count. A `0x58` from an extended-requests v0 asker clears that status
  (`UploadClient.cpp:397-406`) and `CKnownFile::CreateSrcInfoPacket` then returns `NULL`
  for every complete file (`KnownFile.cpp:929`).
- aMule's `PartFile` keys the ID byte order on the SX1 nibble while the stride follows
  the negotiated version
  ([PartFile.cpp#L2640](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L2640)),
  which is unobservable against nibble-3 clients.

## Decision

**Source exchange is a discovery channel into the live candidate pool.** Exchanged
sources enter the download's one candidate pool mid-download (ADR-0030), where backfill
picks them up; there is no separate pool and no single source snapshot. High-ID sources
not already known are pooled, dialed in the family the Dial Chooser picks (ADR-0087), with
the crypt stance the record stated (ADR-0049). Low-ID sources become Low-ID Candidate
records in the connected server's namespace, for whichever road the admission rule leaves
open (ADR-0039, ADR-0061, ADR-0091).

**rmule serves and requests, SX2-grade, with aMule's mechanics.**

### Versions and adverts

- rmule advertises the SX1 nibble **3**, aMule's own value
  ([BaseClient.cpp#L1089](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1089)),
  and SupportsSourceEx2 (`MiscOptions2` bit 10), from the registry (ADR-0047).
- **Asking:** toward an SX2 peer, the ask is the `0x83 <ver=4><opts=0>` sub inside a
  multipacket bundle (ADR-0054). A standalone ask is always the 16-byte `0x81`, because a
  hello cannot tell aMule from rmule, which advertises aMule's own version word. Every
  name ask, bundled or standalone, carries the download's verified-part status at the
  negotiated extended-requests level (ADR-0047), so aMule holds our status and answers for
  complete files. `0x4F` is sent only when `part_count(file_size) > 1`, as aMule gates on
  `GetPartCount()` (`DownloadClient.cpp:232`), so a file of exactly one part size gets
  none.
- **Serving version**, as aMule picks it
  ([KnownFile.cpp#L938](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/KnownFile.cpp#L938)):
  SX2 when the requester advertised SX2 and asked for a version above 0, at
  `min(requested, 4)` in `0x84`; otherwise SX1 at the requester's nibble in `0x82`.
- One version-parameterized entry codec serves both directions. IDs are hybrid exactly
  when the used version is 3 or more, not aMule's `PartFile` quirk.

### Serving

- **Pools**, as aMule builds them: for a shared complete file, upload-engaged clients
  (uploading or queued), with a source of unknown status included
  ([KnownFile.cpp#L965](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/KnownFile.cpp#L965));
  for a download in progress, the file's sources that are downloading or queued, with
  unknown status excluded
  ([PartFile.cpp#L2596](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L2596)).
- **The answer rule.** The part status a peer writes into its name ask, or restates in a
  UDPv4 `OP_REASKFILEPING` (`0x90`, ADR-0057), is kept per peer and file, aMule's
  `m_upPartStatus`. A pooled source is answered when it holds a real part the asker lacks
  (`KnownFile.cpp:976-999`), and a source whose parts are unknown is answered ("send it
  and hope"). A status is read against the file: its count must be
  `size / PARTSIZE + 1` or it is dropped, and the phantom last part of an exact multiple
  never reads as held or lacked.
- **Filters:** skip Low-ID entries and the requester; at most 500 entries; an empty
  answer sends nothing.
- **Throttle** per peer connection, shared by standalone and bundled asks: the first ask
  is free; then 40 minutes for a rare file (50 sources or fewer) and 160 minutes
  otherwise (`SOURCECLIENTREASKS`, `MINCOMMONPENALTY`, `RARE_FILE`).
- **Packing:** every answer above 354 bytes is pack-attempted (ADR-0053), as aMule packs
  at the same gate.
- **Standalone `0x83` is accepted at 19 bytes**, the size eMule checks.
- **Divergence: an asker without a status is answered, not refused.** aMule refuses it
  (`KnownFile.cpp:929-933`). rmule answers it with the rule aMule wrote for it and made
  unreachable: sources holding at least one real part, plus the unknowns, never a source
  whose own status says it holds nothing (`KnownFile.cpp:1000-1024`; eMule's lineage
  answers the same, emule-qt `KnownFile.cpp:1225-1229`). A refusal would starve such a
  peer of sources for the life of the link.
- **Divergence: a count of zero is a complete file.** aMule's writer means it so
  (`WriteUInt16(0)` for a file that is not a part file), while aMule's reader sizes it
  all-zero and drops a complete source from every answer. rmule reads the writer's
  meaning.

**Propagation trust: verified contacts only.** rmule serves onward only sources it has
engaged itself: the upload-engaged pool, and download sources in contact-confirmed
states. Exchanged hearsay is never re-propagated until a real session confirms it. There
is no trust score.

### Consuming

- **Validation, as aMule does**
  ([PartFile.cpp#L2697](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/PartFile.cpp#L2697)):
  a `0x82` is checked by geometry against the nibble rmule advertised and dropped whole on
  a mismatch, as a non-terminal diagnostic; a `0x84` needs a version byte in 1..=4 and
  exact geometry. IDs from version 3 are swapped to ed2k order.
- **Per entry:** drop zero, localhost and our own High-ID endpoints; a Low-ID entry needs
  a plausible server endpoint. The per-file source cap is honoured.
- **Provenance:** the origin tag, the version 2+ User Hash and the version 4 crypt options
  ride onto the candidate (ADR-0046), the input an obfuscated dial needs. Versions 1 to 3
  state no crypt stance, which is silence, not a statement (ADR-0049).

**Requester cadence** is aMule's whole `IsSourceRequestAllowed` gate, defined with the
per-peer and per-download clocks in ADR-0108. UDP reask cadence is ADR-0057's.

**Seams.** The codec lives in `rmule_peer::source_exchange`. Pools, filters and throttle
timestamps live in core with the serve state; the peer crate only encodes. Standalone
packets and bundle subs converge on the same serve path.

### The name-ask and reask surface

Every way a peer asks rmule about a file, against stock aMule 2.3.3 `4e8f2b3c` (`cts`
`ClientTCPSocket.cpp`, `uc` `UploadClient.cpp`, `cus` `ClientUDPSocket.cpp`, `uq`
`UploadQueue.cpp`).

**The Asked File.** aMule's client has one upload file, set by a name ask, a status ask,
a bundle and a slot ask (`cts:462`, `:521`, `:1103`, `:613`); a queued client keeps its
place (`uq:401-431`), and its UDP reask is answered only for that file (`cus:197`).
rmule's waiter standing follows the file it last asked about
(`UploadSlotQueue::follow_asked_file`); the asker's part status stays per peer and file.

**The bundle gate.** A bundle reaches core whole (`PeerEvent::FileBundleRequested`) and
core gates it once on its file, as aMule does before its sub loop (`cts:1061-1085`). A
file rmule does not share, or an `_EXT` size that is not the file's, draws one
`OP_FILEREQANSNOFIL` and nothing else. A sub cut short is reported by the walker
(`BundleCut`), so the gate still comes first. An `OP_MULTIPACKET_EXT` name sub's status is
read by the size the frame carries, which the gate has just matched; a plain
`OP_MULTIPACKET`, which names no size, is walked by its wire count and its status dropped
in core when the count is not the file's.

| Rule | aMule | rmule |
| --- | --- | --- |
| **Name ask (`OP_REQUESTFILENAME`)** | | |
| Shorter than a hash: disconnect | `cts:436`, `:484` | same |
| Before the hello | `cts:307-308` throw | kept as unknown, link open (ADR-0018) |
| Banned IP: silence | `cts:186`, `:433` | refused at accept |
| Unshared file: silence, link kept | `cts:442-447` | same |
| A downloading file over one part is answered | `cts:443-453` | only complete files are shared |
| Sets the Asked File | `cts:462` | same |
| Wait clock starts at the first file ask | `cts:436-438` | starts at the slot ask (divergence 3) |
| Claim 0: status cleared, ask answered | `uc:400-406` | same |
| Hash alone from a claimant: disconnect, counted | `uc:408-412` | same (`malformed_name_asks_total`) |
| Status read by the file's parts; wrong count cleared and answered; cut bitmap disconnects | `uc:414-446` | same |
| Count 0 | `uc:415-416` all-zero | a complete copy (divergence above) |
| Complete-source count for a claim above 1 | `uc:448-455` | never read: rmule claims 1 |
| Answer `OP_REQFILENAMEANSWER`, then a comment if any | `cts:465-480` | same; rmule keeps no comment |
| **Status ask (`OP_SETREQFILEID`)** | | |
| Not exactly a hash: disconnect | `cts:497`, `:536` | same |
| Unshared: `OP_FILEREQANSNOFIL` | `cts:503-512` | same |
| Shared: `OP_FILESTATUS`, a complete file as count 0; sets the Asked File | `cts:521-529` | same |
| **Bundle (`OP_MULTIPACKET` / `_EXT`)** | | |
| Before the handshake | `cts:1050-1054` throw | kept as unknown, link open (ADR-0018) |
| Header cut short: disconnect | `cts:1057-1058` | same |
| Unshared, or `_EXT` size not the file's: one `OP_FILEREQANSNOFIL`, no sub walked | `cts:1061-1085` | same |
| Large file, asker without large-file support: not found | `cts:1070-1073` | not modelled (divergence 4) |
| Sets the Asked File before any sub | `cts:1103` | same |
| Sub cut short: gate first, then disconnect, nothing answered, counted | `cts:1106-1182` | same |
| Name and status subs answered in the `0x93` | `cts:1112-1141` | same |
| AICH sub only from a complete hashset | `cts:1122-1131` | cached root in the `0x93`, else a later standalone `0x9D` (divergence 5) |
| Source subs answered out of band, one throttle | `cts:1144-1180` | same |
| Unknown sub | no `default:` | stop, keep the prefix, report (ADR-0054) |
| `0x93` only when something was answered | `cts:1183` | same |
| `0x93` items in request order | `cts:1106-1182` | always name, status, AICH (divergence 6) |
| **Slot and transfer** | | |
| Slot ask before the handshake: silence | `cts:597-599` | kept as unknown |
| Slot ask not exactly a hash: silence, link kept | `cts:606` | same |
| Slot ask for an unshared file: nothing sent | `cts:607-617` | same |
| Repeat slot ask keeps the place, moves the Asked File | `cts:613`, `uq:401-431` | same |
| Aggressive asker banned | `cts:601`, `cus:194`, `uc:795-824` | not modelled (divergence 7) |
| Parts of a file other than the slot's | `uc:198-249` serves them | not served (divergence 8) |
| A moved Asked File resets the status | `uc:477-479` | kept per peer and file (divergence 8) |
| `OP_CANCELTRANSFER`: slot released, slotless a no-op, link kept, body ignored | `cts:673-678` | same (ADR-0056) |
| **UDP reask, uploader side** | | |
| Shorter than a hash: silence | `cus:176` | same |
| Unshared: `OP_FILENOTFOUND`, obfuscated to a known sender | `cus:181-191` | same |
| Known sender, not its Asked File: silence | `cus:197`, `:227-229` | same |
| Matched: standing refreshed | `cus:198-200` | same |
| UDPv4 status through the name ask's reader; malformed: silence, counted | `cus:202-203` | same |
| UDPv3: complete count only; hash alone silenced | `cus:204-209` | same |
| Ack: our status for a UDPv4 pinger (complete file as count 0), then the rank | `cus:213-222` | same |
| Unknown sender: `OP_QUEUEFULL` in plaintext when nearly full, else silence | `cus:231-236` | same |
| One IP, several ports: silence | `cus:237-239` | same |
| Buddy-relayed reask with a malformed body | `cts:1704-1707` drops the buddy link | ping silenced, link kept |
| **UDP replies, downloader side** | | |
| `OP_REASKACK` status present only when both ends are UDPv4 | `cus:214`, `:258-259` | same |
| `OP_REASKACK` status updates the source's parts | `cus:259` | decoded and dropped (divergence 9) |
| `OP_REASKACK` rank recorded, queue-full cleared | `cus:261-263` | same |
| `OP_QUEUEFULL`: queue full, rank 0 | `cus:243-251` | same |
| `OP_FILENOTFOUND`: source dropped | `cus:267-275` | same |

**Ruled divergences.**

- **Unshared standalone name ask: silence**, as aMule and eMule do. The asker learns "not
  here" from its status ask or its bundle; only a non-bundling client asking for a
  one-part file waits for its own timeout, as it does against aMule.
- **Relayed reask:** aMule's throw drops the buddy link; rmule silences the ping only,
  because the malformed bytes are a third party's that the buddy forwarded.
- **Divergence 3, wait clock.** rmule's starts at the slot ask, aMule's at the first file ask. Both
  references send the two in one exchange, so the clocks differ by one round trip; rmule's
  queue ranks peers that asked for a slot, not those that only looked.
- **Divergence 4, large files.** rmule reads only the crypt bits of `MiscOptions2`, not the
  large-file bit, so this gate belongs to the large-file capability. Today it lets a
  pre-0.47 client learn the name of a file it cannot address anyway.
- **Divergence 5, AICH in a bundle.** rmule builds a file's AICH tree lazily (ADR-0038). A cold
  cache answers the root after the `0x93`, as a standalone `OP_AICHFILEHASHANS`, which
  aMule reads at any time (`cts:1600-1606`).
- **Divergence 6, `0x93` order.** The composer writes name, status, AICH, aMule's own asker order
  (`DownloadClient.cpp:232-266`); every reader walks items in any order.
- **Divergence 7, aggressive askers.** aMule bans a client asking more than once per 590 s until a
  score reaches 10, except while downloading from it. The serve state does not see
  rmule's download state, and a wrongly placed ban would close a download on the same
  link. The flood is bounded by the per-address queue cap (ADR-0088), and a repeat slot
  ask gains nothing.
- **Divergence 8, one file per slot.** rmule serves a slot one file at a time (ADR-0031). Parts of
  another file wait until the peer asks for a slot for it. Statuses stay per peer and
  file, and a status for one file stays true while the peer asks about another.
- **Divergence 9, a UDP ack's status.** rmule's downloader takes a source's parts from TCP answers
  only; the ack's status is decoded, which checks it, and dropped. It is at most one reask
  period stale and is re-read over TCP before any part is asked.

## Consequences

- The deterministic tier covers the entry codec at all four versions in both directions,
  the geometry-against-advert drop, SX2 version bounds, the version 3 ID swap, the pool
  filters and cap, throttle gates, packing above 354 bytes, provenance, verified-contact
  propagation, Low-ID routing and the 19-byte standalone `0x83`.
- Captures: aMule's packed SX2 v4 answer
  (`crates/rmule-peer/tests/fixtures/source_exchange/captured/amule-233-packed-answer-20260728`),
  kno's SX1 answer and emule-qt's ExtSX answers in the same directory, and aMule's
  request to rmule as a server in `crates/rmule-peer/tests/fixtures/reverse_serve/captured/`.
  A `0x82` at strides other than nibble 3 has no compliant emitter toward rmule and is
  covered by the deterministic tier.
- Stock aMule 2.3.3 answers rmule's bundle for a complete file with an SX2 v4 record that
  the download admits and dials.

## Considered options

- **Receive-only source exchange.** Rejected: advertising source exchange is required to
  receive answers, and advertising without serving takes without giving back.
- **Refreshing sources by re-querying the server.** Rejected: more server load and
  re-login bookkeeping, where peers are already connected and exchange is the native
  mechanism.
- **Exchanged sources only seeding the first snapshot, or a separate pool.** Rejected:
  the value is mid-download backfill, and the runner already owns one pool with backfill.
- **Advertising SX1 nibble 4.** Rejected: aMule advertises 3, and 4 invites version-4
  stride `0x82` that no compliant client sends.
- **Geometry inference on consume.** Rejected: it accepts strides rmule never advertised,
  where aMule's cross-check names the damage (wrong hashes, duplicate sources).
- **Replicating aMule's ID-order quirk or its standalone `0x83` size check.** Rejected:
  both are defects.
- **A standalone SX1 ask before the name ask, or both.** Rejected: aMule's status of us
  stays "nothing held" and the bundle stays wrong for every later ask; doing both adds a
  packet for no answer the bundle does not already draw.
- **Trust scoring for propagated sources.** Rejected: verified-contact filtering is
  aMule's own damping and needs no new machinery.
- **Carrying the bundle's sub stream unwalked to core.** Rejected: it moves the codec and
  the SX version pick into core for a shape nobody sends.
