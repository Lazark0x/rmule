# Kad keywords are symmetric: rmule searches, publishes and stores, deriving keywords byte for byte as aMule does

## Context

Kad's keyword layer lets a client find files by name: `KADEMLIA2_SEARCH_KEY_REQ`
(`0x33`) asks a storer for the files under a keyword, `KADEMLIA2_PUBLISH_KEY_REQ`
(`0x43`) publishes a file's keywords, `KADEMLIA2_PUBLISH_RES` (`0x4B`) acknowledges with a
load, and `KADEMLIA2_PUBLISH_RES_ACK` (`0x4C`) acknowledges that. A Kad node without it
leaves its shared files unfindable by keyword and serves no keyword index to the network.

A keyword ID is the MD4 of the UTF-8 bytes of the lower-cased word, stored big-endian
([Kademlia.cpp#L500](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Kademlia.cpp#L500)).
Byte parity is load-bearing: one divergent lower-case fold yields a different MD4 and the
file silently never matches.

The search expression tree's wire grammar comes from aMule 2.3.3's parser
([KademliaUDPListener.cpp#L780](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L780)):
node byte `0x00` is boolean (operator `0x00` AND, `0x01` OR, `0x02` NOT, all binary,
including NOT), `0x01` a string term (u16-length UTF-8, lower-cased and re-tokenized on
receipt), `0x02` a meta-tag term, `0x03` / `0x08` a numeric relation (u32 / u64 and an
operator byte,
[#L873](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L873)),
recursion capped at depth 24, and an unknown node or operator kills the parse.

A captured aMule `0x43` for an unclassifiable file carries three tags, not four:
FILENAME, FILESIZE and SOURCES, with no FILETYPE; small integer values ride aMule's tag
compaction (`CTag::WriteTagToFile` narrows them to one-byte `0x09` tags).

## Decision

rmule is a keyword requester, publisher and storer.

**Keyword derivation, one module for both directions** (`rmule_kad::keyword`).
Tokenize on aMule's separator set `" ()[]{}<>,._-!?:;\/\""`
([SearchManager.h#L89](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/SearchManager.h#L89)),
keep words of at least 3 UTF-8 **bytes**
([SearchManager.cpp#L242](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/SearchManager.cpp#L242)),
lower-case them. The publish path dedupes and strips the file extension first
([KnownFile.cpp#L1491](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/KnownFile.cpp#L1491));
the search path keeps duplicates. No word-count cap. Multilingual fold vectors captured
from aMule pin the fold, and any divergence is matched byte for byte.

**The tree codec is symmetric; the requester emits plain keywords.** `search_tree` encodes
and decodes the full grammar, because golden vectors, adversarial mesh storers and
filtered-search captures need the encoder. The requester sends a plain keyword
(`startpos 0x0000`, no tree), which is what aMule sends for an unfiltered query; the
storer parses and evaluates full trees.

**Storer (`keyword_store`), shaped like aMule's:**

- **Dual-form entries:** a typed projection of the evaluable tags (filename, size,
  sources, file type, media) for tree evaluation, plus the publisher's verbatim tag list,
  re-served untouched
  ([Entry.cpp#L157](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Entry.cpp#L157)).
- **Aggregation** per `(keyword, fileID)` across publishers (name popularity, publisher
  count, trust); served rows append `TAG_PUBLISHINFO` =
  `(names << 24) | (publishers << 16) | (trust * 100)`
  ([Entry.cpp#L594](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Entry.cpp#L594)).
- **Caps and load:** 60 000 keyword entries (`KADEMLIAMAXENTRIES`), 50 000 sources per
  keyword (`KADEMLIAMAXINDEX`), a duplicate-source guard at 45 000
  ([Indexed.cpp#L482](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Indexed.cpp#L482)).
  The `0x4B` load byte is the keyword's fill percent, `indexTotal * 100 /
  KADEMLIAMAXINDEX`, 1 for a new keyword and 100 on reject
  ([Indexed.cpp#L546](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Indexed.cpp#L546)).
- **Lifetime:** 24 hours (`KADEMLIAREPUBLISHTIMEK`); the expiry sweep runs at most every
  30 minutes
  ([Indexed.cpp#L382](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Indexed.cpp#L382)).
- **Accepting `0x43`:** refused silently (no index, no `0x4B`) while UDP-firewalled
  ([KademliaUDPListener.cpp#L998](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L998),
  ADR-0058); a `SEARCHTOLERANCE` distance gate with a LAN bypass; FILENAME and FILESIZE
  typed, the rest stored verbatim. Storer-side keyword-membership verification, a later
  eMule behaviour, is not done: aMule 2.3.3 stores whatever is sent
  ([KademliaUDPListener.cpp#L992](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L992)).
- **Serving `0x33`:** the `startpos` top bit flags a restrictive tree and the low 15 bits
  are an offset, honoured as a skip
  ([Indexed.cpp#L745](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Indexed.cpp#L745));
  rows go 50 per `0x3B`, at most 300 per request, trusted entries first.
- Bounded and explicit-time, like `source_store`. Generic datagram rate limiting belongs
  to ADR-0064.

**Publisher.** Core registers complete shared files; the node derives keywords and
schedules, with aMule's constants: per-(file, keyword) republish every 24 hours, at most
two concurrent store-keyword walks (`KADEMLIATOTALSTOREKEY`), 2 s between publish starts,
150 files per keyword then reference rotation
([SharedFileList.cpp#L776-L832](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/SharedFileList.cpp#L776)).
A walk stores at most 50 files per `0x43` and stops after 10 storing nodes or 140 s
([Search.cpp#L659](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Search.cpp#L659)).

- **Load backoff:** the `0x4B` loads are averaged; above 20, the keyword is embargoed for
  `7 days × avgLoad / 100`, enforced at its next due publish
  ([Search.cpp#L135](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/Search.cpp#L135)).
- **Tags:** FILENAME, FILESIZE, SOURCES (the complete-source count), and FILETYPE only when
  the file classifies to a non-empty type, so three or four tags, byte-identical to
  aMule's. Integers ride the same compaction (`TagValue::compact_uint`). Media tags only
  with verified metadata.
- **Gate:** a live contact, and TCP open or a buddy connected
  ([SharedFileList.cpp#L773](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/SharedFileList.cpp#L773)).
  A TCP-firewalled node with a connected buddy still publishes (ADR-0061). The node holds
  the reachability inputs injected.

**Requester.** The walk targets the MD4 of the query's first token of at least 3 bytes
([SearchManager.cpp#L128](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/kademlia/SearchManager.cpp#L128)),
reusing the lookup walk, with aMule's caps: auto-stop at 300 results, 45 s lifetime. It
always sends offset 0, as aMule 2.3.3 does. Multi-word queries are filtered client-side:
the walk returns the lead keyword's rows and rmule matches the remaining words against
each row's filename locally. Keyword rows decode in dual form (typed and verbatim,
`TAG_PUBLISHINFO` included) and merge into the one search stream (ADR-0034), deduped by
file ID. Each search's answers ride its own sink, keyed by the walked keyword ID and closed
on `KeywordSearchComplete`, which is the search's Kad-leg settle signal.

**One walk per target.** The node's walks are keyed by target, and at most one holds a
target at a time, whatever its purpose, because every answer is routed by target; aMule
keeps the same set (`m_searches`, `AlreadySearchingFor`, `SearchManager.cpp:156`). A walk
holds its target until its terminal action. A keyword search command is always answered by
exactly one `KeywordSearchComplete` for its target:

- No walk holds it: a search walk starts.
- A keyword search walk holds it: the command joins that walk, whose residual screen
  narrows to the tokens both requests share; the joiner is replayed the rows found so far,
  screened by its own query.
- A keyword publish walk holds it: the search preempts the publish. The publish walk ends
  without completion or recorded load, its round goes back to due with its rotation
  rewound, and the search starts at once. aMule refuses the operator instead
  (`PrepareFindKeywords` throws "already on search list"); rmule preempts because a
  republish costs one walk later and a refused search costs the operator their rows.
- Any other walk holds it (a source walk whose file hash equals the keyword ID): the node
  answers at once with `KeywordSearchComplete { result_rows: 0, ended_by: TargetHeld }`.

A preempted publish is told to the search as `SearchDeferredKadPublish`; a `TargetHeld` or
`NoSearchableContacts` end leaves the search's Kad leg `NotSent` with that reason. A publish
round that falls due on a held target stays due and starts when the target frees, as aMule
leaves such a keyword's next publish time unset (`SharedFileList.cpp:1766-1773`).

**`0x4C`.** An inbound `0x4C` is a deliberate, counted drop, matching aMule, whose inbound
`0x4C` hits the unknown-opcode throw. rmule sends a null-payload `0x4C` only when an inbound
`0x4B` sets options bit 0 and arrived under a crypt sender key
([KademliaUDPListener.cpp#L1243](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1243)),
so the plaintext path never emits it.

## Consequences

- Under keyword collision, client-side filtering spends the storer's 300-row cap before
  filtering, where aMule's tree filter would not. A tree-emitting search is not built; the
  codec is ready for it.
- rmule bounds an inbound `0x43` batch at the emit-side 50 files, where aMule trusts the
  u16 count
  ([KademliaUDPListener.cpp#L1014](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/kademlia/net/KademliaUDPListener.cpp#L1014));
  compliant publishers never send more.
- The deterministic tier covers tree round trips over the whole grammar with the depth cap
  and unknown-operator rejection, tokenization vectors, the store's cap, load and expiry
  matrix, the serving matrix, publisher pacing and embargo arithmetic, the gate truth
  table, adversarial trees in the mesh sim, and the `0x4C` rules.
- Captures against aMule 2.3.3 cover rmule publishing to aMule (its `0x4B`), aMule
  publishing to rmule (the `0x43` bytes and fold vectors), rmule searching aMule (keyword
  `0x3B` rows with `TAG_PUBLISHINFO`) and aMule searching rmule with a restrictive tree
  (`crates/rmule-kad/tests/fixtures/keyword/`).

## Considered options

- **Requester and publisher without a storer.** Rejected: it reads the network's index
  and serves none.
- **Opaque entries holding only the raw tag list.** Rejected: tree evaluation and
  `TAG_PUBLISHINFO` aggregation need typed access.
- **Trusting the inbound `0x43` file count.** Rejected: bounding at 50 is unobservable to
  compliant publishers.
- **Storer keyword-membership verification.** Rejected: aMule 2.3.3 does not do it, and it
  would silently drop publishes every 2.3.3 storer accepts.
- **Refusing a search whose keyword a publish walk holds, as aMule does.** Rejected: the
  operator loses rows to save one walk.
