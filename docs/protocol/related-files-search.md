# Related-files search: what the wire offers

Research note. Question: what eMule/aMule's "search
related files" sends on the wire, which servers answer it, what limits it has,
whether Kad has an equivalent, and what rmule can express today.

Placement: the `doctree` guard (`scripts/guards.sh`) keeps `docs/` to a live-only
tree with no research directory, so this wire note lives under `docs/protocol/`.

## Sources and pins

| Short name | What it is | Pin |
|---|---|---|
| eMule | `srchybrid/` in the emule-qt reference pin. It is byte-identical to the eMule 0.70b pin (`docs/reference/emule-source/eMule.meta.toml:5,13`) | irwir/eMule `13983526` |
| aMule | `src/` in the kno fork pin. This is the kno fork, not upstream (`docs/reference/amule-kno/amule-kno.meta.toml:5`) | kno/amule `ab483654` |
| ed2ksrv@eacf7f1 | andrey23127/ed2k-server v0.9.70, the bench's earlier pin and still `tools/ed2ksrv-differ`'s (`Cargo.toml:25`), read from the local cargo git db `~/.cargo/git/db/ed2k-server-b80c5adba11d5604` | `eacf7f1` |
| ed2ksrv@pin | the bench's current pin of record, v0.9.75 (`tools/interop-harness/images/ed2ksrv/pin.env:7-9`), cloned from GitHub for this note | `4da4774f` |
| Lugdunum | closed source, no first-party documentation. What is known comes from ed2k-server's comment about a decompile, a captured `OP_IDCHANGE`, and the captured replies of §6 (bench run `1790603580`, Lugdunum 17.15) | — |

The bench pin moved from `eacf7f1` to `4da4774f` on 2026-09-25. Both
commits are covered below, and on this feature they behave the same.

## 1. How eMule and aMule build the request

**The request is an ordinary `OP_SEARCHREQUEST` (0x16) whose tree holds one
string term, `related::<HASH>`.** There is no separate opcode.

| Fact | Source |
|---|---|
| eMule has three UI entry points, all using `MP_SEARCHRELATED`: the search-result context menu, the download-list context menu and the toolbar | eMule `SearchListCtrl.cpp:841-843,925`, `DownloadListCtrl.cpp:1439-1440,1945`, `ToolbarWnd.cpp:164` |
| The eMule menu item is enabled only when `CanSearchRelatedFiles()` holds: connected to a server, and that server's `GetRelatedSearchSupport()` is true | eMule `SearchResultsWnd.cpp:1658-1663`, `DownloadListCtrl.cpp:1020`, `SearchListCtrl.cpp:706` |
| `GetRelatedSearchSupport()` means TCP flag `SRV_TCPFLG_RELATEDSEARCH = 0x00000040` is set. The flag comes from the `OP_IDCHANGE` tcp-flags word | eMule `Server.h:40,159`, `ServerSocket.cpp:263-279`; aMule `include/protocol/ed2k/Client2Server/TCP.h:73`, `Server.h:159` |
| eMule builds the expression as `"related"`, then appends `"::" + md4str(hash)` for **each** selected file, giving `related::H1::H2…` | eMule `SearchResultsWnd.cpp:1678-1685` |
| The hash is 32 **uppercase** hex characters: eMule's `base16Chars = "0123456789ABCDEF"` and aMule's `EncodeSTL` uses `'A'-10` | eMule `OtherFunctions.cpp:60,1191-1193`; aMule `MD4Hash.h:182-196` |
| eMule's own comment gives the syntax as `related::<file hash>` or `related:<file size>:<file hash>`, says "the file you 'search' for must be shared by at least 5 clients", and says several hashes are accepted "since v17.14". v17.14 is a server version. The comment cites the eMule forum, but the forum page could not be fetched | eMule `SearchResultsWnd.cpp:1665-1669` |
| eMule starts from a fresh `SSearchParams`, so the default `eType = SearchTypeEd2kServer` applies and no type, size or extension constraints are added | eMule `SearchResultsWnd.cpp:1677-1678`, `SearchParams.h:34` |
| **Transport: TCP to the connected server only.** `DoNewEd2kSearch` sends `OP_SEARCHREQUEST`. The global UDP copy (`OP_GLOBSEARCHREQ*`) is armed only when `eType == SearchTypeEd2kGlobal`, which a related search never has | eMule `SearchResultsWnd.cpp:1248-1252` |
| The string passes through the normal search grammar. `keywordchar` is `[^ \"()<>=]` in eMule and `[^ \"()]` in aMule, so `related::…` is lexed as one string token. It is written as node `0x01` followed by `len16` and the string | eMule `Scanner.l:76,317`, `SearchResultsWnd.cpp:869-873`; aMule `Scanner.l:45,59-62` |
| eMule skips spam-filter keyword extraction for expressions starting with `related:` ("ignore special searches") | eMule `SearchList.cpp:167` |
| aMule has one UI entry point: the search-result menu item "Search related files (eD2k, local server)". It is gated on `GetRelatedSearchSupport()` and shows an error otherwise | aMule `SearchListCtrl.cpp:839,990-1017` |
| aMule builds `related` plus `"::" + GetFileHash().Encode()` for each selected result, puts it in the search box, forces search type **"Local"** and calls `StartNewSearch()` | aMule `SearchListCtrl.cpp:1003-1012` |
| aMule's local search sends one TCP `OP_SEARCHREQUEST` | aMule `SearchList.cpp:702-705` |
| Unlike eMule, aMule's `StartNewSearch()` appends any **extended-search constraints** that are enabled in the dialog, so its related request can carry extra AND terms | aMule `SearchDlg.cpp:1472-1507` |

The minimal request bytes, derived from the writers above (not captured):
`E3 <len32> 16 01 <len16=0x0029> "related::" <32 uppercase hex>`.

## 2. Server side

| Fact | Source | Confidence |
|---|---|---|
| A public eD2k server that `source-map.md` calls Lugdunum (45.82.80.155:5687) sent `OP_IDCHANGE` tcp-flags `F9 17 00 00`, which is `0x17F9` and includes bit `0x40` | `crates/rmule-ed2k/tests/fixtures/server/captured/welcome-burst-2026-05-17/02_id_change.bin` bytes 10..14; endpoint in `meta.toml:3`; "lugdunum servers" in `docs/protocol/source-map.md:204` | high for the bytes; medium that it is Lugdunum |
| The bench Lugdunum was also observed advertising `SRV_TCPFLG 0x17F9` | `docs/protocol/parity/server-tcp.md`, the `SRV_TCPFLG_*` row | medium (doc, not re-read from a capture here) |
| **The decompile reading of Lugdunum** is ed2k-server's comment: "`Is_related_search` (eserver decompile) recognises a search term literally beginning "related:", parses up to 32 `count:hash` pairs out of it, and rewrites the node to type 0x4F — so it is an ordinary search whose text has a special shape, not a separate opcode" | ed2ksrv@pin `src/proto/opcodes.rs:150-157` | medium (third party's decompile; not verified here) |
| Lugdunum's answer is an ordinary `OP_SEARCHRESULT` (`0x33`): a count, the rows, a trailing more-results byte `0x00`. For a file with five sources it holds 2 rows, the file itself and the one file its other sources also hold; for a file with one source it holds none | captured, run `1790603580`: `lugdunum_related_res_0x33.bin` (141 bytes, count 2), `lugdunum_related_res_rare_0x33.bin` (11 bytes, count 0), `crates/rmule-ed2k/tests/fixtures/server/captured/search-wire-20260928/` (`meta.toml`); §6 | high |
| Lugdunum's ranking is not known: the one five-source capture holds two rows | same fixtures | — |
| ed2k-server **advertises** TCP flag `0x40`, with hard-coded `tcp_flags = 0x05DD` | ed2ksrv@eacf7f1 `src/server/login.rs:106-124`; ed2ksrv@pin `src/server/login.rs:126,139` | high |
| ed2k-server **does not implement** the query. At the pin this is stated outright: "0x0040 RELATEDSEARCH is advertised and not implemented, deliberately … Documented rather than silently wrong; clearing the bit is one edit" | ed2ksrv@pin `src/proto/opcodes.rs:144,150-157` | high |
| Consequence: ed2k-server treats `related::<HASH>` as a plain filename term. Its tokenizer's separators do not include `:` (`keyword_index.rs:47-56` at eacf7f1, `:46-55` at pin), so the keyword-index lookup is for the literal token `related::<hex>`. Evaluation is `name_lower.contains(term)` (eacf7f1 `src/proto/search.rs:284-295`; pin `:369-372`). A related search therefore returns an empty result unless some filename happens to contain that string | ed2ksrv sources cited | high (source-read; no live probe) |
| The ed2k-server comment labels `0x0040` RELATEDSEARCH in its **UDP** flag table too (`SERVER_UDP_FLAGS = 0x073B`). But eMule and aMule define no `SRV_UDPFLG_*` at `0x40`, so no client reads that bit | ed2ksrv@pin `src/proto/opcodes.rs:126-144`; eMule `Server.h:46-53`; aMule `Client2Server/UDP.h:51-58` | high |

## 3. Limits

| Limit | Source | Confidence |
|---|---|---|
| The server must advertise TCP `0x40`, otherwise eMule greys out the menu and aMule refuses with a message box. Typing the string by hand is not gated: it goes out as an ordinary search | eMule `SearchResultsWnd.cpp:1658-1663`; aMule `SearchListCtrl.cpp:999-1016` | high |
| The request goes only to the connected server (TCP). It is never sent to other servers over UDP | eMule `SearchResultsWnd.cpp:1252`; aMule `SearchListCtrl.cpp:1010-1011` | high |
| Lugdunum accepts at most 32 hashes per request | ed2ksrv@pin `opcodes.rs:152` | medium |
| The target file "must be shared by at least 5 clients". A file with five sources is answered with rows, a file with one source with none; the threshold between 1 and 5 is not known | eMule `SearchResultsWnd.cpp:1667` (quoting the forum); captured, run `1790603580` | medium |
| No client-side cap on the number of hashes was found: both clients add every selected file | eMule `SearchResultsWnd.cpp:1680-1689`; aMule `SearchListCtrl.cpp:1006-1008` | high |
| Result cap: no reply came near one; the five-source answer holds 2 rows. Replies use the normal `OP_SEARCHRESULT` path and "More" (`OP_QUERY_MORE_RESULT`); nothing in either client is specific to related search | captured, run `1790603580`; §6 | high for 2 rows, unknown above |
| LowID: no client check exists. The request needs a logged-in TCP server session, which a LowID client has. A Low-ID requester got the same answers as a High-ID one | eMule `SearchResultsWnd.cpp:1658-1663`; captured, run `1790603580`; §6 | high |
| Rate limits: none found in either client. A server-side flood limit for Lugdunum was not found | — | — |
| Privacy: ed2k-server's maintainer notes the feature "would expose which publisher holds what", which is one reason it is left unimplemented | ed2ksrv@pin `opcodes.rs:155-156` | high (as their stated rationale) |

## 4. Kad equivalent

**None.**

- eMule's Kad search types are `NODE, NODECOMPLETE, FILE, KEYWORD, NOTES,
  STOREFILE, STOREKEYWORD, STORENOTES, FINDBUDDY, FINDSOURCE, NODESPECIAL,
  NODEFWCHECKUDP` (eMule `kademlia/kademlia/Search.h:76-87`).
- Its Kad2 search opcodes are `SEARCH_KEY_REQ 0x33`, `SEARCH_SOURCE_REQ 0x34`,
  `SEARCH_NOTES_REQ 0x35` and `SEARCH_RES 0x3B` (eMule `opcodes.h:588-595`).
- `NOTES` is keyed by file hash, but it returns comments and ratings, not
  related files.
- `rg -i related` over eMule `kademlia/` and aMule `src/kademlia/` finds only
  unrelated comments (eMule `Kademlia.cpp:264`; aMule `Kademlia.cpp:283`,
  `SearchManager.cpp:113`).
- A typed `related::<HASH>` sent to Kad would be split by the Kad keyword
  separators, which include `:` (`" ()[]{}<>,._-!?:;\\/\""`, eMule
  `SearchManager.cpp:56`). That turns it into a meaningless keyword search for
  `related` and the hex string.

Confidence: high.

## 5. rmule today

rmule builds the search as its own query kind, `SearchQuery::RelatedFiles`
(`crates/rmule-primitives/src/search/kind.rs`). The Global Search Sweep and the
Kad keyword walk take a `KeywordQuery`, so a related query cannot reach them.
The request frame's golden is **derived** from the writers in §1: no capture holds
a `related::` request from eMule or aMule. The replies are captured (§6).

| Rule | eMule / aMule | rmule | Status | Test |
|---|---|---|---|---|
| One `0x01` string term `related::<HASH>` in `OP_SEARCHREQUEST` (0x16) | eMule `SearchResultsWnd.cpp:1678-1685,869-873`, `Scanner.l:76,317`; aMule `SearchListCtrl.cpp:1003-1012`, `Scanner.l:45,59-62` | `RelatedSearchRequest::encode_packet` (`crates/rmule-ed2k/src/related_search_request.rs`) | parity (derived) | `session_search::a_related_search_writes_the_one_term_emule_and_amule_write` |
| Hash is 32 upper-case hex characters | eMule `OtherFunctions.cpp:60,1191-1193`; aMule `MD4Hash.h:182-196` | `FileHash::to_hex_upper` | parity | same golden |
| No constraint terms | eMule `SearchResultsWnd.cpp:1677-1678` (aMule may add the dialog's, `SearchDlg.cpp:1472-1507`) | none are carried | eMule parity | same golden |
| One hash per request | both add every selected row (eMule `:1680-1689`; aMule `:1006-1008`) | one, by type | deliberate (ADR-0037) | — |
| Connected server over TCP only | eMule `SearchResultsWnd.cpp:1248-1252`; aMule `SearchListCtrl.cpp:1010-1011` | sweep and Kad legs settled from the start (`service/actor/search.rs`) | parity | `related_search::a_related_search_reaches_neither_the_sweep_nor_kad_and_completes_on_the_empty_answer` |
| Offered only while connected | eMule `SearchResultsWnd.cpp:1658-1663` | `RelatedSearchRefusal::NotConnected`; never dials | parity | `related_search::a_related_search_with_no_session_is_refused_and_dials_nothing` |
| Offered only when `SRV_TCPFLG_RELATEDSEARCH` is granted | eMule `SearchResultsWnd.cpp:1658-1663`, `Server.h:40,159`; aMule `SearchListCtrl.cpp:999-1016` | `RelatedSearchRefusal::NotOffered`, and the eD2k session refuses unsent | parity | `related_search::a_related_search_toward_a_server_without_the_grant_is_refused_unsent`, `session_search::a_related_search_toward_a_server_without_the_grant_is_refused_unsent` |
| The grant is a level a menu reads | eMule re-reads `GetRelatedSearchSupport()` on every menu open | `DiagnosticsSnapshot::connected_server_grants` and `related_search_refusal()`, re-projected on every `OP_IDCHANGE` | parity | `related_search::the_grant_level_follows_a_server_switch`, `multiplexer::tests::related_search::a_mid_session_idchange_moves_the_grant_level` |
| A grant withdrawn between gate and send | — (eMule reads the flag at click time) | the search fails `RelatedSearchNotOffered`; the session stays | rmule-only | `multiplexer::tests::related_search::a_withdrawn_grant_fails_the_related_search_and_keeps_the_session` |
| An empty answer completes the search | normal `OP_SEARCHRESULT` path; Lugdunum's one-source answer is count 0 and more-results `0x00` (captured) | completes on the first answer, no per-server verdict | parity (captured) | the routing test above; the fixture decodes in `crates/rmule-ed2k/tests/ed2k/captured_search_wire.rs` |
| A typed `related::` phrase | goes out as an ordinary search, ungated (§3) | stays a keyword search, swept and sent to Kad | deliberate (ADR-0037) | — |

## 6. Captured

Bench run 1790603580 (Lugdunum 17.15), frames in
`crates/rmule-ed2k/tests/fixtures/server/captured/search-wire-20260928/`:

- The reply to `related::<HASH>` is an ordinary `OP_SEARCHRESULT` (count, rows,
  more-results byte `0x00`).
- A file with **five** sources: 2 rows — the file itself and the one file its other
  sources also hold (`lugdunum_related_res_0x33.bin`).
- A file with **one** source: an empty answer (`lugdunum_related_res_rare_0x33.bin`).
  The 5-source rule holds as far as 1 vs 5 can show.
- A **Low-ID** requester got the same answers as a High-ID one.
- ed2k-server (run 1790605441) granted the search and answered empty for both files.

## Open unknowns

1. Whether Lugdunum honours the `count:hash` / `size:hash` forms, its row cap above
   2 rows, its ranking, and the exact source threshold between 1 and 5.
2. The "v17.14 multi-hash" claim is unverified.
3. The upstream aMule UI was not checked. The kno fork may differ from upstream
   aMule (for example, its multi-select comment at `SearchListCtrl.cpp:992-993`).

## ed2k-server advertises the flag deliberately

At upstream HEAD `78b1e4f`, `src/proto/opcodes.rs:170-183` records `0x0040 RELATEDSEARCH`
as "NOT implemented — kept pending a decision": the maintainer advertises the bit on
purpose, judges the feature's value unproven at the server's index size, and notes that
it "would expose which publisher holds what". rmule's behaviour against such a server:
the action is offered because the server grants it, and an empty answer is reported as
what it is.
