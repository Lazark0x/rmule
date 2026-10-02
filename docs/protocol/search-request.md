# Search request: how a query becomes wire terms

Surface note: how eMule and aMule turn a typed phrase and
the search dialog's constraints into the `OP_SEARCHREQUEST` (`0x16`) expression tree,
the same tree inside the UDP `OP_GLOBSEARCHREQ` family (`0x98` / `0x92` / `0x90`), and
where the Kad keyword search differs — against what rmule sends. The tree grammar
itself is in `crates/rmule-ed2k/src/search_request.rs`; which search an answer
belongs to is ADR-0034 (Search Attribution).

## Sources and pins

| Short name | What it is | Pin |
|---|---|---|
| eMule | `srchybrid/` in the emule-qt reference pin (byte-identical to eMule 0.70b, `docs/reference/emule-source/eMule.meta.toml`) | irwir/eMule `13983526` |
| aMule | `src/` in the kno fork pin (kno fork) | kno/amule `ab483654` |
| ed2k-server | `~/.cargo/git/checkouts/ed2k-server-b80c5adba11d5604/eacf7f1` | `eacf7f1` |
| Lugdunum | closed source | — |

**Captures.** Before this note none of the 48 bench run archives
held an `OP_SEARCHREQUEST`. The bench leg `search-wire` (below) now holds them: runs
**1790603580** (Lugdunum) and **1790605441** (ed2k-server, with the aMule half and the
ed2k-server fixture from run 1790604060), archived per run under
`<run>/search-wire/<server>/` — a tcpdump
tap on the server (`server.pcap`), each requester's report (`high-id/`, `low-id/`),
aMule's `amulecmd` transcript, the server log. The frames the rulings rest on are
promoted, unedited, to `crates/rmule-ed2k/tests/fixtures/server/captured/search-wire-20260928/`.

## What the counterparties do with a phrase

Both clients run the typed text through a flex/bison grammar (aMule
`Scanner.l`/`Parser.y`, eMule the same pair). The scanner skips blanks and makes
every run of other characters a word; `OR`, `AND`, `NOT` (and eMule's `-` prefix)
are operators; a double-quoted run is one word. Words side by side are joined by an
implicit AND (`Parser.y:141-160`). Then, **when the expression holds only ANDs, both
clients join the words back into one string with single spaces and send that as one
`0x01` term** (aMule `SearchList.cpp:143-157`, eMule `SearchResultsWnd.cpp:808-822`).
Captured: aMule sent `ubuntu desktop` as `01 0e 00 "ubuntu desktop"`
(`amule_search_req_joined_0x16.bin`), and a quoted `"ubuntu desktop"` with its quotes
stripped — the same bytes.

rmule sends **one `0x01` term per word, AND-ed with aMule's interleave**: the tree the
lexer produced before the join. The phase-1 reason — that ed2k-server finds nothing
for a joined term — came from reading ed2k-server at `eacf7f1`; the bench image
(built from the `4da4774f` recipe, no commit label on the image) answered aMule's
joined term with the file. So the split does not rest on ed2k-server. It rests on
this: **Lugdunum answered the split form with the byte-identical `OP_SEARCHRESULT`
it gave aMule's joined form** (`lugdunum_search_res_split_0x33.bin` =
`lugdunum_search_res_joined_0x33.bin`), and so did ed2k-server; with Lugdunum's
reading shown to be whole-word per word (ruling 3), one term and AND-ed terms ask the
same question.

## Surface table

Status: **parity** (same bytes as the named counterparty), **fixed** (divergent
before this note, changed with it), **deliberate** (a recorded choice), **not offered**
(rmule has no control for it), **open** (not settled from source; see Gaps).

| Rule | eMule | aMule | rmule today | Status | Test |
|---|---|---|---|---|---|
| A phrase of several words is AND-ed words (lexer), joined into one `0x01` term when only ANDs remain | `Scanner.l:90`, `SearchResultsWnd.cpp:808-822` | `Scanner.l:49`, `Parser.y:141-160`, `SearchList.cpp:143-157` | one `0x01` per word, aMule's AND interleave (`search/terms.rs`, `search_request.rs` `encode_packet`) | deliberate split, **captured equal** on both servers (ruling 1) | `captured_search_wire::amules_joined_request_and_rmules_split_one_ask_lugdunum_the_same_thing`, `search_packets::a_multi_word_phrase_goes_out_as_one_term_per_word_anded`, `search_attribution::a_multi_word_query_reaches_the_server_as_one_term_per_word` |
| Word separator: blank only; other punctuation stays inside the word | `Scanner.l:76` (`[^ \"()<>=]`) | `Scanner.l:45` (`[^ \"()]`) | whitespace, and `(` `)` (never part of an aMule word); `.` `-` `_` stay inside the word | parity (tab also splits: rmule-only, harmless) | `search::terms::tests` |
| Quoting keeps a run whole | kept with its quotes (`Scanner.l:454-456`, `LexInit(..., true)` `SearchResultsWnd.cpp:999`) | quotes stripped (`Scanner.l:64-167`), so quoting changes no byte of an all-AND search | one `0x01` term with its quotes (eMule) | fixed; captured: Lugdunum reads the quotes as a phrase — `"sepspace spaceword"` found `sepspace spaceword.bin`, the reversed order found nothing; ed2k-server matched neither (quotes kept literal) | `search::terms::tests`, `search_packets::a_quoted_run_stays_one_term_with_its_quotes` |
| Explicit `AND` | the implicit join (`Scanner.l:92`) | same (`Scanner.l:51`) | dropped — the join is AND already | fixed (was: sent as the word `AND`) | `search::terms::tests` |
| `OR`, `NOT`, eMule's `-word` → `00 01` / `00 02` prefix nodes | `Scanner.l:91,93,315`; writer `SearchResultsWnd.cpp:1082-1087` | `Scanner.l:50,52`; `SearchList.cpp:177-195,1804-1814` | refused at `KeywordQuery::new`; `-word` is a word (aMule has no `-` rule) | not offered (ruling 2); aMule's `00 01` / `00 02` trees captured, Lugdunum answers both, ed2k-server answers `OR` empty | `search::terms::tests` |
| At most 10 operators, else "too complex" | `SearchResultsWnd.cpp:768-769` | `SearchList.cpp:113-115` | more than 11 words refused | fixed (was: no limit) | `search::terms::tests` |
| Constraint order and the AND interleave: phrase, type, min, max, sources, extension, `AND` before each but the last | prefix tree, constraints after the words (`SearchResultsWnd.cpp:1030-1070`) | interleave (`SearchList.cpp:1614-1680`) | aMule's interleave (`search_request.rs` `write_expression`) | parity (aMule); deliberate vs eMule | `search_packets::every_constraint_encodes_in_amules_order_with_the_prepended_ands` |
| File type strings `Audio` `Video` `Image` `Doc` `Pro`; archive and CD image go out as `Pro`; written ASCII | `SearchResultsWnd.cpp:968-979` | `SearchList.cpp:1555-1565,1629` | `Ed2kFileClass::search_term` (`file_class.rs:108-116`) | parity | `search_packets::archive_and_cd_image_type_filters_ride_the_pro_wire_term` |
| Size operators | `>=` / `<=` (`0x03` / `0x04`, `SearchResultsWnd.cpp:1038-1041`) | `>` / `<` (`0x01` / `0x02`, `SearchList.cpp:1640-1652`) | `0x01` / `0x02` | parity (aMule) | `search_packets::every_constraint_encodes_in_amules_order_with_the_prepended_ands` |
| A zero bound or zero availability writes no term | `> 0` guards (`SearchResultsWnd.cpp:1034-1041`) | `> 0` guards (`SearchList.cpp:1546-1551`) | zero is no bound (`KeywordQuery::with_*`) | fixed (was: a vacuous `> 0` term) | `search_packets::a_zero_bound_writes_no_term` |
| 64-bit size term `0x08`, only toward a server with large-file support; else clamp to `0xFFFFFFFF` in `0x03` | `SearchResultsWnd.cpp:902-920`, gate `:1218-1222` | `SearchList.cpp:225-257`, gate `:622-626` | TCP: per the connected server's `SRV_TCPFLG_LARGEFILES` (`session.rs:263-265`) | parity | `search_packets::an_oversize_size_bound_widens_only_for_a_large_file_server` |
| The same gate on the UDP sweep | packet built for the connected server; a 64-bit packet skips servers without large-file UDP (`SearchResultsWnd.cpp:273-295`) | same (`SearchList.cpp:920-966`) | per addressee: widened where the server advertises large-file UDP, clamped elsewhere (`global_sweep.rs`) | fixed (was: always clamped); deliberate vs both — a server without large files gets the clamped question instead of none | `search::tests::a_sweep_widens_a_large_bound_only_where_the_server_takes_it` |
| Extension `FT_FILEFORMAT`, bare | leading `.` stripped (`SearchParamsWnd.cpp:945`) | verbatim (`SearchDlg.cpp:1473`) | leading `.` stripped (`KeywordQuery::with_extension`) | fixed (was: verbatim on the wire; only the TUI stripped it) | `search_packets::an_extension_goes_out_without_its_dot` |
| Availability `FT_SOURCES` | `>=` (`SearchResultsWnd.cpp:1035`) | `>` (`SearchList.cpp:1654-1659`) | `>` | parity (aMule) | `search_packets::a_single_constraint_prepends_exactly_one_and` |
| Complete sources, codec, bitrate, length, title, album, artist | sent (`SearchResultsWnd.cpp:1046-1065`) | inside `#if 0` (`SearchList.cpp:1682-1730`) | none | not offered (aMule parity) | — |
| String encoding: raw UTF-8, no BOM, no server gate | `UTF8strRaw` (`SearchResultsWnd.cpp:1027`) | `utf8strRaw` ("I assume everyone is unicoded", `SearchList.cpp:1606-1610`) | UTF-8 bytes of `Ed2kText` (`search_request.rs` `write_len_prefixed_text`) | parity | `search_packets::an_accented_word_goes_out_as_its_utf8_bytes` |
| UDP `0x98` / `0x92` / `0x90` body is the TCP tree | `SearchResultsWnd.cpp:273-295` | `SearchList.cpp:920-966` | one encoder (`server_udp/search.rs`) | parity | `search::tests` (sweep variants) |
| Kad lead keyword: first ≥3-byte word, then — when only ANDs — the longest word of ≥3 characters with no Kad separator and no quote, strictly longer wins | `SearchResultsWnd.cpp:791-805` | `SearchList.cpp:612-619,126-141` | same (`rmule_kad::keyword::lead_keyword`) | fixed (was: first ≥3-byte word) | `keyword_derivation::the_lead_keyword_is_the_longest_eligible_word` (derived; the captured `0x33` target agrees) |
| Kad word rule: split on `" ()[]{}<>,._-!?:;\/"`, keep ≥3 UTF-8 bytes, lowercase | — | `SearchManager.cpp:291-311` | `rmule_kad::keyword` fold | parity (captured keyword id) | `captured_keyword_request` |
| Kad `0x33` carries the other words and the constraints as a tree | `GetSearchPacket(.., true, NULL)` `SearchResultsWnd.cpp:1310` | `SearchList.cpp:1597-1602`, captured tree | plain `0x33`, rows screened client-side | deliberate (ADR-0034 §5, ADR-0062) | — |
| Attribution reads the query's keywords as the wire carries them | — | — | each wire word, split again on the separator set, a **whole word** of a name, case- and accent-folded; a quoted run its words in order, side by side (`search/satisfaction.rs`) | fixed (ruling 3; was: substrings of the raw phrase, accents unfolded) | `search::a_row_proves_the_keywords_when_every_token_is_inside_one_name`, `search::a_row_proves_the_words_the_query_sends` |
| Search spacing on one link | one search in flight, ever | same (`SearchList.cpp:643-653`) | two seconds between requests on one server link (`answer_order.rs` `SEARCH_SPACING`) | fixed (ruling 4; was: every request at once) | `multiplexer::tests::search::three_searches_go_out_in_turn_and_each_row_lands_where_it_belongs`, `…::a_search_asked_soon_after_the_last_one_goes_out_two_seconds_after_its_send` |
| `0x98` spacing per server | one sweep, one packet per server | same | 300 ms per server across every sweep (`global_sweep.rs` `UdpSearchPacer`) | fixed (ruling 5) | `search::tests::sweeps_started_together_reach_one_server_spaced` |
| A result row whose `FT_FILETYPE` / `FT_FILEFORMAT` is not a string | read as a string or skipped, row kept (`AbstractFile.cpp:286-294`) | kept in the tag list (`SearchFile.cpp:69-100`) | kept as an extra tag | fixed (was: the whole answer dropped as `TagDecodeFailed`) | `captured_search_wire::an_integer_file_type_keeps_the_row` |

## Rulings (runs 1790603580 and 1790605441)

Lugdunum is `server version 17.15 (lugdunum)`; ed2k-server the bench image. Both
requesters (High-ID `.28`/`.48`, Low-ID `.29`/`.49`) drew the same answers, so Low-ID
changes none of the rulings.

1. **The form of a multi-word query: the split form stands for every server.**
   Lugdunum answered `AND("ubuntu","desktop")` and aMule's joined `"ubuntu desktop"`
   with byte-identical frames; the three-word forms agree too; ed2k-server answered
   both forms with the file. No server family needs detecting.
2. **`OR` / `NOT` stay refused.** Before phase 1 rmule never wrote `00 01` / `00 02`:
   the typed words went out inside the one phrase term
   (`git show a4cbbb96:crates/rmule-ed2k/src/search_request.rs`), so a server read
   `OR` as a word to find — no operator was lost. aMule's operator trees are captured
   (`amule_search_req_or_0x16.bin`, `amule_search_req_not_0x16.bin`): Lugdunum answers
   both; ed2k-server answers `NOT` and returns nothing for `OR` (an upstream
   report is drafted). Offering them is separate feature work: the query model and Search Attribution would both need a tree.
3. **Keyword reading.** Both servers match **whole words** only: `betaga`,
   `alphabet` and `gamma` found nothing in `tokenprobe-alphabetagamma.bin`,
   `alphabetagamma` found it. **Lugdunum folds accents** both ways (`cafe` → `Café…`,
   `résumé` → `resume…`); **ed2k-server does not** (only `café` found `Café…`).
   Separators: both split on `-` `_` `.` space `(` `)` `[` `]` `,`; ed2k-server also
   splits on `+`, Lugdunum does not. Attribution's owner rule reads no keywords, so it
   is never stricter than the server; a non-owner now needs every query word to be a
   whole word of a name, folded by case and accent — the loosest reading either server
   showed, over the union of their separators — and a quoted run its words in order,
   side by side in one name, as Lugdunum reads it.
4. **Spacing.** Lugdunum reads a link's searches by its clock's whole second
   (`search-spacing` leg, runs 1790762764 and 1790765267, 182 sweeps). A search in the
   same second as its link's previous one is answered **empty** (wrong answers, not
   silence); one in the same or the next second is a **strike**, strikes add up over the
   address's links, and the fourth closes the link, after which every later search from
   that address goes unanswered, a new login included. Four searches 900 ms apart on a
   fresh login keep the link (three strikes); after the search-wire probe's history, 1000
   ms lost the link in 12 of 14 sweeps, 1250 ms in 4 of 14, 1500 ms and 2000 ms (run
   1790771321) in none. Older runs
   closed at the fifth or sixth strike, so the count is not pinned. Three searches sent
   together were answered first with rows, then empty; ten together lost the link.
   ed2k-server answered 3, 10 and 30 together, every answer in place. rmule sends a
   server's requests **at least 2000 ms apart**, for every server: two whole seconds
   make neither an empty answer nor a strike — aMule never has two out, so none is owed
   more, and the family is not known before the first answer. A search held back says so
   on its status line — "Waiting its turn on this server · sent in N s"
   (`SearchEvent::SearchWaitingForTurn`) — until `SearchSentToServer`.
5. **The `0x98` burst.** ed2k-server answered 30 of 40, then logged `bot detected —
   banned 24h … qpm=1800000` and stopped answering, a status ping included. Lugdunum
   answered none (it never answers `0x98`) and banned nothing. The sweep now keeps
   **300 ms per server across every sweep** — 200 a minute, the detector's lower bound.
6. **Related-Files Search** (Lugdunum): the reply is an ordinary `OP_SEARCHRESULT`;
   for a file with five sources it listed the file itself and the file its other
   sources hold, 2 rows, more-results byte `0x00`; for a file with one source, an empty
   answer, more-results `0x00` — the 5-source rule holds. Low-ID requesters got the
   same. No reply came near a row cap. ed2k-server granted the search and answered
   empty for both (known: it does not implement it, `related-files-search.md` §2).
   Promoted: `lugdunum_related_res_0x33.bin`, `lugdunum_related_res_rare_0x33.bin`.

## More results

A server answers a search with at most one page of rows and says, in a trailing
byte, whether it holds more; `OP_QUERY_MORE_RESULT` (`0x21`) asks for the next page.
Sources as above; ed2k-server at `eacf7f1`. **Captures:** `rg -a` over the eleven
frames of `search-wire-20260928/` and a frame-by-frame scan of the six `server.pcap`
in the bench run archives (runs 1790602217, 1790602466,
1790603131, 1790603580, 1790604060, 1790605441) found **no `0x21` frame** and **586
`OP_SEARCHRESULT`s, every one ending `0x00`**. So every "more" vector below is
**derived** from source; only "the last page ends `0x00`" is captured.

| Rule | eMule | aMule | rmule today | Status | Test |
|---|---|---|---|---|---|
| The more-results byte: one byte after the rows, `0x01` more, `0x00` none; any other lone byte, or a longer tail, read as none | `SearchList.cpp:266-283` | read on a peer's shared-file list only (`SearchList.cpp:1046-1056`); a server's answer is read for its rows alone (`SearchList.cpp:1094-1106`) | read as eMule reads it (`SearchResults::more_available`); a longer tail still drops the answer as malformed | parity (eMule); `0x00` **captured** (586 answers), `0x01` derived (ed2k-server writes it, `search.rs:187`) | `captured_search_wire::a_captured_answer_says_it_is_the_last_page`, `session_search::the_more_results_byte_reaches_the_event` (derived) |
| Who asks: the operator only — eMule's *More* button, lit on an answer that said more (`SearchResultsWnd.cpp:470`), pressed (`SearchParamsWnd.cpp:671-686`) | operator only | **never**: `OP_QUERY_MORE_RESULT` is declared (`TCP.h:47`) and sent nowhere; its `RequestMoreResults` is Kad's (`SearchList.cpp:1324-1339`) | operator only: `n` on the Held Search (`SearchCommand::MoreResults`); never on its own | parity (eMule); the two references differ — aMule offers nothing, rmule follows eMule | `more::tests::n_asks_for_the_next_page_only_where_the_server_holds_more` |
| Payload: none — the opcode is the whole request, eDonkey protocol | `Packet()` with the opcode set (`SearchResultsWnd.cpp:1273-1289`, `Packets.h:45`) | — | `QueryMoreResults`, `e3 01 00 00 00 21` | parity (derived) | `session_search::a_request_for_more_is_the_bare_opcode_after_login_only` (derived) |
| How many times: five per search | `MAX_MORE_SEARCH_REQ` 5 (`Opcodes.h:61`), counter reset by a new search (`SearchResultsWnd.cpp:1240-1245`) | — | `MORE_RESULTS_ASKS` 5, per search; the status line says when rmule has stopped though the server has more | parity (eMule) | `more_results::a_search_asks_for_at_most_five_more_pages` |
| What the server keeps: one search's remaining rows per connection, replaced by every search request (a related one included) and cleared by an unparseable one | a new search greys *More* (`SearchResultsWnd.cpp:1240-1245`) | — | the session's **pager**: the search whose own answer said more while its request was the newest on the link; any search request put on the link ends it, and a request for more waiting behind one is dropped unsent | derived (ed2k-server `connection.rs:68-70,435,442`); Lugdunum unknown | `more_results::more_said_after_a_later_request_went_out_is_nobodys`, `…a_request_for_more_behind_another_search_is_not_sent` |
| A request for more when none exist | never sent: *More* is lit only by an answer that said more | — | never sent: refused in the session (`MoreNotOffered`) and said to the operator | ed2k-server answers an empty page ending `0x00` (`connection.rs:519-530`, derived); Lugdunum leaves it unanswered: no answer in 6 s, the link kept (captured, run 1790723997 `past-last` and `lapse-more`, both requesters) | `core::search_more_results::the_next_page_joins_the_same_result_set` (the refusal) |
| Telling its answer apart: it carries no search id, like any answer. It is the answer in its place — a request for more is a request on the link like any other, owned by the search that asked, and spaced a second from the last (Lugdunum's flood rule counts it) | its one search takes the next `OP_SEARCHRESULT` (`ServerSocket.cpp:356-363`) | — | Search Attribution's answer order, unchanged: queued, spaced, its answer the oldest request's; rows join the asking search's **Search Result Set** | derived | `more_results::the_next_page_is_the_asking_searchs_own_answer`, `core::search_more_results::the_next_page_joins_the_same_result_set` |
| ed2k-server's page | — | — | — | caps every search at 200 rows and pages 200 (`search.rs:19,138`): its byte is never `0x01` at `eacf7f1` (derived) | — |

The bench leg that would capture a real exchange is `search-wire --more-results`
(450 files under one word; the probe walks every page, one request past the last, and
one after another search). Run 1790723997 against Lugdunum captures the `0x21` request
(`e3 01 00 00 00 21`) and pages that end `0x01`: the Low-ID requester's walk drew 153, 156
and 141 rows (`0x01`, `0x01`, `0x00`), the High-ID one's 309 and 49 while sharer 0 was still
offering its files. A request past the last page, and one after another search whose
answer said no more, drew no answer; a search between them was answered in place.

## Gaps

| Rule | What the run showed | Why it is still open |
|---|---|---|
| How many strikes close a Lugdunum link, whether strikes decay, and how long its per-address silence lasts | every close of runs 1790762764 and 1790765267 (16 of 182 sweeps) fell on the fourth strike; older runs closed at the fifth or sixth (1790603131, 1790603580, 1790724663, 1790725188); the silence outlasted each run | the closed binary shows its rule only by measurement: sweeps that vary the strikes' spacing in time on one address, and a run that waits out the silence |
| Lugdunum's page size | pages of 153–156 rows to a Low-ID requester, 309 to a High-ID one (run 1790723997) | one run; whether the size follows the requester's ID or the load is not separated |

The leg is `search-wire` (`tools/interop-harness`, flow table in its README); one
server per invocation (`--server lugdunum|ed2k-server`) keeps a run inside ten minutes.
