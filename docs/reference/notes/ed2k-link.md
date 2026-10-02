# ED2K link

**Status:** implemented
**Scope:** the `ed2k://` URI family — file, server, server-list — including optional `p=` and `h=` metadata.

ED2K links are how files and servers are exchanged between users out-of-band. They carry enough identity to add a file to a download queue or to add a server to the server list, but they do not start network operations on their own.

## Grammar (informal)

```
ed2k:// "|" TYPE "|" REST "|" "/"
```

Field separator: `|`. Trailing `|/`.

`TYPE` is one of:

- `file`
- `server`
- `serverlist`

(`friend`, `nodes`, and other types exist in the wild but were out of the first parser's scope.)

### File link

```
ed2k:// |file| NAME |SIZE| ED2K_FILE_HASH |[OPTIONAL_FIELDS]| /
```

- `NAME`: percent-encoded file name (spaces as `%20`, not `+`).
- `SIZE`: decimal byte count.
- `ED2K_FILE_HASH`: 32 hex chars (uppercase canonical).

Optional fields (the first parser's scope: `p=`, `h=`; everything else was rejected):

- `p=HASH1:HASH2:...` — the `ED2K Part Hash Set`; uppercase hex; colon-separated. Count rules per `ed2k-hash.md`.
- `h=AICH_ROOT` — the AICH root hash; uppercase unpadded base32, 32 chars.

Optional fields **rejected** by the first parser (per ADR-0008 "lenient links and strict packets" + `docs/protocol/fixtures.md`):

- `s=URL` — HTTP mirror URL. Semantics not modeled.
- `sources,IP:Port,IP:Port,...` — source list suffix. Semantics not modeled.
- Unknown keys. Reject rather than silently preserve.
- Duplicate `p=` or `h=`. Reject as malformed.

### Server link

```
ed2k:// |server| IP_OR_DNS |PORT| /
```

A server link contains a `Server Endpoint` (host + port). It does **not** contain `Server Identity` (name, description, capabilities) — those come from server protocol metadata, not from the link.

### Server-list link

```
ed2k:// |serverlist| URL_TO_SERVERLIST_FILE | /
```

Address payload is preserved without aggressive URL normalization.

## Canonical formatting

When rmule formats a link, it applies these normalizations (all per `docs/protocol/fixtures.md`):

- Lowercase scheme (`ed2k://`) and type names (`file`, `server`, `serverlist`).
- Uppercase hex for ED2K file and part hashes.
- Uppercase unpadded base32 for AICH root hashes.
- Decimal sizes and ports without leading zeroes.
- File names percent-encoded with `%20` for spaces; safe escapes decoded before re-encoding.
- Optional fields ordered `p=` before `h=`.
- No extra separators beyond the final `|/`.
- Lowercase DNS server hostnames; preserve IP literals as-is.
- Preserve server-list address payloads.

## Parsing strategy

Per ADR-0008 and `docs/protocol/fixtures.md`, the link parser is explicit and hand-written. Parser-combinator dependencies are deferred. This keeps the link grammar fully visible in one file for fixture-driven iteration.

## Sources

Cached:

- `docs/reference/amule-wiki/ed2k_link.wikitext` — primary grammar reference, including the file/server/serverlist split and the `p=` / `h=` / `s=` / `sources,` extensions.
- `docs/reference/wikipedia/ed2k_uri_scheme.wikitext` — cross-check on link grammar and examples.

Link-only:

- aMule source (GPLv2): link parsing lives in `src/MagnetURI.cpp` and adjacent files. Pinned commit SHA in `docs/protocol/source-map.md`.

## Open questions

- None were outstanding for the first parser. The decision to reject `s=` and `sources,` until their semantics are modeled is locked in `docs/protocol/fixtures.md`.
