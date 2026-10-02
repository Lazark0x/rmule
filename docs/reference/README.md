# Reference Documents

This directory is a **local protocol reference cache**. It pairs committed metadata with gitignored raw bytes so contributors can read protocol sources offline without redistributing license-uncertain content. See `docs/adr/0013-pinned-local-reference-cache.md`.

## What is committed

- `<source-family>/*.meta.toml` — per-document sidecar with source URL, retrieval date, license verdict, sha256, and reason for caching.
- `<source-family>/LICENSE.md` — what we know about the source family's content license.
- `notes/<topic>.md` — rmule-authored, implementation-facing protocol notes that cite both cached sources and link-only sources.

## What is not committed (gitignored)

- The raw cached bytes themselves: PDFs, wiki HTML, source files. See `.gitignore` for the extension whitelist.

## Filling the cache

Each `*.meta.toml` sidecar names everything needed to rebuild its entry by hand: where the source lives (`source_url`), where its bytes go (`local_path`) and how to verify them. Fill only the entries you need; skip a sidecar whose `fetch_status` is not `"ok"`.

Two source kinds:

| `kind` | Fetch | Integrity check |
| --- | --- | --- |
| `file` (default, may be omitted) | `curl` the `source_url` to `local_path` | `sha256` of the fetched file |
| `git` | clone `source_url`, check out `commit` | `commit` SHA — git objects are content-addressed, so no `sha256` field applies |

From the repo root, with `meta` set to the sidecar you want, this reads the fields:

```sh
meta=docs/reference/emule-qt/emule-qt.meta.toml
field() { sed -nE "s/^$1[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\1/p" "$meta" | head -n 1; }
```

A `git` source: clone it at the pinned commit, then confirm `HEAD` is that commit.

```sh
git clone "$(field source_url)" "$(field local_path)"
git -C "$(field local_path)" checkout "$(field commit)"
git -C "$(field local_path)" rev-parse HEAD    # must print the sidecar's commit
```

A `file` source: fetch it, then compare its digest with the sidecar's `sha256`. Some wikis refuse curl's default user agent; pass `-A 'Mozilla/5.0'` if the fetch returns an error page.

```sh
mkdir -p "$(dirname "$(field local_path)")"
curl -sSL "$(field source_url)" -o "$(field local_path)"
shasum -a 256 "$(field local_path)"            # must print the sidecar's sha256
```

The interop images need two `git` entries: `amule-kno/amule-kno.meta.toml` for `tools/interop-harness/images/amule-kno` and `emule-qt/emule-qt.meta.toml` for `tools/interop-harness/images/emuleqt`. `scripts/audit-reference-constants.py` needs `emule-source/eMule.meta.toml`. An existing clone that is not at the pinned commit is brought there with `git -C <local_path> fetch` and the same `checkout`.

## License tiers

| Tier | Behavior |
| --- | --- |
| Confirmed redistributable | Could be moved to vendored layout under ADR-0013 in the future. For now, cached the same way as everything else. |
| Unconfirmed | License footer unreachable, page returns 403, or PDF carries no license notice. Cached locally only. |
| Restricted | Source is GPLv2 or proprietary site. Cached only when the cache contributor accepts personal responsibility for local-fair-use reading. Never committed. |

The sidecar's `license` field records the actual verdict per source. "unconfirmed" and "restricted" entries stay gitignored even if a future ADR loosens vendoring policy.

## Adding a new source

1. Decide source family (`<source-family>/` directory). License clusters by family.
2. Resolve the immutable URL (e.g. MediaWiki `?oldid=NNN&action=raw`, Debian-snapshot URL).
3. Run `curl -sSL '<url>' -o docs/reference/<family>/<slug>.<ext>` once.
4. Compute `shasum -a 256 docs/reference/<family>/<slug>.<ext>`.
5. Write `docs/reference/<family>/<slug>.meta.toml` with all required fields (see existing sidecars for shape).
6. If the family is new, write `docs/reference/<family>/LICENSE.md`.
7. Commit the sidecar (and LICENSE.md). The raw file is already gitignored.

For a `kind = "git"` source, steps 2-4 become: pin a **commit SHA**, not a branch or tag —
tags are mutable, and the SHA is already the integrity check. Omit `sha256`. Add the
checkout path to `.gitignore` by path, since the whole clone is the cached bytes and the
extension whitelist does not cover it.

Later contributors fill the entry from its sidecar as described under [Filling the cache](#filling-the-cache).
