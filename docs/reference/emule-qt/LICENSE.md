# emule-qt content license

The cached tree is `ModderMule/emule-qt` at commit
`73fff7146d2eec3e8426251ec4959238bae3479a` — a Qt6 / C++23 cross-platform rewrite of
eMule.

## The declared licence is bare GPL-2.0, with no "or later" grant

An exhaustive header audit of the tree at this pin (2026-09-11) found:

- **672 of 677** classifiable files carry **no copyright or licence header at all** —
  not GPL-2-only, not GPL-2-or-later, nothing. The dominant shape is a Doxygen
  `@file`/`@brief` comment straight into `#include`.
- **5** carry an explicit grant, and all five are **inherited eMule boilerplate** rather
  than newly authored: four `src/core/media/*.cpp` files that kept
  `SPDX-License-Identifier: GPL-2.0-or-later` through a direct MFC port, plus
  `data/incoming/readme.txt`.
- **0** state GPL-2-only explicitly.

The only declaration governing the other 672 is repository-level: `README.md` says
`GPL-2.0`, and the root `LICENSE` is the unmodified FSF GPLv2 template. Neither adds an
"or later" grant. (`LICENSE` does contain the phrase inside the FSF's own generic "How to
Apply These Terms" appendix, but that is instructional boilerplate describing what a
licensor *could* choose — not a choice this project made.) There is no `COPYING`,
`NOTICE`, or `AUTHORS` file, and `src/vcpkg.json` has no `license` key.

## What that means for rmule

**Read for facts only. No derived logic, at all.**

This is a *narrower* permission than the one granted for the eMule Reference Source, and
it is narrower for a licence reason rather than a discipline one. rmule is
`GPL-3.0-or-later`; the eMule tree's explicit or-later grant makes it legally derivable
(rmule declines on ADR-0004 discipline grounds), whereas this tree's bare `GPL-2.0`
declaration supplies no such grant. See
[ADR-0082](../../adr/0082-emule-reference-source.md).

Facts about the protocol — what byte an implementation writes, what a spec document
states — are not copyrightable and may be recorded in rmule-authored notes.

## Do not read `srchybrid/` from this clone

The tree vendors the original eMule MFC source under `srchybrid/`. It is registered
separately as rmule's **Reference Source** and pinned at its own upstream
(`irwir/eMule`), because a byte-for-byte diff proved the two identical and routing
through a rewrite's copy adds a dependency for nothing. Read it from
`docs/reference/emule-source/` instead, where its own licence status is recorded.

## Redistribution

**Not vendored.** Bytes are gitignored and live only on contributor machines under
[ADR-0013](../../adr/0013-pinned-local-reference-cache.md). Given the absent
or-later grant, this tree could not be vendored into a GPL-3-or-later repository even if
the local-cache policy allowed it.

To fetch it locally, clone the `source_url` of [`emule-qt.meta.toml`](emule-qt.meta.toml) into its
`local_path` and check out its `commit`; [`../README.md`](../README.md#filling-the-cache) has the steps.

This LICENSE.md is rmule-authored metadata about the upstream license status.
