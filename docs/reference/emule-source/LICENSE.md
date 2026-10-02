# eMule source content license

The cached tree is eMule 0.70b community edition, pinned at `irwir/eMule` commit
`13983526945d58b0bc1123619a795cf1e6b80aba`.

## The eMule devteam code

Per-file headers carry the eMule devteam grant verbatim:

> This program is free software; you can redistribute it and/or modify it under the terms
> of the GNU General Public License as published by the Free Software Foundation; either
> version 2 of the License, or (at your option) any later version.

That "or later" clause makes the tree **GPL-2.0-or-later**, which is compatible with
rmule's `GPL-3.0-or-later`. The repository-level copyright is
`Copyright (C)2002-2024 Merkur`.

**This compatibility does not grant rmule permission to port.**
[ADR-0004](../../adr/0004-gpl-3-or-later-and-no-ported-source.md) forbids
pasting, translating, or mechanically porting eMule source into rmule, and
[ADR-0082](../../adr/0082-emule-reference-source.md)
re-affirms it deliberately rather than by inheritance. The tree is read to learn *facts
about the protocol* — what byte goes where, what a constant is. Facts are not
copyrightable; expression is.

## Third-party code inside the tree

The tree is not uniformly devteam-licensed. Known inclusions under other terms:

| Path | Terms |
| --- | --- |
| `srchybrid/MD4.cpp`, `srchybrid/MD5Sum.h` | RSA Data Security, Inc. permissive attribution notice (not GPL) |
| `srchybrid/SHA.h`, `srchybrid/SHA.cpp` | Brian Gladman dual licence: permissive, **or** GPL at the user's option (no version named) |
| `srchybrid/MD4.h`, `srchybrid/ZIPFile.*`, `srchybrid/UPnPImplWinServ.*` | Shareaza Development Team copyright, GPL-2-or-later |
| `srchybrid/AsyncSocketEx.h`, `TreePropSheet.h`, `ColourPopup.h`, `MemDC.h`, `QArray.h`, `TimeTick.h`, `ProgressCtrlX.h` and similar | Informal "freeware, keep this notice" grants from CodeGuru/CodeProject-era MFC utility classes; not GPL, not any OSI-recognised licence text |

CryptoPP, zlib and id3lib are `#include`d but **not** vendored in this tree; they are
external build dependencies.

## Redistribution

**Not vendored.** The bytes are gitignored and live only on contributor machines, under
the local-cache policy of
[ADR-0013](../../adr/0013-pinned-local-reference-cache.md). This is not a licence
restriction — the or-later grant would permit vendoring — but the
physical-separation argument of
[ADR-0013](../../adr/0013-pinned-local-reference-cache.md): separation enforces the
no-porting rule better than an in-tree notice, and 130 MB of C++ in a Rust repository
degrades every search.

To fetch it locally, clone the `source_url` of [`eMule.meta.toml`](eMule.meta.toml) into its
`local_path` and check out its `commit`; [`../README.md`](../README.md#filling-the-cache) has the steps.

This LICENSE.md is rmule-authored metadata about the upstream license status.
