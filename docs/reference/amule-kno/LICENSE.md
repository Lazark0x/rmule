# amule-kno source content license

The cached tree is the `kno/amule` network-parity fork, pinned at commit
`ab483654f3c975face368184912138513184e3f0` on its `integration/network-parity` branch.

## What it is

The fork's root `LICENSE.md` states that aMule is released under the GNU General Public
License, version 2 or later, and carries the full GPL-2.0 text; the fork also keeps the
FSF's `docs/COPYING` (GNU GPL, Version 2, June 1991) at the pinned commit. The per-file
headers grant the same terms; for example `src/SearchList.cpp` reads:

> This program is free software; you can redistribute it and/or modify it under the terms
> of the GNU General Public License as published by the Free Software Foundation; either
> version 2 of the License, or (at your option) any later version.

That "or later" clause makes the tree **GPL-2.0-or-later**, compatible with rmule's
`GPL-3.0-or-later`.

**This compatibility does not grant rmule permission to port.**
[ADR-0004](../../adr/0004-gpl-3-or-later-and-no-ported-source.md) forbids
pasting, translating, or mechanically porting the tree into rmule, and
[ADR-0082](../../adr/0082-emule-reference-source.md)
re-affirms it deliberately rather than by inheritance. The tree is read to learn *facts
about the protocol* — what byte goes where, what a constant is, which surface a bit
actually reaches. Facts are not copyrightable; expression is.

## Third-party code

The fork's `docs/THIRDPARTY.md` lists the components bundled into aMule binary
distributions that keep their own permissive licenses: picojson (BSD 2-Clause) and the
muleunit test framework (LGPL-2.1). The vendored libutp under `src/extern/libutp/` carries
its own terms and provenance note.

## Why it is cached, not vendored

Per [ADR-0013](../../adr/0013-pinned-local-reference-cache.md) the raw bytes stay
gitignored; only this file and the sidecar are committed.

This LICENSE.md is rmule-authored metadata about the upstream license status.
