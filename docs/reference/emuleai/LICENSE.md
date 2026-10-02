# eMuleAI source content license

The cached tree is eMuleAI v1.6, pinned at `eMuleAI/eMuleAI` commit
`a2f05dc8db772a11ca874adf0a16baaf30560519`.

## What it is

eMuleAI is an eMule mod — its `srchybrid/` tree descends from the eMule devteam's,
whose per-file headers carry the grant verbatim:

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

The tree carries the same third-party notices eMule 0.70b does (RSA Data Security
MD4/MD5 reference notices, Brian Gladman's permissive-or-GPL SHA, Shareaza-copyrighted
files, informal CodeProject-era MFC helpers), plus the NAT-T transport dependencies
(libutp, ngtcp2/GnuTLS bindings) under their own terms. See
[`../emule-source/LICENSE.md`](../emule-source/LICENSE.md) for the shared inheritance.

## Why it is cached, not vendored

Per [ADR-0013](../../adr/0013-pinned-local-reference-cache.md) the raw bytes stay
gitignored; only this file and the sidecar are committed.
