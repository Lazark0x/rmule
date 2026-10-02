# rhash content license

The cached file `ed2k.c` from the rhash project is under a permissive BSD/MIT-style license. The file header reads:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so.

The rhash project COPYING file at <https://sources.debian.org/src/rhash/1.3.8-1/COPYING/> records the same terms.

Sidecar files record the license as `MIT-style`.

**Porting restriction:** Even though the license is permissive, rmule must not port this code (see ADR-0004). The file is cached as reference material for the eMule/aMule exact-part-size ED2K hash variant only. Behavioral findings should be summarized in `docs/reference/notes/ed2k-hash.md` and re-implemented in rmule's own code without textual reuse.

This LICENSE.md is rmule-authored metadata about the upstream license. The raw file itself is gitignored and not redistributed from this repository; see ADR-0013.
