# AniDB wiki content license

The AniDB wiki at `wiki.anidb.net` returns HTTP 403 to scripted clients due to Cloudflare or similar bot protection. The license footer cannot be confirmed without a browser session.

Sidecar files record the license as `unconfirmed`.

**Redistribution restriction:** Until the upstream license is confirmed manually, AniDB content must not be vendored under ADR-0013 vendoring policy. Cached copies live under ADR-0013 local-cache policy: bytes are gitignored, present only on contributor machines, never committed.

If a contributor confirms the license from a browser session, update the sidecar `license` and `license_url` fields and add the verified license text to this file.

This LICENSE.md is rmule-authored metadata about the upstream license status.
