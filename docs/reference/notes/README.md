# Protocol notes

This directory holds rmule-authored, implementation-facing notes about each protocol topic. Each topic note synthesizes evidence from the cached sources under `docs/reference/<source-family>/` and from link-only sources in `docs/protocol/source-map.md`.

See `docs/adr/0015-per-topic-protocol-notes.md` for the discipline these notes follow:

- Implementation-facing — wire-format tables, byte offsets, edge cases, behaviors to test.
- Not a wiki rewrite — if a note grows into paraphrase, that signals the upstream should be vendored (or cached locally with a clear citation) instead.
- Cited — every claim points to a cached file path (with line where useful) or a pinned upstream URL.

Status flags used per topic note:

- `implemented` — rmule implements the topic.
- `next` — primary research target for upcoming work.
- `deferred` — listed for completeness; deep wire details to be written when the implementing work begins.

| Topic | File | Status |
| --- | --- | --- |
| Packet framing | [packet-framing.md](packet-framing.md) | implemented |
| ED2K tags | [tags.md](tags.md) | implemented |
| ED2K hash | [ed2k-hash.md](ed2k-hash.md) | implemented |
| ED2K link | [ed2k-link.md](ed2k-link.md) | implemented |
| User hash | [user-hash.md](user-hash.md) | implemented |
| ED2K login | [ed2k-login.md](ed2k-login.md) | implemented |
| ED2K server protocol index | [ed2k-server-protocol.md](ed2k-server-protocol.md) | implemented |
| ED2K source lookup | [ed2k-source-lookup.md](ed2k-source-lookup.md) | implemented |
| AICH | [aich.md](aich.md) | deferred |
| Kad | [kad.md](kad.md) | deferred |
| Peer transfer | [peer-transfer.md](peer-transfer.md) | implemented |
| Obfuscation | [obfuscation.md](obfuscation.md) | deferred |
| Secure user identification | [secure-ident.md](secure-ident.md) | deferred |
