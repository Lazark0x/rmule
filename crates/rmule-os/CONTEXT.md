# rmule-os

The operating-system calls rmule needs that std does not expose, kept in a crate of their own so every other crate keeps `unsafe_code = "forbid"` (ADR-0111). It owns no socket and no file: `rmule-net` binds every socket and hands each unconnected UDP one here once, at the bind; `rmule-core` opens every part file and lends the handle here for one call; the TUI asks it which app opens an extension. It decides nothing — what to punch and what a reading means are core's.

## Language

**ICMP-reset switch**:
`SIO_UDP_CONNRESET` and `SIO_UDP_NETRESET` set to `FALSE` on a UDP socket. Windows otherwise answers a datagram that drew an ICMP port- or net-unreachable with an error on the socket's next receive, even on an unconnected socket and whichever peer the datagram went to; a run of them ends a receive pump. Linux and macOS never report these on an unconnected socket, so the switch makes Windows receive as they do. A connected socket does not take it: there the ICMP answer is the reply that ends the exchange early, on every platform.
_Avoid_: connreset fix, ICMP workaround, WSA hack

**Sparse flag**:
`FSCTL_SET_SPARSE` on a Windows file handle. Until it is set, NTFS allocates every byte up to the end of the file and a **Punch** writes zeros instead of freeing them; FAT and exFAT refuse it. Off Windows every file can hold holes as it is, so setting it does nothing.
_Avoid_: sparse mode, sparse support

**Punch**:
Freeing a byte range of a file without changing its length: `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` on Linux, `fcntl(F_PUNCHHOLE)` on macOS, `FSCTL_SET_ZERO_DATA` on Windows. The range reads back as zeros. The caller aligns it; a filesystem that cannot punch answers with an error, never a panic.
_Avoid_: trim, deallocate, hole punching

**Default app lookup**:
Which app the system opens a file-name extension with: on macOS the LaunchServices default for the extension's type, for any role, as the bundle's path; on Windows the executable of the extension's `open` verb, with the Unknown type ignored so a type with no app answers none. The extension is the caller's to read from a name; what to start the app on is the TUI's (ADR-0114). Linux has no such call: the freedesktop files are read by the TUI.
_Avoid_: file association, open-with, handler

**The waived functions**:
The functions `scripts/guards.sh` (check `unsafe`) pins by file and name. This crate's lint table relaxes `unsafe_code` to `deny`; each pinned function waives it once and holds one `unsafe` block under a `// SAFETY:` comment, and may declare the foreign function it calls, when no crate in the graph does, in one `unsafe extern` block under its own `// SAFETY:` comment. A safe call is used wherever one exists — the Linux punch through `rustix`, the Unix allocated size through std — and nothing else here, or outside this crate, holds `unsafe` code or a waiver.
_Avoid_: unsafe module, FFI layer
