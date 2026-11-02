# rmule-os

The operating-system calls rmule needs that std does not expose, kept in a crate of their own so every other crate keeps `unsafe_code = "forbid"` (ADR-0111). It owns no socket and no file: `rmule-net` binds every socket, hands each unconnected UDP one here once, at the bind, and lends a stalled TCP stream here for one reading; `rmule-core` opens every part file and lends the handle here for one call; the TUI asks it which app opens an extension. It decides nothing — what to punch and what a reading means are core's.

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

**Exclusive rename**:
`rename_exclusive`: a file moved onto a path with the call itself refusing when something stands there, so no check-then-rename gap can overwrite a file rmule did not write. `renameat` with the no-replace flag through `rustix` on Linux and macOS, `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` on Windows. A filesystem that refuses the flag answers `Unsupported` and a destination that exists answers `AlreadyExists`, both with the files untouched; the completion move lands every file with it (ADR-0115).
_Avoid_: safe rename, no-clobber move

**Default app lookup**:
Which app the system opens a file-name extension with: on macOS the LaunchServices default for the extension's type, for any role, as the bundle's path; on Windows the executable of the extension's `open` verb, with the Unknown type ignored so a type with no app answers none. The extension is the caller's to read from a name; what to start the app on is the TUI's (ADR-0114). Linux has no such call: the freedesktop files are read by the TUI.
_Avoid_: file association, open-with, handler

**Descriptor limit**:
The process's soft `RLIMIT_NOFILE`: how many files and sockets it may hold open at once. A binary raises it once, at its start, toward the hard limit — on macOS no higher than `OPEN_MAX` (10240), above which the kernel refuses a soft limit — and reads back the limit in force; a refused raise keeps the limit as it was. Windows states none, and neither does an unlimited soft limit. The Connection Ceiling the binary derives from it is core's (ADR-0116).
_Avoid_: ulimit, fd limit, max files

**Send side**:
What the kernel can say about a TCP stream's written bytes, one reading of it a `SendProgress`. On Linux (`SIOCOUTQ`) and macOS (`SO_NWRITE`) the bytes it still holds, unsent and unacked, which fall as the peer acknowledges. Windows counts no byte it has not sent, so `SIO_TCP_INFO` gives the bytes acknowledged, which rise. Two readings compare only through `is_past`, and only across a span with no write. A system that refuses answers none, which is never movement. What a reading means for a connection is `rmule-net`'s (ADR-0031).
_Avoid_: send queue length, outq, backlog

**Hang-up**:
A terminal's end as standard input reports it: `POLLHUP` or `POLLERR` from `poll`. macOS reports it only to a `poll` that also asks for input, and `POLLNVAL` is a device `poll` cannot watch, never a hang-up.
_Avoid_: EOF check, disconnect

**Blanked streams**:
The standard streams once a terminal is lost: input a pipe nobody writes, so a reader blocks where it would spin; output and error, where they were the terminal, the null device. Safe `rustix` calls, no waiver.
_Avoid_: closing stdio, redirecting to null

**The waived functions**:
The functions `scripts/guards.sh` (check `unsafe`) pins by file and name. This crate's lint table relaxes `unsafe_code` to `deny`; each pinned function waives it once and holds one `unsafe` block under a `// SAFETY:` comment, and may declare the foreign function it calls, when no crate in the graph does, in one `unsafe extern` block under its own `// SAFETY:` comment. A safe call is used wherever one exists — the Linux punch through `rustix`, the Unix allocated size through std — and nothing else here, or outside this crate, holds `unsafe` code or a waiver.
_Avoid_: unsafe module, FFI layer
