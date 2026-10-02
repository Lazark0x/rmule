# Changelog

All notable changes to rmule are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-02

The first public release.

### eD2k servers

- Log in to an eD2k server over TCP, plain or obfuscated, with a High ID or a
  Low ID.
- A managed server list that keeps each server's name, priority, static pin
  and failure count; add servers one by one or update the list from a
  `server.met` URL. While the list is empty, a `server.met` is fetched at
  start, and a setting turns that off.
- Server UDP: global search, global source requests and status pings to every
  listed server.
- A lost server session is made again while you still want to be connected;
  nothing dials a server until you connect or turn on Autoconnect.

### Search

- One search goes to the connected server, to the other servers over UDP and
  to Kad at once, and the results merge.
- Filters for file type, size, sources and extension; more results from the
  server on request; related-files search.
- Every result says whether you already have, are fetching, failed, had or
  dropped the file.

### Downloads

- Downloads from many peers at once, assembled block by block, with AICH
  recovery of corrupt blocks.
- Sources from the server, server UDP, Kad, source exchange and the `ed2k://`
  link itself.
- Low-ID sources reached by callback: through the server, through a Kad buddy
  or by a direct UDP request.
- Pause and resume; downloads, their verified parts and their known peers
  survive a restart.

### Uploads and sharing

- An upload queue with Secure User Identification and credits, kept in
  `clients.met` as eMule and aMule keep them.
- Queue standing survives a disconnect, kept by UDP reasks.
- Shared directories: whole and recursive, hashed one file at a time and
  watched for changes. Finished downloads are shared.

### Kad

- A full Kad2 node: bootstrap from `nodes.dat`, routing, keyword search and
  publishing, source lookup and publishing, firewall checks, and buddies for
  Low-ID nodes.

### Connectivity

- Protocol obfuscation for peer TCP, peer UDP, Kad and server UDP under one
  setting.
- IPv6 in the dialect emule-qt speaks.
- Port mapping with PCP, NAT-PMP and UPnP, on by default, with a setting to
  turn it off.
- An IP filter read from `ipfilter.dat` and `ipfilter_static.dat` in the data
  directory.
- NAT traversal in the dialect eMuleAI speaks.

### `rmule`, the terminal client

- Six tabs in aMule's order: Networks, Searches, Transfers, Shared Files,
  Statistics and Settings.
- Keyboard and mouse control, sortable tables, a help overlay, and dark,
  light and 256-colour themes.
- A Run Log, `rmule.log`, at a lean level or a detailed one.

### `rmule-cli`, the headless client

- `identity show`, `server add` and `server list`, `config set-download-dir`
  and `config show`, `add` for an `ed2k://` link, and `kad join` as a live
  diagnostic.

### Platforms

- Release archives for macOS (Apple silicon and Intel), Linux (x64 and arm64,
  glibc 2.35 or newer) and Windows (x64), with shell and PowerShell
  installers, SHA-256 checksums and third-party licence notices.
- On Windows the data directory is `%LOCALAPPDATA%\rmule`, and the binaries
  link the C runtime statically.

[0.1.0]: https://github.com/Lazark0x/rmule/releases/tag/v0.1.0
