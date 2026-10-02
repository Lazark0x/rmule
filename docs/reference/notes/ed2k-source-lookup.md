# ED2K source lookup

**Status:** implemented
**Scope:** the TCP server-mediated exchange where a connected client asks the current eD2k server for peers that advertise a known file.

## Packet roster

| Opcode | Direction | Name | Scope |
| --- | --- | --- | --- |
| `0x19` | C->S | `OP_GETSOURCES` | Request sources for one known file |
| `0x42` | S->C | `OP_FOUNDSOURCES` | Reply with sources for one known file |
| `0x23` | C->S | `OP_GETSOURCES_OBFU` | Deferred; preserve as unknown well-formed packet |
| `0x44` | S->C | `OP_FOUNDSOURCES_OBFU` | Deferred; preserve as unknown well-formed packet |

## OP_GETSOURCES (`0x19`)

**Direction:** C->S. Client asks the connected server for sources for a **Source Lookup Target**.

| Offset | Size | Field | Endianness | Notes |
| --- | ---: | --- | --- | --- |
| 0 | 16 | file hash | bytes | Requested **ED2K File Hash** |
| 16 | 4 | file size | little-endian integer | Modern non-large form used by aMule |
| 16 | 4 | zero sentinel | little-endian integer | Large-file form only; value is zero |
| 20 | 8 | file size | little-endian integer | Large-file form used when server advertises large-file support |

The historical spec describes a hash-only request. Current aMule's TCP path sends the Lugdunum extended form: hash plus 32-bit size for normal files, or hash plus a zero sentinel and 64-bit size for large files when the server advertises support. `OP_GETSOURCES` is a domain **eD2k Command**, not a UI search action. It belongs after login because the connected server is the authority answering the lookup.

The decoded packet model should preserve the wire form instead of forcing every request into a `SourceLookupTarget`. The legacy hash-only form does not contain a file size, so decoding it as a target would invent domain data. A suitable packet-layer shape is:

```rust
pub enum GetSourcesRequest {
    Legacy { file_hash: FileHash },
    Normal { target: SourceLookupTarget },
    Large { target: SourceLookupTarget },
}
```

`SourceLookupTarget` should carry the file size as `u64` even for small files. Encoding chooses the wire shape:

- `file_size <= u32::MAX`: encode hash plus 32-bit size.
- `file_size > u32::MAX` and logged-in server's `ServerTcpFlags` has `SRV_TCPFLG_LARGEFILES` (`0x00000100`): encode hash plus zero sentinel plus 64-bit size.
- `file_size > u32::MAX` without that server capability: do not write a source request; surface a typed command failure in the service layer.

`SourceLookupTarget` and `PeerSource` are shared **Protocol Primitives**, not eD2k-only packet types. Put them in a dedicated `rmule-primitives/src/source.rs` module and re-export them from `rmule_primitives`; keep `ClientId` in `identity.rs` and add High ID / Low ID helpers there. Their primitive constructors should be infallible field holders for this slice: do not reject zero-byte file sizes or zero TCP ports without protocol evidence that those values are structurally invalid. The eD2k service owns the projection to and from `OP_GETSOURCES` / `OP_FOUNDSOURCES`.

## OP_FOUNDSOURCES (`0x42`)

**Direction:** S->C. Server replies with sources for the requested **ED2K File Hash**.

| Offset | Size | Field | Endianness | Notes |
| --- | ---: | --- | --- | --- |
| 0 | 16 | file hash | bytes | The **ED2K File Hash** this reply answers |
| 16 | 1 | source count | integer | Number of following source items |
| 17 | `count * 6` | source items | mixed | Each item is `Client ID` plus TCP port |

### Source item

| Offset | Size | Field | Endianness | Notes |
| --- | ---: | --- | --- | --- |
| 0 | 4 | client ID | little-endian integer | eD2k **Client ID**, not always a direct IPv4 endpoint |
| 4 | 2 | TCP port | little-endian integer | Peer listening port as reported by the server |

Model each source item as **Peer Source** (`ClientId`, `tcp_port`) rather than `Ipv4Endpoint`. A High ID can later be projected to a direct IPv4 endpoint when peer transfer needs it; a Low ID needs server-mediated callback handling and must not be flattened into an IP address.

The first source-lookup slice should add High ID / Low ID classification helpers to `ClientId` and `PeerSource`, using aMule's Low ID threshold. It should not add direct endpoint conversion yet.

`OP_FOUNDSOURCES` contains the reply file hash, but not the requested file size. `Ed2kEvent::SourcesFound` should therefore carry `{ file_hash: FileHash, sources: Vec<PeerSource> }`, not a reconstructed `SourceLookupTarget`. Correlating the reply hash with an active known-file target belongs to the future `rmule-core` request/workflow layer.

## Acceptance rules

- Decode `OP_GETSOURCES` payload lengths of 16 bytes (legacy hash-only), 20 bytes (hash plus 32-bit size), and 28 bytes (hash plus zero sentinel plus 64-bit size).
- Preserve decoded `OP_GETSOURCES` as a packet-layer wire-form enum: legacy hash-only, normal target, or large target.
- Encode rmule's source-lookup command from a **Source Lookup Target**, not from a bare hash.
- Support large-file source-lookup targets in the public type model, but gate large-file wire encoding on `ServerTcpFlags::supports_large_files()`.
- Refuse source-lookup commands that cannot be sent by emitting an **eD2k Command Rejection** event; do not overload `Connection::send` for protocol-state or capability failures.
- Keep command rejections compact: emit the command kind and typed reason, not a full copy of the original command payload.
- Decode plain `OP_FOUNDSOURCES` only when payload length is `16 + 1 + count * 6`.
- Emit `SourcesFound { file_hash, sources }` for every well-formed `OP_FOUNDSOURCES`; do not require an outstanding request registry inside `rmule-ed2k`, and do not reconstruct a `SourceLookupTarget`.
- Gate outbound `RequestSources` on `LoggedIn`, but accept inbound well-formed `OP_FOUNDSOURCES` after `start()` even if `OP_IDCHANGE` has not arrived yet. Current live-capture evidence already shows loose welcome-packet ordering, so source replies should not introduce a stricter pre-login ordering rule.
- Preserve `OP_GETSOURCES_OBFU` and `OP_FOUNDSOURCES_OBFU` as unknown well-formed packets until obfuscation semantics are modeled; do not include them in the first source-lookup implementation slice.
- Add High ID / Low ID classification helpers only; leave direct peer-endpoint projection to the peer-transfer phase.
- Keep source primitives semantically light: reject malformed packet lengths and count mismatches in `rmule-ed2k`, not zero-valued primitive fields in `rmule-primitives`.
- Emitting found sources is non-terminal. Bad source-lookup packets are packet decode failures, not **Protocol Violations**.

## Verification boundary

The first source-lookup slice is fixture-driven. It must prove packet projection and session behavior with local deterministic tests before any public-network smoke test is considered.

Required fixture coverage:

- `OP_GETSOURCES` normal encode: file hash plus 32-bit size.
- `OP_GETSOURCES` large encode: file hash plus zero sentinel plus 64-bit size.
- Legacy hash-only `OP_GETSOURCES` decode compatibility.
- Malformed source-request payload lengths.
- `OP_FOUNDSOURCES` decode with at least one High ID source and one Low ID source.
- `OP_FOUNDSOURCES` source-count mismatch or trailing-byte rejection.
- Obfuscated source-lookup opcodes preserved as unknown well-formed packets.
- Session command rejection before login.
- Session command rejection for a large-file target when the logged-in server lacks `SRV_TCPFLG_LARGEFILES`.
- Session packet write for a normal target after login.
- Session packet write for a large-file target after login when the server advertises `SRV_TCPFLG_LARGEFILES`.
- Incoming `OP_FOUNDSOURCES` emits a found-source event even when `rmule-ed2k` has no pending request for that file hash.

Do not make live public-server source lookup part of the default verification path. A later live smoke test, if added, should be opt-in, single-request, and rate-limited, with the target supplied explicitly by environment or fixture capture rather than by probing synthetic random hashes.

Command rejection events should be shaped for application decisions while avoiding payload echoing:

```rust
pub enum Ed2kCommandKind {
    RequestServerList,
    RequestSources,
    Disconnect,
}

pub enum CommandRejectReason {
    NotLoggedIn,
    UnsupportedServerCapability {
        capability: ServerCapability,
    },
}

pub enum ServerCapability {
    LargeFiles,
}

Ed2kEvent::CommandRejected {
    command: Ed2kCommandKind,
    reason: CommandRejectReason,
}
```

`NotLoggedIn` applies to commands such as `RequestServerList` or `RequestSources` before the session has accepted login. `UnsupportedServerCapability { capability: LargeFiles }` applies when a large-file `RequestSources` command reaches a logged-in server that did not advertise large-file support.

`rmule-tools` may support source-lookup packet inspection in this slice, but only as an offline fixture tool:

- `rmule-tools ed2k client-packet inspect <fixture>` may print `kind: get_sources`, the requested hash, decoded size when present, and the request wire form.
- `rmule-tools ed2k server-packet inspect <fixture>` may print `kind: found_sources`, the reply hash, source count, and each `PeerSource`.
- `rmule-tools` should not add a live source-lookup command in this slice. Live source lookup is exercised through the library/session path: `Connection::send(RequestSources)` followed by `Ed2kEvent::SourcesFound` or an **eD2k Command Rejection**.

## Sources

- `docs/reference/emule-spec/emule_protocol_specification.pdf`, sections 6.2.11 and 6.2.12: TCP get-sources request and found-sources reply layout.
- aMule source, pinned commit `377ec8d9`: `src/include/protocol/ed2k/Client2Server/TCP.h:36-38,59-61` records legacy and extended `OP_GETSOURCES`, `OP_FOUNDSOURCES`, and obfuscated variants: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/include/protocol/ed2k/Client2Server/TCP.h#L36-L61>
- aMule source, pinned commit `377ec8d9`: `src/DownloadQueue.cpp:1096-1121` builds TCP source requests with hash plus size and uses the large-file form only when the server supports it: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/DownloadQueue.cpp#L1096-L1121>
- aMule source, pinned commit `377ec8d9`: `src/ServerSocket.cpp:342-348` dispatches found-sources packets to the part-file source consumer: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/ServerSocket.cpp#L342-L348>
- aMule source, pinned commit `377ec8d9`: `src/ServerSocket.cpp:371-381` consumes the reply file hash and logs unknown-file replies without treating them as protocol errors: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/ServerSocket.cpp#L371-L381>
- aMule source, pinned commit `377ec8d9`: `src/PartFile.cpp:1699-1759` reads source count, `userid`, and port; filters High IDs as IP-like values while preserving Low ID handling: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/PartFile.cpp#L1699-L1759>
- aMule source, pinned commit `377ec8d9`: `src/NetworkFunctions.h:123-128` defines the Low ID threshold used by source handling: <https://github.com/amule-project/amule/blob/377ec8d9d56618f1059d8705ae53a70fa4ffbe87/src/NetworkFunctions.h#L123-L128>

## Open questions

- Whether future peer transfer needs a richer ID classifier beyond `ClientId::is_low_id()` / `ClientId::is_high_id()`.
- Exact wire captures from current public servers remain optional evidence; handwritten fixtures are sufficient for the first source-lookup implementation slice.
