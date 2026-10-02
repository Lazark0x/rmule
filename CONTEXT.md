# rmule

rmule is a Rust implementation of the eMule network protocol family, built library-first so protocol crates can be reused independently of the desktop application.

## Language

**Protocol Library**:
A reusable implementation of eMule-compatible network behavior that can be embedded by applications and tools.
_Avoid_: app backend, core app

**Protocol Service**:
A stateful implementation of one eMule network capability, such as server communication, Kad, or peer transfer.
_Avoid_: manager, module, background worker

**Core Orchestrator**:
The application-facing layer that coordinates protocol services, storage abstractions, bandwidth policy, and command/event flow.
_Avoid_: UI backend, protocol library

**Application Front-End**:
A consumer process that owns command-line/config parsing, the diagnostic subscriber install, and human presentation, then drives the **Core Orchestrator**'s command/event service. It holds no protocol or durable orchestration state of its own — managed server list, preferences, persisted **Client Identity**, and multi-download state all live in the **Core Orchestrator**. Two exist: the headless `rmule-cli` and the `rmule` **Terminal Client**, siblings over the same Core surface.
_Avoid_: product CLI logic owner, app backend, app-core middle layer, rmule-tools (diagnostic, not a product front-end)

**Download Orchestration**:
The **Core Orchestrator** capability that turns a user-selected **ED2K Link** into coordinated server source lookup, peer transfer, part verification, storage writes, and app-level download events.
_Avoid_: peer transfer, source lookup, desktop download screen

**Verification Authority**:
The metadata source the **Core Orchestrator** trusts when deciding whether downloaded bytes match the user-selected file identity.
_Avoid_: peer hash, checksum source, validation data

**Provisional Verification Authority**:
A peer-supplied **ED2K Part Hash Set** trusted for one download only when the user-selected **ED2K Link** has no `p=` hash set.
_Avoid_: permanent file identity, peer preference, source ranking

**Durable Download State**:
The persisted app-level record of a download's file identity, verification authority, verified parts, and lifecycle state across process restarts.
_Avoid_: cache, temp file, peer session state

**Partial Download**:
A download whose **Durable Download State** has at least one verified **ED2K Part** but has not reached file completion.
_Avoid_: failed download, incomplete packet, peer transfer

**Pause/Resume**:
The **Download Orchestration** lifecycle that stops active network work while preserving **Durable Download State**, then later continues from already verified parts.
_Avoid_: cancellation, retry, reconnect, failed download

**Multi-peer Download Scheduling**:
The **Download Orchestration** capability that coordinates multiple **Peer Sessions** for one download by assigning missing **ED2K Parts**, avoiding duplicate active requests, replacing failed peers, and persisting verified parts through **Durable Download State**.
_Avoid_: peer swarm, peer-net driver, bandwidth policy, search

**Part Assignment**:
A **Multi-peer Download Scheduling** decision that reserves one missing **ED2K Part** for one active **Peer Session** until that peer produces verified bytes, fails, or releases the reservation.
_Avoid_: request packet, storage write, peer outcome

**In-flight Part**:
An **ED2K Part** with an active **Part Assignment** that has not yet been verified or released for reassignment.
_Avoid_: partial byte range, wire chunk, unverified progress

**Peer Availability**:
The set of **ED2K Parts** a specific peer claims to have for a file.
_Avoid_: source lookup result, file status event, rarest-first score

**Retired Peer**:
A candidate peer that **Multi-peer Download Scheduling** will not use again for the current download after a trust or transfer failure.
_Avoid_: banned client, disconnected socket, failed download

**Source Snapshot**:
The usable **Peer Sources** returned by one peer-discovery lookup for a download attempt, such as **eD2k Source Lookup** or **Kad Source Lookup**.
_Avoid_: managed server list, search result set, refreshed source cache, download scheduler

**Source Discovery Policy**:
The per-download selection of which peer-discovery channels **Download Orchestration** should use, such as **eD2k Source Lookup**, **Kad Source Lookup**, or both. It does not start or stop long-lived protocol services.
_Avoid_: Kad enabled flag, server connection state, scheduler policy

**Scheduler Event**:
An app-level **Core Event** emitted by **Multi-peer Download Scheduling** for orchestration facts such as **Part Assignment**, part release, or **Retired Peer** decisions.
_Avoid_: peer packet event, protocol event, log line

**Diagnostic Trace**:
The third diagnostic channel alongside typed events and **Capture**, emitted via `tracing` from runtime and **Core Orchestrator** crates for cross-cutting observability of hangs, decisions, and timing. Library-first: emitters never install a subscriber; consumers do. Sans-I/O crates (`rmule-primitives`, `rmule-ed2k`, `rmule-peer`) stay silent.
_Avoid_: typed event, capture byte stream, log line, app-facing fact

**Worker Phase**:
The currently observed orchestration state of one **Multi-peer Download Scheduling** worker slot, derived by **Core Orchestrator** from observed **Peer Events** and scheduler decisions, exposed via a diagnostics-dump command for hang investigation. Lives in `rmule-core` because it mixes connection-level facts (handshake, slot grant) with orchestration facts (waiting for slot, verifying part). Not a **Scheduler Event** and not an `rmule_net::peer` accessor.
_Avoid_: peer connection state, scheduler event, log line, tracing span

**Protocol Primitives**:
The shared eMule-compatible identifiers, hashes, links, packet conventions, and fixtures that higher-level protocol libraries build on.
_Avoid_: utilities, helpers, common code

**User Hash**:
The 16-byte eMule-compatible client identity value used across server and peer protocol flows.
_Avoid_: ED2K file hash, account ID

**Client Identity**:
Defined by [`rmule-primitives`](crates/rmule-primitives/CONTEXT.md), which owns the type.

**Capability Registry**:
The single source of truth for what rmule advertises about itself (ADR-0047): the shipped-feature set (compile-time facts — a feature-cluster spec flips one entry when it ships) plus per-connection policy (the crypt stance). Every advertising surface derives from it — the server-login `CT_SERVER_FLAGS`/`CT_EMULE_VERSION` tags and the peer-hello **Capability Block** alike — so **Honest Capability Advertisement** has one enforcement point instead of per-site conventions. Holds feature facts only; wire tag ids and bit offsets stay in the surface crates.
_Avoid_: capability config, feature flags (entries are dispatch reality, not tunables); Server Capabilities (that is the per-server store of what a *server* granted, not what rmule advertises)

**Credit**:
The per-identity record of how many bytes rmule has uploaded to and downloaded from a peer, kept by the **Core Orchestrator** (`CreditStore`) and converted into an upload-slot priority modifier so a peer that has served rmule is admitted to an upload slot sooner. Recorded from **Peer Session** serve/transfer facts; spoofable by claiming another peer's **User Hash** until **Secure User Identification** makes it a **Secured Identity**. The stored value is the raw uploaded/downloaded totals; the queue modifier (eMule's `GetScore`) is derived, not stored.
_Avoid_: reputation, payment, the score (that is the derived modifier, not the stored totals)

**Secured Identity**:
A peer's **Credit** record once **Secure User Identification** has proven the peer owns the **User Hash** it claims, binding the record to the peer's RSA public key. A later peer presenting the same **User Hash** with a different key is denied the secured credit (identity-theft protection); a peer that never runs SUI keeps an *unsecured* record that still accrues but any peer could claim. Non-SUI peers are grandfathered, never gated out — SUI is a protection layer, not an admission requirement.
_Avoid_: verified user, authenticated peer, trusted client, login state

**Server Hash**:
The 16-byte server identity value carried by `OP_SERVERIDENT` and persisted in server-list records, used to recognise the same eD2k server across IP or port changes.
_Avoid_: user hash, file hash, server endpoint

**Client ID**:
The 32-bit eD2k server-assigned client address value used by server-mediated flows; High IDs are IPv4-shaped direct addresses, while Low IDs require server-mediated callback handling.
_Avoid_: user hash, application session ID, always-IP address

**AICH Root Hash**:
Optional eMule integrity metadata that identifies a file's AICH hash tree root.
_Avoid_: ED2K hash, file ID

**AICH Hash Set**:
The per-file SHA-1 hash tree (`rmule-primitives`) whose leaves are the SHA-1 of each
180 KiB (`EMBLOCKSIZE`) block and whose root is the **AICH Root Hash** (eMule's
"master hash"). The SHA-1 sibling of the **ED2K Part Hash Set**: it enables sub-part
**AICH Block Recovery**, not file identity. Built from file bytes; its per-part
*recovery data* is the tree branch exchanged on the wire to prove a part's block
hashes against a **Trusted AICH Root**.
_Avoid_: AICH tree (informal), master hash set, ED2K part hash set

**ED2K Part**:
A contiguous 9,728,000-byte section of a file used by ED2K hashing and part verification, except that the final part may be shorter.
_Avoid_: chunk, block

**ED2K File Hash**:
The 16-byte ED2K content identity used by file links to identify a shared file.
_Avoid_: AICH root hash, part hash, file checksum

**ED2K Part Hash**:
The 16-byte ED2K hash for one ED2K part used by part-level verification.
_Avoid_: file hash, chunk checksum

**ED2K Part Hash Set**:
The ordered ED2K hashset carried by `p=` metadata for a known file size, including the special trailing empty hash at exact part-size boundaries.
_Avoid_: file identity, AICH tree

**ED2K Link**:
A URI that identifies a file, server, or server list for the eMule network.
_Avoid_: download task, transfer

**Server Endpoint**:
A user-facing eD2k server network location made of a host or IP address and TCP port; may need DNS resolution before a socket can be opened.
_Avoid_: server identity, server metadata, wire endpoint

**Ipv4 Endpoint**:
A wire-level IPv4 address and TCP port pair carried in eD2k binary payloads such as **Server List** entries; never carries a DNS name.
_Avoid_: server endpoint, socket address, peer source

**Server Identity**:
Static-ish protocol metadata learned about an eD2k server, such as name, description, version string, and capability flags. Refreshed when the server is reconfigured, not on a polling cadence.
_Avoid_: server endpoint, DNS name, server status report

**Server Status Report**:
Dynamic protocol metrics learned about an eD2k server, such as reported user count and file count. Refreshed on a polling cadence independent of **Server Identity**.
_Avoid_: server identity, capability flags

**Server TCP Flags**:
The eD2k server-session capability bitmask learned during **eD2k Server Login**. Unknown bits are preserved, while named predicates are added only when a behavior needs them.
_Avoid_: server identity, client capability tags, raw integer

**eD2k Server Protocol**:
The server-mediated eMule network capability for server session setup, search, source lookup, and server list exchange. The offline packet and state model lives in `rmule-ed2k`; the live runtime layer (sockets, **Driver**, **Connection**) lives in `rmule-net`'s `ed2k` module.
_Avoid_: ED2K link parsing, peer transfer, Kad

**eD2k Server Login**:
The eD2k server session setup exchange where a client announces itself before using server-mediated capabilities.
_Avoid_: user authentication, account login

**eD2k Source Lookup**:
The eD2k server exchange where a connected client asks for peers advertising a **Source Lookup Target**.
_Avoid_: search, download, Kad lookup, peer transfer

**Kad Source Lookup**:
The Kad exchange where a client asks the serverless network for **Peer Sources** advertising a **Source Lookup Target**. It is a peer-discovery channel for a known file identity, not a user-facing **Search Query**.
_Avoid_: Kad search, server search, download, peer transfer

**Kad Routing Table**:
The long-lived Kad node set a client maintains after bootstrapping into the serverless network. **Kad Source Lookup** depends on this state; it is not rebuilt for each download.
_Avoid_: server list, peer source pool, search result set

**Kad ID**:
The 128-bit Kad node identity used by the serverless network. It is distinct from **User Hash** even when protocol research later confirms how the two are related.
_Avoid_: user hash, client id, file hash

**Kad Node Endpoint**:
A Kad node's reachable UDP network location, made of an IPv4 address and UDP port.
_Avoid_: peer endpoint, server endpoint, TCP endpoint

**Kad Bootstrap Node**:
A manually supplied or imported starting point for joining Kad, made of a **Kad Node Endpoint** and, when known, the node's **Kad ID**.
_Avoid_: server list entry, peer source, routing-table bucket

**Kad Command**:
An application-facing request to the Kad protocol service, such as bootstrapping from **Kad Bootstrap Nodes**, requesting sources for a **Source Lookup Target**, or shutting down. Commands do not name UDP packet opcodes.
_Avoid_: packet opcode, routing-table mutation, raw outbound packet

**Kad Event**:
A domain notification emitted by the Kad protocol service, such as bootstrap progress, readiness, found **Peer Sources** for a known file, lookup failure, unknown well-formed Kad packet observation, or shutdown. Events describe protocol-service facts without exposing routing-table internals.
_Avoid_: decoded packet, log line, routing-table dump

**eD2k Server Search**:
The eD2k server exchange where a connected client submits a user-facing file query and receives candidate files as **Search Results**. Distinct from **eD2k Source Lookup**, which starts after the user already has a known file identity.
_Avoid_: Kad search, source lookup, download, desktop search screen

**Search Query**:
The user-facing criteria submitted to **eD2k Server Search**: a required text phrase plus any of the five **Search Constraints**. Boolean expression trees are a wire capability, not part of the app-facing query language — the phrase is one literal term, so the tree rmule builds is always all-AND.
_Avoid_: packet search expression, source lookup target, regex

**Search Constraint**:
One of the five optional narrowings a **Search Query** may carry beside its phrase: file type (an **eD2k File Class**), minimum size, maximum size, minimum availability, and filename extension. Each becomes one term of the request's wire expression tree; an absent constraint contributes nothing, so an unconstrained query encodes exactly as a bare phrase does. Constraints outside this five are not query vocabulary — complete-source, bitrate and length filters exist on the wire but no reference client sends them.
_Avoid_: search filter, facet, predicate, boolean expression

**Source Lookup Target**:
The known-file identity used by **eD2k Source Lookup**, made of an **ED2K File Hash** and 64-bit file size.
_Avoid_: file hash only, search query, download task

**Search Result**:
Defined by [`rmule-primitives`](crates/rmule-primitives/CONTEXT.md), which owns the type.

**eD2k File Class**:
The network's seven-way file taxonomy — audio, video, image, document, program, archive, CD-image — derived from a file name's extension. It has three names per class: the wire term a query or publish may carry in an `FT_FILETYPE` tag (which folds archive and CD-image into `Pro`), the client-internal label that keeps those two distinct, and the description a UI prints.
_Avoid_: MIME type, file format (that is the `FT_FILEFORMAT` extension string)

**Peer Source**:
A server-reported candidate peer for a known **ED2K File Hash**, made of the peer's **Client ID** and TCP port before rmule has opened any peer connection.
_Avoid_: peer endpoint, source IP, download source

**eD2k Login Request**:
The client-to-server packet that starts **eD2k Server Login** by carrying the client's user hash, current client ID value, TCP port, and login tags.
_Avoid_: raw packet blob, user sign-in

**eD2k Login Response**:
A server-to-client packet that answers **eD2k Server Login**, such as client ID assignment, server message, or login rejection.
_Avoid_: search result, source lookup response

**eD2k Command**:
An application-facing request to the eD2k protocol service that names a domain intent, such as connecting with a **Client Identity** to a **Server Endpoint**, requesting sources for a known **ED2K File Hash**, requesting a refreshed server list, or disconnecting. Commands do not name packet types; the service translates intent into outbound **Client Packets** internally.
_Avoid_: packet opcode, UI action, raw outbound packet

**eD2k Event**:
A domain notification emitted by the eD2k protocol service, such as connection progress, accepted login, rejected login, server-pushed text, refreshed server status, identified server metadata, received server list, found peer sources for a file hash, an unknown well-formed server packet, or disconnection. Each event represents one fact arriving on its own cadence; events do not bundle across packets. `Disconnected` carries a typed **Close Reason** rather than a free-form string.
_Avoid_: decoded packet, log line, server notice umbrella

**eD2k Command Rejection**:
An **eD2k Event** emitted when the protocol service refuses an **eD2k Command** because the current session state or server capabilities make that command impossible. It carries the command kind and typed reason, not a copy of the original command payload.
_Avoid_: silent no-op, send error, protocol violation, echoed command payload

**Close Reason**:
The typed taxonomy of why an **Ed2k Session** ended: caller asked, server closed the socket, session refused to continue on a **Protocol Violation**, socket-level I/O failure, connect timed out, or login timed out. Always the final fact of a session; new variants are added when new evidence appears.
_Avoid_: error string, disconnect message, generic Error

**Terminal Client**:
The `rmule` **Application Front-End** (ADR-0069): a terminal UI with the core embedded in-process behind a `CoreClient` seam, presenting protocol and orchestration state and sending app-level commands. It is one front-end over the **Core Orchestrator**, not a separate owner of durable state or protocol behavior; the headless `rmule-cli` is its sibling.
_Avoid_: desktop client, protocol core, library, app-core (durable state lives in Core, not the front-end)

**eMule Network**:
The family of peer-to-peer networks and protocols used by eMule-compatible clients.
_Avoid_: torrent network, generic P2P network

**Compatibility Target**:
The external behavior rmule must interoperate with when protocol references are incomplete or ambiguous.
_Avoid_: inspiration, loose reference

**Real eD2k Server**:
An external eD2k server implementation run as a local compatibility dependency so rmule and eMule-compatible clients exercise real server-session behavior. It is not rmule-authored test logic and should be kept out of the repository when licensing or redistribution is uncertain.
_Avoid_: mock server, fixture server, local rendezvous server

**Reference Source**:
The pinned upstream eMule source tree, read to *specify* protocol behavior — what byte goes where, what a constant is, what an implementation does at a decision point. It is the normative eD2k/Kad implementation in a way a port is not. It is never evidence: a value read from it still needs a capture before it closes a parity row, and it is never ported, translated, or pasted into rmule. Lives in the local reference cache, gitignored, sidecar committed.
_Avoid_: oracle, reference tier, spec tier, vendored source, counterparty

**Stimulus Counterparty**:
A pinned third-party client run on the wire to elicit behavior a two-node setup cannot produce — the role `emulecored` plays alongside the pinned aMule and eserver. It is a stimulus, not an authority: its own bytes never score a parity row, and where it makes a blocked row reachable the proof is still the pinned **Real eD2k Server** or aMule counterparty's reaction. Promotion to a corroborating role is earned by measurement, never assumed.
_Avoid_: third oracle, secondary counterparty, corroborating tier, stimulus tier

**Compatibility Fixture**:
A checked-in protocol example that proves rmule behavior against a documented, observed, or deliberately handwritten compatibility case. Provenance tag is one of `handwritten`, `documentation`, `amule-generated`, or `captured`. `captured` fixtures come from real eMule-compatible runtime traffic, either through an rmule **Driver** capture writer or a **Local Interop Harness** packet capture, and are curated into the fixture tree.
_Avoid_: vector, sample, test data

**Local Interop Harness**:
An opt-in compatibility exercise that runs rmule and/or local external eMule-compatible processes, including a **Real eD2k Server** or aMule/amuled instances, using synthetic local content. It complements default protocol, replay, and loopback tests without becoming part of ordinary `cargo test`.
_Avoid_: unit test, default CI test, public-network live test

**Interop Run Artifact**:
A retained, gitignored evidence file produced by one **Local Interop Harness** execution, such as process logs, generated synthetic content, ED2K links, rmule CLI output, or optional captures. It is not a curated **Compatibility Fixture** unless a human explicitly promotes safe, minimal protocol evidence into the fixture tree.
_Avoid_: checked-in fixture, golden file, test snapshot

**Correctness Tier**:
Defined by [`rmule-core`](crates/rmule-core/CONTEXT.md), where the tier's fakes and its bar live.

**Compatibility Tier**:
Defined by [`rmule-core`](crates/rmule-core/CONTEXT.md), beside the **Correctness Tier** it sits above.

**Testkit**:
The dev-only workspace crate holding the shared deterministic scaffolding for **Correctness Tier** tests: protocol-counterparty fakes and scenario wiring consumed as a dev-dependency by crate, CLI, and orchestration tests. Never published and never part of the production dependency graph or the **Local Interop Harness**.
_Avoid_: published crate, production dependency, Docker harness component

**FakeEd2kServer**:
The **Testkit**'s behaviour-faithful, not byte-faithful, in-process eD2k server. It models exactly the server seams under test — reachability probe, Low-ID assignment, callback relay, source answers — and grows a new seam only when a test demands it.
_Avoid_: Real eD2k Server replacement, byte-faithful eserver re-implementation, upfront full-protocol fake

**FakePeer**:
The **Testkit**'s scriptable protocol-counterparty peer, used for adversarial paths a real peer cannot express on command: stalling, queueing forever, dropping mid-part, never completing a handshake. Happy paths use a real rmule counterparty instead of a script.
_Avoid_: happy-path mock, real peer replacement

**Protocol-Counterparty Test**:
A **Correctness Tier** test whose subject speaks the eD2k or peer protocol to a faked other side. These tests consume the **Testkit** fakes rather than hand-rolled counterparties.
_Avoid_: transport probe, driver test

**Transport Probe**:
A **Correctness Tier** test that exercises driver or connection pipe invariants — drain, write-error convergence, synthesized disconnect — against raw scripted sockets. There is no protocol counterparty to fake, so it stays off the **Testkit** by design.
_Avoid_: protocol-counterparty test, testkit consumer

**Tag Name Encoding**:
The on-wire representation used for an eD2k tag name, including compact numeric names and length-prefixed names.
_Avoid_: tag identity, tag value type

**eD2k Text**:
A wire-faithful byte string carried by eD2k packets and tags. Preserves original server-emitted bytes losslessly; exposes a strict UTF-8 view for ASCII-clean content and a lossy display projection for UI rendering. Used for server-pushed message text, server name and description, and all tag string values. (Reserved for any future server-sourced text fields; `OP_REJECT` itself carries no payload per cited sources, so login rejection is a unit signal rather than a text field.)
_Avoid_: String, raw bytes, message text

**Packet Frame**:
The eD2k wire wrapper made of a protocol byte, little-endian length, opcode, and payload.
_Avoid_: packet header when opcode inclusion is ambiguous

**Compressed Packet Frame**:
A **Packet Frame** whose protocol byte marks the opcode-specific payload bytes as zlib-compressed while the length and opcode remain in their normal frame positions.
_Avoid_: stream obfuscation, compressed part, compressed transport

**Server Packet**:
A typed value representing a server-to-client eD2k packet payload, dispatched from an opcode into one of a closed set of variants plus an `Unknown` catch-all for well-formed frames with unrecognised opcodes.
_Avoid_: server response, server message, server frame

**Client Packet**:
A typed value representing a client-to-server eD2k packet payload, dispatched from an opcode into one of a closed set of variants plus an `Unknown` catch-all for well-formed frames with unrecognised opcodes. Symmetric with **Server Packet** so the future runtime layer has matching read and write types.
_Avoid_: client request, client frame, outbound packet

**Compressed Frame Skipped**:
An **eD2k Event** emitted when an inbound eD2k server **Compressed Packet Frame** cannot be inflated and is skipped without closing the session.
_Avoid_: unknown packet, disconnect, protocol violation, generic frame skipped

**Compressed Frame Skip Reason**:
The typed reason an inbound eD2k server **Compressed Packet Frame** was skipped, such as failed inflation or exceeding the decompressed-size ceiling.
_Avoid_: zlib error string, session error, close reason

**eD2k Peer Protocol**:
The peer-to-peer eMule client-to-client TCP and UDP protocol that carries hello, file/status requests, slot queue management, part exchange, AICH negotiation, secure user identification, chat, and compressed parts. The offline packet and state model lives in `rmule-peer`; the live runtime layer (sockets, drivers, captures) lives in `rmule-net`'s `peer` module. Distinct from **eD2k Server Protocol**, which carries client-to-server traffic.
_Avoid_: server protocol, peer transfer (transfer is one capability inside it), Kad

**Peer Endpoint**:
A connectable peer-side network location made of a wire IPv4 address and TCP port. Always derivable from a High ID **Peer Source**; never from a Low ID **Peer Source**, which requires server-mediated callback before any direct connection.
_Avoid_: peer source, server endpoint, Ipv4 endpoint without intent

**Peer Identity**:
The typed projection of a peer's `OP_HELLO` / `OP_HELLOANSWER` body — **User Hash**, **Client ID**, listening TCP port, optional nickname (**eD2k Text**), optional protocol version, optional **Ipv4 Endpoint** of the server the peer is attached to, and a preserved tail of unknown well-formed tags. Lives in `rmule-peer` for now; promoted to **Protocol Primitives** when a second consumer (Kad) needs it.
_Avoid_: client identity, peer source, server identity

**Peer Hello Body**:
The shared eMule peer hello payload — user hash, client ID, TCP port, tag list, trailing connected-server **Ipv4 Endpoint** — wrapped distinctly by `OP_HELLO` (with a legacy hash-size byte prefix) and `OP_HELLOANSWER` (without). Encoded from a **Peer Handshake Context**; decoded into a **Peer Identity** projection.
_Avoid_: client packet payload blob, login request

**Peer Session**:
Defined by [`rmule-peer`](crates/rmule-peer/CONTEXT.md), which owns the state machine.

**Peer Command**:
An application-facing request to a **Peer Session**. The first peer work carried only `Disconnect`; later work added file request, slot acquisition, part request, hash set exchange. Commands never name packet opcodes.
_Avoid_: peer packet, opcode, raw outbound frame

**Peer Event**:
A domain notification emitted by a **Peer Session**: hello written, peer identified with a **Peer Identity**, unknown peer packet observed, or disconnected with a **Peer Close Reason**. Each event is one fact; events do not bundle across packets.
_Avoid_: decoded packet, log line

**Peer Close Reason**:
The typed taxonomy of why a **Peer Session** ended: caller asked, peer closed the socket, refused to continue on a **Protocol Violation**, socket-level I/O failure, connect timed out, or peer-hello timed out. Always the final fact of a peer session. Separate from **Close Reason** because peer semantics (`PeerClosed`, `HelloTimeout`) differ from server semantics (`ServerClosed`, `LoginTimeout`).
_Avoid_: close reason, error string, generic Error

**Peer Handshake Context**:
The bridge value used to build an outbound `OP_HELLO`. Carries the static **Client Identity**, the runtime-assigned **Client ID** from an active **Ed2k Session**, and an optional **Ipv4 Endpoint** of the server we are attached to. The application layer assembles a **Peer Handshake Context** from the live **Ed2k Session** and passes it to `rmule_net::peer::Connection::connect` — the first peer work had no orchestrator, so the application was the coordination point between **eD2k Server Protocol** and **eD2k Peer Protocol**.
_Avoid_: client identity, peer identity, ed2k session reference

**Peer Callback Requested**:
An **eD2k Event** emitted when the eD2k server pushes an `OP_CALLBACK`-family packet over our server connection telling us that a High ID peer is asking us to dial out to them because we are Low ID. Carries the requesting **Peer Endpoint** and is consumed by the application layer to trigger an outbound `rmule_net::peer::Connection::connect`.
_Avoid_: callback request (outbound, not modeled by the first peer work), peer source

**Protocol Obfuscation**:
The eMule transport-layer scheme that RC4-streams every byte of a TCP connection after an **Obfuscated Handshake**, hiding the eD2k/eMule protocol byte from middleboxes that throttle or block the protocol. A connection is either obfuscated or plaintext, chosen by **Byte-0 Discrimination**. It defeats protocol fingerprinting, not eavesdropping — it is not confidentiality and is orthogonal to **Secure User Identification**.
_Avoid_: encryption, crypt layer (informal), stream obfuscation (informal), SUI, Compressed Packet Frame

**Obfuscated Handshake**:
The opening exchange that establishes a **Protocol Obfuscation** stream's paired RC4 keys before any protocol bytes flow. Two forms: the **peer** form derives the keys from the target's **User Hash** (both ends already know it); the **server** form agrees a secret by 768-bit Diffie-Hellman (client and server share no prior secret). Distinct wire shapes sharing one tail — an RC4-encrypted sync magic that confirms both ends derived matching keys.
_Avoid_: SUI handshake, Peer Hello Body, DH (DH is only the server form's key agreement)

**Byte-0 Discrimination**:
The rule that classifies an accepted TCP connection as plaintext or **Protocol Obfuscation** by its first byte: a known protocol byte (`0xE3`/`0xC5`/`0xD4`) means plaintext, anything else means an **Obfuscated Handshake**. This is what keeps plaintext peers working unchanged, so obfuscation is a pure additive superset of the existing transport.
_Avoid_: magic byte, protocol sniffing, port-based detection

**Obfuscation Policy**:
The per-connection stance toward **Protocol Obfuscation**, a four-state ladder mirroring eMule's crypt flags: `Disabled`, `Supported` (accept obfuscated inbound, never initiate), `Requested` (initiate when possible, fall back to plaintext), `Required` (obfuscated only, refuse plaintext). Only `Required` refuses a plaintext peer; the other three all still serve plaintext exactly as today.
_Avoid_: three separate crypt bools, on/off toggle, encryption level

## Relationships

- A **Terminal Client** uses the **Core Orchestrator**, never a **Protocol Library** directly.
- A **Protocol Library** implements part of the **eMule Network**; a **Protocol Service** owns one capability's state machines and speaks only in commands and events.
- The **Core Orchestrator** coordinates **Protocol Services** for applications without owning UI behavior, and is the Tokio-using layer: the sans-I/O split lives inside each protocol library, not between core and a core-runtime crate.
- An **Application Front-End** drives the **Core Orchestrator** through commands and events. Core owns the **Managed Server List**, persisted **Client Identity**, and multi-download state, so every front-end (`rmule-cli`, the **Terminal Client**) shares one source of truth; front-end-owned configuration (ADR-0069) is the exception, and it is told to core per command rather than pushed into it.
- **User Hash**, **Client ID**, **Server Endpoint**, **Peer Endpoint**, **Source Lookup Target**, and **Peer Source** belong to **Protocol Primitives**: server lookup, Kad lookup, peer transfer and orchestration all need the same identity and candidate-peer language.
- Shared **eD2k Server Search** values such as **Search Query** and **Search Result** belong to **Protocol Primitives** because both `rmule-ed2k` and `rmule-core` consume them; wire-only expression encoding and packet projection stay in `rmule-ed2k`.
- A **Server Hash** belongs to **Server Identity** the way a **User Hash** belongs to client identity and a **File Hash** to a shared file: all are typed 16-byte identity primitives in `rmule-primitives`.

### Downloads

- **Download Orchestration** belongs to the **Core Orchestrator** because it coordinates **eD2k Source Lookup**, **Peer Sessions**, part verification and storage without adding wire behavior. A command starts from a file **ED2K Link** plus connection context; core derives the **Source Lookup Target**, the **Peer Endpoints**, and the part ranges itself.
- A file **ED2K Link**'s `p=` **ED2K Part Hash Set** is the **Verification Authority** when present. Without one, the first valid peer-supplied hash set becomes the **Provisional Verification Authority** and is persisted in **Durable Download State**, so a resume verifies against the same authority it started with. A peer contradicting the authority becomes a **Retired Peer**; link metadata is never overridden.
- A file with no part hash set at all is verified as a whole against its **ED2K File Hash**.
- Only verified complete **ED2K Parts** are durable progress. A **Partial Download** accumulates into a non-final `.part` content file, and core moves it to the user-visible path only after full-file verification.
- **Pause/Resume** is not cancellation: cancellation ends the workflow, pause preserves **Durable Download State** as the basis for continuation. A network error is a failure even when the remaining state could be resumed.
- Resuming starts from the persisted link, server context and verified-part map, and performs a fresh **eD2k Source Lookup** — a previously selected **Peer Source** is never authoritative.
- **ED2K File Hash** plus size is the duplicate-download identity; a different filename is not a different download.
- **Multi-peer Download Scheduling** owns **Part Assignment**. Per-peer execution streams part, hash-set, slot and failure facts back rather than returning a whole-download outcome, and its decisions surface as **Scheduler Events** — app-level **Core Events**, not peer protocol events.
- A part is assigned to one peer while fresh parts remain; when none are left a **backup** peer may race an in-flight part so a scarce part is not stranded on a slow one. First verified copy wins, losing racers are dropped (ADR-0026 racing amendment).
- An in-flight **ED2K Part** is assembled into one core-owned **contiguous-prefix** buffer per part, fed by every contributor. A peer dropping mid-part preserves the prefix, so the next assignment resumes from its end. Assembly is in-memory and per-session; on a part-hash failure core has no per-block attribution, so it retires every contributor and refetches from offset 0 (ADR-0029).
- One granted upload slot serves the whole file: the first block earns it with `OP_STARTUPLOADREQ`, and every later block and part rides the held slot as a bare `OP_REQUESTPARTS`. The worker releases it explicitly; a request for a *different* file while it is held is `SlotBusy` — one active slot per connection (ADR-0025, amended).
- Peer disconnect, slot rejection or transfer failure releases that peer's in-flight part for reassignment. The download fails only when missing parts remain and no connected or unused candidate peers remain.
- When both **eD2k Source Lookup** and **Kad Source Lookup** are enabled, discovery fails only if every enabled channel fails, times out, or returns nothing usable; one channel's failure is survivable.
- **Kad Source Lookup** does not depend on an **eD2k Server Login**. A Kad-only download runs serverless end to end, its **Peer Handshake Context** built from the persisted **Client Identity** rather than a server-assigned **Client ID** (ADR-0043).

### Search

- A **Search Result** is candidate metadata, not a command: selecting one starts a separate download workflow from the strongest file identity in the row, with a fresh **eD2k Source Lookup**. The reporting **Peer Source** is evidence, never the source pool.
- Results with the same **ED2K File Hash** and size describe one candidate file; differing advertised names are kept as aliases behind the first-seen primary name. The same hash with a conflicting size is suspicious metadata and must not merge.
- A **Search Result** exposes typed metadata only for fields rmule understands and preserves unrecognized well-formed descriptor tags.
- Reported availability is advisory for display or sorting — never scheduler truth, and never a substitute for a fresh source lookup.
- A **Search Result**'s displayed type is its **eD2k File Class**, taken from the primary name's extension and falling back to the server's `FT_FILETYPE` term only for a name that does not classify: the wire term is coarser, and most counterparties send none.
- A **Search Constraint** on file type stays an **eD2k File Class** all the way to the encoder, which folds archive and CD-image into the `Pro` wire term at the last moment — the query keeps what the operator picked, only the wire loses the distinction.
- A **Search Query**'s size constraint widens to the 64-bit wire term only against a server that advertised large-file support. Whether the *packet* ended up 64-bit, not whether the query wanted to be, decides which servers the global-UDP sweep may ask.
- **Search Constraints** reach an eD2k server as expression-tree terms it evaluates itself, but reach a Kad storer not at all: the keyword requester sends a non-restrictive request, so Kad rows are screened against the **Search Query** before joining the merged set. One table never mixes filtered and unfiltered rows.
- Two eD2k reports of one result add their source counts, each server counting only its own logins; as soon as a Kad report is involved the counts take the maximum, because every storer republishes the same global figure. A row that has absorbed a Kad report keeps folding by maximum.
- `rmule-ed2k` emits every well-formed search-result packet as an **eD2k Event**; whether it belongs to an active **Search Activity** is core's decision.

### Files, links and the wire

- An **ED2K Part** is 9,728,000 bytes except for a shorter final part.
- An **ED2K File Hash** identifies a file independently of optional **AICH Root Hash** metadata, and rmule computes it with eMule/aMule's exact-part-size boundary behavior rather than the fixed-boundary variant some tools use.
- An **ED2K Part Hash Set** supports verification and transfer but is not required to parse a link; it is valid only when its hash count matches aMule's hashset count for the file size.
- An **ED2K Link** can describe a file, a server, or a server list without starting any network operation. A server link carries a **Server Endpoint**, not a **Server Identity**.
- A wire **Server List** payload carries **Ipv4 Endpoints**, not **Server Endpoints**: the format holds an IPv4 address and TCP port and never a DNS name. A **Server Endpoint** with an IP-literal host converts without resolution; a DNS-host one needs runtime resolution before it can be encoded.
- A source-lookup reply carries **Peer Sources**, not **Ipv4 Endpoints**, because the wire field is a **Client ID** whose Low ID form is not an address.
- A **Server Identity** says who a server is; a **Server Status Report** says how busy it is now. Different packets populate them on different cadences, so they stay distinct values. Identity merges contributions from several sources — `OP_SERVERIDENT`, `server.met` records, UDP status replies — so it holds optional typed fields, a preserved unknown-tag tail, and explicit merge precedence.
- A **Server Packet** and a **Client Packet** share one shape: closed variants plus an `Unknown` catch-all, so a forward-compatible counterparty never forces a disconnect. Malformed **Packet Frames** are still rejected.
- A **Packet Frame** length counts the opcode byte plus payload; the protocol byte and the length field itself sit outside the count.
- A **Compressed Packet Frame** carries its opcode outside the compressed bytes — only the payload inflates — and can travel in either direction on the server link. Peer compressed file parts are a different message family. Frame parsing preserves the compressed bytes; packet dispatch decides whether to inflate.
- Inbound server frames inflate under a 250,000-byte ceiling, matching aMule's server TCP unpack path. A failed inflation emits **Compressed Frame Skipped** with a **Compressed Frame Skip Reason** — not a **Protocol Violation**, not an **Unknown Server Packet**, and not a raw compression-library error.
- Packet fixtures preserve **Tag Name Encoding**, so a decoded tag re-encodes to the exact original bytes.
- **eD2k Commands** and **eD2k Events** describe service behavior while packet models describe bytes: a command carries a **Client Identity**, never an **eD2k Login Request**, so application code never names a packet type.

### Peers

- A **Peer Session** is per-connection and sans-I/O; the runtime holds one `Connection` per peer, and multi-peer work composes those rather than replacing them.
- A **Peer Identity** is built from a decoded **Peer Hello Body** and emitted as `PeerIdentified`; the session does not persist it.
- A **Peer Handshake Context** is built by the application from a live **Ed2k Session**'s `LoginAccepted` and the **Client Identity** used for that login — or, on Kad, from the persisted identity alone. The **Peer Session** never reads an **Ed2k Session** itself.
- rmule both dials and accepts: `rmule_net::peer`'s listener owns the inbound socket and hands accepted connections to core, which decides what to serve (ADR-0031). Two Low-ID clients still cannot reach each other, so server-mediated callback remains the path for that case — the **Peer Callback Requested** **eD2k Event** is the cross-service signal, and the **Peer Session** sees only the dial that follows.
- A **Peer Endpoint** is derivable from a High ID **Peer Source**; a Low ID one has none until a callback yields it.
- The peer hello advertises exactly what the **Capability Registry** says rmule ships (ADR-0047), which is what makes **Honest Capability Advertisement** checkable rather than a convention.
- **Protocol Obfuscation** wraps both peer and server transports *below* their **Packet Frame** codecs, so a session sees only decrypted bytes: the shared RC4 stream and **Byte-0 Discrimination** live in `rmule-net`'s `driver` module, the two **Obfuscated Handshake** forms live in `rmule-peer` and `rmule-ed2k`, and the crypto primitives live in `rmule-primitives` beside **User Hash** and the SUI keypair. No dedicated obfuscation crate (ADR-0042).
- Obfuscated *dialing* needs the target's **User Hash**, so only **Peer Sources** that carry one (source exchange, Kad) can be dialed obfuscated; a server-lookup source is plaintext by necessity. *Accepting* an obfuscated peer needs no source data — the key comes from our own **User Hash**.
