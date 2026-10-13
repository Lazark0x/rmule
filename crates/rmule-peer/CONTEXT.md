# rmule-peer

The offline eD2k peer-protocol library: peer packet decoders, the `PeerPacket` umbrella, the sans-I/O peer session state machine, and the peer command/event vocabulary. Runtime-agnostic; no Tokio. The live socket layer lives in `rmule-net`'s `peer` module.

## Language

**Peer Session**:
The sans-I/O state machine that owns one peer connection's protocol state, following the same contract as the **Ed2k Session** (`start()` / `handle_bytes` / `handle_command` push effects; `poll_output()` drains `Write` / `Event` / `Close`). A peer connection is **bidirectional on one socket**: the same session both pulls parts from the remote peer (its **Requester Capability**) and serves parts to the remote peer (its **Server Capability**). Role is not fixed by who dialed — either side may request files from the other after the hello exchange.
_Avoid_: requester session, served session, upload session, download session (the session is one type with two capabilities, not two types)

**Requester Capability**:
The half of a **Peer Session** that expresses *our* intent to download: probe a file, request a hash set, acquire an upload slot on the remote peer, request and receive part bytes. Models the slot as the one **we are chasing** (`active_slot`).
_Avoid_: download session, leech side

**Server Capability**:
The half of a **Peer Session** that answers the remote peer's intent to download *from us*: reply to an inbound hello, answer file/hash-set probes for files we share, admit or queue the remote peer, and send part bytes on a granted slot. The **upload-slot queue policy** (who to admit, ranking, slot budget) is NOT owned here — it lives in the **Core Orchestrator**; the **Server Capability** only carries per-connection grant mechanics and reports inbound requests as events.
_Avoid_: upload session, seed side, served session

**Vocabulary Group**:
The group a **Peer Session**'s event or command belongs to, by the side of the conversation aMule's handler for it serves. *Connection*: the hello, the peer's identity and its revisions, the Secure User Identification verdict, ID and IPv6 changes, the close, and our `Disconnect`. *Requester*: the **Requester Capability**'s asks and what answers them, including the file comment an uploader sends about the file we pull. *Server*: the **Server Capability**'s inbound asks and our answers, grants, ranks and blocks. *Side*: node-wide services riding the link, the Kad firewall checks, the buddy relay and the public-IP ask. *Notice*, events only: what the session counted or dropped and no capability acts on, such as unknown and unsolicited frames, rejected commands, chat and browse. `PeerEvent` and `PeerCommand` nest one sub-enum per group on one ordered stream, so an owner routes a whole group at once and a new variant reaches the compiler inside its group. `OP_CANCELTRANSFER` is split by direction (ADR-0056): ours is a Requester command, the peer's a Server event.
_Avoid_: capability (Connection, Side and Notice are not capabilities), channel, role

**Capability Block**:
The set of eMule extended-protocol features a peer advertises in its hello (carried as misc-options tags) — data compression, source exchange, AICH, secure identification, multipacket, large-file support, and more, each a version field. A peer invokes an extended feature against us only if our advertised **Capability Block** declared support for it, so the block is the negotiation that gates the whole eMule extended protocol. rmule models the full block even while implementing only part of it.
_Avoid_: feature flags, hello flags (it is a structured version-field set, not loose booleans); eMule info (that names the legacy `OP_EMULEINFO` carrier, not the capability set itself)

**Honest Capability Advertisement**:
rmule's rule for filling its own **Capability Block**: advertise a capability *iff* it is implemented; every unimplemented field stays at "unsupported." Extends the minimum-honest hello (ADR-0047) from identity to capabilities — a peer is never told rmule supports an extended feature it cannot actually honor. Each protocol slice lights exactly one more field as it lands (ADR-0047).
_Avoid_: capability negotiation (that is the two-sided wire exchange; this is the one-sided honesty constraint on what *we* put on the wire)

**Client Software**:
Which client a peer runs, as its **Software Evidence** tells it: a family (the `CT_EMULE_VERSION` compatible code, or a user-hash, **Hello Trailer** or tag heuristic for pre-mule clients; a code no table names kept raw; rmule itself by its `CT_MOD_VERSION`), version numbers as numbers, and the `CT_MOD_VERSION` mod as the bytes sent. A fact, never a label — a front end renders it, and a sort compares it by family rank then version. Read with eMule's mule test, rendered with aMule's notation (docs/protocol/parity/peer-tcp.md, *Client identification*).
_Avoid_: user agent, client string, software version (a rendered label, not the fact)

**Compatible Client**:
The program a mule hello says it is, by the top byte of `CT_EMULE_VERSION` (or the code in a legacy block) — aMule's `EClientSoftware`. The ids come from the counterparty: several codes name one family (three for Shareaza, two for MLDonkey), and a code no table names stays raw rather than guessed.
_Avoid_: client id, software code

**Software Evidence**:
What one connection has heard about a peer's software, folded in arrival order as both references keep it in one client's fields: the hello, its **Hello Trailer**, and any **Legacy Mule Info**. An `OP_HELLO` starts it afresh; an `OP_HELLOANSWER` folds into a block that arrived before it. The **Client Software** is read off it, and so is its mule flag (aMule's `ExtProtocolAvailable()`): set by a mule hello or a legacy block, cleared by a block under an unknown protocol byte, and the only thing a source ask or a queue rank waits on beyond identification.
_Avoid_: client info, hello facts (the hello alone is only part of it)

**Peer Identity**:
What a peer's hello said about it — User Hash, Client ID, ports, capability stances, its buddy, its IPv6 — read once into `PeerIdentity` and kept current by the **Peer Session** that read it: a later **Legacy Mule Info** revises its **Client Software**, its client-UDP reask contact or its source-exchange facts, an `OP_CHANGE_CLIENT_IP` its IPv6, and an `OP_CHANGE_CLIENT_ID` its Client ID and the server it names (its "on our server" claim then reads that address). The session reports it whole: `Identified` at the hello, then `IdentityRevised` naming what changed. The facts consumers derive — the peer-UDP crypt target, the peer as a source, its UDP contact, its "on our server" claim — are read off it, never copied apart from it, and it lives as long as the connection. The peer as a source is read against the link it was met on: over IPv4 a claim that is no Low ID is the link's address, as aMule reads a High-ID client (`BaseClient.cpp:661`, `:678-680`), so a hello never chooses where rmule dials.
_Avoid_: hello record (core's name for this same value), hello facts (a copy that stops tracking the peer)

**Hello Trailer**:
The four bytes some clients append after a hello's connected-server endpoint: `KDLM` for MLDonkey, any other word for old eDonkey Hybrid. Read only at exactly that length, as both references do; a tail of any other length is ignored, never a reason to refuse the hello.
_Avoid_: trailing bytes (that names a refusal rmule does not make)

**Hello Refusal**:
A peer's hello that rmule refuses under a named code, not as plain malformed input. Today there is one code: a hello that **counts a tag it never wrote**. Its tags end exactly where the connected server (and an optional **Hello Trailer**) begins, so a reader that trusts the count takes that endpoint for a tag. Both references refuse such a frame, and so does rmule. The refusal carries the name and mod the peer wrote before its frame went wrong, as the peer's own text. Core counts every refusal and raises it as an event; no peer address travels with it (ADR-0050).
_Avoid_: malformed hello (a refusal without a code), tolerated hello (rmule reads the count as the references do)

**Legacy Mule Info**:
The `OP_EMULEINFO` / `OP_EMULEINFOANSWER` block (protocol byte `0x01`) with which a pre-0.42 mule names its capabilities, compatible code, mod and — in its first byte — its only version. rmule reads it into the **Software Evidence** and the session's capabilities, answers it, and writes its own as a projection of the hello it advertises (ADR-0047). aMule's OS-info block (protocol `0xFF`) shares the opcode and is not one.
_Avoid_: eMule info (ambiguous with the capability set), mule info packet

**Static Capability Claim**:
A hello bit that says what rmule *can* do regardless of current state — the mod-misc options (`CT_MOD_MISCOPTIONS`: ExtSX, uTP NAT-T, IPv6, skip-tags) sent in every hello (ADR-0087, ADR-0091). The *fact* rides in a separate tag (`CT_MOD_IP_V6` present only while a Known IPv6 is advertisable). Complements **Honest Capability Advertisement**: the bit is honest about capability, the tag is honest about now.
_Avoid_: feature flag, has-IPv6 (that is the tag, not the bit)

**ExtSX Record**:
The IPv6-carrying source-exchange record (version pinned at 1): id, port, and a tag list read with bounds-checked, skip-unknown-by-type rules — never a whole-packet abandon. Admitted only as the carrier of a peer's IPv6 endpoint; emitted only to peers that claimed ExtSX.
_Avoid_: extended source exchange (the wider emule-qt feature this map ruled out), SX3

**Reask Responder**:
The uploader half of the peer-UDP reask (ADR-0057), sans-I/O and stateless. It reads an `OP_REASKFILEPING` (`0x90`) into a typed ping, then answers it once core has resolved the pinger against its queue: *Known* (the file it waits for, its rank, its UDP version, its extended-requests claim and its crypt target), *Ambiguous* (several waiters behind one IP) or *Unknown*, together with the queue's waiting length and maximum and the file as we share it — its size and the parts we hold, which a whole file states as the count `0` alone. The answer is a reply plus the peer it may be obfuscated for, or a named silence, plus the part status the ping restated for core to record. Every aMule rule sits inside: the sender is resolved before the file, the UDP version gates what is read, a malformed ping is silenced and counted, `OP_QUEUEFULL` goes only to an unknown pinger while `waiting + 50 > max`, and a hash mismatch, an ambiguous IP or an unknown pinger with room are dropped silently.
_Avoid_: reply matrix (the rules, not where they live), reask handler

**Reask Requester**:
The downloader half of the peer-UDP reask, sans-I/O and stateless. It frames the `0x90` for a file from our version, the source's version and our part status, and reads a `0x91`/`0x92`/`0x93` reply into a typed outcome: a rank with the part status it carried, queue full, file not found, or ignored with the reason. It negotiates `ours.min(theirs)` itself for both directions. The per-source standing, the clock and the one-ping-in-flight latch are core's **Remote-Queued Pool**; the requester only says what was heard.
_Avoid_: reask scheduler (that is the pool's clock), pinger

**Rendezvous**:
The introduction that lets two firewalled peers punch (ADR-0091): the requester's observed UDP endpoint carried to the target by a coordinator — the Kad serving buddy (eMuleAI's `OP_RENDEZVOUS` embedded in the buddy reask; standalone form accepted) or an ed2k-server's `0x61` — answered by an **Endpoint Hint**, after which both sides **Punch**. Direction is decided by which frame arrived, never by a bit; a claimed address is a lookup key unless the observed source is unusable and the claim is public.
_Avoid_: callback (that is the reachable-side dial-back family), hole-punch request, NAT-T request

**Punch**:
The simultaneous burst of empty `OP_HOLEPUNCH` datagrams (six, plus a ±16-port sweep, jittered, scheduled at half the measured relay RTT when known) that opens both NATs' mappings so a **Tunnel** can rise. Attempted for every eligible pair within eMuleAI's budget; never gated on a NAT-type label.
_Avoid_: hole punching (the technique; this is one attempt), probe

**Endpoint Hint**:
`OP_NATT_ENDPOINT_HINT` (`0xC5 0xAA`, fixed 56 bytes) — the **serving buddy's** answer to a **Rendezvous** that asked for one (`0x20`): the target's live UDP endpoint *as the buddy observes it*, the one address in the exchange a third party saw. Believed only when buddy ID, source address and source port all match the buddy the rendezvous went to. Not the target's own statement — eMuleAI builds it on the buddy (`ClientUDPSocket.cpp:1271`), and ADR-0091's first wording had the sender wrong.
_Avoid_: address announcement, candidate (ICE vocabulary), target's answer

**Precedence Rule**:
How a **Rendezvous** becomes a **Punch** destination (amule#1177 corrections 1, 4, 5): an *observed* source beats anything the datagram claims; a *claimed* endpoint is adopted only when nothing usable was observed and the claim is publicly routable; everywhere else the claim is a *lookup key* into peers already known, so an unresolvable claim does nothing. Whatever arm fires, the result is public or there is none. Its routability test is eMuleAI's thorough `IsPublicIP` and is deliberately stricter than **Address Learning**'s admissibility — that asks whether an observed value could be ours, this asks whether a stranger's unverified claim may aim our datagrams somewhere.
_Avoid_: address selection, candidate priority (ICE vocabulary)

**Rendezvous Schedule**:
One source's NAT-T budget, sans-I/O and explicit-time with the jitter handed in: a trigger grants retries (2 route chosen / 4 candidate promotion / 6 rendezvous answer — grants never stack), a transport failure backs off 60 s, and five failures or 120 s without a **Tunnel** make the source *temporarily unreachable* for 60 s with the reason kept. A source whose grant is spent goes idle with its clock stopped and its failures remembered. There is no NAT-type gate — this budget is what bounds a pair that can never succeed.
_Avoid_: retry policy, backoff timer (it is both and the cap), NAT-T state machine

**Own Mapping**:
What our own observers saw of our UDP mapping in the current Extern Port Round (ADR-0091's amendment): *Endpoint-Dependent* when two distinct Kad observers saw two different external ports, *Endpoint-Independent* when two or more saw one, *Unknown* otherwise. The only input that can start **Port Prediction**, and the one narrow exception to "no NAT-type gate" — it is a measurement of our own mapping, never a label or a peer's claim.
_Avoid_: NAT type, symmetric verdict, NAT classification

**Peer Mapping**:
A peer's coordinator-observed UDP port against the client-UDP port it advertised: *Hard* when they differ, *Easy* when equal, *Unknown* when either is missing. It only ever vetoes a **Port Prediction** role, so nothing a peer claims can make rmule probe it.
_Avoid_: peer NAT type

**Port Prediction**:
The one-symmetric birthday policy behind `natt.port_prediction = birthday` (the default since its bench row passed; `off` is eMuleAI's baseline alone). An Endpoint-Dependent node plays the **Fan**: 256 extra sockets, one empty `0xA1` from each to the punch target. An Endpoint-Independent node plays the **Probe**: 256 empty `0xA1` to a **Probe Set** of distinct random ports in 1024–65535 at the target's IP, 3 s later. Two attempts, 60 s apart, per introduction; the baseline burst is unchanged underneath.
_Avoid_: port guessing, sweep widening (the sweep stays ±16)

**NAT-T Envelope**:
`OP_UDPRESERVEDPROT2` (`0xB2`) and its one-byte frame-type namespace — `0x00` uTP, `0x01` QUIC, `0x02`/`0x03` **CAPS** / CAPS-ACK, `0xFF` **Key Frame** (ADR-0091). Opcode-free by design: `[0xB2][frame type][payload]`, minimum two bytes, and an undefined type is dropped rather than answered, because the type space is the dialect's only extension point. This crate owns the codec; the sockets and engines are `rmule-net::natt`'s.
_Avoid_: NAT-T packet, tunnel header (the **Tunnel** is what rises *inside* the envelope)

**CAPS Negotiation**:
The second, per-**endpoint** capability stage that overrides the hello's **Static Capability Claim**: a CAPS frame carries the one **Connect-Options Byte** and is answered with exactly one CAPS-ACK. A peer that claimed uTP and not QUIC and has not answered within 1500 ms is legacy-uTP-only; a QUIC failure blacklists that endpoint for 120 s; a rendezvous carrying a uTP hint pins the transport outright. Keyed by endpoint, never by peer — a blacklist, a probe timer and a caps answer are all facts about one `(ip, port)` mapping.
_Avoid_: capability block (that is the hello's per-connection nibble set), handshake

**Connect-Options Byte**:
The single `byCryptOptions` byte shared by the crypt ladder (`0x01`/`0x02`/`0x04`), the direct-UDP callback (`0x08`), the endpoint-hint *request* (`0x20`) and the two NAT-T transports (`0x40` QUIC, `0x80` uTP) — one byte, one namespace, which is the correction amule#1177 settled after the opposite was published. Bit 7 means something else entirely in a source-exchange record ("the source's user hash follows"), so the NAT-T reading lives on its own type rather than on `SourceCryptOptions`.
_Avoid_: crypt options (that is three of its eight bits), flags

**Key Frame**:
`0xB2 0xFF` — the sender's own 16-byte **User Hash**, and the dialect's whole key-distribution mechanism: `0xB2` is never obfuscated in its plaintext form, but a transport frame *is* obfuscated once a key for the endpoint is known, and this frame is how the key arrives. Sent once per endpoint per 10 s on a uTP `ST_SYN` or a QUIC long header; the learned hash lives 10 minutes. The TTLs and the map are `rmule-net::natt`'s; the frame is here.
_Avoid_: handshake, key exchange (nothing is exchanged — each side asserts its own hash)

**QUIC Proof**:
The 37-byte `EAQN1 ‖ sender hash ‖ expected hash` that must be accepted before one application byte crosses a NAT-T QUIC stream. QUIC's own handshake proves nothing here — the certificates are self-signed and unverified — so this is what ties the connection to a **User Hash**. uTP has no counterpart and needs none: the eD2k hello inside the tunnel is the identification.
_Avoid_: authentication, SUI (**Secure User Identification** is a different, signed proof, unaffected by the tunnel)

**Compressed Part**:
A part transfer whose payload is compressed (`OP_COMPRESSEDPART`) rather than raw (`OP_SENDINGPART`). Negotiated *per direction* through each side's **Capability Block**: a peer sends us compressed parts only if our block advertised data compression, and we send compressed only if the downloading peer's block did. Independent per direction, so "accept compressed, send raw" is a valid state.
_Avoid_: compressed file (the file content is unchanged; only the on-wire part payload is compressed)

**Advertised Parts**:
The parts a peer's part status says it holds of one file — an `OP_FILESTATUS`, a `0x91` ack's status, the status a name ask or a reask ping carries — read over the file's real parts: a count of `0` is a complete source, every part; a count of `ed2k_status_part_count(size)` gives the first `part_count(size)` bits, so the phantom part of an exact multiple is never read; any other count is refused whole, as aMule throws. `PartBitmap::advertised_parts` is the one reader; rmule-core keeps each source's on its record.
_Avoid_: availability, file status (that is the packet), bitmap (that is the wire form)

**AICH Exchange**:
The peer C2C packets that carry **AICH Hash Set** recovery data (`OP_AICHREQUEST 0x9B` /
`OP_AICHANSWER 0x9C`) and master-hash discovery (`OP_AICHFILEHASHREQ 0x9E` /
`OP_AICHFILEHASHANS 0x9D`), all under `OP_EMULEPROT 0xC5`. Gated by the **Capability
Block** AICH-version field and bidirectional like every transfer capability: a **Peer
Session** both requests recovery for its own download and answers a peer's request for a
file it shares. The session carries `recovery_data` as opaque bytes; the SHA-1 tree
semantics live in `rmule-primitives`.
_Avoid_: AICH negotiation (that is the capability-version handshake in the hello), hash set request (that is the MD4 `OP_HASHSETREQUEST`)

**Secure User Identification**:
The RSA challenge/response that proves a **Peer Session**'s counterparty actually
owns the **User Hash** it claims, so credit cannot be spoofed by claiming another
peer's hash. Three C2C packets under `OP_EMULEPROT 0xC5` — `OP_SECIDENTSTATE 0x87`
(a state byte plus a random `u32` **SUI Challenge**), `OP_PUBLICKEY 0x85` (DER public
key), `OP_SIGNATURE 0x86` (a signature over the *verifier's* public key ‖ its
challenge, which binds each proof to one peer and one exchange — anti-relay plus
anti-replay). Gated by the **Capability Block** secure-identification nibble
(`MiscOptions1` bits [16..20)); the exchange negotiates the lower common version. V1
signs the challenge only; V2 also binds the sender's IP via a `byIPUsed` kind flag
that stays honest under Low-ID/NAT. Bidirectional like every transfer capability. The
RSA keypair and its sign/verify live in `rmule-primitives` next to **User Hash**; the
packet codecs, the challenge state machine, and the signing-input assembly live here.
The signing scheme is RSASSA-PKCS1v15 with MD5 — deterministic, so a captured
`(key, challenge, signature)` triple is a reproducible **Compatibility Fixture**.
_Avoid_: authentication, login, encryption (SUI proves identity for credit; it does
not encrypt traffic — that is obfuscation), secure channel, user hash (the value it
proves ownership of)

**SUI Challenge**:
The random `u32` freshness nonce a **Peer Session** generates and sends in its
`OP_SECIDENTSTATE`, which the counterparty must fold into the bytes it signs. Each
side issues its own challenge to the other; a replayed or stale challenge is the
primary adversarial path a **FakePeer** scripts.
_Avoid_: signature, session key, nonce (unqualified)

**Private-Citizen Parity**:
The human-layer sibling of **Empty-Storer Parity** (rmule-kad): rmule behaves
byte-exact as an aMule 2.3.3 client with every human-layer feature at its most
private / refusing setting — `CanSeeShares = nobody` (browse answered with
`OP_ASKSHAREDDENIEDANS`), no comments/ratings feature, chat received but never
answered. Every byte sent — and every silence — is one some legitimate aMule
client produces today, so no invented bytes are possible by construction.
Handlers are explicit, gate-counted, and either respond-by-parity, surface a
display payload as a session event, or drop-with-counter (ADR-0068).
_Avoid_: stub handler, fake answer, opcode blackhole, silent mode

## Relationships

- A **Peer Session**'s **Requester Capability** and **Server Capability** are active concurrently after the hello exchange; one accepted or dialed socket carries both directions (eMule peer connections are bidirectional, which the credit system rewards).
- A **Peer Session** projects every decoded **Peer Packet** onto a **Peer Event** in its **Vocabulary Group**; the inbound serve-side opcodes (`OP_REQUESTFILENAME`, `OP_SETREQFILEID`, `OP_HASHSETREQUEST`, `OP_STARTUPLOADREQ`, `OP_REQUESTPARTS`, the source and AICH asks) drive the **Server Capability** rather than being dropped as `Unknown`.
- The session keeps the wire facts it negotiates and never hands them out to be echoed: the source-exchange version a peer's ask is answered in, and the framing limit that leaves an IPv6-only source out of a classic entry list. Core answers a Server ask with files and sources; the session picks the opcode and the entry form, and an answer left empty sends nothing (ADR-0055).
- A **Peer Session** declares its **Capability Block** in the hello and reads the remote peer's; together they gate every eMule extended-protocol exchange (**Compressed Part** transfer first, then source exchange, AICH, … as ADR-0047 slices land). Under **Honest Capability Advertisement** rmule's block advertises only implemented fields, so a peer never invokes a feature the session would otherwise drop as `Unknown`.
- **Secure User Identification** is the last transfer capability lit under ADR-0047; it shares the exact math-vs-framing split as **AICH Exchange** (crypto in `rmule-primitives`, packets + state machine here) and is gated by its own **Capability Block** nibble. Its purpose is upstream of the peer session: proving **User Hash** ownership so the **Core Orchestrator**'s credit accounting rewards the right peer — the session performs the proof, but the credit ledger and any policy toward unproven peers live in Core.
- The wire codec layer (`packet.rs`, `slot.rs`, `parts.rs`, `file_request.rs`, `hash_set.rs`, `hello.rs`) is already symmetric — every packet has both `encode` and `decode`; only the session/orchestration layer carries the requester/server split.
- The **NAT-T Envelope** codec, the **CAPS Negotiation** state and the **QUIC Proof** live here because they are wire and clock, not socket; `rmule-net::natt` owns the demux, the uTP and QUIC engines, the **Key Frame** TTL maps and the **Tunnel**. ADR-0091's seam list puts CAPS negotiation in this crate and the `0xB2` demux in the runtime, and the split is exactly that line.
- The **peer-UDP module** (`peer_udp`) holds the client-UDP codec, the **Reask Responder**, the **Reask Requester** and the pure peer-UDP crypt rules: aMule's per-peer `ShouldReceiveCryptUDPPackets` predicate, the public-IP gate that picks the sender address a send is keyed on, the **Connect-Options Byte** ↔ crypt stance mapping, and the plaintext `0x95` direct-callback framing. Core keeps the shared socket and its demux, the upload queue and the Remote-Queued Pool that the two halves read through their seams, and the I/O half of crypt: the OS nonce, our own identity and public address, and the key calls into `rmule-primitives`.
- `rmule-peer` has no dependency on `tokio`; all runtime concerns (dialing, the inbound listener, capture) live in `rmule-net`'s `peer` module.
