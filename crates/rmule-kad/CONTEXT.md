# rmule-kad

`rmule-kad` is the sans-I/O Kad protocol library for packet envelopes, Kad identities, deterministic lookup state, and fixture-gated source lookup behavior.

## Language

**Kad Evidence Gate**:
A named compatibility fact that blocks a Kad behavior until it is proven by references, private captures, or promoted fixtures. It protects production APIs from pretending that unresolved byte order, identity, or routing behavior is known.
_Avoid_: TODO flag, test skip, implementation blocker

**Private Kad Transcript**:
A packet-level evidence set captured from harness-owned Kad nodes on a private network using synthetic content. It proves Kad source lookup, publish, or routing behavior without public Kad peers. The harness may control node identities and topology — and rmule itself may participate as a **Kad Stimulus Node** — to elicit a specific exchange. Evidence bytes are only the bytes a real client (aMule/amuled) emits; rmule-authored bytes can never prove a **Kad Evidence Gate**.
_Avoid_: public Kad crawl, live-network smoke test, synthetic packet (bytes the harness authored, as opposed to a real-client packet the harness merely provoked)

**Kad Stimulus Node**:
A harness-owned rmule node that participates in a private Kad exchange (e.g. as publisher or requester) to provoke a real client into emitting the response under proof. Its own bytes are stimulus, retained in the transcript for context only — never evidence. A real client's independent re-encoding of stimulus data (parse → store → re-serialize, or substitution with its own observation, such as the storer overwriting a published source IP with the observed UDP sender) is evidence.
_Avoid_: fake node, mock peer, synthetic client

**Core-Pumped Stimulus Node**:
A **Kad Stimulus Node** whose Kad node runs inside the Core pump rather than on a direct Kad-UDP driver, so the counterparty can reach core-owned surfaces during the exchange — the held buddy link, the serve listener it dials back on, the shared client-UDP socket. The distinction is load-bearing for evidence: a direct-driver stimulus node presents a Kad-UDP-only surface, so an exchange whose second leg arrives over peer-TCP or the client-UDP socket (buddy serve, callback relay) cannot complete against it, and its capture stays deferred however correct the code is. Realized as `rmule-tools ed2k serve start --kad` and harness flow M (`kad-core-buddy`), which proved the distinction live: a firewalled aMule's `0x51` recruit drew rmule's `0x5A`, and the counterparty then dialed the **serve listener's own port** and spoke eD2k on it — a frame that cannot exist against a Kad-UDP-only stimulus.
_Avoid_: full-core harness node, integrated runner, real-node stimulus

**Stimulus Posture**:
A declared value for rmule's *own* network position, standing in for a self-check that cannot converge in a harness swarm — today the ADR-0058 reachability verdicts a **Core-Pumped Stimulus Node** needs before the ADR-0061 recruit gate will accept (`--kad-assume-open`). It is stimulus configuration in the same class as a pinned Kad ID: it shapes what rmule offers, never what the counterparty says. Off by default, so a genuinely firewalled deployment still refuses to serve as a buddy.
_Avoid_: fake verdict, forced state, mocked reachability (nothing is mocked — the store holds the same value the projection would settle on)

**Kad Node Role**:
One of four separable capabilities of a Kad node: **Routing Responder** (answers hello/ping/bootstrap/routing lookups; makes the node routable), **Kad Requester** (walks lookups and searches for sources), **Kad Publisher** (announces its own shared files' sources to nodes near the target key), and **Kad Storer** (indexes others' source publishes near its own ID and answers their searches). rmule implements all four over both the source index and the keyword index (ADR-0062), and answers firewall checks (ADR-0058) and buddy mediation (ADR-0061) — all dispatched from the node's own opcode routing. Notes indexing is deliberately not a role: that layer is answered via **Empty-Storer Parity** (ADR-0063). The Routing Responder excludes nothing about the asker from a `KADEMLIA2_RES` — no ID, no address — matching aMule's `CRoutingBin::GetClosestTo`, which takes no `except` parameter either: a peer that once helloed to us can be handed straight back to itself. The guard against dialing that self-named row back is the Kad Requester's own: `KadLookupWalk::add_candidate` drops any candidate whose ID is ours before it ever occupies a walk slot.
_Avoid_: server mode, DHT provider, seeder

**Kad Source Result Row**:
One row inside a `KADEMLIA2_SEARCH_RES` payload, made of a source identity plus tags that may describe direct, Low ID, firewalled, buddy, or callback-mediated source forms.
_Avoid_: peer source, search result, routing contact

**Kad IPv6 Tag**:
`ip6` (a source's own IPv6) and `bi6` (its buddy's), each a string tag of exactly 32 ASCII hex characters, MSB-first, parsed case-insensitively and ignored at any other length (ADR-0087). Nothing else about Kad changes — no opcode, no version, no contact format — and contacts themselves stay IPv4 end to end; the tags ride *inside* a source publish and a source result, which is how a 128-bit address travels a 32-bit network. `ip6` is published only while core reports a Known IPv6, because the tag is a claim that the address works now; `bi6` rides a firewalled row inside its buddy contact (`KadBuddyContact::buddy_ipv6`), from the held buddy link core states, and never makes a row dialable. rmule writes both in upper-case hex.
_Avoid_: IPv6 contact (there is no such thing in Kad), AAAA record

**Publish Connect Options**:
The connect-options byte a source publish (`0x44`) carries last, as `TAG_ENCRYPTION` — core's composition, injected by `KadCommand::SetPublishConnectOptions` and never assembled by the node, which holds none of the facts its bits state. A node never told a byte omits the tag rather than claiming zero. Read back through the **Kad Source Row Projection**, where bit 7 means uTP NAT-T (an eMuleAI or rmule publisher) and never "hash follows".
_Avoid_: encryption tag (the tag's name, not its meaning)

**Kad Source Row Projection**:
The evidence-gated mapping from a proven **Kad Source Result Row** into one of four answers — a direct-connectable **Peer Source**, a **Kad Buddy Contact** to reach it through, a **Direct-Callback Source Row**'s Kad UDP endpoint, or a Kad diagnostic — each carrying the row's whole facts beside it (ADR-0043's source-row amendment): the publisher's **User Hash** (the row's 16-byte source ID, word-swapped), its connect-options byte, its Kad UDP endpoint and its buddy. It is narrower than decoding the whole Kad result packet. A **Kad IPv6 Tag** on a row the 32-bit projection refuses — a Low ID, a buddy callback, a firewalled source — rescues it into an IPv6 **Peer Source**; a row that already yielded a direct High ID keeps it, since dialling IPv4 needs no address of our own. Every answer but a diagnostic crosses to a download as one **Source Sighting** (`rmule-primitives`), its road the projection's verdict.
_Avoid_: source parsing, peer discovery policy, result ranking

**Kad Buddy Contact**:
The serving buddy a firewalled publisher names in a type-3/5 source row: the relationship ID `~publisherKadID` (`TAG_BUDDYHASH`) and the buddy's UDP endpoint (`TAG_SERVERIP`/`TAG_SERVERPORT` — the *buddy's*, despite the tag names). It is the only thing that makes such a row reachable, so a type-3/5 row without one stays a diagnostic. The same shape rides the other way: a held buddy, injected by core through `SetPublishPosture` (`KadPublishPosture::Firewalled`), turns every source publish into the firewalled row; firewalled with no buddy, the node publishes no source row at all (aMule's `PrepareToStop`). The layout is pinned to a firewalled aMule's own `0x44` (`tests/fixtures/buddy/captured/amule-233-publish-source-req-20260922`): `TAG_BUDDYHASH` is upper-case hex in `ToByteArray` big-endian order, `TAG_SERVERIP` carries the address octet-first, and no publisher writes `TAG_SOURCEUPORT`. ADR-0061 records it with its citations and the one byte-order trap that stays a source reading (the eMule/eMuleAI family's `GetData()` spelling of the same tag). The contact therefore has two **spellings** of its buddy ID: the primary, aMule's captured reading, and the fallback (`fallback_buddy_id`), the same 32 characters read the eMule way — one per-word swap away (`KadId::word_swapped`). rmule writes only the primary; a requester tries the fallback once, after the primary drew no dial-back.
_Avoid_: buddy slot (that is core's held link), server (the tag names lie; no server is involved)

**Direct-Callback Source Row**:
The type-6 source row a firewalled publisher writes when it can be called back by direct UDP: `TAG_SOURCETYPE` 6, its TCP port, the size, and the **Publish Connect Options** with bit 3 — no buddy trio, no large twin. The node chooses it from bit 3 of the byte core stated, never from a fact of its own, and ahead of a held buddy, as aMule does (`Search.cpp:821-839`). Read back, a row with bit 3 and the storer's observed Kad UDP endpoint projects to that endpoint — where a requester's `0x95` goes — and one without either stays a firewalled diagnostic. Pinned from source and captured at both tiers off a storer's own capture (ADR-0061): rmule-authored and aMule-authored. Stock aMule 2.3.3 writes it only while it still holds a Low-ID buddy, because its publish gate has no direct-callback branch. Its row carries `TAG_SOURCEUPORT`, which rmule's does not.
_Avoid_: firewalled row (that is type 3/5, which needs a buddy), direct row (type 1/4, dialable over TCP)

**Extern Port Round**:
How the UDP self-check learns the **Extern Kad Port** before it engages any helper (ADR-0058; aMule `FindExternKadPort`/`SetExternKadPort`, `Prefs.cpp:291-334`): while the test runs, a `0x60` every 15 s to one contact of Kad version ≥ 6 that is not failing (`Kademlia.cpp:223-243`), plus a `0x60` to any version > 5 node whose `HELLO_REQ`/`HELLO_RES` arrives while the round collects. A `0x61` counts only from an IP we pinged in the last 180 s, once per observer, up to three observers, and is stated as `UdpPortObserved` — never judged here. The round ends on core's answer: a nonzero learned port, or a zero answer to the third observer (unreliable: the port becomes `0` and the check runs on the intern port alone). Until it ends no helper is engaged, so the `0xA7` always carries the answer that ended it. Every recheck opens a new round; the learned port stands until that round settles another. The node marks the boundary with `KadEvent::ExternPortRoundStarted` — emitted exactly when a recheck actually restarts an armed tester — so core's store can forget the previous round's votes rather than let one back a report named after the boundary, matching aMule's `FindExternKadPort(true)` clearing the observer lists.
_Avoid_: port discovery (vague about who owns the rule), NAT probe (that is the harness's reflector)

**Extern Kad Port**:
The port the outside world reaches our Kad socket at, which a NAT may remap (aMule `GetExternalKadPort`). Owned by core's Address Learning store — the UDP role's learned port, with the `0x61` agreement rule applied there — and injected into the node by `SetExternalUdpPort`; the node keeps a copy for the `0xA7` body and the tester's open-port preference, never a rule of its own. Core's pump restates this answer outside any observation too, at Kad start and on the recruit tick (the reconciler in core's Kad Pump State); `set_extern_udp_port` only skips a zero answer while the **Extern Port Round** still collects (that answer may yet be settled by a later one) — once it has settled, a zero answer writes through, so the node's copy follows the store the moment its 30-minute window ages out rather than sitting on a value the store no longer holds. The round boundary forgets the store's votes, never the node's already-settled copy: `ExternPortRoundStarted` clears the UDP role's `KadCheck` rung so the port needs two fresh observers again, exactly as aMule starts each round's observer lists empty.
_Avoid_: public port, mapped port (a mapping grant is one source of it)

**Helper Lookup**:
The UDP self-check's own lookup (ADR-0058; aMule's `NODEFWCHECKUDP`, `SearchManager.cpp:594-603`): a walk toward a random target, drawn from the driver's entropy, launched by the first Kad datagram after the check is armed (aMule's `Connected()`) and again by every recheck. It asks each seed for eleven contacts and never walks the answer: every row goes to the tester's possible list instead, because a **UDP Firewall Helper** is only fresh while we have never sent it a datagram — rows that became walk candidates or routing contacts would spend exactly that. The tester pops the list by aMule's `QueryNextClient` rules — Kad version above 5, not ourselves, an IP never engaged before, an IP absent from our routing zone — and engages at most two at a time; a cancelled helper frees its slot for the next row, a failed one counts toward the two. aMule's last rule, refusing an IP its client list already knows, is core state this sans-I/O node cannot hold: the candidate is still engaged and emitted here, and core's **Peer Roster** applies that gate one hop later, before it ever dials, reporting cancelled unasked. The hourly recheck launches a fresh lookup too, not only the ADR-0086 external one: a recheck mid-test aborts it rather than waiting, and a result from the abandoned round lands `Stale` — dropped without touching the verdict — never `Duplicate` or a fresh conclusion.

When *this* node is the **UDP Firewall Helper** for a stranger's request: its `0x62` answer is keyed to whatever the `0xA7` carried, never to a stored contact — aMule's `ProcessFirewallCheckUDPRequest` passes the request's own sender key as `targetKey` and `NULL` as `cryptTargetID` unconditionally (`BaseClient.cpp:4008-4013`), so the reply always rides the KadVerify family under that value (the requester's own verify key for our IP) and never the NodeID family, plaintext only when the request carried no key. The errorcode is biased when the requester is a routing-zone contact *or* `caller_known` says core's Peer Roster already has an active upload with it — that second fact is core's, carried in as a plain bool since the node cannot hold it itself.
_Avoid_: helper search, random lookup (it is random only in where it walks), self-lookup (that walks our own ID)

**Callback Walk**:
aMule's `FINDSOURCE` search: a lookup toward a firewalled source's buddy ID for a row whose **Kad Buddy Contact** carried no usable endpoint (the tags absent or zero, which aMule reads alike). The walk never learns the buddy's endpoint as a fact: at convergence it sends the `0x52 KADEMLIA_CALLBACK_REQ` to every responded contact inside `SEARCHTOLERANCE` of the ID (or on a LAN), closest first, at most 21 — the buddy was recruited by a walk toward the same ID, so it sits among them. Sent under the node's obfuscation matrix like every walk datagram, where the endpoint-known `0x52` goes in the clear. One walk per target: a second toward an ID already walked ends at once as `AlreadyWalking`. Ends in `CallbackWalkEnded`: `Asked(n)`, or `NoneNear` when nobody could be the buddy.
_Avoid_: buddy walk, FINDBUDDY walk (that is recruitment toward `~ourKadID`), source search (that walks a file's key)

**Bootstrap Dial List**:
An ordered list of candidate contacts dialed one at a time with bootstrap requests until the routing table warms — sourced from config endpoints, a v3 bootstrap-edition nodes.dat (closest-50 to own ID), or an **ed2k→Kad handoff** (a connected eD2k peer's Kad endpoint, ADR-0067), all unified into one list. Dialed on aMule's cadence (2 s while the table is empty, 15 s once it holds contacts); each dialed candidate is discarded, never re-queued. Every dial stamps one shared throttle (aMule's `m_bootstrap`): the handoff gates its own seed on **≥ 10 s since the last dial**, so peer hints and list dials rate-couple. Its contacts are never merged into the routing table directly; only their answers seed it. Exists so bootstrap files don't concentrate load on a few famous nodes.
_Avoid_: seed nodes (they're candidates, not table entries), routing table import, contact list

**Seeded Bootstrap**:
A routing-table admission via `KadCommand::MergeContacts`: each contact enters
directly `Responded` (aMule's nodes.dat `AddUnfiltered`, `RoutingZone.cpp:139-233`
— no `BOOTSTRAP_REQ` round trip earns the slot), so this node can serve and walk
through it at once. That says nothing about the reverse: a counterparty only
ever learns of *this* node once this node's own `HELLO_REQ` reaches it
(`Process2HelloRequest` → `AddContact2`, `KademliaUDPListener.cpp:577-649`), and
a merge sends none by itself. The **Small-Timer Hello Pass** closes that gap,
joined or not: a merged contact is never-checked, so it draws a hello on the
first pass that finds it at its bucket's front — within seconds of a
table-seeded start, and ≤ 1 min once it is its bucket's oldest when merged
into an already-joined node (aMule: 1–2 min). The pass once skipped while
joined, which is why a bench flow (run `1790118192`) switched its
helpers to `KadCommand::Bootstrap`; that is still the quickest greeting (the
answer is probed at once) but no longer the only one.
_Avoid_: nodes.dat import (aMule's own file format; rmule takes contacts as a
command, not a file), bootstrap seed (that names the **Bootstrap Dial List**,
a different admission path entirely)

**Small-Timer Hello Pass**:
aMule's per-zone `OnSmallTimer` (`RoutingZone.cpp:926-1010`), run by the node
every minute once the driver arms it, with no joined gate
(`Kademlia.cpp:187,277-280`). Each non-empty bucket's oldest entry is looked at
once per pass: if its expiry has passed (or it was never checked) it gets one
`HELLO_REQ` and a 2-min hold (`CheckingType`); otherwise it moves to the back.
An answer from a contact already held marks it alive — held out 1 h, 1.5 h or
2 h by its age in the table (`UpdateType`) and moved to the back — so a live
table is re-greeted every hour or two. A silent contact gets a second
`HELLO_REQ` and check window before eviction, never fewer than aMule's own
dead-sweep minimum (`RoutingZone.cpp:960-968`): the pass evicts a due
contact directly once it has had two unanswered checks, rather than the
ordinary probe timeout failing it. The per-entry expiry, creation instant and
check count are the only pieces of aMule's contact type ladder rmule keeps
(ADR-0067).
_Avoid_: join-hello pass (its earlier name, when it ran only while not
joined), keepalive, routing refresh (that is the big timer's random lookup),
probe-timeout eviction (that is what a lapsed small-timer hello no longer
triggers)

**Network-Joined (HasHadContact)**:
Whether the node is connected to Kad — aMule's `IsConnected` = `HasHadContact`: any Kad datagram received within the last 20 min (`KADEMLIADISCONNECTDELAY`), stamped at the packet entry gate. It gates the bootstrap dial loop (dialing stops once joined) and the forced self-lookup is the *act* of joining. Distinct from having live routing contacts — a table loaded from a file is non-empty yet not joined until a real datagram arrives.
_Avoid_: has contacts (table non-empty ≠ joined), online, bootstrapped

**Forced Self-Lookup**:
A `FindNode` walk toward the node's own Kad ID, run 3 min after the join begins and every 4 h after — it warms the own-ID neighborhood and is the join proper. Rides the ordinary lookup machinery but has no terminal search or publish; the warming is the lookup traffic itself.
_Avoid_: bootstrap dial (a self-lookup queries, it doesn't bootstrap), keepalive ping, routing refresh (that's per-bucket maintenance)

**Verified Contact**:
A routing-table contact whose IP has been proven not spoofed — by a hello carrying a valid receiver key, by the `HELLO_RES_ACK` three-way handshake, or by arriving pre-verified from a bootstrap file. Only verified contacts are served in routing answers or seed own lookup walks; unverified contacts wait in their bins until a verification path completes.
_Avoid_: responded contact (liveness, not identity), trusted node, known peer

**Admission Cap**:
One of the three limits on how much of the routing table one address or one /24 may hold (aMule's `CRoutingBin` caps, ADR-0064): one contact per IPv4 address and ten per /24 across the table, two per /24 inside one bucket. The table-wide counts are tallies the table keeps in step with every stored contact's IP; a newcomer, a `Failed` contact's replacement and a move to a new IP all pass the caps, and a refused move leaves the entry as it was. The private ranges and loopback are exempt from the /24 caps, loopback from the per-IP cap too. A deterministic mesh gives each member its own /24 for this reason.
_Avoid_: IP limit, subnet filter (the IP filter is the **Kad Node Start**'s contact admission, a different gate)

**Kad Node Start**:
The one value a `KadNode` is built from: start instant, contact admission, join cadence, firewall self-check, and obfuscation with its optional verify keys. The node orders it internally (admission before any traffic, obfuscation before its keys), and verify keys exist only inside the obfuscation, because their trailer rides inside the crypt header — a keyed node with plaintext sends cannot be started.
_Avoid_: arming, enable calls, post-construction setup

**Kad UDP Verify Key**:
The 4-byte value a node derives per counterparty IP from a private, never-transmitted installation secret and hands that counterparty in the crypt trailer of every obfuscated Kad datagram. It is one half of a directional pair: the **sender key** a node hands out, and the **receiver key** it expects echoed back. An echo that matches our own derivation for the sender's IP is the entire IP proof behind a **Verified Contact** — only a node that actually receives datagrams at the address it claims can have learned the key. A learned key is bound to the *own* public IP it was learned under, so an address change silently retires every key rather than leaving stale ones authoritative — `KadNode::set_own_public_ip` (`KadCommand::SetOwnPublicIp`) is the driver's way to move that binding after Kad start; the key we hand a target is unaffected, since it derives from the target's IP alone. Value zero is the no-key sentinel, never a derivable key.
_Avoid_: session token, nonce, node ID (public, in every routing table — it proves nothing), shared secret (the secret is never shared; only its per-IP derivations are)

**Empty-Storer Parity**:
A graceful posture where rmule adopts a byte-exact *legitimate degenerate state* of the real client — an empty or refusing index — so that every response or silence it produces is one an aMule node produces today. It handles a layer as a citizen without building its feature state. Distinct from dropping an opcode as unknown: the handler is explicit, gate-ordered, and counted.
_Avoid_: stub handler, fake ack, opcode blackhole

**Keyword Derivation**:
The byte-exact pipeline from a filename or query to Kad keyword IDs: split on aMule's separator set, keep words of at least 3 UTF-8 bytes, lowercase, then MD4 over the UTF-8 bytes. The publish direction dedupes and strips the file extension first; the search direction keeps duplicates and targets the first word. Parity is byte-level — a divergent lowercase fold silently unfinds the file — so capture-pinned fold vectors guard it.
_Avoid_: tokenization helper, text normalization, fuzzy matching

**Kad Keyword Store**:
The bounded keyword index a **Kad Storer** serves: entries keyed by keyword ID and file ID, holding a typed projection of evaluable tags for search-expression evaluation plus the publisher's verbatim tag list for faithful re-serving, aggregated across publishers into publish-info (name popularity, publisher count, trust). Caps, load reporting, and expiry follow aMule's constants.
_Avoid_: keyword cache, DHT storage, file database

**Kad Keyword Result Row**:
One row inside a `KADEMLIA2_SEARCH_RES` payload answering a keyword target: a file ID plus served tags and the storer's publish-info tag. Sibling of the **Kad Source Result Row** — same envelope, different index.
_Avoid_: search hit, file listing, source row

**Kad Distance Ordering Evidence**:
Observed Kad2 routing traffic that proves how aMule orders candidate **Kad IDs** for a lookup target. Stored contacts or exported node lists may support identity mapping, but do not prove ordering on their own.
_Avoid_: byte-order guess, routing-table unit test, node list

## Example Dialogue

Developer: "Can we expose nearest-contact selection now?"

Domain expert: "Only after **Kad Distance Ordering Evidence** is promoted. A **Private Kad Transcript** with `KADEMLIA2_REQ` / `KADEMLIA2_RES` traffic must show the ordering, not just a stored node list."

Developer: "Can this `KADEMLIA2_SEARCH_RES` row become a `PeerSource`?"

Domain expert: "Only through **Kad Source Row Projection**, and only when the promoted fixture proves the row is a direct-connectable High ID source. Otherwise it remains a diagnostic."
