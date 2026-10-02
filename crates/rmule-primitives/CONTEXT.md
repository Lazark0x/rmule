# rmule-primitives

The workspace's shared vocabulary of wire values. Everything here is pure
data — no I/O, no runtime, no orchestration — so every other crate can name the
same things without depending on any of them. Nothing in this crate depends on
another rmule crate; every other crate depends on it.

The rule for what belongs here: a type earns a place when **two** wire surfaces
already speak it, or when a single value type is the identity a protocol keys
on. A type used by one protocol crate alone stays in that crate.

## Language

**Wire Value**:
A type whose in-memory shape is dictated by the bytes on the wire, not by what
is convenient in Rust: it decodes byte-faithfully and re-encodes to exactly
what arrived. Round-trip fidelity is the crate's defining property — a decode
that "cleans up" its input would silently rewrite evidence.
_Avoid_: DTO, model, POJO

**Packet**:
The eD2k frame envelope: a protocol byte (**eDonkey**, **eMule**, or the packed
`0xD4` spelling), a length prefix, an opcode, and the payload. Decoding
enforces a frame ceiling so a malformed length cannot make a reader allocate on
a counterparty's word. The envelope alone — every opcode body lives in the
protocol crate that owns it.
_Avoid_: message, frame header, datagram

**Tag**:
A self-describing name/value pair, the extension mechanism the whole protocol
family hangs optional fields off. Names come in a numeric-id and a string
spelling; values in the integer and string types the wire defines, plus the
sixteen raw bytes of `TAGTYPE_HASH` — the type every address tag in the IPv6
dialect rides (ADR-0087), and one that must not be written as a length-prefixed
blob, since a reader expecting `HASH` takes the blob's length bytes as the
start of the value and every later tag in the packet shifts. Tag decoding
preserves both name spellings so a re-encode is byte-identical.
_Avoid_: attribute, property, field

**Ed2k Text**:
A string that keeps the bytes a counterparty sent. Server banners, file names
and descriptions are routinely Windows-1252 or mojibake, so text is stored as
bytes and UTF-8 is an opt-in projection, never an assumption.
_Avoid_: String, utf8 string, name

**Safe File Name**:
A file name from a link, a search row or a peer, cleaned to one path
component the way aMule cleans a completed file's name, so joining it to the
download directory names a file inside it. The one way a remote name becomes
a local path; the **Ed2k Text** it came from stays byte-faithful.
_Avoid_: sanitized name, filename, basename

**File Hash Summary**:
The result of hashing a local file the eD2k way: the file hash plus, for files
over one part, the **Part Hash Set** it is folded from. The one place the
`9_728_000`-byte part geometry is applied.
_Avoid_: checksum, digest, fingerprint

**Client Identity**:
Who a client claims to be at login: its **User Hash**, nickname, listening TCP
port, protocol version, and any extra capability tags the application layer
chose to advertise. The identity is data; deciding what to advertise is an
application decision (ADR-0047) and happens above this crate.
_Avoid_: credentials, account, profile

**Client Id**:
The 32-bit id a server assigns at login, whose value *is* the reachability
verdict: a routable address means **High ID**, a value below the low-id
ceiling means **Low ID** and no inbound dials.
_Avoid_: user id, session id, peer id

**Endpoint**:
Where a party is reached. `Ipv4Endpoint` and `Ipv6Endpoint` are the bare
address+port wire values of one **Address Family** each; `ServerEndpoint` is a
host string plus port; `PeerEndpoint` is the closed enum over the families a
peer can be dialed at (ADR-0085). The distinction is load-bearing — servers and
peers travel in different tag families and are dialed by different code.
_Avoid_: address, socket, host, `SocketAddr` (a runtime type, never a wire value)

**Address Family**:
IPv4 or IPv6 as a property of an **Endpoint** or a socket. A type is exactly as
wide as its wire meaning: where every implementation packs an address into 32
bits (**Client Id** High IDs, Kad contacts, the UDP source record) the type
stays `Ipv4`; where the wire can carry either (a peer, a server-handed source)
the type is the enum. One TCP/UDP port pair applies to both families.
_Avoid_: protocol version, stack, dual-stack (a socket strategy, not a value)

**Placeholder Low ID**:
The LowID-range client id given to an IPv6-only source so no garbage IPv4 is ever dialled; it names nothing on the IPv4 network and is never sent in a callback request. Written into an **ExtSX Record**'s fixed-width id field, where a `0` would read as a Low ID with no server behind it and send the reader down a callback nobody can broker.
_Avoid_: fake id, zero id

**IPv6 Half**:
The IPv6 endpoint an exchanged source carries beside its **Client Id** — a dual-stack High ID, or a Low ID still dialable over IPv6 — at the source's one port (ADR-0087). One source with two addresses, never two sources: both are the same peer, and which family is dialed is the dial chooser's call. An IPv6-only source has no half; its IPv6 *is* its address.
_Avoid_: sidecar, second source, dual-stack source (as a separate kind)

**Tag Identity**:
An address arriving in a 16-byte tag, judged by whether it can stand as one at all (`IsUsableTagIdentity`, ADR-0087). A tag carries the address and nothing else — there is no room for a scope id — so a link-local peer is `fe80::1` in the tag and `fe80::1%3` on the socket, and two peers on two interfaces collapse into one identity. Only global unicast (`2000::/3`) survives the round trip, so only global unicast is admitted. Dropping the scope from the index is not the fix: `fe80::1%3` and `fe80::1%9` really are different peers.
_Avoid_: valid address, routable check (this is about the tag, not the route)

**Ed2k Wire Form**:
The form an **Endpoint** takes in a 32-bit wire field — a `.part.met` seed, a classic source-exchange entry, a server source list — or its absence (`HasEd2kWireForm`, ADR-0087). A native-IPv6 peer is **omitted** from such a field, never written as `0`; `0.0.0.0` is refused for the same reason, being the absence of an address wearing one.
_Avoid_: IPv4 projection, downcast

**Accounting Key**:
The bucket per-address rate limiting uses: the exact address for IPv4, the `/64` prefix for IPv6 (ADR-0087). A host is delegated a whole `/64` and can mint addresses inside it — RFC 4941 privacy addressing does it on a timer — so a per-`/128` bucket is evaded by rotating the low half. Accounting **only**: never an identity, a ban scope, an index or a routing decision, which is why reask attribution goes the other way and compares the whole 128 bits.
_Avoid_: subnet ban, prefix identity

**Sentinel Source**:
A server-handed source whose 32-bit id field is `0xFFFFFFFF`, meaning "this
record's IPv6 address follows inline, as its last field" — after the port, and
on `0x44` after the crypt byte and optional User Hash (emule-qt `ipv6-spec.md`
§4.4). A reader always consumes the sixteen bytes in place, so the next record
reads in step; an address that is not a usable identity costs its record and
nothing else. Never a desync, never a whole-packet rejection (ADR-0085 as
amended 2026-09-25).
_Avoid_: trailing block, appended address (the address is inline), extended source

**Malformed Tail**:
A source list that does not measure what its records declare: a walk that runs
short once a **Sentinel Source** has been met, or a frame-delimited list that
leaves bytes nothing accounts for. The verdict rides the decoded body and its
event, so the reader reports it instead of failing: every record from the first
sentinel on is dropped, every record before it still stands, and the frame is
never rejected whole (ADR-0085).
_Avoid_: parse error, corrupt packet, trailing garbage

**Ed2k Link**:
An `ed2k://` URI in one of its three forms (file, server, server list), parsed
from its pipe-delimited text and printed back in the canonical spelling.
_Avoid_: magnet, URL, download link

**IPv6 Source Hint**:
An IPv6 endpoint a file **Ed2k Link** carries in its `s6=` token (ADR-0089
§6.2). A *hint*, never identity: a link is complete without one, and an entry
that did not parse, names an address that is not a usable identity, or names
port 0 is skipped rather than costing the rest of the list. At most 64 across
every source token of one link, emule-qt's cap.
Emission always brackets the literal and always names the port; ingest also
accepts `[addr]` at the default 4662 and a bare literal, which parses as a
*whole* address and is never split at its last colon (`2001:db8::1:4662` is
itself an address). Placement is load-bearing in both directions: the token
follows the `/` that closes the parameter section and precedes any `|sources,`
token, because stock eMule asserts on an unknown parameter and scans for
sources from the first occurrence of that substring to the end of the link.
_Avoid_: source list (that is the IPv4 `sources,` token, which rmule refuses),
peer hint

**Search Result**:
One file as search reports it, keyed by **File Hash** and tagged with the
**Search Result Origin** it came from (a server or Kad). Rows for one file from
several origins fold into a single result, summing availability rather than
listing duplicates.
_Avoid_: hit, match, search row

**Source**:
A peer that has some of a file. Three shapes with different provenance: the
**Source Lookup Target** a request asks about, the `PeerSource` a server hands
back (a High-ID IPv4 endpoint, a Low ID, or a **Sentinel Source**'s IPv6
endpoint), and the richer `ExchangedSource` peers trade among themselves (which may
carry a **User Hash** and crypt options, and so may be dialed obfuscated).
_Avoid_: seed, provider, host

**Session Core**:
The two traits (`SessionCore`, `SessionOutput`) that define the sans-I/O shape
every protocol session implements — commands in, outputs out, no clock and no
socket. Declared here so the runtime crate can drive any of them without
depending on all of them.
_Avoid_: state machine, actor, connection

**Datagram Obfuscation**:
The UDP-side crypt layer (keys, nonces, sync markers, per-family key
derivation) shared by the eD2k server, eD2k client, and Kad datagram surfaces.
It lives here rather than in one protocol crate because all three families
derive from the same primitive and must agree byte-for-byte. The ed2k client
key's *width* follows the datagram's actual source **Address Family** — 23
bytes for IPv4, 35 for IPv6, with the magic byte after the address rather than
at a fixed offset (ADR-0087). Selected, never probed: both widths are valid key
material, so a wrong guess decrypts to garbage that is indistinguishable from
an unobfuscated peer.
_Avoid_: encryption, TLS, tunnel

**Secure User Identification**:
The RSA key material and public-key encoding behind SUI (ADR-0041) — the
identity proof a peer offers to bind a **User Hash** to a keypair. The key
types are primitives; the challenge/response protocol lives in `rmule-peer`.
_Avoid_: auth, certificate, signature scheme

## Relationships

- Every crate in the workspace depends on `rmule-primitives`; it depends on
  none of them. A back-edge would be a layering error, not a shortcut.
- Protocol crates (`rmule-ed2k`, `rmule-peer`, `rmule-kad`) own opcodes, bodies,
  and session behaviour, and speak in these values at their boundaries.
- Byte-fidelity here is what makes the capture fixtures meaningful: a decode
  that normalizes its input would make a re-encode comparison prove nothing.
