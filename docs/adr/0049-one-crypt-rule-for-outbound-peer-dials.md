# One crypt rule decides every outbound peer dial, with no plaintext retry

## Context

A peer's crypt stance is three flags, supports, requests and requires, carried in its
hello's `MiscOptions2` bits, and obfuscation toward a peer is keyed on its User Hash
(ADR-0042). Peers rmule has not yet met are known from records that restate a stance on
the peer's behalf: a server's `OP_FOUNDSOURCES_OBFU`, source exchange v4, a Kad row's
`TAG_ENCRYPTION`, a Kad dial-back request, a buddy's answer. Some records carry no crypt
byte at all.

aMule refuses a dial whose two stances cannot meet in `CheckContactPreconditions`, and
its `OnError(ERR_ENCRYPTION)` path ends a dial whose crypt handshake failed. The server
connection keeps an unobfuscated second pass (`ServerConnect.cpp:73-81`, skipped under
`Required`).

## Decision

The registry's `CryptStance` (supports, requests, requires; ADR-0047) is what every
outbound peer-TCP dial reads on both sides, through one rule, `PeerCrypt::outbound`:

- **Refuse** before any socket when `(theirs.requires && !ours.supports) ||
  (ours.requires && !theirs.supports)`, as aMule's `CheckContactPreconditions` does, or
  when either side requires and the peer's User Hash is not in hand. The source retires
  as `CryptIncompatible`.
- **Obfuscate** toward the peer's hash when both support and either requests; as a must
  when either requires.
- Otherwise **plaintext**: support met by support dials clear.

**No plaintext retry.** A failed crypt handshake ends the peer dial, required or merely
requested, as aMule's `OnError(ERR_ENCRYPTION)` path does. A retry would hand the
middlebox obfuscation exists to defeat a downgrade, and the failure it would paper over
is a wrong or stale hash, meaning an endpoint that is not the peer the record names. The
server connection keeps its unobfuscated second pass, which is aMule's own.

**Which stance a dial believes.** A peer's stance is the three crypt flags plus the User
Hash a dial is keyed on (`PeerCrypt`), one stance for TCP and UDP alike.

| Source | Attaches to | Rank |
| --- | --- | --- |
| The peer's own hello (`MiscOptions2` crypt bits, hello User Hash) | the `PeerIdentity` its worker's Source Book record holds in its Worker stage, replaced whole at each revision, until the worker ends; a queue standing the worker earns keeps its peer-UDP crypt target for the standing's life | outranks every record |
| `OP_FOUNDSOURCES_OBFU`, source exchange v4, a Kad row's `TAG_ENCRYPTION` | High ID: `peer_crypts` per endpoint; Low ID: its `LowIdCandidate` | newest statement wins |
| `KADEMLIA_FIREWALLED2_REQ`, `OP_DIRECTCALLBACKREQ`, a buddy's `KADEMLIA_FINDBUDDY_RES` | the one dial-back or buddy link it authorizes | never merged |
| An accepted peer's hello (serve side) | the `PeerIdentity` the serve state keeps for its connection | only source on that road |

- **Silence is not a statement.** A record with no crypt byte (a plain source row,
  source exchange v1–v3, a Kad row without the tag) reads dark at the dial but never
  overwrites a stance another record stated (`PeerCrypt::fold_newer`).
- **A record naming another User Hash replaces the record whole**: the endpoint changed
  owner.
- **Newest record wins; the hello wins over all.** aMule keeps the earliest known client
  until the hello; rmule takes the newest relay as the better guess, and the hello
  settles it.
- A stance attaches to one owner's record, never outlives it and never moves to another
  User Hash. No dial invents a stance the peer never stated.
- `OP_CALLBACKREQUESTED`'s crypt extension is decoded and unread: rmule does not adopt
  that callback, so the byte would have no reader.

## Consequences

- A stance mismatch and a missing key both retire as `CryptIncompatible`; the
  `*_crypt_incompatible_total` counters already separate refusals caused by our own
  policy from every other reason.
- A downgrade cannot be forced on a peer dial: a failed handshake ends it.

## Considered options

- **A plaintext retry after a failed optional crypt handshake.** Rejected: it is a
  downgrade an adversarial middlebox can force.
- **A distinct refusal reason for a missing key.** Rejected for now: nothing downstream
  reads the distinction.
