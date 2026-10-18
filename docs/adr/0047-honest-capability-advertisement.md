# Honest Capability Advertisement from one registry

## Context

eMule-family clients and servers decide what to do with rmule from what it advertises.
The peer hello (`OP_HELLO` / `OP_HELLOANSWER`) carries `CT_EMULE_VERSION`,
`MiscOptions1`, `MiscOptions2`, `CT_EMULE_UDPPORTS` and more; the server login carries
`CT_SERVER_FLAGS` and `CT_EMULE_VERSION`. Peers gate AICH, source exchange, Secure User
Identification, compressed parts, multipacket and UDP on those bits. A bit rmule cannot
dispatch makes a peer drive a flow rmule cannot answer, every such packet lands in the
unknown-packet catch-all, and captures record a false compatibility profile. aMule
assembles its adverts inline at each emit site from its preferences.

The peer session tolerates unmodelled opcodes (`PeerPacket::Unknown`, stay open), so
capabilities can be lit one at a time as they ship.

Facts from the wire that shape the adverts:

- aMule 2.3.3's login carries exactly four tags (`CT_NAME`, `CT_VERSION`,
  `CT_SERVER_FLAGS`, `CT_EMULE_VERSION`); the port rides the fixed field.
- The Lugdunum 17.15 server gates login on a minimum client version. It refused rmule's
  own `0.1.0` in the version word with "Your edonkey client is too old" and closed the
  socket before any `OP_IDCHANGE`.
- A server's `OP_IDCHANGE` carries an extension (aux port, the server-reported public
  IP, the obfuscation TCP port), and aMule accepts a second `OP_IDCHANGE` mid-session as
  a Low-ID/High-ID re-assignment.
- eMuleAI reads a vendor tag without a readable mod version as a "ghost mod" and cuts its
  upload score (`BaseClient.cpp:1186-1187`, `:1451-1464`; `UploadClient.cpp:464`), and
  every rmule hello carries `CT_MOD_MISCOPTIONS` (ADR-0087). So sending no mod name is
  already a fingerprint.

## Decision

### Honest Capability Advertisement

**A capability bit is advertised if and only if rmule dispatches it.** The advert and
the behaviour land together; a bit is never lit ahead of the code that serves it.

**One registry.** `Capabilities` in `rmule-primitives` holds the shipped feature set and
policy, and every advertising surface derives from it: the server login
(`CT_SERVER_FLAGS`, `CT_EMULE_VERSION`), the peer hello (`MiscOptions1`, `MiscOptions2`,
`CT_EMULE_VERSION`) and the legacy `OP_EMULEINFO` block. A feature that ships flips one
registry entry, and a registry invariant test checks advertised bits against the shipped
set.

**The version word is identity, not capability.** `CT_EMULE_VERSION` is aMule 2.3.3's
word `0x0304_0D80` = `(SO_AMULE << 24) | make_full_ed2k_version(2, 3, 3)` on both
surfaces, exactly what aMule builds for the login
([ServerConnect.cpp#L253](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ServerConnect.cpp#L253))
and the hello
([BaseClient.cpp#L1077](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1077)),
from one constant set through `Capabilities::emule_version_word`. The word is a
minimum-version gate and a fingerprint, not a path selector, so no counterparty selects
a path rmule cannot handle because of it.

**rmule names itself in `CT_MOD_VERSION`.** The hello ends with `CT_MOD_VERSION` (`0x55`)
= `rmule <version>`, last in the block as aMule's own builds write it. It is the
ecosystem's channel for a derivative to name itself, no reader acts against it, and it
is taken back by deleting one line. Servers never see it; the word, the compatible code
and the login are unchanged. `ClientSoftware` names a peer `ClientFamily::Rmule` only
when its hello is aMule-coded and its mod text is `rmule ` plus a version, and rmule
grants nothing on that claim.

**The login matches aMule's shape.** Four tags in aMule's order, and no `CT_PORT` tag.
With a bound IPv4 client-UDP socket, `CT_EMULE_UDPPORTS` (`0xF9`,
`kadUDP << 16 | clientUDP`) rides as a fifth tag after them: its presence is the NAT-T
capability claim a server introduction is gated on (ADR-0091). `0xF9` follows `CT_MOD_IP_V6`
(`0xAE`, ADR-0087) when both ride, which makes it the sixth tag; a six-tag login is
unmeasured against Lugdunum. The Kad half is read
fresh from `SharedUdpPortsAdvert` on every login and hello and cleared the moment the Kad
node stops.

**Extended requests at level 1.** `MiscOptions1` bits 8..12 claim extended-requests
version 1: the name ask carries the download's verified-part bitmap, and the bundle
walker reads a peer's at the same level. The level spoken on a link is `min(own, peer)`,
because aMule's asker writes at the uploader's claim and its uploader reads at the
asker's. The bitmap uses aMule's `size / PARTSIZE + 1` part count, phantom part included
(`PartFile.cpp:1338`); any other count makes aMule drop the status. A v0 claim costs
every source-exchange answer for a complete file (ADR-0055).

**The legacy `OP_EMULEINFO` block is the same advert in an older encoding.** rmule
answers every `OP_EMULEINFO` with `OP_EMULEINFOANSWER`, and sends `OP_EMULEINFO` before
its `OP_HELLOANSWER` to an accepted hello from behind eMule's hash mark that lacks
`CT_EMULE_VERSION` (a pre-0.42 client that learns capabilities no other way). The block
is projected from the hello rmule advertises on that connection
(`LegacyMuleInfo::advertised`), so the two encodings cannot claim different things. Its
first byte is aMule's `CURRENT_VERSION_SHORT` `0x47`. An OS-info block is read and never
answered.

### What rmule reads from a server

**Server grants are typed.** Every `SRV_TCPFLG_*` bit is modelled in `ServerGrants`:
`COMPRESSION` gates packed frames toward the server (ADR-0053), `NEWTAGS` and `UNICODE`
gate tag-codec variants, and `TCPOBFUSCATION` with the `OP_IDCHANGE` obfuscation port
feeds the server-crypt dial (ADR-0042).

**The `OP_IDCHANGE` extension is projected** into typed session facts: aux port,
server-reported public IP, obfuscation TCP port. The public IP feeds Address Learning
(ADR-0084). A second `OP_IDCHANGE` is a re-assignment, not a protocol violation.

**`CAPABLE_AUXPORT` is lit, because the aux port is acted on.** aMule answers an aux-port
login by replacing the row's port with the standard one and keeping the dialed port in an
aux-ports list (`ServerSocket.cpp:289-311`, `Server.cpp:233-241`); the Managed Server List
does the same (ADR-0080, "Aux ports"). The login flags word is therefore `0x11D`, aMule's
own (`ServerConnect.cpp:287-288`).

## Consequences

- The honest-advert invariant has one enforcement point instead of a convention at each
  emit site.
- Other clients' users see `rmule` as the peer's mod where they saw nothing.
- `PeerSession::with_extended_requests_capture_override` is the capture-only way back to
  extended-requests level 0 for a bench stimulus.
- The harness flow `peer-hello-surface` shows stock aMule 2.3.3, kno's aMule and
  emule-qt accepting rmule's named hello, running Secure User Identification and
  trading parts, and two rmules naming each other.

## Considered options

- **Per-site assembly**, as aMule does. Rejected: the honest-advert invariant becomes N
  conventions that drift. A registry gives one checkable derivation without changing
  wire bytes.
- **Advertising capabilities ahead of shipping them.** Rejected: peers and servers would
  select paths rmule cannot dispatch.
- **rmule's own version in `CT_EMULE_VERSION`.** Rejected: servers' minimum-version
  gates read a `0.x` major as ancient and refuse the login.
- **Keeping a `CT_PORT` login tag.** Rejected: it adds no function and a fingerprintable
  divergence from aMule's shape.
- **Treating a repeated `OP_IDCHANGE` as an error.** Rejected: it diverges from aMule and
  breaks on servers that re-assign.
- **Extended-requests level 2.** Rejected: it adds a complete-source count rmule does not
  keep.
- **Recognising rmule by a private hello tag.** Rejected: eMuleAI punishes any unknown
  hello tag (`Shield.cpp:880-908`).
- **Recognising rmule by a user-hash mark.** Rejected: the user hash is the identity
  every credit ledger keys on and cannot be taken back, and a mark on eMule's bytes would
  turn rmule into eDonkey in aMule's eyes.
