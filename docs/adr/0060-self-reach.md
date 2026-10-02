# Self Reach: one owner answers every reader of our reachability

## Context

Every firewalled-adjacent behaviour (buddies, direct callbacks, crypt gating, the reask
gate of ADR-0057, the publish row type) depends on knowing whether rmule is reachable.
aMule learns it two ways: a server's High ID, and Kad's firewall self-check (ADR-0058).

aMule (`4e8f2b3c`) answers its readers from four predicates, each computed at the call:

- `IsFirewalledKad` (`amule.cpp:1677-1681`): Kad not connected, or
  `CKademlia::IsFirewalled` (`Prefs.cpp:161-172`, the two-ack verdict). Not running
  counts as firewalled. Its only writers are the self-check's own; the server never
  writes it.
- `IsFirewalled` (`amule.cpp:1668-1675`): not firewalled on a connected eD2k High ID,
  else `IsFirewalledKad`.
- `CanDoCallback` (`amule.cpp:1758-1805`): High ID, or Kad open, except Low-ID on the
  candidate's own server.
- Direct UDP callback (`Prefs.cpp:228`): `IsFirewalled` and Kad running and UDP verified
  open. The hello's `MiscOptions2` bit 12 (`BaseClient.cpp:1131-1132`) is the same test
  on the Kad flag alone.

When each reader assembled its own subset of these facts and cached its own copy, each
drifted separately: a stopped node's last verdict was read as live, a mid-session
`OP_IDCHANGE` was missed, a full inbox dropped an edge.

## Decision

`SharedSelfReach`, one per core, is woven from each family's single writer and cloned into
every reader:

- **Kad TCP and Kad UDP:** one watch cell (`SharedKadVerdicts`), written only by the Kad
  pump, reset to firewalled and unverified at the node's start and at its end (a drop
  guard, so a panicking pump resets it too).
- **Server High ID:** the session self-facts (`SharedOwnIdentity`), written at login,
  re-written on a mid-session `OP_IDCHANGE`, cleared when the session ends; read, never
  copied.
- **NAT-T front:** whether its loop runs, read at use.
- **Listener:** the serve listener's bound cell, `CanDoCallback`'s own conjunct.

The union rules live in the owner, never in a reader:

| Answer | Rule | aMule |
| --- | --- | --- |
| `kad_tcp_open` | Kad TCP verdict `Open` (a stopped node reads firewalled) | `!IsFirewalledKad()` |
| `server_high_id` | a live session whose ID is High | `IsConnectedED2K() && !IsLowID()` |
| `firewalled` | not `server_high_id` and not `kad_tcp_open` | `IsFirewalled()` |
| `accepts_direct_udp_callback` | `firewalled` and Kad UDP open | connect-options bit `0x08` |
| `hello_direct_udp_callback` | not `kad_tcp_open` and Kad UDP open | `MiscOptions2` bit 12 |
| `callback_capability` | listener and (High ID or (`kad_tcp_open` and not (Low ID and candidate on our server))) | `CanDoCallback` |
| `natt_live` | the NAT-T front's loop runs | — |

**Readers.** The publish connect-options byte, the publish row type and the hello's buddy
tags read `firewalled` and `accepts_direct_udp_callback`; the route chooser and the reask
gate read `firewalled` at the ask; download admission reads `callback_capability`; the
hello's `MiscOptions2` bit 12 reads `hello_direct_udp_callback` per hello. The buddy
recruit gate, the FINDBUDDY responder and the `0x95` consume gate read the Kad TCP and UDP
verdicts, the Kad flag alone, as aMule does. Three readers read one family's writer at use
and compose nothing: the serve runner's Low-ID guard (it also needs the session's server),
the port mapper's High-ID trigger (woken by the owner) and the node's injected TCP level.

**The publish row type** follows from two answers: `accepts_direct_udp_callback` gives
type 6; else `firewalled` with a held buddy gives 3/5 (ADR-0061); `firewalled` with no
buddy publishes **no row**, as aMule stops (`Search.cpp:626-628`), because a firewalled
node's direct row sends every asker to a dead port; otherwise 1/4.

**Invariants.**

1. Each family has exactly one writer, and `SharedSelfReach` is the one reader API.
2. Every reader reads at use or subscribes to the **Reach Generation**
   (`SharedSelfReach::changes`), which wakes on a Kad verdict write, a Server High ID move,
   the NAT-T front's end and a listener bind or clear.
3. A subscriber that must cache (the sans-I/O node's byte and buddy row, the download's
   capability) re-derives on the generation; no snapshot survives a change.
4. A reader asks the question aMule asks and never composes two facts itself.

## Consequences

- A stopped node's last verdict, a mid-session `OP_IDCHANGE` and a dropped edge no longer
  leave a reader with a stale answer: every reader reads the owner at use or re-derives on
  the Reach Generation.
- A firewalled node with no buddy publishes no source row.

## Considered options

- **A verdict private to the Kad node.** Rejected: the reask gate, the advert registry and
  the buddy and callback routes live outside the Kad crate; the fact is core-tier.
- **A union composed in each reader.** Rejected: that is how each reader drifted.
- **Publishing a direct row while firewalled with no buddy.** Rejected: it costs the
  storer a slot and sends askers to a port nothing forwards.
