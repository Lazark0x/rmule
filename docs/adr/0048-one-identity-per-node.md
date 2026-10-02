# One identity per node, owned by the core

## Context

Every hello, login and Secure User Identification exchange presents the node's identity:
its user hash, its SUI keypair, and the advert cells every hello reads (ADR-0047). aMule
loads its user hash and key once per process (`Preferences.cpp:925-953`,
`ClientCreditsList.cpp:49-54`), so one node has one identity for its lifetime.

When each credentialed command carried the key and hash, the last command won, a keyless
command cleared the key, and adapters injected for tests kept empty adverts of their own.

## Decision

A node has one identity for its lifetime, owned by the core:

- The **SUI keypair** is loaded once by `Core::builder` from the store's generate-once
  row (ADR-0041). A failed load warns and runs without SUI. No command carries a key.
- The **user hash** is written by `CoreBuilder::build` before the actor spawns, from the
  store's generate-once identity row or from `CoreBuilder::user_hash` for a tool or test.
  No command carries a hash: `ClientCredentials` holds nickname, TCP port, protocol
  version and extra tags, and the actor composes the wire identity from them and the
  build-time hash.
- **Every hello-emitting road reads the same cells.** One `HelloAdverts`, built in the
  builder, starts every connection's options: `CT_EMULE_UDPPORTS` with its Kad-version
  nibble, `CT_MOD_IP_V6` from the Address Learning verdict (ADR-0084, ADR-0087), the
  serving buddy while a buddy link is held (ADR-0061), the crypt stance from
  `CoreConfig::peer_crypt` (ADR-0049), and the SUI nibble with a challenge minted per
  connection. A road that omits one says so at its site.
- Every builder-owned shared cell lives in one `AdapterCells`, and every adapter, the
  builder's own or one injected for tests, adopts it through `adopt_cells`, so no adapter
  holds a private copy of the session, ban store, IP filter, Address Learning, Kad
  handoff, Peer Roster (ADR-0059) or Hello Adverts.

Presentation fields (nickname, TCP port) come from each command's credentials and apply
to the next hello, as aMule's preferences do.

## Consequences

- The user hash every credit ledger keys on cannot change within a run, and no command
  can clear the key.
- A test or tool that injects an adapter gets the same cells as the builder's own, so its
  hellos advertise what a real node's would.

## Considered options

- **A per-command identity**, where each credentialed command carries the key and hash.
  Rejected: the last command won, a keyless command cleared the key, and injected
  adapters kept empty adverts of their own.
