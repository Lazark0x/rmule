# Commands describe intent, not packets

## Context

`Ed2kCommand` is the application's contract with the eD2k service. If a command
carries a packet-layer type — a `LoginRequest`, a tag bag, a capability bitmask —
every caller has to know how the protocol encodes that intent, and every new request
(search, offer files, ask for sources) repeats the leak. Protocol-version tags and
capability bits then end up built in application code that has no business holding
them.

Who rmule is on the network (user hash, nickname, TCP port, protocol version) is
shared identity, in the same family as `UserHash`, `ServerIdentity` and
`ServerEndpoint`, and the Kad and secure-identification code need it too.

## Decision

Commands name domain intent; the protocol crate turns intent into packets.

- `ClientIdentity` lives in `rmule-primitives` with private fields: `user_hash`,
  `nickname` (`Ed2kText`), `tcp_port`, `protocol_version`, and an `extra_tags`
  list for forward-compatible tags that are not yet typed. `ClientIdentity::new`
  takes the four required facts; `with_extra_tags` attaches the rest.
- Capability tags (`CT_SERVER_FLAGS`, `CT_EMULE_VERSION`) are never carried in
  `ClientIdentity`. They come from the capability registry (ADR-0047).
- `LoginRequest::from_identity(&ClientIdentity, &Capabilities)` in `rmule-ed2k`
  builds the login packet. It drops any extra tag whose name collides with a
  canonical login tag, so a collider never reaches the wire. The low-level
  `LoginRequest` constructors stay public for fixture tests; application code does
  not use them.
- Connecting is not a command. The endpoint and identity are construction inputs of
  `Connection::connect` / `connect_with_options` in `rmule-net` (ADR-0021). A
  `Connect` variant in `Ed2kCommand` would be a second, silently dead connect path.
- `Ed2kCommand` holds only in-flight intents, such as `RequestServerList`,
  `Search`, `RequestSources`, `OfferFiles` and `Disconnect`.

## Consequences

- Callers never build tags or bitmasks; a change to login encoding stays inside
  `rmule-ed2k`.
- A tag that gains a typed meaning moves out of `extra_tags` into a `ClientIdentity`
  field without breaking command callers.
- Each new server request is a new intent variant, with its packet construction in
  the protocol crate.
