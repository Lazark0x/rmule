# Lenient eD2k links, strict packets

## Context

eD2k links reach rmule from people: pasted from web pages, forums and other clients,
with variations in casing, delimiters and percent-encoding that aMule and eMule accept.
Packets reach rmule from the network, where a malformed length or an impossible field
is either a bug in the sender or an attack, and silently recovering from it hides both.

## Decision

eD2k link parsing (`crates/rmule-primitives/src/link.rs`) is lenient: it accepts the
common real-world eMule and aMule variants, such as a case-insensitive `ed2k://` scheme
and link kind, case-insensitive hex hashes, case-insensitive optional fields, and
percent-encoded file names, then normalizes them into strict typed values.

Packet codecs are strict: a malformed length, an impossible field or ambiguous bytes
produce a typed error, never silent recovery.

## Consequences

- Link parsing accepts harmless formatting variants; it never accepts a link whose
  meaning is ambiguous.
- Packet codecs put protocol correctness and security ahead of forgiving malformed
  input. A well-formed packet that rmule does not understand is a different case,
  covered by ADR-0018.
- Tests keep accepted compatibility variants apart from rejected malformed data.

## Considered options

- **Strict parsing for links too.** Rejected: it refuses links that every other
  eMule-family client opens.
- **Lenient parsing for packets too.** Rejected: guessing at malformed wire data hides
  sender bugs and widens the attack surface.
