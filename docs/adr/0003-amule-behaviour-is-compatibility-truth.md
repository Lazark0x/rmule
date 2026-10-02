# Compatibility truth is aMule's behaviour, read through the references and proven by fixtures

## Context

No single source tells rmule how an eMule-compatible client must behave. The written
eMule protocol references are incomplete and in places out of date. aMule is the
client rmule interoperates with day to day, but its behaviour includes quirks that
cannot always be explained. The eMule source states what a byte means, yet reading it
proves nothing about what rmule actually sends.

## Decision

rmule takes its compatibility truth from three sources, each with a fixed role:

- **aMule behaviour** is the practical interoperability oracle.
- **eMule protocol references**, including the eMule Reference Source (ADR-0082), give
  terminology and wire-format intent. They specify what to look for; they are never
  evidence on their own.
- **Packet fixtures and conformance tests** are the final evidence. A behaviour is
  settled when a fixture or test shows it.

A third-party client such as the emule-qt Stimulus Counterparty (ADR-0082) may help
produce conditions on the wire, but its own bytes are never the oracle.

## Consequences

- Protocol documentation says whether a behaviour comes from a reference, from aMule,
  from a fixture, or is an unresolved gap.
- Compatibility tests keep packet-level examples wherever they can.
- A contradiction between sources is written down, not hidden in implementation code.

## Considered options

- **Implement primarily from the written eMule references.** Rejected: the references
  are incomplete, and an implementation that matches them can still fail against aMule.
- **Treat aMule behaviour as the only oracle.** Rejected: it reproduces quirks blindly,
  including ones that cannot be explained or tested.
