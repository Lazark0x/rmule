# rmule is GPL-3.0-or-later and never ports eMule or aMule source code

## Context

rmule belongs to the eMule/aMule open-source ecosystem and depends on modern Rust
crates, most of them Apache-2.0 or MIT licensed. Its reference material is C++ source
under several GPL variants. aMule source may be GPLv2-only. The upstream eMule tree
carries "either version 2 of the License, or (at your option) any later version" in
its headers, so it is GPL-2.0-or-later and would be legally derivable into a
GPL-3.0-or-later tree (ADR-0082).

## Decision

The workspace licence is GPL-3.0-or-later. eMule and aMule source code is behavioural
reference material only: rmule never pastes, translates or mechanically ports it, and
its implementation is written independently.

The no-porting rule is a clean-room discipline, not only a licence constraint, so a
compatible licence does not lift it. rmule may read source to learn facts about the
protocol and record those facts in its own notes and code comments; facts are not
copyrightable, expression is.

## Consequences

- Protocol docs may cite aMule and eMule behaviour, but implementation code is written
  from scratch.
- Contributors do not paste or mechanically translate C++ source into Rust, whatever
  its licence.
- Dependency review checks licence compatibility before a crate is adopted.

## Considered options

- **A permissive licence with a stricter clean-room process.** Rejected: it separates
  rmule from the GPL ecosystem it interoperates with.
- **GPL-2.0, mirroring the eMule/aMule lineage.** Rejected: it is incompatible with
  Apache-2.0 dependencies.
- **Port from eMule now that its or-later grant is proven.** Rejected: every defect the
  eMule source has surfaced came from knowing what the bytes are, which is
  specification; none needed ported logic, so porting would give up the clean-room
  posture for no demonstrated gain.
