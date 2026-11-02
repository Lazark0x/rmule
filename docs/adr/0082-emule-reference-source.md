# eMule 0.70b is the Reference Source for specification; parity is measured against aMule, and against the eMule family only where aMule implements nothing

## Context

rmule's compatibility knowledge has one shape: read aMule upstream, then prove the
behaviour with bytes captured from a pinned counterparty (ADR-0045). aMule 2.3.3 tracks
eMule ~0.50a and is itself a port, so where aMule and eMule disagree, or where aMule
cannot produce a shape at all, rmule has no way to notice. Two defects found this way
show the gap: the Kad keyword-result decoder rejected the `TAGTYPE_BSOB` tag every eMule
storer emits, and the source-list reader desynchronised on a record shape aMule never
writes. Neither was reachable from an aMule-only counterparty.

Two external artifacts can close that gap:

- **eMule 0.70b community edition**, `irwir/eMule` at commit
  `13983526945d58b0bc1123619a795cf1e6b80aba`. Its file headers grant "either version 2
  of the License, or (at your option) any later version", so it is GPL-2-or-later and
  compatible with rmule's licence. The same tree sits vendored under `srchybrid/` in
  `ModderMule/emule-qt`; a byte-for-byte diff found all 922 common files identical to
  the upstream release, imported in one commit and never edited.
- **`emulecored`**, the headless daemon of `ModderMule/emule-qt` at commit
  `73fff7146d2eec3e8426251ec4959238bae3479a`, a rewrite first published in 2026. 672 of
  677 classifiable files under its `src/` carry no licence header, and the only governing
  declaration is a repo-level bare `GPL-2.0` with no "or later" grant.

Several parity rows are blocked not by missing code but by a two-node artefact — a buddy
ping/pong where both nodes play the same role, a server dropping concurrent High-ID
logins — which a third distinct client on the wire can dissolve.

Some behaviour rmule speaks has no aMule implementation at all: stock aMule 2.3.3 ignores
every tag and opcode of the IPv6 dialect (ADR-0087) and has no NAT traversal (ADR-0091). No
aMule bytes can score those rows; only the eMule-family clients that define and speak them —
emule-qt and eMuleAI — can.

## Decision

**The Reference Source is eMule 0.70b at the upstream pin above.** It is read to
*specify* behaviour: what byte goes where, what a constant is, what an implementation
does at a decision point. The pin is a commit SHA, not a tag: git objects are
content-addressed, so the SHA is the integrity check, and tags are mutable. rmule reads
upstream rather than emule-qt's identical copy, which would add a hop and buy nothing.

**The Reference Source is never evidence.** A value read from source still needs a
capture from a pinned counterparty before it closes a row; source says what to look for,
capture proves rmule got it right. A row supported only by a source reading is an open
row with a good hypothesis.

**Reading, not porting.** ADR-0004 governs unchanged: eMule source is behavioural
reference, not code to paste, translate or mechanically port. Its or-later grant would
make derivation legal; rmule declines because every defect this reference has surfaced
came from knowing what the bytes are, which is specification, and none needed ported
logic. rmule may read the source to learn facts about the protocol and record those facts
in rmule-authored notes and comments; facts are not copyrightable, expression is.

**Caching.** aMule source stays link-only (ADR-0013). The eMule tree's licence version
can be assumed, so it may be cached locally as a gitignored clone with a committed sidecar
(ADR-0013's local-cache mechanics); nothing of it enters git history. Contributors fetch
it by cloning the sidecar's `source_url` and checking out its `commit`; the commit SHA is
the integrity check (`docs/reference/README.md`).
`docs/protocol/source-map.md` lists both artifacts with their cache status.

**Parity is measured against aMule.** A row of behaviour aMule implements is scored only
on the pinned aMule counterparty's bytes (ADR-0045). **For behaviour aMule does not implement
at all — today the IPv6 dialect (ADR-0087) and NAT traversal (ADR-0091) — the eMule-family
counterparty that implements it, emule-qt or eMuleAI, is the evidence source**, pinned like
any counterparty, beside an aMule Fork Pin that ports the behaviour (ADR-0045). The ADR that
decides such a behaviour names its evidence source per surface. Whether aMule implements a
behaviour is a fact about the pinned aMule, so a behaviour a pinned aMule implements is
measured against aMule again.

**The Stimulus Counterparty is `emulecored`** at the pin above, run as a third body on the
wire. For behaviour aMule implements, its bytes never score a row: treating a 2026 rewrite's
emissions as normative there would let its defects become rmule's parity facts. Where a
three-body setup makes a blocked row reachable, the proof is the pinned aMule
counterparty's bytes under those conditions.

**emule-qt's source is read for facts only and may not inform derived logic at all.**
Without an or-later grant, the argument that makes the eMule tree derivable is absent;
this permission is narrower for a licence reason, not a discipline one.

**Source-derived values never become Compatibility Fixtures.** A fixture's provenance is
`handwritten`, `documentation`, `amule-generated` or `captured`; a constant read from the
Reference Source is none of these and gets no fifth tag. A fixture is executable evidence,
and a class that looks like evidence and is not is the confusion the never-evidence rule
prevents. A source reading informs the code; the fixture that proves the code comes from
one of the four provenances.

**The pins are snapshots, re-pinned on need.** There is no watcher, review cadence or
staleness policy. A sweep of eMule 0.50a → 0.70b, about fourteen years of releases, found
no new opcodes, tags, bits or framing; against that drift rate a cadence decays into an
ignored chore. Whoever needs newer behaviour bumps the pin and re-runs
`scripts/audit-reference-constants.py`, which proves nothing moved underneath the bump. A
re-pin changes which source text the Reference Source speaks for; no version of it ever
closes a parity row. The audit itself never rots: CI's `reference-constants` job fetches
the pinned commit and runs it on every change, and `scripts/guards.sh` runs it locally
whenever the tree is present, saying in one line when it is not.

## Consequences

- rmule has a normative answer to "what does eMule do", which aMule could only
  approximate and sometimes could not express.
- Rows already capture-verified may have been verified against a counterparty that
  cannot emit the modern shape. That is a limit of a single-counterparty oracle, not a
  defect in the capture, and it is now nameable.
- A fresh clone has a dangling cache path until the populate script runs.
- rmule's own licence posture is unchanged: no GPLv2-only code is ported and no external
  bytes enter git history.
- Promotion of `emulecored` to a corroborating role for behaviour aMule implements would
  have to be earned by measurement against rmule's golden corpus; it is not granted.
- Rows of behaviour aMule does not implement rest on the eMule family's bytes, and a defect
  in that family can become an rmule parity fact there; a surface with a single
  eMule-family oracle says so (ADR-0087).

## Considered options

- **Let GPL-2-or-later sources inform derived logic, with in-file attribution.** Legally
  available; declined because it trades the clean-room posture for a benefit rmule has
  not demonstrated.
- **Treat the eMule tree like aMule source, link-only.** Rejected: it loses offline reading
  and makes every consult a network round trip, for no licence benefit.
- **Admit source readings as evidence for parity rows.** Rejected: it would gut ADR-0045.
- **Vendor the tree.** Rejected: 130 MB of C++ in a Rust repository degrades every search,
  and physical separation still enforces the no-porting rule better than a notice.
- **Pin the Reference Source at emule-qt's vendored copy.** Rejected as an unnecessary hop.
- **A review cadence for the pins.** Rejected: the measured drift does not justify one.
