# rmule-cli

The headless **Application Front-End**: a thin command router over the **Core
Orchestrator**. It owns argument parsing, the diagnostic subscriber install,
and human-readable output — and nothing else. Every durable fact (the persisted
**Client Identity**, the managed server list, preferences, download state) lives
in `rmule-core`, reached through its stores and its command/event surface.

## Language

**Command**:
One user-facing verb — `identity`, `server`, `config`, `add`, `kad` — that
opens the stores in the data directory, issues core commands, and prints what
the core reports back. A command holds no state between runs; the data
directory is the only continuity.
_Avoid_: action, task, job

**Data Directory**:
The directory holding rmule's Durable Store (`rmule.redb`) and its data files
(`clients.met`, `nodes.dat`, the IP filter), selected by the global
`--data-dir` flag, else by the same variables `rmule` reads (core's rule).
Every command resolves it first, so two invocations against different
directories are two independent clients.
_Avoid_: workspace, home, profile dir

**Kad Join**:
The one long-lived command: it drives `rmule_net::kad::spawn` directly rather
than going through the core, reading the persisted Kad identity, bootstrapping
against an operator-supplied contact, and rendering a routing census. A
deliberate exception, documented with ADR-0043's live smoke run — the core's Kad surface is
download-coupled, and a join-only diagnostic does not fit it. Any *product* Kad
behaviour still goes through the core.
_Avoid_: kad daemon, node command

## Relationships

- `rmule-cli` depends on `rmule-core` (and, for the join exception, on
  `rmule-net` and `rmule-kad`). Nothing depends on `rmule-cli`.
- It is a sibling of `rmule` under `apps/`: two front-ends over one core
  surface, sharing no code of their own.
- It is *not* `rmule-tools`. Tools are protocol diagnostics that deliberately
  bypass the core; this is a product front-end that deliberately does not.
