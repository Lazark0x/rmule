# The Announce Policy: shares may be withheld from servers that answer related searches

## Context

On a server that grants related search (`SRV_TCPFLG_RELATEDSEARCH`, `0x40`, in its
`OP_IDCHANGE`), anyone can ask which files are shared alongside a given file, and the answer
includes what this operator shares together. rmule controls only what it announces, and to which
server.

aMule references are to 2.3.3 (`4e8f2b3c`); read, never ported (ADR-0082).

## Decision

**The Announce Policy:** announce by default; a preference, off by default, withholds the share
set from servers that grant related search (`ServerPolicy::withhold_from_related_search`, stored
as `WithholdSharesFromRelatedSearch`). Withheld shares stay available over Kad and on every server
that does not grant it; there is no per-server switch. It is core-owned server-list configuration
beside the Dead Server Limit (ADR-0052), read at the actor's start and changed live by
`CoreCommand::SetServerPolicy`.

The Session Follower decides per session, from the session's grants as they stand:

| Policy | Server grants related search | Told this session | The follower |
|---|---|---|---|
| off | either | anything | announces the current set (`OP_OFFERFILES`) |
| on | no | anything | announces the current set |
| on | yes | nothing, or Withheld | sends nothing: **Withheld** |
| on | yes | Announced | sends nothing more: **Announced before withholding** |

Switching the policy off while a session is Withheld announces at once. What was announced cannot
be taken back in the session: aMule's offers are incremental (`SharedFileList.cpp:1599-1607`,
`:1657-1665`), and an empty `OP_OFFERFILES` is the keep-alive the Lugdunum author recommends
(`ServerConnect.cpp:641-648`), not "forget my files"; the operator is told a disconnect ends it.
An announce's result is typed (`AnnounceOutcome::Announced { file_count }`,
`Withheld { file_count, reason }`, or `Unsaid`), and the serve raises
`ServeEvent::FilesAnnounced` or `ServeEvent::FilesWithheld` from it, so a withheld set is never
logged as announced. `DiagnosticsSnapshot::share_announcement` carries what the connected session
was told, and the Networks detail pane words it (ADR-0080).

## Consequences

- Whether Lugdunum drops a client's offered files on disconnect, and what it does with an empty
  offer, are unmeasured; nothing here rests on either.

## Considered options

- **A per-server announce switch.** Rejected: the policy is one rule about a server capability.
