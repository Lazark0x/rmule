# Keys with consequences are bound only on the tab that shows what they change

## Context

A missed Shift turns one key into another: Transfers' `C` clears completed downloads, and
a global `c` would drop the server session. Links reach rmule both through the TUI and
through `rmule-cli add` (ADR-0069).

## Decision

- **`c` is the Networks tab's key for its selected row**, not a global key. On a server
  the operator's intent does not stand on, it connects there; on the server it does
  stand on (connected, or being reconnected), it disconnects and ends the intent. Every
  other tab leaves `c` unbound, so a missed Shift on Transfers' `C` (Clear completed)
  cannot drop the session. `K` in Networks is Kad's switch.
- **`L` in Transfers opens the Add-link form.** The link is read by `Ed2kLink::read`
  and started by the same `StartDownload` the Search tab sends, so the TUI and
  `rmule-cli add` accept, skip and refuse the same links. A refusal stays under the
  field with the typing kept; a field no client reads is named in the status feed once
  the download is asked for.

## Consequences

- No key on another tab can drop the session.
- The TUI and the CLI cannot disagree about a link.
