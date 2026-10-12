# rmule-words

The operator's words, written from the codes core hands a front end. Core carries codes and data and never a sentence; both front ends speak from here — the TUI on its log pane, status bar and flashes, the CLI on its output lines — so the same fact reads the same way in each, and the language can be translated in one place. It holds no front end's types: a sentence that words the TUI's own state (its command line, a Settings edit, a search entry's paging) stays in the TUI's own words modules, beside the shared module of its domain.

## Language

**Sentence**:
A line an operator reads, written in a **Words module** from a code and the data beside it. The TUI's log pane, status bar note and flash take only a `Sentence`, so no `Debug` dump and no core type's `Display` reaches them; a sentence is made only in a words module, which `scripts/guards.sh` holds (check `sentence`), and a test that exercises a surface's layout rather than its words makes one through the `test-support` feature. An address reads `host:port`, a hash or a Kad id its short hex form.
_Avoid_: message, string, label (a label is a word in a cell; a sentence is a line said)

**Words module**:
One per domain — app, download, event, kad, login, os, peer, port mapping, reach, scan, search, serve, server, software, store, units — each wording its vocabulary with an exhaustive `match`, so a code core adds cannot reach an operator without its words. A front end's own words module of the same name re-exports the shared one and adds what words that front end's own types. `scripts/guards.sh` refuses a Debug format in this crate's source as in the front ends'.
_Avoid_: messages, strings, i18n table, formatter

**Clause**:
A fragment a sentence is built from — the reason after a colon, `the folder is not there` — returned as text rather than a **Sentence**, so a caller fits it into a line of its own. A front end ends a sentence with a clause; it never words the code itself.
_Avoid_: reason string, description

**Unit**:
How a quantity or an identity a sentence carries is spelled, one spelling everywhere: an address as `host:port`, a hash or a Kad id as its first ten upper-case hex digits and `…`, a wait in whole seconds rounded up, a byte quantity in binary units at one decimal. A table cell that shows the same quantity spells it the same way.
_Avoid_: format, pretty-print
