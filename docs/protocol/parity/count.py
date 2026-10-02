#!/usr/bin/env python3
"""Count the amuled parity tables in this directory.

Reads every surface table (each `*.md` here but README.md), takes every
Markdown table row whose header carries `Status` and `Evidence` columns, and
prints counts per surface and in total: by status, and by evidence.

Rules it enforces, so a count never rests on a row it cannot read:

- Status is one of `at parity`, `partial`, `missing`, `exempt`.
- Evidence is `code only` (optionally followed by a remark), `—` (nothing
  to prove: allowed on `missing` and `exempt` rows only), or one or more
  backticked repository paths under `crates/` or `tools/`, each of which
  must exist. A row whose evidence names paths is fixture-proven.
- A `partial` or `exempt` row carries a Note saying what differs or why.

Usage: `python3 docs/protocol/parity/count.py [--markdown]`. Exits 1 when any
row breaks a rule; the errors are printed and no counts are.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
STATUSES = ("at parity", "partial", "missing", "exempt")
SURFACES = ("server-tcp", "server-udp", "peer-tcp", "peer-udp", "kad-udp", "bootstrap")
PATH = re.compile(r"`((?:crates|tools)/[^`\s]+)`")


def cells(line):
    """Split one Markdown table line into stripped cells, honouring `\\|`."""
    body = line.strip()[1:-1].replace("\\|", "\0")
    return [c.replace("\0", "|").strip() for c in body.split("|")]


def rows(path):
    """Yield (line number, {column: cell}) for every counted row in a file."""
    header = None
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.startswith("|"):
            header = None
            continue
        row = cells(line)
        if header is None:
            header = row
            continue
        if all(set(c) <= set("-: ") for c in row):
            continue
        if "Status" in header and "Evidence" in header:
            yield number, dict(zip(header, row))


def evidence_class(status, evidence, where, errors):
    if evidence.startswith("code only"):
        return "code only"
    if evidence == "—":
        if status not in ("missing", "exempt"):
            errors.append(f"{where}: `—` evidence on a `{status}` row")
        return "none"
    paths = PATH.findall(evidence)
    if not paths:
        errors.append(f"{where}: evidence names no repository path: {evidence[:60]}")
        return "none"
    for p in paths:
        if not (REPO / p).exists():
            errors.append(f"{where}: evidence path does not exist: {p}")
    return "fixture"


def count():
    errors, table = [], {}
    for surface in SURFACES:
        path = HERE / f"{surface}.md"
        tally = {k: 0 for k in STATUSES + ("fixture", "code only", "none", "parity+fixture")}
        for number, row in rows(path):
            where = f"{path.name}:{number}"
            status = row.get("Status", "")
            if status not in STATUSES:
                errors.append(f"{where}: unknown status `{status}`")
                continue
            if status in ("partial", "exempt") and not row.get("Note"):
                errors.append(f"{where}: `{status}` row without a Note")
            tally[status] += 1
            kind = evidence_class(status, row.get("Evidence", ""), where, errors)
            tally[kind] += 1
            if status == "at parity" and kind == "fixture":
                tally["parity+fixture"] += 1
        table[surface] = tally
    return table, errors


COLUMNS = (  # (Markdown header, plain-text header)
    ("Rows", "rows"), ("At parity", "parity"), ("Partial", "partial"),
    ("Missing", "missing"), ("Exempt", "exempt"), ("Fixture-proven", "fixture"),
    ("Code only", "code"), ("No evidence", "none"),
    ("At parity, fixture-proven", "parity+fix"),
)


def render(table, markdown):
    keys = STATUSES + ("fixture", "code only", "none", "parity+fixture")
    total = {k: sum(t[k] for t in table.values()) for k in keys}
    if markdown:
        lines = ["| Surface | " + " | ".join(c[0] for c in COLUMNS) + " |",
                 "|---|" + "---:|" * len(COLUMNS)]
    else:
        lines = [f"{'surface':<12}" + "".join(f"{c[1]:>11}" for c in COLUMNS)]
    for name, t in list(table.items()) + [("Total", total)]:
        vals = [str(sum(t[s] for s in STATUSES))] + [str(t[k]) for k in keys]
        if not markdown:
            lines.append(f"{name:<12}" + "".join(f"{v:>11}" for v in vals))
        elif name == "Total":
            lines.append("| **Total** | " + " | ".join(f"**{v}**" for v in vals) + " |")
        else:
            lines.append(f"| {name} | " + " | ".join(vals) + " |")
    return "\n".join(lines)


def main():
    table, errors = count()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(render(table, "--markdown" in sys.argv[1:]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
