#!/usr/bin/env python3
"""Audit rmule's protocol constants against the eMule Reference Source.

rmule has twice shipped a self-authored wrong byte that a normative source would
have caught at spec time (`OP_KAD_FWTCPCHECK_ACK` pinned as `0xA9` when it is
`0xA8`; the datagram-crypt sync word framed big-endian when the wire is little-
endian). Both were found late, by capture, after the wrong value had been built
on.

This script closes that class mechanically. Wherever rmule declares a constant
under eMule's own symbol name, the two must agree. Any disagreement is a bug in
one of them, and historically it has been rmule's.

Requires the Reference Source (ADR-0082) cloned at its pinned commit: the
sidecar `docs/reference/emule-source/eMule.meta.toml` names the URL, the commit
and the path, and `docs/reference/README.md` gives the steps. CI's
`reference-constants` job fetches that commit and runs this script;
`scripts/guards.sh` runs it when the tree is present. An optional argument
names another copy of the tree's `srchybrid/` directory. Findings are
*specification*, not evidence — a constant confirmed here still needs a capture
before it closes a parity row (ADR-0045).

Exit status is 1 if any shared symbol disagrees, 2 if the tree is missing.
"""

import pathlib
import re
import subprocess
import sys

REF = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "docs/reference/emule-source/eMule/srchybrid")

# eMule declares wire constants three ways: plain `#define NAME 0xNN`, a
# `#define NAME "\xNN"` string form used throughout the Kad tag block, and an
# occasional `const <type> NAME = 0xNN;`. All three carry wire bytes.
DEFINE = re.compile(
    r'^\s*#define\s+([A-Z][A-Z0-9_]*)\s+\(?\s*((?:0[xX][0-9a-fA-F]+)|\d+)[uUlL]*\s*\)?\s*(?:$|//|/\*)', re.M)
DEFINE_STR = re.compile(r'^\s*#define\s+([A-Z][A-Z0-9_]*)\s+"\\x([0-9a-fA-F]{2})"', re.M)
CONST = re.compile(r'\bconst\s+\w+\s+([A-Z][A-Z0-9_]*)\s*=\s*((?:0[xX][0-9a-fA-F]+)|\d+)[uUlL]*\s*;')

# rmule reuses eMule's symbol names for wire constants; these prefixes are the
# families that carry a byte rather than a local tuning knob.
RMULE_CONST = re.compile(
    r'const\s+((?:OP|CT|FT|ST|TAG|TAGTYPE|KADEMLIA|KADEMLIA2|SRV|SRVCAP|MAGICVALUE|ET)_[A-Z0-9_]+)'
    r'\s*:\s*u(?:8|16|32|64)\s*=\s*((?:0[xX][0-9a-fA-F_]+)|\d+)')


def emule_symbols() -> dict[str, dict[int, list[str]]]:
    """Every named numeric constant in the Reference Source, by name then value."""
    out: dict[str, dict[int, list[str]]] = {}
    for path in list(REF.rglob("*.h")) + list(REF.rglob("*.cpp")):
        text = path.read_text(errors="replace")
        rel = str(path.relative_to(REF))
        for pattern, base in ((DEFINE, 0), (DEFINE_STR, 16), (CONST, 0)):
            for match in pattern.finditer(text):
                try:
                    value = int(match.group(2), base) if base else int(match.group(2), 0)
                except ValueError:
                    continue
                out.setdefault(match.group(1), {}).setdefault(value, []).append(rel)
    return out


def rmule_constants() -> list[tuple[str, str, int]]:
    """Every rmule constant declared under an eMule-style symbol name."""
    tracked = subprocess.run(["git", "ls-files", "crates", "tools"],
                             capture_output=True, text=True, check=True).stdout.split()
    out = []
    for name in tracked:
        if not name.endswith(".rs"):
            continue
        for match in RMULE_CONST.finditer(pathlib.Path(name).read_text(errors="replace")):
            try:
                out.append((name, match.group(1), int(match.group(2).replace("_", ""), 0)))
            except ValueError:
                continue
    return out


def main() -> int:
    if not REF.is_dir():
        print(f"Reference Source not present at {REF}.\n"
              "Clone it at the commit named in docs/reference/emule-source/eMule.meta.toml\n"
              "(steps in docs/reference/README.md, ADR-0082).", file=sys.stderr)
        return 2

    emule = emule_symbols()
    rows = rmule_constants()

    mismatched, unshared, agreed = [], [], 0
    for path, name, value in rows:
        if name not in emule:
            unshared.append((path, name, value))
        elif value in emule[name]:
            agreed += 1
        else:
            mismatched.append((path, name, value, emule[name]))

    print(f"Reference Source symbols: {len(emule)}")
    print(f"rmule constants under an eMule symbol name: {len(rows)}\n")

    print("== Disagreements on a shared symbol ==")
    for path, name, value, known in mismatched:
        alts = "; ".join(f"0x{v:02X} ({', '.join(sorted(set(f))[:2])})" for v, f in known.items())
        print(f"  {name}: rmule 0x{value:02X}, eMule {alts}  [{path}]")
    if not mismatched:
        print("  none")

    print(f"\n== Agreeing: {agreed} ==")

    # A name rmule invented for a concept eMule names differently is not a
    # defect, but it is unaudited: only a human can match the two semantically.
    print(f"\n== rmule-local names, not auditable by name ({len(set(n for _, n, _ in unshared))}) ==")
    for name in sorted({n for _, n, _ in unshared}):
        value = next(v for _, n, v in unshared if n == name)
        print(f"  {name} = 0x{value:02X}")

    return 1 if mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
