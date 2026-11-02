#!/usr/bin/env python3
"""The word checks scripts/guards.sh runs on the TUI's source.

drawnword: a string literal holding a letter in a module that draws. What the
operator reads comes from a words module, so a word can be translated and no
code can decide on one; a format string's holes are not letters.
plural: a word chosen by `== 1` or a `1 =>` arm in a words module, where the
one way is rmule_words::plural: a language has up to six forms.

The source is lexed, so comments, a `#[cfg(test)]` item, an attribute and a
`tracing::` call are read past, and a brace in a string counts for nothing.
Prints `<check>\t<path>\t<lines>` for each file with a violation.
"""

import os
import re
import sys

DRAWN = (
    "apps/rmule/src/chrome",
    "apps/rmule/src/chrome.rs",
    "apps/rmule/src/form",
    "apps/rmule/src/form.rs",
    "apps/rmule/src/row_filter.rs",
    "apps/rmule/src/row_selection",
    "apps/rmule/src/row_selection.rs",
    "apps/rmule/src/table",
    "apps/rmule/src/table.rs",
    "apps/rmule/src/view.rs",
    "apps/rmule/src/views",
    "apps/rmule/src/views.rs",
)
WORDS = (
    "apps/rmule/src/words",
    "apps/rmule/src/words.rs",
    "crates/rmule-words/src",
)
EXEMPT_FROM_PLURAL = "crates/rmule-words/src/plural.rs"

RAW = re.compile(r'b?r(#*)"')
CHAR = re.compile(r"b?'(\\.[^']*|[^\\'])'")
HOLE = re.compile(r"\{\{|\}\}|\{[^{}]*\}")
ESCAPE = re.compile(r"\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|\n\s*|.)")
TRACING = re.compile(r"tracing::\w+!\s*\(")


def tokens(source):
    """Yield (kind, line, text) for code runs and string literals."""
    at, line, end = 0, 1, len(source)
    code = 0
    while at < end:
        c = source[at]
        if source.startswith("//", at):
            yield "code", line, source[code:at]
            stop = source.find("\n", at)
            at = code = end if stop < 0 else stop
            continue
        if source.startswith("/*", at):
            yield "code", line, source[code:at]
            stop = source.find("*/", at) + 2
            line += source.count("\n", at, stop)
            at = code = stop
            continue
        raw = RAW.match(source, at)
        prior_ident = at > 0 and (source[at - 1].isalnum() or source[at - 1] == "_")
        if raw and not prior_ident:
            yield "code", line, source[code:at]
            close = '"' + raw.group(1)
            stop = source.find(close, raw.end())
            yield "str", line, source[raw.end() : stop]
            line += source.count("\n", at, stop)
            at = code = stop + len(close)
            continue
        if c == '"':
            yield "code", line, source[code:at]
            stop = at + 1
            while source[stop] != '"':
                stop += 2 if source[stop] == "\\" else 1
            yield "str", line, source[at + 1 : stop]
            line += source.count("\n", at, stop)
            at = code = stop + 1
            continue
        if c == "'":
            char = CHAR.match(source, at)
            if char:
                at = char.end()
                continue
        if c == "\n":
            line += 1
        at += 1
    yield "code", line, source[code:]


def spans(source):
    """The tokens outside test items, attributes and tracing calls."""
    skip_until = None  # ("brace"|"bracket"|"paren", depth) or "item"
    depth = 0
    pending_test = False
    for kind, line, text in tokens(source):
        if kind == "str":
            if skip_until is None and not pending_test:
                yield kind, line, text
            continue
        kept = []
        offset = 0
        while offset < len(text):
            if skip_until is not None:
                c = text[offset]
                opener, closer = skip_until
                if c == opener:
                    depth += 1
                elif c == closer:
                    depth -= 1
                    if depth == 0:
                        skip_until = None
                offset += 1
                continue
            if pending_test:
                c = text[offset]
                if c == "{":
                    pending_test = False
                    skip_until, depth = ("{", "}"), 1
                elif c == ";":
                    pending_test = False
                offset += 1
                continue
            if text.startswith("#[cfg(test)]", offset):
                pending_test = True
                offset += len("#[cfg(test)]")
                continue
            if text.startswith("#[", offset) or text.startswith("#![", offset):
                skip_until, depth = ("[", "]"), 1
                offset = text.index("[", offset) + 1
                continue
            call = TRACING.match(text, offset)
            if call:
                skip_until, depth = ("(", ")"), 1
                offset = call.end()
                continue
            kept.append(text[offset])
            offset += 1
        if kept:
            yield "code", line + "".join(kept[:0]).count("\n"), "".join(kept)


def holds_a_letter(literal):
    bare = ESCAPE.sub("", HOLE.sub("", literal))
    return any(c.isalpha() for c in bare)


def drawn_lines(source):
    return sorted(
        {
            line
            for kind, line, text in spans(source)
            if kind == "str" and holds_a_letter(text)
        }
    )


PLURAL = re.compile(r"==\s*1\b|(^|[\s(|])1\s*=>")


def plural_lines(source):
    found = set()
    for kind, line, text in spans(source):
        if kind != "code":
            continue
        for number, row in enumerate(text.split("\n")):
            if PLURAL.search(row):
                found.add(line + number)
    return sorted(found)


def files(roots):
    for root in roots:
        if os.path.isfile(root):
            yield root
        for folder, _, names in os.walk(root):
            for name in sorted(names):
                if name.endswith(".rs"):
                    yield os.path.join(folder, name)


def is_test(path):
    name = os.path.basename(path)
    return name == "tests.rs" or "/tests/" in path


def report(check, path, lines):
    if lines:
        print(f"{check}\t{path}\t{' '.join(map(str, lines))}")


def main():
    for path in files(DRAWN):
        if not is_test(path):
            with open(path, encoding="utf-8") as source:
                report("drawnword", path, drawn_lines(source.read()))
    for path in files(WORDS):
        if not is_test(path) and path != EXEMPT_FROM_PLURAL:
            with open(path, encoding="utf-8") as source:
                report("plural", path, plural_lines(source.read()))


if __name__ == "__main__":
    sys.exit(main())
