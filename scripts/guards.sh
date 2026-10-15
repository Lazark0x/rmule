#!/usr/bin/env bash
# Machine-checkable subset of the repository's code and docs conventions.
#
# Walks crates/ apps/ tools/ docs/ (and, for the two text checks, every public
# tracked file) and reports every violation of the fourteen
# guards below. A violation is suppressed when its exact `<check>:<path>` line appears
# in scripts/guards-allow.txt (the ratchet — debt drained over time, never
# grown without justification in the PR).
#
#   size       .rs file over MAX_LINES lines
#   modrs      file named mod.rs (named-file module style only)
#   layername  .rs file or directory named util/utils/helpers/common/misc/
#              manager/handler
#   moddoc     .rs file under src/, tests/ or examples/ with no `//!` module doc
#   itemdoc    crate root without `#![warn(missing_docs)]`, or an
#              `allow(missing_docs)` anywhere — with CI's `-D warnings` the pair
#              holds undocumented public items at zero
#   glossary   workspace member directory without a CONTEXT.md
#   adr        ADR with a Status: line or without a row in the ADR index
#   adrcite    an ADR citation or docs/adr/ link that names no file
#   doctree    docs/ top-level entry outside the live-only tree (adr,
#              architecture, protocol, reference)
#   uidebug    a Debug format (`{:?}`, `{:#?}`, `{name:?}`) in text an operator
#              can read: rmule's, rmule-cli's and rmule-words' source outside
#              test code and `tracing::` macros, and the `#[error(...)]` texts
#              of every other crate under crates/; the Run Log may hold one
#   unsafe     `unsafe` code or an `unsafe_code` waiver outside the functions
#              crates/rmule-os pins, a pinned function without exactly one
#              waiver on it and one `unsafe` block in it or with more than one
#              `unsafe extern` block, a block or an extern block without a
#              `// SAFETY:` comment above it, another manifest setting
#              `unsafe_code`, or rmule-os's lint table drifting from
#              [workspace.lints]
#   trackerref a reference into this repository's own tracker (a hash and a
#              number, a numbered local plan issue, or an issue or pull URL)
#              in any public tracked file
#   vocab      private workflow vocabulary, a plan label or coordinate, a
#              private branch, worktree or image-tag name, or a path into the
#              private tree, in any public tracked file
#   sentence   a `Sentence` made outside a words module: rmule-words, or the
#              TUI's own words (apps/rmule/src/words.rs and words/)
#
# Exit 0 when every violation is suppressed, 1 otherwise.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ALLOW_FILE="scripts/guards-allow.txt"
MAX_LINES=1000
ROOTS="crates apps tools"
LAYER_NAMES="util utils helpers common misc manager handler"
# Own workspace, own manifest — not a member of the root workspace.
EXCLUDED_MEMBER="tools/ed2ksrv-differ"

violations=0
suppressed=0

# Allowlist lines, comments and blanks stripped.
allow_entries=""
if [ -f "$ALLOW_FILE" ]; then
    allow_entries="$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$ALLOW_FILE" | grep -v '^$' || true)"
fi

is_allowed() {
    printf '%s\n' "$allow_entries" | grep -qxF "$1"
}

# report <check> <path> <message>
report() {
    entry="$1:$2"
    if is_allowed "$entry"; then
        suppressed=$((suppressed + 1))
        return
    fi
    violations=$((violations + 1))
    printf '%s: %s — %s\n' "$1" "$2" "$3"
}

# Every tracked-or-not .rs file under the guarded roots, target/ and .scratch/
# excluded. Printed one path per line, repo-relative.
rs_files() {
    find $ROOTS -type f -name '*.rs' 2>/dev/null \
        | grep -v '/target/' \
        | grep -v '/\.scratch/' \
        | sort
}

# Every file and directory under the guarded roots, same exclusions.
all_paths() {
    find $ROOTS \( -type f -o -type d \) 2>/dev/null \
        | grep -v '/target/' \
        | grep -v '/\.scratch/' \
        | sort
}

# Workspace member directories: the immediate children of each root that carry
# a Cargo.toml, minus the excluded differ.
member_dirs() {
    for root in $ROOTS; do
        [ -d "$root" ] || continue
        for dir in "$root"/*/; do
            dir="${dir%/}"
            [ -f "$dir/Cargo.toml" ] || continue
            [ "$dir" = "$EXCLUDED_MEMBER" ] && continue
            printf '%s\n' "$dir"
        done
    done
}

echo "== guards =="

# 1. size — no .rs file over MAX_LINES lines.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    lines="$(wc -l < "$f" | tr -d ' ')"
    if [ "$lines" -gt "$MAX_LINES" ]; then
        report size "$f" "$lines lines > $MAX_LINES"
    fi
done <<EOF
$(rs_files)
EOF

# 2. modrs — named-file module style, no mod.rs anywhere.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$(basename "$f")" in
    mod.rs) report modrs "$f" "mod.rs — use named-file module style" ;;
    esac
done <<EOF
$(rs_files)
EOF

# 3. layername — no layer-name files or directories.
while IFS= read -r p; do
    [ -n "$p" ] || continue
    base="$(basename "$p")"
    base="${base%.rs}"
    for name in $LAYER_NAMES; do
        if [ "$base" = "$name" ]; then
            report layername "$p" "layer-name '$name' — name for the domain"
        fi
    done
done <<EOF
$(all_paths)
EOF

# 4. moddoc — every .rs under src/, tests/ or examples/ opens with a //! module doc.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
    */src/* | */tests/* | */examples/*) ;;
    *) continue ;;
    esac
    if ! grep -q '^//!' "$f"; then
        report moddoc "$f" "no //! module doc"
    fi
done <<EOF
$(rs_files)
EOF

# 5. itemdoc — every crate root asks rustc for the item docs, and nothing waives
# it. The lint stays per crate root rather than in [workspace.lints] because the
# workspace form also demands a crate doc on every integration-test root.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
    */src/lib.rs | */src/main.rs)
        grep -q '^#!\[warn(missing_docs)\]' "$f" ||
            report itemdoc "$f" "crate root without #![warn(missing_docs)]"
        ;;
    esac
    if grep -q 'allow(missing_docs)' "$f"; then
        report itemdoc "$f" "allow(missing_docs) — item docs are not waivable"
    fi
done <<EOF
$(rs_files)
EOF

# 6. glossary — every workspace member carries a CONTEXT.md.
while IFS= read -r d; do
    [ -n "$d" ] || continue
    if [ ! -f "$d/CONTEXT.md" ]; then
        report glossary "$d" "no CONTEXT.md"
    fi
done <<EOF
$(member_dirs)
EOF

# 7. adr — a file in docs/adr/ is a decision in force: it carries no Status:
# line, since a changed decision is edited in place and a dropped one deleted,
# and it has a row in the index.
for f in docs/adr/[0-9][0-9][0-9][0-9]-*.md; do
    [ -e "$f" ] || continue
    if grep -q '^Status:' "$f"; then
        report adr "$f" "carries a Status: line; an ADR is edited in place, never marked"
    fi
    if ! grep -qF "($(basename "$f"))" docs/adr/README.md; then
        report adr "$f" "no row in docs/adr/README.md"
    fi
done

# 8. doctree — docs/ holds only the live-only tree's top-level names.
DOC_TREE_ALLOWED="adr architecture protocol reference"
if [ -d docs ]; then
    for p in docs/*/; do
        [ -e "$p" ] || continue
        name="$(basename "$p")"
        allowed=0
        for ok in $DOC_TREE_ALLOWED; do
            [ "$name" = "$ok" ] && allowed=1 && break
        done
        if [ "$allowed" -eq 0 ]; then
            report doctree "$p" "docs/ top-level entry outside adr/architecture/protocol/reference"
        fi
    done
fi

# 9. uidebug — no Debug format reaches what an operator reads. Reach:
#   - every `.rs` under apps/rmule/src, apps/rmule-cli/src and
#     crates/rmule-words/src (the words both front ends speak), minus test
#     code (`tests.rs`, `tests/`, the cfg(test) `fixture.rs` and `golden.rs`,
#     any `#[cfg(test)]` item), comments, and `tracing::` macro calls, whose
#     free-form lines reach the Run Log at its full level only. The Run Log's
#     own module is scanned like any other: its lines are written from typed
#     fields, never Debug;
#   - every `#[error(...)]` text under crates/*/src, which a front end prints
#     when it shows a failure, whichever crate raised it.
# What it cannot see: a Debug format written any other way (`?value` outside
# `tracing::`, `dbg!`, a hand-written `fmt` that calls `Debug::fmt`), a format
# string built at run time, a `Display` that delegates to a value whose own
# `Display` renders Debug in another crate, and the `Display` of core's events
# (`service/event/display.rs`): those lines are the Run Log's and the logs'
# diagnostic form, and no operator-facing surface prints them. Formats are
# matched a line at a time, so a `{:?}` split from its format string by a line
# break is missed.
UI_SRC="apps/rmule/src"
CLI_SRC="apps/rmule-cli/src"
WORDS_SRC="crates/rmule-words/src"
uidebug_lines() {
    awk '
        function count(s, c,   n, i) { n = 0; for (i = 1; i <= length(s); i++) if (substr(s, i, 1) == c) n++; return n }
        FNR == 1 { skip = 0; depth = 0; pending = 0; tracing = 0; parens = 0 }
        /^[[:space:]]*\/\// { next }
        skip {
            depth += count($0, "{") - count($0, "}")
            if (depth <= 0) skip = 0
            next
        }
        pending {
            if ($0 ~ /\{/) {
                depth = count($0, "{") - count($0, "}")
                skip = depth > 0
                pending = 0
            } else if ($0 ~ /;[[:space:]]*$/) {
                pending = 0
            }
            next
        }
        /#\[cfg\(test\)\]/ {
            rest = $0
            sub(/.*#\[cfg\(test\)\]/, "", rest)
            if (rest ~ /\{/) {
                depth = count(rest, "{") - count(rest, "}")
                skip = depth > 0
            } else if (rest !~ /;[[:space:]]*$/) {
                pending = 1
            }
            next
        }
        tracing {
            parens += count($0, "(") - count($0, ")")
            if (parens <= 0) tracing = 0
            next
        }
        /tracing::(trace|debug|info|warn|error)!\(/ {
            call = $0
            sub(/.*tracing::(trace|debug|info|warn|error)!/, "", call)
            parens = count(call, "(") - count(call, ")")
            tracing = parens > 0
            next
        }
        /\{[A-Za-z0-9_.]*:[^{}"]*\?\}/ { print FNR }
    ' "$1"
}
# The first line of each `#[error(...)]` whose text, however many lines it
# spans, holds a Debug format.
uidebug_error_lines() {
    awk '
        function count(s, c,   n, i) { n = 0; for (i = 1; i <= length(s); i++) if (substr(s, i, 1) == c) n++; return n }
        open {
            text = text $0
            parens += count($0, "(") - count($0, ")")
            if (parens <= 0) { open = 0; if (text ~ /\{[A-Za-z0-9_.]*:[^{}"]*\?\}/) print start }
            next
        }
        /^[[:space:]]*#\[error\(/ {
            text = $0; start = FNR
            parens = count($0, "(") - count($0, ")")
            if (parens > 0) { open = 1 } else if (text ~ /\{[A-Za-z0-9_.]*:[^{}"]*\?\}/) print start
        }
    ' "$1"
}
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
    "$UI_SRC"/* | "$CLI_SRC"/* | "$WORDS_SRC"/*)
        case "$f" in
        */tests.rs | */tests/* | "$UI_SRC"/fixture.rs | "$UI_SRC"/golden.rs) continue ;;
        esac
        hits="$(uidebug_lines "$f" | tr '\n' ' ' | sed 's/ $//')"
        message="word it in a words module or render the value"
        ;;
    crates/*/src/*)
        hits="$(uidebug_error_lines "$f" | tr '\n' ' ' | sed 's/ $//')"
        message="an #[error(...)] text renders values, not Debug"
        ;;
    *) continue ;;
    esac
    if [ -n "$hits" ]; then
        report uidebug "$f" "Debug format at line(s) $hits — $message"
    fi
done <<EOF
$(rs_files)
EOF

# 10. unsafe — `unsafe_code` is forbidden workspace-wide. One crate, rmule-os,
# relaxes it to deny for the operating-system calls no safe wrapper offers
# (ADR-0111), and only the functions pinned below may waive it: each carries
# one waiver directly on it and holds one `unsafe` block under a `// SAFETY:`
# comment, and may declare the foreign function it calls, when no crate does,
# in at most one `unsafe extern` block under a `// SAFETY:` comment of its own.
# Nothing else in the crate, or outside it, holds `unsafe` code or a waiver;
# the crate's lint table repeats every other workspace lint, and no other
# manifest sets the lint.
UNSAFE_CRATE="crates/rmule-os"
# The waived functions, `<file under the crate>:<fn name>`. Two definitions
# under different `cfg`s share a name and count as one.
UNSAFE_PINNED="src/winsock.rs:disable_udp_connection_reset
src/sparse/macos.rs:punch_hole
src/sparse/windows.rs:set_sparse
src/sparse/windows.rs:punch_hole
src/sparse/windows.rs:allocated_bytes
src/fs/windows.rs:rename_exclusive
src/default_app/macos.rs:drop
src/default_app/macos.rs:cf_string
src/default_app/macos.rs:content_type
src/default_app/macos.rs:default_app
src/default_app/macos.rs:file_path
src/default_app/windows.rs:for_extension"
UNSAFE_CODE='(^|[^[:alnum:]_])unsafe[[:space:]]*(\{|fn[[:space:]]|impl[[:space:]]|extern[[:space:]]|trait[[:space:]])'
UNSAFE_WAIVER='(allow|expect)\([^)]*unsafe_code'
# A file's code lines: `//` comment lines dropped.
code_lines() {
    grep -v '^[[:space:]]*//' "$1"
}
# unsafe_sites <file>: one line per waiver and per `unsafe` code line,
#   waiver <line> <fn>              the fn the waiver sits on, `-` for none
#   block <line> <fn> <safe> <ufn>  the fn declared last above the block (`-`
#                                   for none); safe = 1 when the `//` run
#                                   right above holds `SAFETY:`; ufn = 1 for
#                                   an `unsafe fn`
#   extern <line> <fn> <safe> 0     an `unsafe extern` block, read as a block
#                                   is; the fns it declares are not the fn a
#                                   later block lies in
# A waiver sits on a fn when only attribute and comment lines lie between
# them (or the fn follows it on its line); an inner `#![...]` sits on none.
unsafe_sites() {
    awk '
        function fn_name(line,   name) {
            if (!match(line, /(^|[^[:alnum:]_])fn[[:space:]]+[[:alpha:]_][[:alnum:]_]*/)) return ""
            name = substr(line, RSTART, RLENGTH)
            sub(/^.*fn[[:space:]]+/, "", name)
            return name
        }
        function settle(name,   i, n, lines) {
            n = split(pending, lines, " ")
            for (i = 1; i <= n; i++) print "waiver", lines[i], (name == "" ? "-" : name)
            pending = ""
        }
        /^[[:space:]]*\/\// {
            if ($0 ~ /SAFETY:/) safety = 1
            next
        }
        {
            attribute = ($0 ~ /^[[:space:]]*#!?\[/)
            if (pending != "" && !attribute) settle(fn_name($0))
            if ($0 ~ /(allow|expect)\([^)]*unsafe_code/) {
                rest = $0
                sub(/^[[:space:]]*#\[[^]]*\][[:space:]]*/, "", rest)
                if ($0 ~ /^[[:space:]]*#!/) print "waiver", NR, "-"
                else if (fn_name(rest) != "") print "waiver", NR, fn_name(rest)
                else pending = pending " " NR
            }
            if (depth > 0) {
                depth += gsub(/[{]/, "{") - gsub(/[}]/, "}")
                safety = 0
                next
            }
            name = fn_name($0)
            if (name != "") current = name
            if ($0 ~ /(^|[^[:alnum:]_])unsafe[[:space:]]+extern[[:space:]]/) {
                print "extern", NR, (current == "" ? "-" : current), safety + 0, 0
                depth = gsub(/[{]/, "{") - gsub(/[}]/, "}")
            } else if ($0 ~ /(^|[^[:alnum:]_])unsafe[[:space:]]*([{]|fn[[:space:]]|impl[[:space:]]|extern[[:space:]]|trait[[:space:]])/)
                print "block", NR, (current == "" ? "-" : current), safety + 0, ($0 ~ /unsafe[[:space:]]+fn[[:space:]]/)
            safety = 0
        }
        END { if (pending != "") settle("") }
    ' "$1"
}
unsafe_waived=""
unsafe_blocks=""
unsafe_externs=""
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
    "$UNSAFE_CRATE"/*)
        rel="${f#"$UNSAFE_CRATE"/}"
        while read -r kind line fn safe ufn; do
            [ -n "$kind" ] || continue
            key="$rel:$fn"
            if ! printf '%s\n' "$UNSAFE_PINNED" | grep -qxF "$key"; then
                if [ "$kind" = waiver ]; then
                    report unsafe "$f" "line $line: an unsafe_code waiver not directly on a function this guard pins"
                else
                    report unsafe "$f" "line $line: unsafe code outside a function this guard pins"
                fi
                continue
            fi
            if [ "$kind" = waiver ]; then
                unsafe_waived="$unsafe_waived$key
"
                continue
            fi
            if [ "$kind" = extern ]; then
                unsafe_externs="$unsafe_externs$key
"
                [ "$safe" = 1 ] ||
                    report unsafe "$f" "line $line: an unsafe extern block without a // SAFETY: comment right above it"
                continue
            fi
            unsafe_blocks="$unsafe_blocks$key
"
            [ "$safe" = 1 ] ||
                report unsafe "$f" "line $line: an unsafe block without a // SAFETY: comment right above it"
            [ "$ufn" = 0 ] ||
                report unsafe "$f" "line $line: an unsafe fn — a pinned function is a safe wrapper"
        done <<SITES
$(unsafe_sites "$f")
SITES
        ;;
    *)
        if code_lines "$f" | grep -qE "$UNSAFE_CODE|$UNSAFE_WAIVER"; then
            report unsafe "$f" "unsafe code or an unsafe_code waiver — only the functions $UNSAFE_CRATE pins may hold one"
        fi
        ;;
    esac
done <<EOF
$(rs_files)
EOF
while IFS= read -r key; do
    [ -n "$key" ] || continue
    waived=$(printf '%s' "$unsafe_waived" | grep -cxF "$key")
    blocks=$(printf '%s' "$unsafe_blocks" | grep -cxF "$key")
    if [ "$waived" -ne 1 ] || [ "$blocks" -ne 1 ]; then
        report unsafe "$UNSAFE_CRATE/${key%%:*}" "${key#*:}: $waived waiver(s) and $blocks unsafe block(s) — exactly one of each"
    fi
    externs=$(printf '%s' "$unsafe_externs" | grep -cxF "$key")
    if [ "$externs" -gt 1 ]; then
        report unsafe "$UNSAFE_CRATE/${key%%:*}" "${key#*:}: $externs unsafe extern blocks — at most one"
    fi
done <<EOF
$UNSAFE_PINNED
EOF
while IFS= read -r d; do
    [ -n "$d" ] || continue
    [ "$d" = "$UNSAFE_CRATE" ] && continue
    if grep -q 'unsafe_code' "$d/Cargo.toml"; then
        report unsafe "$d/Cargo.toml" "sets unsafe_code — the workspace lint table owns it"
    fi
done <<EOF
$(member_dirs)
EOF
# Every workspace lint line but `unsafe_code` appears in the crate's table.
while IFS= read -r lint; do
    [ -n "$lint" ] || continue
    grep -qxF "$lint" "$UNSAFE_CRATE/Cargo.toml" ||
        report unsafe "$UNSAFE_CRATE/Cargo.toml" "lint table lacks the workspace's $lint"
done <<EOF
$(awk '/^\[/ { inlints = ($0 ~ /^\[workspace\.lints\./); next }
       inlints && NF && $0 !~ /^#/ && $0 !~ /^unsafe_code/' Cargo.toml)
EOF

# 11. trackerref and 12. vocab — the public tree states facts, not pointers
# into this repository's tracker, plans or private files. Reach: every tracked
# file but the private tree (the `$private` prefixes below, never published),
# data and lock files, upstream patches and binary files (a NUL in the first
# 8 KiB). Every line is read: in Rust a hash followed by a digit only occurs in
# comments and string literals, so trackerref needs no parser; vocab reads a
# Rust code line's string literals and trailing comment only, so identifiers
# are never matched. One violation per file, naming its first offending line;
# docs/adr/ is reported once per check as the directory, because the ADR
# rewrite renumbers its files.
#
# trackerref, after masking Rust format specs (`{:#04x}`), Markdown in-page
# anchors and the UI's `Queued #N` rank:
#   - a hash and one to four digits not glued to a word, entity or format spec
#     (`amule#1177`, `PKCS#1`, `&#38;` and `#121212` stay);
#   - a numbered local plan issue (the word issue, then two digits);
#   - an issue or pull URL into this repository.
# vocab: the workflow words the first patterns below name (one keeps its
# dial-back engagement sense, by path and by phrase); plan labels (a numbered
# wave or step label, with or without a step letter); plan coordinates written
# the way the plans wrote them (a capital letter and one or two digits, possessive,
# parenthesised or before a section sign; the letters U and V are left out,
# since `V2` and `U32` are names on the wire); private branch, worktree and
# image-tag names; and paths into the private tree. Two masks, by phrase:
# kno's numbered audit findings on upstream amule#1177, and the
# private-directory `doctree:` entries of scripts/guards-allow.txt, which drain
# with their directories at the public cut. A public file that needs one of
# these literally gets a mask here, never an allowlist entry. Character
# classes such as `[i]` inside a word keep this file from matching its own
# patterns.
# `read -d ''` rather than `$(cat <<…)`: bash 3.2 (macOS) misparses quotes
# inside a heredoc in a command substitution.
IFS= read -r -d '' TEXT_SCAN <<'PERL' || true
use strict;
use warnings;
my $private = qr{^(?:AGENTS\.md|CLAUD[E]\.md|\.claud[e]/|docs/(?:[a]gents|parity|release-prep)/|scripts/(?:worktree-new|bench-images-gc|populate-references)\.sh|graphif[y]-out/)};
my $skipped = qr{\.(?:bin|lock|gitkeep|patch)$};
my @masks = (qr/\{[\w.]*:[^{}\s]*\}/, qr/\]\(#[^)\s]*\)/, qr/\b[Qq]ueued #\d+/);
my @tracker = (
    qr/(?<![\w&{:#])#\d{1,4}(?!\w)/,
    qr/\b[Ii]ssues?[ -]\d{2}(?!\d)/,
    qr{github\.com/Lazark0x/rmule/(?:issues|pull)/\d+},
);
my $domain_word = qr/\b[Tt][i]ckets?\b/;
my @vocab = (
    qr/\b[Aa]ttended\b|\b[Ww]ayfinder\b|\bHITL\b|\bAFK\b|\b[Mm]ilestones?\b|\b[Gg]rill/,
    qr/\b[Ss]lices?[ -](?:\d+|[A-E])\b/,
    qr/\b(?:[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able)\b(?!-)/,
    qr/dispatch\.md|\b(?:[Aa]gent|[Ss]ubagent|[Tt][i]cket)s?[- ][Dd]ispatch|\b[Dd]ispatch(?:es|ed|ing)?\s+(?:an?\s+|the\s+)?(?:[Ss]ub)?[Aa]gents?\b/,
    qr/\b(?:W\d{1,2}[a-z]?(?:\.\d{1,2}[a-z]?)?|(?<!Apple )M\d(?:\.\d{1,2})?|[Ww]ave[ -]?\d+|S\d{1,2}[a-z])\b/,
    qr/\b[A-TW-Z]\d{1,2}[a-z]?'s\b|\([A-TW-Z]\d{1,2}[a-z]?(?=[),;]| §)|\b[A-TW-Z]\d{1,2}[a-z]? §/,
    qr{\b(?:feat|fix|chore|research)/[a-z][\w.-]*|\bnat-\d{3}\b|\brmule/interop-[a-z-]+:[a-z]+-},
    qr{~/[P]rojects/|\$HOME/[P]rojects/|docs/(?:[a]gents|parity|release-prep|plans)/|\bAGENTS\.md|\bCLAUDE\.md|(?<![\w/])\.claud[e]/|worktree-new\.sh|bench-images-gc\.sh|populate-references\.sh|\.scratc[h]/issues},
);
my @domain_paths = (qr{^crates/rmule-core/src/reachability/}, qr{^crates/rmule-core/src/adapters/kad_runtime/node/pump/dial_back\.rs$});
my $domain_phrase = qr/(?:dial-back|engagement|per-endpoint engagement)\s+t[i]cket/;
my $vocab_masks = qr/iana-time-zone-haiku|kno's audit finding F\d|kno's `(?:feat|fix)\/[\w.-]+`/;
sub blank { my ($s, $re) = @_; $s =~ s/$re/' ' x length($&)/ge; return $s; }
# A Rust code line's prose: its string literals and its trailing comment.
sub prose {
    my ($s) = @_;
    my ($pos, @parts) = (0);
    while ($s =~ /"(?:[^"\\\n]|\\.)*"?/g) {
        my ($start, $end) = ($-[0], $+[0]);
        my $code = substr($s, $pos, $start - $pos);
        my $at = index($code, '//');
        return join(' ', @parts, substr($code, $at)) if $at >= 0;
        push @parts, substr($s, $start, $end - $start);
        $pos = $end;
    }
    my $rest = substr($s, $pos);
    my $at = index($rest, '//');
    push @parts, substr($rest, $at) if $at >= 0;
    return join(' ', @parts);
}
local $/ = "\0";
my %seen;
while (my $path = <STDIN>) {
    chomp $path;
    next if $path =~ $private || $path =~ $skipped;
    open(my $fh, '<', $path) or next;
    binmode $fh;
    read($fh, my $head, 8192);
    if (defined $head && index($head, "\0") >= 0) { close $fh; next; }
    seek($fh, 0, 0);
    local $/ = "\n";
    my $where = $path =~ m{^docs/adr/} ? 'docs/adr/' : $path;
    my $at = $where eq $path ? 'line ' : "$path:";
    my $rust = $path =~ /\.rs$/;
    my $domain = grep { $path =~ $_ } @domain_paths;
    while (my $line = <$fh>) {
        chomp $line;
        my $text = $line;
        $text = blank($text, $_) for @masks;
        if (!$seen{"trackerref:$where"}) {
            for my $re (@tracker) {
                next unless $text =~ $re;
                $seen{"trackerref:$where"} = 1;
                print "trackerref\t$where\t$at$.\t$&\n";
                last;
            }
        }
        next if $seen{"vocab:$where"};
        next if $path eq 'scripts/guards-allow.txt' && $line =~ m{^doctree:docs/};
        my $words = ($rust && $line !~ m{^\s*//}) ? prose($text) : $text;
        $words = blank($words, $domain_phrase);
        $words = blank($words, $vocab_masks);
        for my $re ($domain ? () : ($domain_word), @vocab) {
            next unless $words =~ $re;
            $seen{"vocab:$where"} = 1;
            print "vocab\t$where\t$at$.\t$&\n";
            last;
        }
    }
    close $fh;
}
PERL
while IFS="$(printf '\t')" read -r check path at hit; do
    [ -n "$check" ] || continue
    case "$check" in
    trackerref) message="a tracker reference — state the fact it pointed to" ;;
    *) message="private workflow word, plan label or private name — state the fact in public words" ;;
    esac
    report "$check" "$path" "$at: \`$hit\` — $message"
done <<EOF
$(git ls-files -z | perl -e "$TEXT_SCAN")
EOF

# 13. adrcite — every ADR citation names an ADR that exists. Reach: every text
# file git tracks or would track, minus the docs/ directories the doctree
# allowlist exempts (notes outside the public tree, which may cite ADR numbers
# that no longer exist). Forms: ADR-NNNN, ADR NNNN, slash lists (ADR-NNNN/NNNN),
# a path ending in adr/NNNN-<slug>.md, and a docs/adr/ file's local link
# ](NNNN-<slug>.md).
adrcite_excludes="$(printf '%s\n' "$allow_entries" \
    | sed -n 's|^doctree:\(docs/[^/]*\)/$|:(exclude)\1|p' | tr '\n' ' ')"
adrcite_hits() {
    adr_files="$(cd docs/adr 2>/dev/null && ls [0-9][0-9][0-9][0-9]-*.md 2>/dev/null | tr '\n' ' ')"
    git grep -I --untracked -n -o -E \
        'ADR[- ][0-9]{4}[a-z]?(/[0-9]{4}[a-z]?)*|adr/[0-9]{4}[A-Za-z0-9._-]*\.md|\]\((\./)?[0-9]{4}-[A-Za-z0-9._-]*\.md' \
        -- . $adrcite_excludes 2>/dev/null \
        | awk -v files="$adr_files" '
            BEGIN {
                n = split(files, f, " ")
                for (i = 1; i <= n; i++) { have[f[i]] = 1; num[substr(f[i], 1, 4)] = 1 }
            }
            {
                path = $0; sub(/:.*/, "", path)
                hit = $0; sub(/^[^:]*:[0-9]+:/, "", hit)
                if (hit ~ /^ADR/) {
                    m = split(substr(hit, 5), ids, "/")
                    for (i = 1; i <= m; i++)
                        if (length(ids[i]) != 4 || !(ids[i] in num)) print path "\tADR-" ids[i]
                } else if (hit ~ /^adr\//) {
                    if (!(substr(hit, 5) in have)) print path "\t" hit
                } else if (path ~ /^docs\/adr\//) {
                    name = hit; sub(/^\]\((\.\/)?/, "", name)
                    if (!(name in have)) print path "\t" name
                }
            }' \
        | sort -u
}
adrcite_last=""
adrcite_names=""
while IFS="$(printf '\t')" read -r path name; do
    [ -n "$path" ] || continue
    if [ "$path" != "$adrcite_last" ] && [ -n "$adrcite_last" ]; then
        report adrcite "$adrcite_last" "cites no existing ADR:$adrcite_names"
        adrcite_names=""
    fi
    adrcite_last="$path"
    adrcite_names="$adrcite_names $name"
done <<EOF
$(adrcite_hits)
EOF
if [ -n "$adrcite_last" ]; then
    report adrcite "$adrcite_last" "cites no existing ADR:$adrcite_names"
fi

# 14. sentence — a Sentence is made only in a words module. Its constructors
# are public because the TUI's own words, which word the TUI's own types, live
# in another crate than the type; this keeps every other module from making
# one out of any String. Reach: every `.rs` under the guarded roots outside
# rmule-words and the TUI's words, comment lines dropped. A test's
# layout-only sentence goes through `Sentence::for_test`, which only a build
# with rmule-words' `test-support` feature has.
SENTENCE_NEW='Sentence::(fixed|owned)[[:space:]]*\('
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
    "$WORDS_SRC"/* | "$UI_SRC"/words.rs | "$UI_SRC"/words/*) continue ;;
    esac
    hits="$(grep -nE "$SENTENCE_NEW" "$f" | grep -vE '^[0-9]+:[[:space:]]*//' \
        | cut -d: -f1 | tr '\n' ' ' | sed 's/ $//')"
    if [ -n "$hits" ]; then
        report sentence "$f" "Sentence made at line(s) $hits — word it in a words module"
    fi
done <<EOF
$(rs_files)
EOF

echo
if [ "$suppressed" -gt 0 ]; then
    echo "suppressed: $suppressed allowlisted (scripts/guards-allow.txt — ratchet debt)"
fi

if [ "$violations" -gt 0 ]; then
    echo "FAIL: $violations unsuppressed violation(s)"
    exit 1
fi

echo "OK: 0 unsuppressed violations"
exit 0
