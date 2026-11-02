#!/usr/bin/env bash
# One bounded pass over every fuzz target: build them once, give each the same
# budget, and fail if any crashed, after the rest have run, so one crash hides
# no other. A crashing input lands in fuzz/artifacts/<target>/. Corpora in
# fuzz/corpus/ carry over between runs.
#   scripts/fuzz-pass.sh [seconds per target] [toolchain]
set -u

seconds="${1:-30}"
toolchain="${2:-nightly}"

cd "$(dirname "$0")/../fuzz" || exit 1
# The package is outside the workspace: fuzz what the workspace pins.
cp ../Cargo.lock Cargo.lock

cargo "+$toolchain" fuzz build || exit 1

failed=()
for target in $(cargo "+$toolchain" fuzz list); do
    echo "== $target: ${seconds} s"
    cargo "+$toolchain" fuzz run "$target" -- \
        -max_total_time="$seconds" -timeout=25 -rss_limit_mb=2048 ||
        failed+=("$target")
done

if ((${#failed[@]} > 0)); then
    echo "crashed: ${failed[*]}" >&2
    exit 1
fi
