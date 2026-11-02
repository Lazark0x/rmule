#!/usr/bin/env python3
"""After a kill -9: were the bytes the next run did not ask for on disk?

`kill_check.py <source file> <part at the kill> <ranges json of the taps after>`.
What the run after the kill never asked for is what the store counted. Each such
byte must already match the source in the copy of `.part` taken at the kill.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wire_ranges import merge  # noqa: E402


def main():
    source, part, ranges = sys.argv[1:4]
    want = open(source, "rb").read()
    have = open(part, "rb").read()
    have += bytes(max(0, len(want) - len(have)))
    asked = merge(tuple(r) for r in json.load(open(ranges))["asked"])
    counted, at = [], 0
    for a, b in asked:
        if a > at:
            counted.append((at, a))
        at = max(at, b)
    if at < len(want):
        counted.append((at, len(want)))
    wrong = sum(
        sum(1 for x, y in zip(want[a:b], have[a:b]) if x != y)
        for a, b in counted
    )
    total = sum(b - a for a, b in counted)
    print(f"counted_bytes={total} counted_not_on_disk={wrong} ranges={len(counted)} asked_after={len(want) - total}")


if __name__ == "__main__":
    main()
