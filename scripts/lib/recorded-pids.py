"""Every pid the daemon wrote down in one of its own records.

Used by `harness_reap_home` to stop what a suite started without matching on
command lines. The daemon records the pid of every guest it boots on that
instance's handle, and the pid of every volume server on that volume's lease,
so this is the product's own account of what it spawned rather than a guess
made from the process table.

Anything unreadable prints nothing: a half-written or absent record means
there is nothing to stop, which is the same outcome as an empty one.
"""

import json
import sys


def pids(node):
    if isinstance(node, dict):
        value = node.get("pid")
        if isinstance(value, int) and value > 0:
            yield value
        for child in node.values():
            yield from pids(child)
    elif isinstance(node, list):
        for child in node:
            yield from pids(child)


def main():
    if len(sys.argv) != 2:
        print("usage: recorded-pids.py <state.json>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return 0
    for pid in sorted(set(pids(document))):
        print(pid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
