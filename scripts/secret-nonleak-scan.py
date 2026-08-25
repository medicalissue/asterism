#!/usr/bin/env python3
"""Find an exact secret in files and process environments, without leaking it.

The needle is read from stdin, so it never appears in a process argument or
environment variable. Exit 0 means absent, 1 means found, and 2 means the scan
was incomplete. Sparse files are read through allocated extents only.
"""

from __future__ import annotations

import argparse
import errno
import os
import stat
import sys
from collections.abc import Iterator


CHUNK = 1024 * 1024


def files_below(roots: list[str], maximum: int) -> Iterator[str]:
    def fail(error: OSError) -> None:
        raise error

    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for directory, _dirs, names in os.walk(root, onerror=fail):
            for name in names:
                path = os.path.join(directory, name)
                metadata = os.stat(path, follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum:
                    yield path


def contains(path: str, needle: bytes) -> bool:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        size = os.fstat(fd).st_size
        at = 0
        overlap = b""
        sparse = hasattr(os, "SEEK_DATA") and hasattr(os, "SEEK_HOLE")
        while at < size:
            if sparse:
                try:
                    at = os.lseek(fd, at, os.SEEK_DATA)
                    end = os.lseek(fd, at, os.SEEK_HOLE)
                except OSError as error:
                    if error.errno == errno.ENXIO:
                        break
                    if error.errno in (errno.EINVAL, errno.ENOTSUP):
                        sparse = False
                        end = size
                    else:
                        raise
            else:
                end = size
            os.lseek(fd, at, os.SEEK_SET)
            overlap = b""
            remaining = end - at
            while remaining > 0:
                block = os.read(fd, min(CHUNK, remaining))
                if not block:
                    return False
                window = overlap + block
                if needle in window:
                    return True
                overlap = window[-(len(needle) - 1) :] if len(needle) > 1 else b""
                remaining -= len(block)
                at += len(block)
            at = max(end, at + 1)
        return False
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--proc-pids")
    parser.add_argument("roots", nargs="+")
    args = parser.parse_args()
    needle = sys.stdin.buffer.read()
    if not needle:
        print("secret scanner received an empty needle", file=sys.stderr)
        return 2
    try:
        candidates = list(files_below(args.roots, args.max_bytes))
        if args.proc_pids:
            with open(args.proc_pids, encoding="ascii") as members:
                candidates.extend(
                    f"/proc/{pid.strip()}/environ"
                    for pid in members
                    if pid.strip().isdigit()
                )
        found = []
        for path in candidates:
            try:
                if contains(path, needle):
                    found.append(path)
            except FileNotFoundError:
                if not path.startswith("/proc/"):
                    raise
        if found:
            print("\n".join(found))
            return 1
        return 0
    except (OSError, UnicodeError) as error:
        print(f"secret scan incomplete: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
