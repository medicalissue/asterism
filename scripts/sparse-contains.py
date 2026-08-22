#!/usr/bin/env python3
"""Search allocated extents of a sparse file for an exact byte string.

Exit 0 when found, 1 when absent, and 2 when the filesystem cannot provide
SEEK_DATA/SEEK_HOLE. Holes are zeroes, so skipping them is exact for every
non-empty text needle and avoids reading a 10 GiB virtual disk to inspect the
few blocks a guest actually wrote.
"""

import errno
import os
import sys


CHUNK = 1024 * 1024


def usage() -> int:
    print(f"usage: {sys.argv[0]} FILE TEXT", file=sys.stderr)
    return 2


def main() -> int:
    if len(sys.argv) != 3 or not sys.argv[2]:
        return usage()
    path = sys.argv[1]
    needle = os.fsencode(sys.argv[2])
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        at = 0
        while at < size:
            try:
                data = os.lseek(fd, at, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    break
                if error.errno in (errno.EINVAL, errno.ENOTSUP):
                    print(f"{path}: filesystem does not support sparse extent inspection", file=sys.stderr)
                    return 2
                raise
            hole = os.lseek(fd, data, os.SEEK_HOLE)
            os.lseek(fd, data, os.SEEK_SET)
            remaining = min(hole, size) - data
            overlap = b""
            while remaining > 0:
                block = os.read(fd, min(CHUNK, remaining))
                if not block:
                    break
                window = overlap + block
                if needle in window:
                    return 0
                overlap = window[-(len(needle) - 1) :] if len(needle) > 1 else b""
                remaining -= len(block)
            at = max(hole, data + 1)
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
