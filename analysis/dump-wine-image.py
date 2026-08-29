#!/usr/bin/env python3
"""Dump a PE image out of a running Wine process.

    dump-wine-image.py <process-name-substring> [imagebase] [size] [outfile]

A packed binary unpacks itself; the simplest way past a packer you cannot
decompress offline is to let it finish and read the result out of memory.
Wine runs the PE inside an ordinary Linux process, so /proc/<pid>/mem gives
direct access with no debugger involved.

The dump is the image as loaded (unpacked code at its virtual addresses), not
a runnable file. That is fine for analysis: load it in Ghidra as raw x86 at the
image base.
"""
import os
import re
import sys


def find_pid(needle):
    hits = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\x00", b" ").decode("latin-1", "replace")
        except OSError:
            continue
        if needle.lower() in cmd.lower() and "dump-wine-image" not in cmd:
            hits.append((int(entry), cmd.strip()))
    return hits


def maps_covering(pid, base, size):
    """Return the mapped ranges overlapping [base, base+size)."""
    out = []
    with open(f"/proc/{pid}/maps") as fh:
        for line in fh:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
            if not m:
                continue
            start, end, perms = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
            if end > base and start < base + size:
                out.append((start, end, perms, line.strip()))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    needle = sys.argv[1]
    base = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x400000
    size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0xC000
    out = sys.argv[4] if len(sys.argv) > 4 else "/mnt/share/dump.bin"

    pids = find_pid(needle)
    if not pids:
        print(f"no process matching {needle!r}", file=sys.stderr)
        return 1
    for pid, cmd in pids:
        print(f"pid {pid}: {cmd[:100]}")

    for pid, _ in pids:
        ranges = maps_covering(pid, base, size)
        if not ranges:
            continue
        print(f"\npid {pid} maps covering 0x{base:x}:")
        for r in ranges:
            print("  " + r[3][:100])
        try:
            with open(f"/proc/{pid}/mem", "rb", 0) as mem:
                mem.seek(base)
                data = mem.read(size)
        except OSError as exc:
            print(f"  read failed: {exc}", file=sys.stderr)
            continue
        if not data or data.count(0) == len(data):
            print("  region read but empty - the image may not be mapped here")
            continue
        with open(out, "wb") as fh:
            fh.write(data)
        print(f"\nwrote {len(data)} bytes to {out}")
        print(f"first 16 bytes: {data[:16].hex()}")
        if data[:2] == b"MZ":
            print("MZ header present - this is the loaded image")
        return 0

    print("no process had that address mapped", file=sys.stderr)
    return 1


sys.exit(main())
