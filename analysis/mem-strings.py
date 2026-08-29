#!/usr/bin/env python3
"""Extract UTF-16LE strings from a live process, with addresses.

    mem-strings.py <pid-or-name> [min-len] [filter-substring]

VB6 keeps every string as a BSTR (UTF-16LE, length-prefixed), so a serial the
program computed for comparison is sitting in the heap as readable text right
after the check runs. Reading it out is far cheaper than decoding P-code.

Prints address, region and text so a candidate can be correlated with the
input that produced it.
"""
import os
import re
import sys

MIN_DEFAULT = 5


def resolve_pid(arg):
    if arg.isdigit():
        return int(arg)
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\x00", b" ").decode("latin-1", "replace")
        except OSError:
            continue
        if arg.lower() in cmd.lower() and "mem-strings" not in cmd:
            return int(entry)
    return None


def readable_regions(pid):
    out = []
    with open(f"/proc/{pid}/maps") as fh:
        for line in fh:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (r[-w])", line)
            if not m:
                continue
            start, end = int(m.group(1), 16), int(m.group(2), 16)
            # Skip enormous mappings and anything obviously file-backed and huge;
            # the interesting data is the heap and the loaded image.
            if end - start > 64 * 1024 * 1024:
                continue
            out.append((start, end, line.strip()))
    return out


def utf16_strings(data, base, min_len):
    """Yield (offset, text) for UTF-16LE runs of printable ASCII."""
    pattern = re.compile((b"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    for m in pattern.finditer(data):
        text = m.group().decode("utf-16-le", "ignore")
        yield base + m.start(), text


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    pid = resolve_pid(sys.argv[1])
    if not pid:
        print(f"no process matching {sys.argv[1]!r}", file=sys.stderr)
        return 1
    min_len = int(sys.argv[2]) if len(sys.argv) > 2 else MIN_DEFAULT
    needle = sys.argv[3].lower() if len(sys.argv) > 3 else None

    print(f"pid {pid}, min length {min_len}"
          + (f", filter {needle!r}" if needle else ""))

    seen = set()
    total = 0
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for start, end, desc in readable_regions(pid):
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except OSError:
                continue
            for addr, text in utf16_strings(data, start, min_len):
                if needle and needle not in text.lower():
                    continue
                key = text
                if key in seen:
                    continue
                seen.add(key)
                total += 1
                print(f"0x{addr:012x}  {text}")
    print(f"\n{total} distinct strings")
    return 0


sys.exit(main())
