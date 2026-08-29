#!/usr/bin/env python3
"""Classify a binary's functions as shared library/engine code or unique to it.

    classify-shared-functions.py <hashes_A.txt> <hashes_B.txt> [-o outdir]

Input is the output of the DumpFunctionHashes.java Ghidra script, one line per
function:

    <fullHash> <specificHash> <codeUnits> <address> <name>

WHY HASHES AND NOT BYTES

The same library function linked into two different images sits at different
addresses, so every absolute operand differs and a raw byte compare finds almost
nothing. Ghidra's FID hash is built to mask the operands that vary, which is
exactly the question being asked here: is this the same function as that one, in
a different image.

WHAT IT ANSWERS

Two games built with the same SDK and engine share their library code. Anything
present in both is engine, runtime or SDK; anything in only one is that game's
own logic. For a recompilation that distinction is worth more than names,
because shared code can be replaced with a real implementation rather than
recompiled, and the unique set is the part that actually has to be understood.

Verify the SDK build matches first (see the XBE library-version table in the
README) - the whole method rests on the library code being identical, and if the
builds differ the overlap collapses and the result means nothing.

CAUTION ON NAME TRANSFER

A name is only carried across when the hash matches exactly one function on each
side. A one-to-many match cannot say which candidate the name belongs to, and
guessing there would plant a wrong name that later work would trust.
"""
import argparse
import collections
import os
import sys

DEFAULT = ("FUN_", "thunk_FUN_")


def load(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            parts = line.rstrip("\n").split(" ", 4)
            if len(parts) != 5:
                continue
            full, spec, cus, addr, name = parts
            try:
                rows.append((full, spec, int(cus), addr, name))
            except ValueError:
                continue
    if not rows:
        sys.exit(f"no usable rows in {path}")
    return rows


def index(rows):
    # Key on both hashes. The full hash alone collides for very short
    # functions, which would classify unrelated stubs as shared.
    idx = collections.defaultdict(list)
    for full, spec, cus, addr, name in rows:
        idx[(full, spec)].append((addr, name, cus))
    return idx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a", help="hashes for the binary being classified")
    ap.add_argument("b", help="hashes for the comparison binary")
    ap.add_argument("-o", "--outdir", default=".")
    args = ap.parse_args()

    rows_a, rows_b = load(args.a), load(args.b)
    ia, ib = index(rows_a), index(rows_b)
    shared = set(ia) & set(ib)

    os.makedirs(args.outdir, exist_ok=True)
    cls_path = os.path.join(args.outdir, "classification.txt")
    xfer_path = os.path.join(args.outdir, "transferable_names.txt")

    n_shared = 0
    with open(cls_path, "w") as w:
        w.write("# addr\tclass\tcode_units\tname\n")
        for full, spec, cus, addr, name in sorted(rows_a, key=lambda r: r[3]):
            is_shared = (full, spec) in shared
            n_shared += is_shared
            w.write(f"{addr}\t{'SHARED' if is_shared else 'UNIQUE'}\t{cus}\t{name}\n")

    transfers, ambiguous = [], 0
    for key in shared:
        side_a, side_b = ia[key], ib[key]
        named = [n for _, n, _ in side_a if not n.startswith(DEFAULT)]
        if not named:
            continue
        if len(side_a) == 1 and len(side_b) == 1:
            transfers.append((named[0], side_b[0][0]))
        else:
            ambiguous += 1

    with open(xfer_path, "w") as w:
        for name, addr in sorted(transfers, key=lambda t: t[1]):
            w.write(f"{name} = 0x{int(addr, 16):08x}\n")

    total = len(rows_a)
    print(f"A: {total:,} functions   B: {len(rows_b):,} functions")
    print(f"  SHARED (library/engine): {n_shared:,}  ({n_shared * 100 // total}%)")
    print(f"  UNIQUE (this binary)   : {total - n_shared:,}")
    print(f"  transferable names     : {len(transfers):,}  ({ambiguous:,} rejected as ambiguous)")
    print(f"  -> {cls_path}")
    print(f"  -> {xfer_path}   (feed to ApplyXbSymbols.java)")


if __name__ == "__main__":
    main()
