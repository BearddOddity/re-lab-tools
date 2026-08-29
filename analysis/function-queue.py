#!/usr/bin/env python3
"""Work through unnamed game functions, a batch at a time, keeping state.

    function-queue.py next   [-n 8]     # build the next batch of evidence packets
    function-queue.py record names.txt  # mark reviewed, feed names back in
    function-queue.py status

WHY A QUEUE

Automatic naming runs out. RTTI reaches virtual functions, vtable stores reach
constructors, proximity reaches whatever sits between two known neighbours - and
then several thousand functions are left that only reading will identify. That is
slow and open-ended, so it wants a queue with state rather than a session that
starts from nothing each time and re-reads what it already read.

WHAT A PACKET CONTAINS

Decompilation alone is the hard way to identify a function. Each packet carries
the context that usually settles it faster: callers and callees by name, the
string constants it touches, its classification bucket and its size. "Called by
CCEPowerup::vfunc4, calls GetScriptEngine" is often enough on its own.

ORDER

Largest first. A 2,000-instruction function is worth more attention than a stub,
and the big ones tend to be the systems everything else hangs off.

STATE

reviewed.json records every address already looked at and the name given, so a
later run neither repeats work nor silently overwrites an earlier decision. A
name recorded here is also a claim someone can check: keep the evidence line
that justified it.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "queue-state")
GHIDRA = os.environ.get("GHIDRA_HOME", "/opt/ghidra_12.1.3_PUBLIC")
PROJECTS = os.environ.get("GHIDRA_PROJECTS", "/home/oddity/ghidra-projects")
PROJECT = os.environ.get("GHIDRA_PROJECT", "X-men Legends Recomp")
PROGRAM = os.environ.get("GHIDRA_PROGRAM", "default.xbe (in progress)")
SCRIPTS = os.environ.get("GHIDRA_SCRIPTS", "/home/oddity/ghidra_scripts")

GAME_BUCKETS = ("GAME_UNIQUE", "GAME_PORTABLE", "XMEN_SERIES")
INFERRED = ("::near_", "::helper_")


def paths():
    os.makedirs(STATE, exist_ok=True)
    return (os.path.join(STATE, "reviewed.json"),
            os.path.join(STATE, "batch_addrs.txt"),
            os.path.join(STATE, "batch.c"))


def load_reviewed(p):
    if not os.path.exists(p):
        return {}
    with open(p) as fh:
        return json.load(fh)


def candidates(classification, analysis, reviewed):
    """Unnamed game-bucket functions, largest first, minus anything reviewed."""
    size, bucket = {}, {}
    with open(classification) as fh:
        next(fh, None)
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) == 4:
                size[f[0]], bucket[f[0]] = int(f[2]), f[1]

    named = {}
    with open(analysis) as fh:
        for line in fh:
            if line.startswith("F\t"):
                f = line.split("\t")
                named[f[1]] = f[2]

    out = []
    for addr, b in bucket.items():
        if b not in GAME_BUCKETS or addr in reviewed:
            continue
        n = named.get(addr)
        # Unnamed, or carrying only an inferred affiliation - those still need
        # a real identification.
        if n is None or n.startswith("FUN_") or any(t in n for t in INFERRED):
            out.append((addr, size.get(addr, 0), b, n or "FUN_" + addr))
    out.sort(key=lambda r: -r[1])
    return out


def run_ghidra(script, *args):
    cmd = [os.path.join(GHIDRA, "support", "analyzeHeadless"), PROJECTS, PROJECT,
           "-process", PROGRAM, "-noanalysis", "-scriptPath", SCRIPTS,
           "-postScript", script, *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=3600)


def cmd_next(a):
    rev_p, addr_p, out_p = paths()
    reviewed = load_reviewed(rev_p)
    cands = candidates(a.classification, a.analysis, reviewed)
    if not cands:
        print("queue empty - nothing left in the game buckets")
        return 0
    batch = cands[:a.n]
    with open(addr_p, "w") as fh:
        for addr, *_ in batch:
            fh.write(addr + "\n")

    print(f"{len(cands):,} remaining; decompiling {len(batch)}:")
    for addr, sz, b, n in batch:
        print(f"  {addr}  {sz:>5} units  {b:<14} {n}")

    r = run_ghidra("DecompileList.java", addr_p, out_p)
    if "DL decompiled" not in r.stdout:
        sys.stderr.write(r.stdout[-2000:] + r.stderr[-2000:])
        return 1
    print(f"\nevidence packets -> {out_p}")
    print("Read them, then: function-queue.py record <names.txt>")
    print("names.txt format:  Name = 0xADDR      (one per line)")
    return 0


def cmd_record(a):
    rev_p, addr_p, _ = paths()
    reviewed = load_reviewed(rev_p)

    named = {}
    with open(a.names) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            nm, addr = (x.strip() for x in line.split("=", 1))
            named[addr.lower().replace("0x", "").zfill(8)] = nm

    applied = 0
    if named:
        r = run_ghidra("ApplyXbSymbols.java", os.path.abspath(a.names))
        for line in r.stdout.splitlines():
            if "renamed_functions=" in line:
                applied = int(line.split("renamed_functions=")[1].split()[0])
        print(f"applied {applied} names")

    # Everything in the batch counts as reviewed, named or not: a function
    # looked at and left unnamed must not come back to the top of the queue
    # every run.
    if os.path.exists(addr_p):
        for addr in open(addr_p):
            addr = addr.strip()
            if addr:
                reviewed[addr] = named.get(addr, "<reviewed, not identified>")
    with open(rev_p, "w") as fh:
        json.dump(reviewed, fh, indent=1, sort_keys=True)
    print(f"reviewed total: {len(reviewed):,}")
    return 0


def cmd_status(a):
    rev_p, _, _ = paths()
    reviewed = load_reviewed(rev_p)
    cands = candidates(a.classification, a.analysis, reviewed)
    ident = sum(1 for v in reviewed.values() if not v.startswith("<"))
    print(f"reviewed    : {len(reviewed):,}  ({ident:,} identified)")
    print(f"remaining   : {len(cands):,}")
    if cands:
        units = sum(s for _, s, _, _ in cands)
        print(f"code left   : {units:,} units, largest {cands[0][1]:,} at {cands[0][0]}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classification", default="/mnt/share/xml1_classification.tsv")
    ap.add_argument("--analysis", default="/mnt/share/xml1_analysis.txt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("next");   p.add_argument("-n", type=int, default=8); p.set_defaults(fn=cmd_next)
    p = sub.add_parser("record"); p.add_argument("names");                    p.set_defaults(fn=cmd_record)
    p = sub.add_parser("status"); p.set_defaults(fn=cmd_status)
    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
