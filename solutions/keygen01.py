#!/usr/bin/env python3
"""Keygen for crackme01, derived from the Ghidra decompilation.

    h = 0x1505
    per char:  t = h*0x21 ^ c ;  h = rotl32(t, 3)
    h ^= 0xC0DEBABE
    serial = "%04X-%04X-%04X" % (h>>16, h&0xFFFF, (h>>8 ^ len(name)) & 0xFFFF)

The decompiler renders the rotate as
    (c ^ h*0x21) << 3 | (h*0x21) >> 0x1d
which reads as though only the low half is XORed. Both readings are tried and
checked against the binary rather than assumed - guessing which one the
compiler meant is exactly the sort of thing that quietly produces a keygen
that works for one name and fails for the next.
"""
import sys

MASK = 0xFFFFFFFF


def rotl(v, n):
    v &= MASK
    return ((v << n) | (v >> (32 - n))) & MASK


def derive_rot_of_xor(name):
    """Rotate the XORed value - the natural reading of a djb2-xor + rotl."""
    h = 0x1505
    for c in name.encode("latin-1"):
        h = rotl((h * 0x21) ^ c, 3)
    return (h ^ 0xC0DEBABE) & MASK


def derive_literal(name):
    """Literal reading: high bits from h*0x21, low bits from (h*0x21 ^ c)."""
    h = 0x1505
    for c in name.encode("latin-1"):
        t = (h * 0x21) & MASK
        h = (((t ^ c) << 3) | (t >> 29)) & MASK
    return (h ^ 0xC0DEBABE) & MASK


def serial(name, derive):
    h = derive(name)
    return "%04X-%04X-%04X" % (h >> 16, h & 0xFFFF, ((h >> 8) ^ len(name)) & 0xFFFF)


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "oddity"
    if len(name) < 4:
        print("name must be at least 4 characters (the binary checks this)")
        raise SystemExit(1)
    print("name            : %s" % name)
    print("rot-of-xor      : %s" % serial(name, derive_rot_of_xor))
    print("literal reading : %s" % serial(name, derive_literal))
