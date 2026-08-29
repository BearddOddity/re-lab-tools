#!/usr/bin/env python3
"""Keygen for BFCrackMe40 (Boba Fett / Lockless, 2000).

Recovered by disassembling the VB6 P-code of the Login handler at 0x402c38.

    A = Asc(first char of Name)
    B = Asc(last char of Name)
    C = Asc(second-to-last char of Name)
    X = str(A) + str(B) + str(C)          # decimal digits, concatenated

The program then computes X+1 and X-1 numerically, converts both back to
strings, and requires:

    (X-1) < serial < (X+1)                # STRING comparison, GtStr / LtStr

Because the comparison is lexicographic rather than numeric, a whole family of
serials satisfies it - which is why several different strings were accepted for
one name during black-box testing, and why guessing a "the" answer kept
failing. X itself is always in range and is the natural answer.

Company is not part of the check; it is only echoed in the success message.
"""
import sys


def serial_for(name: str) -> str:
    if len(name) < 2:
        raise ValueError("name must be at least 2 characters")
    return f"{ord(name[0])}{ord(name[-1])}{ord(name[-2])}"


def in_range(name: str, candidate: str) -> bool:
    """Reproduce the program's own check, including its string comparison."""
    x = int(serial_for(name))
    lo, hi = str(x - 1), str(x + 1)
    return lo < candidate < hi


if __name__ == "__main__":
    names = sys.argv[1:] or ["test", "abc", "abcd", "ac", "AB", "ad", "BeardedOddity"]
    for n in names:
        s = serial_for(n)
        ok = "ok" if in_range(n, s) else "OUT OF RANGE"
        print(f"{n:<16} -> {s:<14} ({ok})")
