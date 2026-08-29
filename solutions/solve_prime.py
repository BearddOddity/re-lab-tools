#!/usr/bin/env python3
"""Recover the password for prime.exe (crackmes.one).

From the decompilation of FUN_00401617 / FUN_004015cf:

    for each input char c at index i:
        t = pow(129, c, 251)            # 129 = 0x81, 251 = 0xfb (prime)
        t ^= key[i % len(key)]          # key = "Th4t's a P455W0rD"
        out += "%02x" % t
    strcmp(out, TARGET) == 0

The character is the EXPONENT, not the base - that is the "prime numbers
properties" hint. Inverting it is a discrete log, but the input is constrained
to printable ASCII, so 95 candidates per position is faster to write and to
run than anything clever.
"""

KEY = "Th4t's a P455W0rD"
TARGET_HEX = "113e5c6eac71358d3a4727639f55f02457565ae57662a2a2727610d84646"
BASE = 129
MOD = 251

target = bytes.fromhex(TARGET_HEX)

# Build the reverse table once: pow(129, c, 251) -> c, for printable c only.
table = {}
for c in range(0x20, 0x7F):
    table.setdefault(pow(BASE, c, MOD), c)

password = []
unsolved = []
for i, tb in enumerate(target):
    wanted = tb ^ ord(KEY[i % len(KEY)])
    c = table.get(wanted)
    if c is None:
        unsolved.append(i)
        password.append("?")
    else:
        password.append(chr(c))

pw = "".join(password)
print(f"target bytes : {len(target)}  (so the password is {len(target)} chars)")
print(f"password     : {pw}")
if unsolved:
    print(f"UNSOLVED positions (no printable exponent): {unsolved}")

# Re-run the forward algorithm as the binary does, as a self-check. Getting the
# inverse right and the forward direction wrong is an easy way to produce a
# confident wrong answer.
check = "".join(
    "%02x" % (pow(BASE, ord(ch), MOD) ^ ord(KEY[i % len(KEY)]))
    for i, ch in enumerate(pw)
    if ch != "?"
)
print(f"forward check: {'MATCHES' if check == TARGET_HEX else 'MISMATCH'}")
if check != TARGET_HEX:
    print(f"  computed : {check}")
    print(f"  expected : {TARGET_HEX}")
