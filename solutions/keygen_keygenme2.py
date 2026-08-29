#!/usr/bin/env python3
"""Keygen for "Keygen #2 by Nicohogtag" (crackmes.one, 2013, MinGW g++ 32-bit).

sha256 b279b6e034480c48890eb147b3eded42fbc51b43d604156492117bfa436a5a42

The whole check is inline in main() at 0x401390. The binary shipped with its
STABS debug sections intact, which name every local:

    user   char[8]  ebp-8      serial int  ebp-12     num int  ebp-16
    a      char     ebp-17     b      int  ebp-24     c   int  ebp-28
    i      int      ebp-32

    num = b = 0; b = 0x80899; c = 7
    for (i = 0; i <= 9; i++) { a = user[i]; num += a; b += num; }
    c *= (num + b);
    c *= (c - num) + 13 * (b / 2);
    if (abs(c) == serial) win;

The loop runs ten times over an eight-byte array. user[8] and user[9] are the
low two bytes of the SAVED EBP, so the expected serial depends on the stack
address of main's frame - the author's off-by-two, not a deliberate design.

Under the lab's 32-bit Wine prefix that saved EBP is 0x0066ff30, giving tail
bytes (0x30, 0xff); 0xff is read as a *signed* char, so it contributes -1.
Verified stable across separate processes. On a machine whose stack lands
elsewhere, re-read it: run to the system("pause") at the end, find the username
on the stack, and take the dword at &user[8].

A name of ten or more characters overwrites both bytes itself, so those serials
are independent of the stack address and portable anywhere.
"""
import ctypes
import sys

SAVED_EBP_TAIL = (0x30, 0xFF)


def i32(v):
    return ctypes.c_int32(v).value


def frame_bytes(user, tail=SAVED_EBP_TAIL):
    """The ten bytes the loop actually reads."""
    buf = [0] * 8 + list(tail)      # char user[8] = {0}, then the saved EBP
    name = user.encode()
    for i, ch in enumerate(name[:10]):
        buf[i] = ch
    if len(name) < 10:              # cin >> writes the terminating NUL too
        buf[len(name)] = 0
    return buf


def serial_for(user, tail=SAVED_EBP_TAIL):
    buf = frame_bytes(user, tail)
    num, b = 0, 0x80899
    for i in range(10):
        ch = buf[i] - 256 if buf[i] > 127 else buf[i]    # signed char
        num = i32(num + ch)
        b = i32(b + num)
    c = i32(7 * i32(num + b))
    q = int(b / 2) if b >= 0 else -int(-b // 2)          # C truncates toward zero
    c = i32(c * i32(i32(c - num) + i32(13 * q)))
    return abs(c)


def _self_check():
    # Read out of the live process at the system("pause"): user "ZQXWVUT" gave
    # num=648, b=530803, c=744578194 with saved ebp 0x0066ff30.
    assert serial_for("ZQXWVUT") == 744578194
    # Confirmed against the binary under Wine, one process per case.
    for name, want in [("ODDITY", 742880226), ("a", 382602),
                       ("test123", 687173614), ("ABCDEFGH", 410317090),
                       ("ABCDEFGHI", 1812347936), ("ABCDEFGHIJ", 1915785268)]:
        assert serial_for(name) == want, name
    print("self-check ok")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _self_check()
        print("usage: keygen_keygenme2.py <username>")
    else:
        name = sys.argv[1]
        print(f"username : {name}")
        print(f"serial   : {serial_for(name)}")
