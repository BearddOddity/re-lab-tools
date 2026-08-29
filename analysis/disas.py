#!/usr/bin/env python3
"""Disassemble a range of a fixed-up dump, where file offset == RVA.

    disas.py <file> <virtual-address> <length> [imagebase]

Ghidra's auto-analysis frequently declines to create functions in VB6 native
code, because the forms' event handlers are reached through runtime dispatch
rather than direct calls. Reading the bytes directly sidesteps that.
"""
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    path = sys.argv[1]
    va = int(sys.argv[2], 0)
    length = int(sys.argv[3], 0)
    base = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x400000

    data = open(path, "rb").read()
    off = va - base                      # holds because the dump was fixed up
    if off < 0 or off + length > len(data):
        print(f"range outside file (file is 0x{len(data):x} bytes)", file=sys.stderr)
        return 1

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    for ins in md.disasm(data[off:off + length], va):
        print(f"{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic:<8} {ins.op_str}")
    return 0


sys.exit(main())
