#!/usr/bin/env python3
"""Read the VB6 header out of a fixed-up dump.

    vbinfo.py <fixed-dump.exe> [imagebase]

Answers the question that decides the whole approach to a VB6 target: was it
compiled to native code or to P-code? Native code disassembles normally.
P-code is bytecode for the msvbvm60 interpreter and disassembling it as x86
produces confident nonsense.

Also walks the object table to list the forms and their method names, which is
how you find the event handler holding the check without guessing.
"""
import struct
import sys


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def cstr(d, o, limit=64):
    end = d.find(b"\x00", o)
    if end < 0 or end - o > limit:
        end = o + limit
    return d[o:end].decode("latin-1", "replace")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    base = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x400000
    d = open(path, "rb").read()

    def rva(va):
        """File offset for a virtual address; the dump was fixed so they match."""
        return va - base

    sig = d.find(b"VB5!")
    if sig < 0:
        print("no VB5! header - not a VB5/VB6 binary")
        return 1
    print(f"VB header at 0x{sig + base:08x}")
    print(f"  runtime build   : {u16(d, sig + 4)}")
    print(f"  lang dll        : {cstr(d, sig + 6, 14)}")
    print(f"  LCID            : 0x{u32(d, sig + 0x24):x}")
    print(f"  lpSubMain       : 0x{u32(d, sig + 0x2c):08x}")

    proj = u32(d, sig + 0x30)
    print(f"  lpProjectData   : 0x{proj:08x}")

    p = rva(proj)
    version = u32(d, p + 0x00)
    obj_table = u32(d, p + 0x04)
    code_start = u32(d, p + 0x0C)
    code_end = u32(d, p + 0x10)
    native = u32(d, p + 0x20)
    print("\nProjectInfo")
    print(f"  version         : 0x{version:x}")
    print(f"  lpObjectTable   : 0x{obj_table:08x}")
    print(f"  code start/end  : 0x{code_start:08x} - 0x{code_end:08x}")
    print(f"  lpNativeCode    : 0x{native:08x}   -> {'NATIVE code' if native else 'P-CODE'}")

    # Object table: forms and modules, each with a name and a method list.
    t = rva(obj_table)
    obj_count = u32(d, t + 0x10)
    obj_array = u32(d, t + 0x14)
    proj_name_ptr = u32(d, t + 0x18)
    print("\nObjectTable")
    print(f"  project name    : {cstr(d, rva(proj_name_ptr))}")
    print(f"  object count    : {obj_count}")

    if obj_count > 64:
        print("  (implausible count - stopping rather than printing noise)")
        return 0

    a = rva(obj_array)
    for i in range(obj_count):
        o = a + i * 0x30
        name_ptr = u32(d, o + 0x10)
        method_count = u32(d, o + 0x14)
        methods_ptr = u32(d, o + 0x18)
        try:
            name = cstr(d, rva(name_ptr))
        except Exception:
            name = "?"
        print(f"\n  object {i}: {name}   ({method_count} methods)")
        if 0 < method_count <= 200 and methods_ptr:
            m = rva(methods_ptr)
            for j in range(method_count):
                try:
                    addr = u32(d, m + j * 4)
                except Exception:
                    break
                if base <= addr < base + len(d):
                    print(f"      method[{j:2}] -> 0x{addr:08x}")
    return 0


sys.exit(main())
