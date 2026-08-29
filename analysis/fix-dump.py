#!/usr/bin/env python3
"""Turn a process memory dump of a PE into something a disassembler can map.

    fix-dump.py <dump.bin> <out.exe>

In a file on disk, a section's bytes live at PointerToRawData. In memory they
live at VirtualAddress. A dump is the memory view, so loading it with the
original headers puts every section at the wrong offset and the disassembly is
garbage. Setting PointerToRawData = VirtualAddress (and the raw size to the
virtual size) makes file offsets and RVAs agree, which is exactly what a dump
needs.

This produces a file for *analysis*, not for running: the import table still
holds resolved addresses rather than thunks, so it will not load as a program.
"""
import sys

import pefile


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    src, dst = sys.argv[1], sys.argv[2]

    data = bytearray(open(src, "rb").read())
    pe = pefile.PE(data=bytes(data))

    align = pe.OPTIONAL_HEADER.SectionAlignment
    print(f"{'section':<12} {'vaddr':>10} {'vsize':>10}  {'old raw':>10} -> {'new raw':>10}")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        vsize = s.Misc_VirtualSize
        # Round the virtual size up to section alignment; a dump is page-granular.
        raw = (vsize + align - 1) // align * align
        print(f"{name:<12} 0x{s.VirtualAddress:08x} 0x{vsize:08x}  "
              f"0x{s.PointerToRawData:08x} -> 0x{s.VirtualAddress:08x}")
        s.PointerToRawData = s.VirtualAddress
        s.SizeOfRawData = min(raw, len(data) - s.VirtualAddress) if s.VirtualAddress < len(data) else 0

    out = pe.write()
    open(dst, "wb").write(bytes(out))
    print(f"\nwrote {len(out)} bytes to {dst}")
    print("Load this for analysis only - the IAT holds resolved addresses, so it")
    print("will not run.")
    return 0


sys.exit(main())
