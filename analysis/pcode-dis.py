#!/usr/bin/env python3
"""VB6 P-code disassembler.

    pcode-dis.py <fixed-dump.exe> <ProcDscInfo-VA> [imagebase] [constpool-VA]

The opcode table comes from the `visualbasic` crate's data/opcodes.csv
(BinFlip/bn-vb6), which carries verified instruction sizes and operand formats
traced from MSVBVM60.DLL handlers. Guessing those by eye produces confident
nonsense, which is exactly why this reads a real table.

Layout facts that matter:
  * The address in an ObjectInfo method array points at the ProcDscInfo, and
    the P-code stream sits IMMEDIATELY BEFORE it:
        pcode_start = procdsc_va - wPCodeBackOffset   (u16 at +0x08)
    Decoding forward from the descriptor reads the cleanup tables instead and
    runs into filler.
  * Lead bytes 0xFB-0xFF select extended dispatch tables 1-5.

Operand formats: %1/%2/%4 literals, %a stack var (i16 EBP offset), %s constant
pool index, %l jump target, %c control index, %v vtable ref, %x external call.
"""
import csv
import struct
import sys

OPCODES_CSV = "/home/oddity/targets/opcodes.csv"
LEAD = {0xFB: 1, 0xFC: 2, 0xFD: 3, 0xFE: 4, 0xFF: 5}
OPERAND_SIZE = {"%1": 1, "%2": 2, "%4": 4, "%a": 2, "%s": 2,
                "%l": 2, "%c": 2, "%v": 4, "%x": 4}


def load_table(path=OPCODES_CSV):
    table = {}
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or len(row) < 5:
                continue
            try:
                tbl = int(row[0])
                op = int(row[1], 16)
                size = int(row[2])
            except ValueError:
                continue
            table[(tbl, op)] = {
                "size": size,
                "mnemonic": row[3],
                "operands": row[4],
                "desc": row[13] if len(row) > 13 else "",
            }
    return table


def fmt_operands(spec, data, pos, constpool):
    """Render operands and return (text, bytes_consumed)."""
    out, used = [], 0
    for tok in spec.split():
        n = OPERAND_SIZE.get(tok)
        if n is None or pos + used + n > len(data):
            break
        raw = data[pos + used:pos + used + n]
        if tok == "%1":
            out.append(f"{raw[0]:#x}")
        elif tok == "%2":
            out.append(f"{struct.unpack('<h', raw)[0]}")
        elif tok == "%4":
            out.append(f"{struct.unpack('<i', raw)[0]}")
        elif tok == "%a":
            v = struct.unpack("<h", raw)[0]
            out.append(f"var_{-v:x}" if v < 0 else f"arg_{v:x}")
        elif tok == "%s":
            idx = struct.unpack("<H", raw)[0]
            out.append(f"const[{idx:#x}]" + (f"=@{constpool + idx:08x}" if constpool else ""))
        elif tok == "%l":
            out.append(f"loc_{struct.unpack('<H', raw)[0]:#x}")
        elif tok == "%c":
            out.append(f"ctl[{struct.unpack('<H', raw)[0]:#x}]")
        elif tok in ("%v", "%x"):
            a, b = struct.unpack("<HH", raw)
            out.append(f"({a:#x},{b:#x})")
        used += n
    return ", ".join(out), used


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    path = sys.argv[1]
    proc_va = int(sys.argv[2], 0)
    base = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x400000
    constpool = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0

    data = open(path, "rb").read()
    table = load_table()

    o = proc_va - base
    obj_info, arg_size, frame_size, back, total = struct.unpack_from("<IHHHH", data, o)
    start_va = proc_va - back
    print(f"ProcDscInfo @ {proc_va:#010x}")
    print(f"  lpObjectInfo     {obj_info:#010x}")
    print(f"  wArgSize         {arg_size:#x}")
    print(f"  wFrameSize       {frame_size:#x}")
    print(f"  wPCodeBackOffset {back:#x}   -> P-code {start_va:#010x} .. {proc_va:#010x}")
    print()

    pos = start_va - base
    end = o
    while pos < end:
        va = base + pos
        b = data[pos]
        if b in LEAD and pos + 1 < end:
            tbl, op, ilen_base = LEAD[b], data[pos + 1], 2
            key = (tbl, op)
        else:
            tbl, op, ilen_base = 0, b, 1
            key = (0, b)

        info = table.get(key)
        if info is None:
            print(f"{va:08x}  {b:02x}                    ??? (table {tbl} op {op:#04x})")
            pos += 1
            continue

        opnd_pos = pos + ilen_base
        text, used = fmt_operands(info["operands"], data, opnd_pos, constpool)

        size = info["size"]
        if size > 0:
            ilen = size + (1 if tbl else 0)      # size excludes the lead byte
        elif size == -1:
            n = struct.unpack_from("<H", data, opnd_pos)[0]
            ilen = ilen_base + 2 + n
            text = f"({n} bytes)"
        else:
            ilen = ilen_base + used

        raw = data[pos:pos + ilen].hex(" ")
        line = f"{va:08x}  {raw:<22} {info['mnemonic']:<18}"
        if text:
            line += f" {text}"
        print(line)
        pos += max(ilen, 1)
    return 0


sys.exit(main())
