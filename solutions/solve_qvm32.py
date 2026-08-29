#!/usr/bin/env python3
"""Solver for `qvm32` (crackmes.one) - password: iWasteMyTime

    $ ./qvm32
    ENTER PASS : iWasteMyTime
    WIN

The binary is a 32-bit Linux ELF, 56 KB, with a single 46 KB `main`, eight
imports (write/read/rand/malloc/free/exit), 8 bytes of .rodata and no useful
strings. That shape - almost all code, almost no data - is a bytecode VM, and it
is: the dispatch fetch is

    mov   eax, [0x8055504]                  ; VM program counter
    movzx eax, byte [eax + 0x8054130]       ; fetch opcode
    cmp   eax, 0xee                         ; halt
    je    ...

The interpreter body is written in mixed boolean arithmetic - every add is a
chain of and/or/not/shl - so reading it is not the cheap path. Emulating it is:
six libc calls, one call site each, so stubbing those and running the real code
gives exact behaviour.

WHAT MAKES IT SOLVABLE

The x86 control flow is constant regardless of the password, because it is an
interpreter - the loop runs the same way whatever the bytecode does. Comparing
x86 traces for two wrong passwords therefore shows no divergence, which invites
the wrong conclusion that the check is branchless. It is not. The branching
happens one level up, in the VM, and it only becomes visible once a password is
correct far enough to get past the first comparison.

So the oracle is the number of VM instructions executed, not x86 instructions:

    wrong first byte   366 VM steps
    correct first byte 368 VM steps

Each correct byte buys a few more steps, which makes it a straightforward
byte-at-a-time recovery over 12 positions and ~95 candidates each.

The check itself is one comparison per byte: `password[i] ^ K[i]` against a
constant, where K[0] = 0x13. The VM reads exactly 12 bytes, so a 13th character
is ignored - "iWasteMyTimee" also wins.
"""
import ctypes
import struct
import sys

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32, Uc, UcError
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

BIN = sys.argv[1] if len(sys.argv) > 1 else "qvm32"

MAIN = 0x08048570
FETCH = 0x08048D60          # cmp eax, 0xee - one hit per VM instruction
PLT = {
    0x08048410: "malloc", 0x08048420: "rand", 0x08048430: "read",
    0x08048440: "write", 0x08048450: "exit", 0x08048460: "free",
}
STACK, STACK_SZ = 0x7F000000, 0x100000
HEAP, HEAP_SZ = 0x20000000, 0x200000

libc = ctypes.CDLL("libc.so.6")
libc.rand.restype = ctypes.c_int


class Emu:
    def __init__(self, password):
        self.password = password if isinstance(password, bytes) else password.encode()
        self.out = b""
        self.vm_steps = 0
        self.brk = HEAP

        # The program never seeds rand(), so a real process always starts from
        # glibc's default seed of 1. Borrowing the host's generator means the
        # host's sequence position carries over between emulations unless it is
        # reset here. Without this every run after the first builds a different
        # table and quietly stops matching the real binary - which produced a
        # confident but wrong key model before it was noticed.
        libc.srand(1)

        self.uc = uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self._load()
        uc.mem_map(STACK, STACK_SZ)
        uc.mem_map(HEAP, HEAP_SZ)
        sp = STACK + STACK_SZ - 0x1000
        uc.mem_write(sp, struct.pack("<IIII", 0xDEADBEEF, 1, sp + 0x100, sp + 0x200))
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.hook_add(UC_HOOK_CODE, self._code)
        uc.hook_add(UC_HOOK_CODE, self._vm_tick, begin=FETCH, end=FETCH)

    def _load(self):
        data = open(BIN, "rb").read()
        e_phoff, = struct.unpack_from("<I", data, 0x1C)
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x2A)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            (p_type, p_offset, p_vaddr, _, p_filesz,
             p_memsz, _, _) = struct.unpack_from("<8I", data, off)
            if p_type != 1:                     # PT_LOAD
                continue
            base = p_vaddr & ~0xFFF
            size = ((p_vaddr + p_memsz - base) + 0xFFF) & ~0xFFF
            self.uc.mem_map(base, size)
            self.uc.mem_write(p_vaddr, data[p_offset:p_offset + p_filesz])

    def _vm_tick(self, uc, address, size, _):
        self.vm_steps += 1

    def _arg(self, n):
        esp = self.uc.reg_read(UC_X86_REG_ESP)
        return struct.unpack("<I", self.uc.mem_read(esp + 4 + 4 * n, 4))[0]

    def _ret(self, value):
        uc = self.uc
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
        uc.reg_write(UC_X86_REG_ESP, esp + 4)
        uc.reg_write(UC_X86_REG_EAX, value & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_EIP, ret)

    def _code(self, uc, address, size, _):
        name = PLT.get(address)
        if not name:
            return
        if name == "malloc":
            n = self._arg(0)
            ptr, self.brk = self.brk, (self.brk + n + 0xFFF) & ~0xFFF
            self._ret(ptr)
        elif name == "rand":
            self._ret(libc.rand())
        elif name == "read":
            buf, n = self._arg(1), self._arg(2)
            data = self.password[:n]
            uc.mem_write(buf, data)
            self._ret(len(data))
        elif name == "write":
            buf, n = self._arg(1), self._arg(2)
            self.out += bytes(uc.mem_read(buf, n))
            self._ret(n)
        elif name == "free":
            self._ret(0)
        elif name == "exit":
            uc.emu_stop()

    def run(self):
        try:
            self.uc.emu_start(MAIN, 0, 0, 0)
        except UcError:
            pass
        return self


def attempt(pw):
    e = Emu(pw).run()
    return e.vm_steps, e.out


def solve(length=12, candidates=range(0x20, 0x7F)):
    """Recover the password one byte at a time, using VM step count as the oracle."""
    prefix = b""
    for _ in range(length):
        best, best_steps = None, -1
        for c in candidates:
            steps, out = attempt(prefix + bytes([c]))
            if b"WIN" in out:
                return prefix + bytes([c])
            if steps > best_steps:
                best, best_steps = c, steps
        if best is None:
            break
        prefix += bytes([best])
    return prefix


if __name__ == "__main__":
    # Confirmed against the real binary: prints WIN.
    steps, out = attempt(b"iWasteMyTime")
    assert b"WIN" in out, out
    assert b"WIN" not in attempt(b"iWasteMyTim")[1]      # one short
    assert b"WIN" not in attempt(b"IWasteMyTime")[1]     # case matters
    print("self-check ok")
    print("recovered:", solve().decode())
