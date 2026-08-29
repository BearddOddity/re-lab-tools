---
name: anti-debug-reference
description: Reference for anti-debugging, anti-analysis and obfuscation techniques found in protected binaries - how each one works, how to recognise it in a disassembler, and how to defeat it. Use when a binary detects a debugger, behaves differently under analysis, resists decompilation, or when reviewing an unfamiliar protection.
---

# Anti-debug and obfuscation reference

Recognition first, then defeat. Most protections are cheap to spot once you know
the shape they make in a disassembler.

Static analysis sidesteps nearly all of this — a binary cannot detect a debugger
that is never attached. Reach for dynamic analysis only when the algorithm
genuinely cannot be read.

New findings belong in the knowledge vault (`save_pattern`, topic `anti-debug`),
not appended here.

## Debugger presence

### IsDebuggerPresent

Reads the `BeingDebugged` byte at `PEB+0x02`.

**Spot it:** a call to `kernel32!IsDebuggerPresent` feeding a conditional jump.
If the import was avoided, a direct read of `gs:[0x60]+0x02` (x64) or
`fs:[0x30]+0x02` (x86).

**Defeat:** zero `EAX` after the call, or patch the `BeingDebugged` byte once at
attach. ScyllaHide handles it.

### NtQueryInformationProcess

Asks the kernel, so patching the PEB alone does not help.

- `ProcessDebugPort` (0x07) — non-zero when debugged
- `ProcessDebugObjectHandle` (0x1E) — valid handle when debugged
- `ProcessDebugFlags` (0x1F) — **0 when debugged, 1 when not**

**Spot it:** a call to `ntdll!NtQueryInformationProcess` with second argument 7,
0x1E or 0x1F. Ghidra often shows the class as a bare integer, so search the
decompilation for the constants rather than a named enum.

**Defeat:** hook and fix the output buffer *per class*. The inverted sense of
`ProcessDebugFlags` catches people who blanket-zero the buffer — that is a
common way to get caught.

### CheckRemoteDebuggerPresent / OutputDebugString

`CheckRemoteDebuggerPresent` is a wrapper over `NtQueryInformationProcess`.
Older `OutputDebugString` tricks check whether `GetLastError` changes.

## Timing checks

Measure elapsed time across a block; a human stepping through takes far longer
than the code should.

**Spot it:** `rdtsc` (`0F 31`) twice with a subtraction, or paired
`GetTickCount` / `QueryPerformanceCounter` / `timeGetTime` calls. Look for a
comparison against a constant threshold.

**Defeat:** patch the comparison, or run past the block rather than stepping
through it. Set a breakpoint after the check instead of inside it.

Timing checks also break under emulation, which is worth remembering when a
binary works natively but fails in a sandbox.

## Exception-based tricks

- `INT 3` (`0xCC`) planted deliberately: a debugger swallows the exception, so
  the handler never runs — the binary detects the missing exception.
- `INT 2D`, `ICEBP` (`0xF1`) — behave differently when traced.
- Structured Exception Handling used for control flow: the "impossible" branch
  is where the real code lives.

**Spot it:** an SEH handler installed right before a deliberate fault, or
disassembly that appears to run into garbage.

**Defeat:** configure the debugger to pass the exception to the application.

## Anti-attach and process checks

- Scanning the process list for `ollydbg`, `x64dbg`, `ida`, `wireshark`.
- Checking the parent process — a debugger-launched process has an unexpected parent.
- `NtSetInformationThread` with `ThreadHideFromDebugger` (0x11) to detach the
  debugger silently.

**Spot it:** `CreateToolhelp32Snapshot` + `Process32First/Next` loops, or string
comparisons against tool names.

## Integrity checks

The binary hashes its own `.text` section and compares against a stored value.
Any software breakpoint (`0xCC`) changes the bytes and fails the check.

**Spot it:** a loop reading its own image base with a running checksum.

**Defeat:** use hardware breakpoints, which do not modify memory. Or patch the
comparison — but find every copy of the check first.

## Obfuscation

### Packing

Very few strings, odd section names (`UPX0`, `.aspack`, `.themida`), tiny import
table, high entropy, a tiny `.text` with a huge `.data`.

**Defeat:** `upx -d` for UPX. Otherwise dump from memory after the unpacking
stub runs — set a breakpoint at the original entry point, then dump and fix the
imports.

**Do not analyse a packed binary statically.** The decompilation is the packer's
stub, not the program, and reading it is wasted effort.

### String encryption

Strings decrypted at use, so `strings` shows nothing useful.

**Spot it:** a small function called from many places with a constant argument,
returning a pointer. That is the decryptor and the argument is an index or key.

**Defeat:** reimplement the decryptor in Python and run it over the table. Far
faster than stepping each call.

### Control-flow flattening

The function becomes a `while` loop around a `switch` on a state variable; real
basic blocks are cases, and the order is data-driven.

**Spot it:** one large switch on a variable reassigned in every case.

**Defeat:** recover the order by tracing state transitions. Symbolic execution
helps. Frequently it is faster to treat the function as a black box and study
its inputs and outputs.

### Opaque predicates and junk

Conditions that are always true but not obviously so, guarding dead branches, or
overlapping instructions that disassemble differently depending on entry offset.

**Spot it:** Ghidra showing bad disassembly or branches into the middle of
instructions.

**Defeat:** correct the function boundaries by hand. Trust the decompiler less
and read the bytes with `read_bytes`.

## Virtualisation

VMProtect, Themida and similar convert code into bytecode for a custom
interpreter. The most expensive protection to defeat.

**Spot it:** a large dispatch loop, no recognisable original code, huge
functions of arithmetic on a virtual context.

**Defeat:** realistically, attack the boundaries — inputs and outputs — rather
than the VM. Devirtualisation is a research project, not an afternoon.

## Detection order in practice

When a binary behaves differently under a debugger, check in this order:

1. `IsDebuggerPresent` / PEB read — most common by a wide margin
2. `NtQueryInformationProcess`
3. Timing checks
4. Integrity/checksum
5. Everything else

Most protected binaries stack several cheap checks rather than one strong one.
Finding the first is rarely the end.
