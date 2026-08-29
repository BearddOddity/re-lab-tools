---
name: crackme-workflow
description: A repeatable method for solving a crackme or reversing an unfamiliar binary - triage, locating the check, understanding it, deriving a key or patch, verifying, and recording the result. Use when starting work on a crackme, keygen-me, licence check, or any binary whose validation logic needs to be understood.
---

# Crackme workflow

A method, not a script. The order matters: each phase narrows where to look, so
skipping ahead usually costs more time than it saves.

## 0. Snapshot first

```powershell
D:\re-lab\snapshot.ps1 -Name "before-<target>"
```

Before the risky thing, not after.

Put the target in `D:\re-lab-share\`; it is `/mnt/share/<name>` inside the lab.

## 1. Triage — before opening a disassembler

Cheap, and it often decides everything that follows.

```bash
re-triage /mnt/share/target.exe
```

One command covering identity (size, md5, sha256, entropy), PE header (arch,
entry point, build date), per-section entropy with packer detection, imports
filtered to the ones that matter for a crackme, and strings filtered to likely
leads. It ends by telling you the `import_binary` call to run next.

Read the output asking:

- **Packed?** Very few strings, odd section names (`UPX0`, `.aspack`), tiny
  import table, huge entropy. Try `upx -d` first; a packed binary decompiles
  into nonsense and wastes hours.
- **What language?** Rust/Go/.NET binaries have distinctive runtimes and want
  different tools than a C binary.
- **Any gift strings?** "Wrong serial", "Congratulations" — these are the
  fastest route to the check.

Record the hash now: `sha256sum`. It identifies the exact target later.

## 2. Load and orient

```
import_binary(path="/mnt/share/target.exe", analyze=True)
get_program_info()
list_imports()
```

Imports tell you what the binary *can* do. For a crackme:

- `GetVolumeInformation`, `GetComputerName` → machine-bound key
- `IsDebuggerPresent`, `NtQueryInformationProcess` → anti-debug present
- `strcmp`, `strlen`, `wsprintf` → string-comparison check
- crypto imports, or none at all → likely hand-rolled maths

## 3. Find the check

Fastest first:

1. **String cross-reference.** Find the failure message, then `get_xrefs_to` its
   address. The function referencing it almost always *is* the check.
2. **Input function.** Cross-reference `scanf`, `GetDlgItemText`, `fgets`.
3. **Byte pattern.** `search_bytes` for a distinctive constant seen in strings
   or a known magic value.

Rename it the moment you find it: `rename_function(..., new_name="check_serial")`.

## 4. Understand it

```
decompile_function(name="check_serial")
```

Read for the *shape* before the detail:

- Where does it return true?
- What is compared against what?
- Is the serial transformed, or compared literally?
- Is there a loop over characters? That is usually the key derivation.

Then improve the decompilation rather than fighting it. Set the prototype, name
the variables, fix the types. Re-decompile. Most "obfuscated" output is just
wrong types.

Use `read_bytes` when the decompiler hides something — embedded key tables and
magic constants are often clearer as raw bytes.

## 5. Derive the answer

Three outcomes, in order of preference:

**Keygen** — you understood the algorithm and can generate valid serials. The
real solution. Write it as a small Python script; `capstone`, `pefile` and
`lief` are installed.

**Patch** — you bypassed the check without understanding it. Legitimate when the
goal is access, weaker as a solution.

```
patch_bytes(address="0x401256", bytes_hex="9090")   # keep the returned original bytes
export_program(path="/mnt/share/patched.exe", format="binary")
```

**Brute force** — last resort, and usually a sign the algorithm was not
understood.

## 6. Verify

A solution that has not run is a hypothesis.

```bash
re-run /mnt/share/target.exe
re-run /mnt/share/target.exe MyName ABC-123     # arguments pass straight through
```

`re-run` reads the PE header and picks the 32- or 64-bit Wine prefix itself,
creating it on first use. Getting that wrong by hand is the usual cause of a
crackme that "just exits" — most are 32-bit, and a 64-bit prefix cannot run
them. It refuses non-PE files rather than handing them to Wine.

Test the failure case too — a keygen that accepts everything proves nothing.

Only run challenges from a source you trust. Wine executes with your user's
privileges in a lab that shares the network. Unknown provenance goes in a
Hyper-V VM, not here.

## 7. Record it

```
log_solved_problem(
  category="re",
  name="<target>",
  summary="<one line: the technique that cracked it>",
  technique="<how the check worked and how it was defeated>",
  fullNotes="<address of the check, the algorithm, the keygen, dead ends>"
)
```

Write down the **dead ends** as well. Knowing what did not work is worth as much
as the solution when the next binary looks similar.

If the target used a reusable protection, log that separately as a pattern so it
compounds:

```
save_pattern(category="re", topic="anti-debug", technique="…", details="…")
```

## Getting stuck

- **Decompilation is nonsense** → packed, or wrong types. Check entropy and
  section names before assuming obfuscation.
- **Check found but maths is opaque** → work a concrete example by hand. Take a
  known input, trace the bytes, and the pattern usually appears.
- **Cannot find the check** → the comparison may not be a string compare. Look
  for checksums over the input, or a table lookup.
- **Anti-debug fires** → see the `anti-debug` notes in the knowledge vault;
  static analysis avoids most of it entirely.
