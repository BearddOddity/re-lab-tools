# re-lab-tools

Tooling for the isolated Kali reverse-engineering lab. The *knowledge* lives in
the `knowledge-vault` repo; this is the code that knowledge describes.

Everything here runs inside the lab, not on Windows. Install with
`./install.sh` (run it in the lab as root).

## lab/

Operating the lab itself.

| Script | What |
|---|---|
| `re-desktop` | XFCE in one window via Xephyr; also `re-desktop-stop` |
| `re-ctl` | GUI control surface — screenshot, click, type, focus, run |
| `re-triage` | Pre-analysis report: hashes, entropy, PE sections, packer detection, imports, dynamically-resolved APIs, likely strings |
| `re-run` | Run a Windows PE under Wine, picking the 32/64-bit prefix from the header |
| `run-target` | Same but **blocks**, for GUI targets that must stay alive |
| `re-clipsync` | Shares the clipboard between the nested desktop and Windows |
| `tmog` | Launches Task Manager TMOG with Wayland stripped and Qt pinned to xcb |
| `ghidra-mcp-run` | Launch Ghidra in foreground mode |
| `ghidra-mcp-start` | Cold start of the whole Ghidra MCP stack to a verified server |

## analysis/

| Script | What |
|---|---|
| `pcode-dis.py` | **VB6 P-code disassembler.** Needs `opcodes.csv` from the `visualbasic` crate — see below |
| `vbinfo.py` | VB5/VB6 header: native vs P-code, object table, code range |
| `disas.py` | x86-32 disassembly of a fixed-up dump, where file offset == RVA |
| `fix-dump.py` | Repair a memory dump's section headers so a disassembler maps it |
| `dump-wine-image.py` | Dump a PE image out of a running Wine process via `/proc/pid/mem` |
| `mem-strings.py` | UTF-16LE strings from a live process, with addresses |
| `catch-vbastrcmp` | Break on `msvbvm60!__vbaStrCmp` and log both arguments |
| `ApplyXbSymbols.java` | Ghidra script — applies XbSymbolDatabase output (`NAME = 0xADDR`) to the open program |
| `ParseXboxHeaders.java` | Ghidra script — parses the flattened Xbox SDK header into data types, and writes a reusable `.gdt` |
| `ApplyXboxSignatures.java` | Ghidra script — gives the named SDK functions their real prototypes |
| `BuildFidDatabase.java` | Ghidra script — builds a Function ID (`.fidb`) database from a program's named functions |
| `DumpFunctionHashes.java` | Ghidra script — dumps every function's FID hash, for cross-binary comparison |
| `WalkMsvcRtti.java` | Ghidra script — walks MSVC RTTI to vtables and names virtual functions |
| `ExportAnalysis.java` | Ghidra script — exports names, prototypes and labels as diffable text |
| `ApplyAnalysis.java` | Ghidra script — re-applies an export to a freshly imported program |
| `NameVtableStorers.java` | Ghidra script — names constructors/destructors by the vtable pointer they store |
| `ProximityCluster.java` | Ghidra script — infers class membership from neighbouring functions (93% accurate) |
| `ProximityValidate.java` | Ghidra script — measures that heuristic against functions whose class is known |
| `CallGraphAffiliate.java` | Ghidra script — infers class from unanimous callers. **81% — measured and rejected** |
| `CallGraphValidate.java` | Ghidra script — the accuracy check that rejected it |
| `DecompileUnnamed.java` | Ghidra script — batch-decompiles the largest unnamed functions with call context |
| `DecompileList.java` | Ghidra script — batch-decompiles a given list of addresses |
| `NameByStringXref.java` | Ghidra script — names functions from the string constants they reference |
| `ForceRename.java` | Ghidra script — renames unconditionally; the only way to back out a bad name |
| `function-queue.py` | Works through unnamed game functions in batches, keeping state |
| `classify-shared-functions.py` | Splits a binary's functions into shared library/engine code and code unique to it |

### pcode-dis.py needs the opcode table

Not vendored here — it is someone else's research and carries its own
attribution. Fetch it:

```bash
curl -sL -o /tmp/vb.crate https://static.crates.io/crates/visualbasic/visualbasic-0.1.0.crate
tar xzf /tmp/vb.crate -C /tmp
cp /tmp/visualbasic-0.1.0/data/opcodes.csv /home/oddity/targets/opcodes.csv
```

1536 entries with verified instruction sizes and operand formats traced from
MSVBVM60.DLL. Original P-code research: **MrUnleaded**, **Moogman**,
**Napalm**; packaged by the `visualbasic` crate / `BinFlip/bn-vb6`.

## mcp/

`lab_mcp.py` — MCP server exposing the above as tools, so an agent can drive
the lab directly. Runs inside the lab, which is the point: commands sent
through PowerShell → `wsl.exe` → bash get Unix paths rewritten into Windows
ones and shell variables silently emptied.

```powershell
claude mcp add re-lab --scope user -- wsl.exe -d kali-linux -- /opt/re-lab-mcp/venv/bin/python /opt/re-lab-mcp/lab_mcp.py
```

Needs `mcp<2` in a venv at `/opt/re-lab-mcp/venv` — `FastMCP` was renamed in 2.x.

24 tools in five groups:

| Group | Tools |
|---|---|
| Shell | `lab_exec`, `lab_exec_root`, `lab_kill` |
| RE toolchain | `lab_triage`, `lab_strings`, `lab_r2`, `lab_disas`, `lab_hexdump`, `lab_wine_run`, `lab_python` |
| VB6 | `lab_vbinfo`, `lab_pcode_dis`, `lab_fetch_pcode_table` |
| Live process | `lab_run_target`, `lab_mem_strings`, `lab_dump_memory`, `lab_fix_dump` |
| GUI | `lab_windows`, `lab_window_tree`, `lab_screenshot`, `lab_click`, `lab_type`, `lab_key`, `lab_focus` |

Ghidra is a separate MCP (`ghidra`, 37 tools) because it talks to a plugin
inside a running Ghidra rather than to a shell. The two are meant to be used
together — `lab_triage` and `lab_r2` to find out what the file is, Ghidra once
that is known.

**Run `install.sh` before using the MCP.** `lab_vbinfo`, `lab_disas`,
`lab_fix_dump` and `lab_pcode_dis` shell out to `/usr/local/bin/*.py`. In a lab
where those scripts were only ever copied into a working directory, every one of
those tools answers "No such file or directory" — which reads as a broken MCP
rather than a missing install.

## skills/

The Claude Code skills written alongside this tooling. They are the operating
knowledge that `provision/rebuild-lab.sh` cannot restore — the script brings the
lab back, these describe how to drive it and what has already gone wrong.

| Skill | Covers |
|---|---|
| `re-lab-ops` | Running the lab: the desktop, `re-ctl`, the MCP tool inventory, snapshots, and the traps that have cost real time |
| `ghidra-mcp-usage` | Driving Ghidra through its MCP — loading a binary, picking the right tool, annotating as you go |
| `crackme-workflow` | The order to work a crackme in: triage, locate the check, understand it, derive, verify, record |
| `anti-debug-reference` | Anti-debug and obfuscation techniques, how each looks in a disassembler, and how to defeat it |

Install by copying into `~/.claude/skills/` on the machine running Claude Code
(they live on the Windows side, not in the lab):

```powershell
Copy-Item D:
e-lab-tools\skills\* $env:USERPROFILE\.claude\skills\ -Recurse -Force
```

## Xbox / XBE work

The lab can load Xbox executables. `ghidra-xbe` (Matt Borgerson's XBE loader) is
installed into `~/.config/ghidra/<ver>/Extensions`; it ships built for Ghidra
12.0.3 and its `extension.properties` version must be edited to match the
installed Ghidra or the extension is silently ignored. Patched to 12.1.3 it
loads and imports XBEs correctly - verified by importing a game XBE headless and
seeing `Using Loader: Xbox Executable Format (XBE)`.

`XbSymbolDatabase` (RadWolfie/jarupxx/PatrickvL, OOVPA signatures originally by
Caustik) identifies Xbox SDK functions and globals by signature. It ships a
prebuilt `linux_x64/bin/XbSymbolDatabaseCLI` that needs no compilation:

```bash
XbSymbolDatabaseCLI default.xbe > symbols.txt     # "NAME = 0xADDR" per line
```

Apply the result with `analysis/ApplyXbSymbols.java`, run headless so the GUI
does not hold the project:

```bash
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript ApplyXbSymbols.java symbols.txt
```

A signature match is worth less than a name a person chose, so the script leaves
any non-default function name alone and attaches the SDK name as a secondary
label instead of overwriting it.

### Xbox SDK data types

Ghidra ships `win32` type archives and nothing for Xbox, so XAPI and D3D8 calls
decompile as `undefined4 param_1` with no calling convention. The
`xbox-includes` project fixes that, and its own Makefile does the hard part -
Ghidra's C parser is not a full preprocessor, so feed it one flat file rather
than fighting include paths:

```bash
gcc -o xbox.h -x c -P -E -Iinclude xbox.cpp     # ~7k lines, no includes left
```

GCC cannot COMPILE the result - `__stdcall` is an MSVC keyword - but that does
not matter and the error is not a problem to fix: Ghidra's parser understands
those annotations, and they are what carries the calling convention across.

Then, in order:

```bash
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript ParseXboxHeaders.java xbox.h xbox_sdk.gdt
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript ApplyXboxSignatures.java symbols.txt
```

The second step is the one that pays. XbSymbolDatabase says *which* function an
address is; the headers say what its arguments are. Either alone changes little
- a name still decompiles with `undefined4` parameters, and a signature with no
address has nothing to attach to. Joined, a function goes from

    undefined4 FUN_0035d900(undefined4 param_1, undefined4 param_2)

to

    void __fastcall D3D8__D3DDevice_SetRenderState_Simple(DWORD Method, DWORD Value)

Measured on X-Men Legends: 2,084 types parsed, program types 97 -> 2,161, and
142 of 344 symbols got real prototypes. The rest are data symbols (67) or
internal SDK functions that no public header declares (129).

### Function ID (FID) across titles from the same SDK

Ghidra ships the FunctionID engine but **no `.fidb` data at all**, and the
normal way to populate one is a GUI dialog whose worker
(`FidServiceLibraryIngest`) is package-private and unreachable from a script.
`analysis/BuildFidDatabase.java` uses the public `FidDB` API instead, which also
makes the ingest filter explicit: only functions with real names are stored,
because a `FUN_` hash can never usefully name anything.

```bash
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts     -postScript BuildFidDatabase.java out.fidb <LibName> <Version> <Variant>
```

**Check the SDK build before expecting cross-title matches.** An XBE records
every linked library and its build in its header, so this is a fact to read, not
a guess:

| offset | field |
|---|---|
| `0x104` | `dwBaseAddr` |
| `0x160` | `dwLibraryVersions` (count) |
| `0x164` | `dwLibraryVersionsAddr` |

Each entry is 16 bytes: `char szName[8]; u16 major; u16 minor; u16 build; u16 flags`.
The header region maps 1:1 from file offset 0, so `file_offset = addr - base`.

X-Men Legends and X-Men Legends II both report **XDK 5849 for every library**,
including `LIBCMT` and `LIBCPMT` - the C and C++ runtimes are statically linked
and byte-identical between them. That is what makes FID worth building here: a
match is not a guess when the library code is literally the same bytes.

**What FID cannot do here.** It transfers names that already exist; it does not
invent them. There is no source of MSVC CRT names in this toolchain - no XDK
`.lib` files, and Ghidra ships no MSVC FID data - so the thousands of statically
linked CRT/STL functions stay unnamed. FID moves the ~671 known names to other
XDK 5849 titles, which is worth having and is not the same as solving the
unnamed-function problem.

### Reaching non-virtual functions

RTTI names virtual functions and nothing else, so once the vtables are walked
the naming stalls. Constructors and destructors are the way back in: MSVC writes
the class vtable pointer into the object, `mov [ecx], offset SomeClass::vftable`,
and those functions are not virtual.

```bash
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript NameVtableStorers.java
```

634 functions in X-Men Legends, 1,153 in Legends II.

**Named `ctor_or_dtor`, not `ctor`.** MSVC frequently shares code between
constructor and destructor, and a function storing a vtable may be a factory, so
naming it a constructor would be a guess presented as a fact.

**When a function stores several vtables, the last one wins.** A derived
constructor usually has its base constructors inlined, so base vtables are
stored first and the class's own last - the store at the highest instruction
address names the function. 92 of the 634 stored more than one.

### Statically linked libraries you can name exactly

A game binary usually contains third-party libraries whose names are public. In
X-Men Legends: **zlib 1.1.3** (`inflate 1.1.3 Copyright 1995-1998 Mark Adler`)
and **TinyXML** (`TiXmlDocument`, `TiXmlElement`, `TiXmlAttribute` as RTTI
classes). Those are exact identifications, not inference.

`NameByStringXref.java` names a function from a string it references - a rule
file of `name<TAB>literal`. It reaches what RTTI and proximity cannot:
non-virtual, non-member code with no useful neighbours.

**It works less often than it looks like it should.** zlib keeps its diagnostics
in a `z_errmsg[]` table that several functions index, so `"invalid
literal/length code"` was referenced by four functions and named none - the
reference cannot say which one owns it. Of ten zlib rules, one named a function
and seven were ambiguous. The script reports ambiguity rather than picking a
winner.

The lesson generalises: a string identifies a function only when the compiler
put it in that function's code path, not in a shared table.

### Decompiling the remainder

Once the automatic sources are spent, what is left needs reading. Batch
decompilation makes that practical - the expensive part happens once, unattended,
and each entry carries its callers and callees, which usually identify a function
faster than its body does.

```bash
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts     -postScript DecompileUnnamed.java out.c 12 600     # 12 largest over 600 bytes
analyzeHeadless ... -postScript DecompileList.java addrs.txt out.c
```

**Target the game bucket, not just "largest".** The three biggest unknowns in
this binary turned out to be a bit-stream decoder - zlib, library code nobody
needs named. Filtering by the classification first put real gameplay functions
at the top instead.

Name from evidence and claim no more than that. `FUN_00062f10` copies a string,
scans for a `%END%` marker and pulls replacements from the resource manager: it
is `ExpandTextMacros_PercentEnd`. Its callers are `CBlock` virtuals, but `this`
being a `CBlock` is inference, so no class prefix was claimed.

### A queue for the functions only reading will identify

Automatic naming runs out. What is left needs a person to read it, which is slow
and open-ended - so it wants a queue with state rather than a session that starts
from nothing and re-reads what it already read.

```bash
analysis/function-queue.py status
analysis/function-queue.py next -n 8      # decompile the next batch with context
analysis/function-queue.py record names.txt
```

Each packet carries callers, callees, size and classification bucket alongside
the decompilation, because the context usually settles a function faster than its
body does - "called by CCEPowerup::vfunc4, calls GetScriptEngine" is often enough
on its own. Largest first: the big functions are the systems everything else
hangs off.

`record` marks the whole batch reviewed, named or not. A function that was looked
at and could not be identified must not return to the top of the queue on the
next run.

**Keep a way to back out a name.** `ApplyXbSymbols` refuses to overwrite an
existing name, which is correct for importing and useless for correcting a
mistake. `ForceRename.java` overwrites, and restores a true default name by
clearing it rather than writing the `FUN_` text - setting that literally leaves a
user-defined symbol that merely looks default.

### Measure a heuristic before letting it name anything

Three inference heuristics were tried on the functions RTTI cannot reach. Each
was validated the same way - apply it to functions whose class IS known and see
how often it agrees - because otherwise the output is an unmeasured guess that
everything downstream will trust.

| heuristic | accuracy | assigned | verdict |
|---|---|---|---|
| Proximity - unnamed function between two of the same class | **93%** | 706 + 1,125 | applied |
| Call graph - unanimous named callers | **81%** | 241 | **rejected** |
| Alchemy `ig*` metaclass records | n/a | ~30 | not worth it |

Call-graph propagation was rejected on the measurement, not on a feeling: one
name in five would be wrong. Tightening it did not rescue it either - requiring
3 callers gave 79% and 4 gave 83%, on shrinking samples. Some heuristics are
simply weak, and the check is what tells you which.

The `ig*` metaclass route looked promising - 842 name strings - but only 189 are
referenced by a pointer at all and only 30 of those have a function pointer
nearby. The structure is there (`igMetaObject` appears) but pinning down the
record layout needs Alchemy documentation.

Names from an inference say so: `Class::near_<addr>` for proximity, never
something that reads like a real method name.

### Keep the analysis in git, not the project

A Ghidra project is an opaque binary - 465 MB here across five programs, with
single files up to 98 MB. It cannot be diffed, reviewed in a pull request, or
merged when two people work at once, and it is regenerable from the executable
plus these scripts. What is worth versioning is the analysis, and that is text:

```bash
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript ExportAnalysis.java analysis.txt
# ... later, against a freshly imported binary
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript ApplyAnalysis.java analysis.txt
```

For X-Men Legends that is 4,560 functions with prototypes and calling
conventions plus 6,856 labels - **636 KB instead of 465 MB**, and a pull request
shows exactly which functions gained names.

The export records the program's SHA-256 and the apply side refuses to run
against a different binary. Names are applied by address, so running an export
against the wrong build would not fail - it would silently produce a program
full of confident, wrong labels. Verified by pointing one game's export at
another game's program and watching it refuse.

### RTTI is the biggest single source of names

Ghidra's RTTI analyzer is tied to PE, so on an XBE it never runs - and the
binaries are full of it. MSVC RTTI has a fixed layout, so walking it by hand is
straightforward:

    TypeDescriptor            +0x00 vftable, +0x04 spare, +0x08 ".?AVFoo@@"
    RTTICompleteObjectLocator +0x00 signature(0), +0x0C TypeDescriptor*
    vtable                    the COL pointer sits at vtable[-1]

Find the name string, step back 8 to the descriptor, find what points at it,
step back 0x0C to a candidate locator, find what points at THAT, and the next
dword starts the vtable.

```bash
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript WalkMsvcRtti.java
```

On X-Men Legends: 873 classes, 743 vtables, 55,832 slots walked.

| | before | after |
|---|---|---|
| named functions | 714 | **4,475** |
| total functions | 14,824 | **17,308** |

Six times the names, and 2,484 functions that analysis had never found at all -
vtable targets that were never recognised as code.

**Index once, not per class.** The first version scanned all of memory to answer
"what points at this address", once per class and again per locator. With ~900
classes that is quadratic and produced nothing in two minutes. Building a single
map of every 4-byte-aligned dword whose value lands inside the image makes each
lookup constant time and the whole walk finish in about a minute - and the index
is small (51k entries here) because non-pointer values are skipped.

### The same game on two platforms pins the platform layer

The cleanest split does not come from more titles - it comes from ONE title
built for two platforms. Everything in the Xbox build but not the PC build of
the same game is, by construction, Xbox platform code.

Marvel: Ultimate Alliance, Xbox against the 2006 PC build (both x86):

| | |
|---|---|
| portable (engine + game logic) | 3,973 |
| **Xbox-only (XDK / Xbox CRT / D3D8)** | **14,244** |

Applied to X-Men Legends, 15,742 functions:

| bucket | | |
|---|---|---|
| **Xbox platform (XDK/CRT)** | **7,815** | 49% |
| **game - unique to this title** | **5,557** | 35% |
| engine (cross-game, cross-platform) | 1,496 | 9% |
| X-Men portable code | 730 | 4% |
| X-Men series only | 144 | <1% |

For a recompilation to Windows, those 7,815 are the functions to REPLACE with
real Win32/CRT rather than recompile.

**Get the right build.** The 2016 re-releases of Marvel: Ultimate Alliance are
x64 and cannot take part in byte-level comparison at all. The 2006 retail build
is x86 and works - but its retail executable is SafeDisc-wrapped, so entropy and
string count are the check before trusting it (6.44 and 14,575 here, versus 7.5+
for anything still packed).

### Cross-binary name transfer has a hard ceiling

Transferring names between binaries named by the SAME technique yields almost
nothing, and it is worth knowing why before spending effort on it.

From two Marvel: Ultimate Alliance builds carrying 8,533 and 6,384 RTTI-derived
names, X-Men Legends gained **4**. The reason is not ambiguity. Of 10,433
unnamed hash groups in X-Men Legends:

| | |
|---|---|
| no counterpart in either donor | 4,146 |
| **counterpart exists but is also unnamed** | **6,277** |
| named donor but ambiguous | 9 |
| usable | 1 |

Both sides were named by walking RTTI vtables, so both are blind in the same
place: non-virtual functions, which RTTI cannot reach. Breaking through needs a
DIFFERENT naming source - diagnostic string references, call-graph propagation
from named callers, or the engine's own type-registration table - not another
binary named the same way.

### Three-way split: engine, platform, and game

With a third title on the same SDK and a build of one title for another
platform, the "shared" bucket splits further. Presence in a PC build means the
code is not Xbox platform code; presence in an unrelated title on the same
engine means it is not this game's logic.

X-Men Legends, against X-Men Legends II (Xbox), Marvel: Ultimate Alliance
(Xbox) and X-Men Legends II (PC) - all XDK 5849, all Vicarious Visions Alchemy:

| bucket | functions | |
|---|---|---|
| Xbox-side shared (XDK / CRT / engine) | 7,504 | 47% |
| **unique to this game** | **5,573** | 35% |
| engine/runtime, cross-platform | 1,774 | 11% |
| portable, X-Men only | 747 | 4% |
| X-Men series only (Xbox) | 144 | <1% |

Library/engine surface 9,278; game surface 6,464. Of the game surface, 1,851 are
named and **3,866 are not** - that is the remaining work, and it is a far
smaller number than the 14,000 the binary starts with.

**Read the cross-platform bucket as a floor, not a measurement.** The PC build
is a separate compilation, so only functions that compiled identically match at
all - it yields 11,699 hashed functions against the Xbox build's 19,490. Plenty
of Alchemy engine code sits in "Xbox-side shared" purely because it did not
match the PC build, not because it is Xbox-specific.

**Architecture has to match.** FID hashes are instruction bytes, so this works
only within one architecture. Xbox and the 2005 PC build are both x86-32. The
2016 Marvel: Ultimate Alliance re-releases are x64 and cannot participate in any
byte-level comparison at all.

Class names can still be compared across architectures, because they are
source-level. Comparing RTTI class name sets across all four titles put 471 of
X-Men Legends' 873 classes in the engine/framework set, 34 in X-Men-series-only,
and 183 unique to the game - which confirmed the function-level split rather
than overturning it.

### Separating engine code from game code

Two titles built with the same SDK and engine share their library code, so
anything present in both is engine/runtime/SDK and anything in only one is that
game's own logic. For a recompilation that split is worth more than names -
shared code can be replaced with a real implementation instead of recompiled,
and the unique set is the part that actually has to be understood.

Raw byte comparison does not work: the same function links at a different
address in each image, so every absolute operand differs. Ghidra's FID hash
masks exactly those operands, which makes it the right instrument.

```bash
# once per binary
analyzeHeadless <projects> <Project> -process <program> -noanalysis     -scriptPath ~/ghidra_scripts -postScript DumpFunctionHashes.java hashes_X.txt
# then
analysis/classify-shared-functions.py hashes_A.txt hashes_B.txt -o out/
```

Measured on X-Men Legends vs X-Men Legends II (both XDK 5849, both Intrinsic
Alchemy):

| | |
|---|---|
| XML1 functions | 14,119 |
| SHARED - engine, CRT, XDK | **8,537 (60%)** |
| UNIQUE - the game's own code | **5,582** |

That is the number that matters: the recomp's real surface is about 5,600
functions, not 14,000.

Names transfer as a side effect, but expect little: only 364 of the shared
functions carried a name, and 320 of those were SDK functions XbSymbolDatabase
had already found in both binaries. 44 were genuinely new. A name is carried
only when the hash matches exactly one function on each side - a one-to-many
match cannot say which candidate it belongs to, and guessing plants a wrong name
that later work would trust.

### The engine is Vicarious Visions Alchemy, not a Raven engine

Worth knowing before hunting for documentation. Both games carry `ig*` class
names as plain strings - 693 unique in X-Men Legends, 490 in Legends II, 208 in
the PC build of Legends II - alongside literal `Alchemy`, `Intrinsic`,
`IGBFile` and `.igb` markers.

    igObject  igActor  igAnimationDatabase  igArenaMemoryPool  igIGBFile ...

In X-Men Legends those 693 names sit in one contiguous blob (540 of 684
consecutive names within 64 bytes of each other), which is the shape of a
runtime type-registration table rather than scattered debug text. Following the
references into that table is a route to naming classes and their vtables, and
therefore virtual methods, in bulk.

## solutions/

`solve_qvm32.py` needs `python3-unicorn` (`apt install python3-unicorn`); the
others need only the standard library.

Per-target keygens, kept as worked examples.

| Script | Target |
|---|---|
| `keygen01.py` | `crackme01` — self-authored pipeline test |
| `solve_prime.py` | `prime.exe` (crackmes.one) — inverts `pow(129, char, 251)` then XOR |
| `keygen_bfcrackme40.py` | `BFCrackMe40` (crackmes.one) — VB6 P-code; string-range check |
| `keygen_keygenme2.py` | `Keygen #2 by Nicohogtag` (crackmes.one) — MinGW C++; STABS symbols, and a check that reads two bytes past its input buffer |
| `solve_qvm32.py` | `qvm32` (crackmes.one) — Linux ELF bytecode VM; Unicorn emulation with VM-step counting as the oracle |

## Development in the lab

The lab is not only for reversing - it builds and runs native Linux software,
and cross-builds Windows binaries that Wine then runs in place.

| Purpose | What is installed |
|---|---|
| Build | `cmake`, `ninja`, `make`, `gcc`/`g++`, `clang`, `lld`, `ccache`, `pkg-config` |
| Cross-build to Windows | `mingw-w64` — produces PE32+ binaries, runnable via `re-run` |
| Libraries | SDL2, OpenSSL, epoxy, GL, ALSA (dev headers) |
| Debug | `gdb`, plus the RE tooling above |
| Source control | `git`, `git-lfs`, `gh` (from GitHub's own apt repo) |

Verified end to end: a CMake + Ninja project linking SDL2, OpenSSL and epoxy
compiles and runs, and `x86_64-w64-mingw32-gcc` produces a Windows PE32+ that
`re-run` executes under Wine. That closes the loop — write, build and test both
targets without leaving the lab.

**GitHub authentication is not scripted.** Run `gh auth login` in the lab
yourself; provisioning sets the git identity but never handles credentials.

GPU acceleration is real inside the desktop — `D3D12 (AMD Radeon RX 7600 XT)`,
OpenGL 4.6, direct rendering. **Vulkan is software only**: the `dzn` ICD that
maps Vulkan onto D3D12 is not installed, so only `lavapipe` is available. Work
that needs a real Vulkan device will not perform here.

## Rebuilding the lab elsewhere

The lab snapshot is ~13 GB — far past GitHub's 100 MB per-file limit — so this
repo stores what is needed to **recreate** it rather than an image of it. That
is also the only form that works on a different machine.

```bash
wsl --install kali-linux --no-launch
# put this repo where the lab can see it, then:
wsl -d kali-linux -u root -- bash /mnt/share/provision/rebuild-lab.sh
```

`provision/rebuild-lab.sh` recreates the user and sudo rule, the isolation
config, the package set, Ghidra, our GhidraMCP fork (built from upstream plus
`ghidra-mcp/ghidramcp-relab.patch`), both MCP bridges, the tooling, and the
Wine prefixes. It prints the few steps that cannot be automated — the
`wsl --shutdown`, MCP registration, and the one-time Ghidra tool save.

| File | Purpose |
|---|---|
| `provision/wsl.conf` | No automount, no Windows PATH, one shared folder |
| `provision/fstab` | Mounts that single share at `/mnt/share` |
| `provision/packages-manual.txt` | Explicitly-installed packages (`apt-mark showmanual`) |
| `ghidra-mcp/ghidramcp-relab.patch` | Our 10 added MCP tools, against upstream `27f316f` |
| `ghidra-mcp/bridge-relab.patch` | Bridge wrappers + raised HTTP timeouts |

**For a same-machine restore the snapshot is still the fast path** —
`D:\re-lab\restore.ps1` takes minutes rather than a full rebuild. Use this
script when the snapshot is gone, or on a new machine.

## windows/ - the app

`Install.ps1` sets the lab up as an ordinary Windows application: Start-menu
entry, icon, and a line in Apps & features. Per-user, no elevation.

```powershell
.\Install.ps1                       # %LOCALAPPDATA%\Programs\RE Lab
.\Install.ps1 -InstallDir 'D:
e-lab' -SnapshotDir 'D:
e-lab\snapshots'
.\Install.ps1 -LinkDistro           # move the distro inside the app folder
```

`-LinkDistro` uses `wsl --manage <distro> --move`, so the virtual disk ends up
under the install directory and the app owns the machine rather than pointing at
one registered elsewhere. Within a drive that is quick; across drives it copies
every byte of a ~16 GB disk.

The installer refuses to run if the distro is missing, rather than creating
shortcuts that open nothing.

`Uninstall.ps1` removes the shortcuts, the registry entry and the installed
scripts, and deliberately keeps the snapshots and the distro - reporting both
so they can be removed on purpose. It deletes a shortcut only after checking
that it points at *its own* install directory. Name matching alone is not
enough: an earlier revision matched on name, and a test run against redirected
folders used a stale copy that predated the redirect and deleted the real
shortcuts on the desktop instead.

## Making it feel like a desktop, not a tool

`re-desktop` takes `fullscreen`, `portrait` (1080x1920), `wide`, `tall`, or an
explicit `WxH`. Shortcuts for the first two are created by
`windows/make-shortcuts.ps1`.

- **GPU acceleration.** Mesa defaults to `llvmpipe` in WSL even though
  `/dev/dxg` and the d3d12 Gallium driver are both present, so everything
  renders on the CPU and WSLg labels the window `[WARN:COPY MODE]`.
  `re-desktop` sets `GALLIUM_DRIVER=d3d12`, which gives
  `OpenGL renderer string: D3D12 (<your GPU>)` and direct rendering, inside the
  nested desktop as well as on WSLg directly.
- **Dark everywhere.** The XFCE theme alone leaves Qt apps light next to a dark
  panel, so `re-desktop` also exports `GTK_THEME`, `QT_STYLE_OVERRIDE` and
  `QT_QPA_PLATFORMTHEME`, and `~/.config/gtk-{3,4}.0/settings.ini` sets
  `gtk-application-prefer-dark-theme`.
- **The Windows title bar cannot be themed.** The desktop window is hosted by
  `msrdc.exe`, which **custom-draws its own caption**. Setting
  `DWMWA_USE_IMMERSIVE_DARK_MODE`, `DWMWA_CAPTION_COLOR` and
  `DWMWA_BORDER_COLOR` all return `S_OK` and change nothing, and Windows being
  in dark mode system-wide makes no difference either. **Use `fullscreen`** -
  there is no caption at all, which is also the closest thing to a real Linux
  desktop.
- Apps installed with `apt` appear in the XFCE menu on their own, sound works
  through WSLg's PulseServer, and the network is shared with the host.
- **systemd runs as PID 1**, via `[boot] systemd=true` in `wsl.conf`. Without it
  WSL uses a minimal init and there are no services at all - no cron, no timers,
  no NetworkManager, no printing, no container daemon - which is the practical
  difference between a desktop and a working machine. It needs a full
  `wsl --shutdown` to take effect; restarting the distro alone leaves
  `systemctl` reporting `offline`.

  `tpm-udev` is masked because WSL passes no TPM through, and that single
  permanently-failing unit is enough to make the whole system report
  `degraded`, which hides real failures behind constant noise.
- **Task Manager TMOG replaces xfce4-taskmanager.** Plummer's Software's Qt6
  system monitor, on `Ctrl+Shift+Escape` and in the menu. Not packaged by Debian
  or Kali, so `provision/rebuild-lab.sh` installs it from a `TMOG-*.deb` left in
  the source directory or `/mnt/share`, and pulls `libqt6multimedia6` - the
  package under-declares its dependencies and will not start without it.

  It is launched through the `tmog` wrapper rather than directly. Qt6 prefers
  Wayland whenever `WAYLAND_DISPLAY` is set, WSLg sets it for every process in
  the lab, and the result is a window that opens on WSLg's compositor as a
  *Windows* window - present in neither X server's window tree. The process runs,
  spins and appears hung. The wrapper strips `WAYLAND_DISPLAY` and pins
  `QT_QPA_PLATFORM=xcb`.

  `xfce4-taskmanager` stays installed because `kali-desktop-xfce` depends on it;
  its launcher is hidden with a `NoDisplay=true` override in `/usr/local/share`
  instead.

- **The clipboard is shared with Windows.** Xephyr's `:10` is a separate X
  server from WSLg's `:0`, and only `:0` is bridged to Windows, so without help
  the desktop's clipboard is an island - text copied inside Linux cannot be
  pasted into Windows at all. `re-clipsync` polls both displays and copies
  whichever changed to the other; `re-desktop` starts it and kills it with the
  session.

## Things that will bite

- **Processes started from Windows die immediately.** A process launched by a
  *one-shot* `wsl.exe` call is killed when that call returns; `nohup`, `&` and
  `setsid` do not save it. Anything that must survive needs a launcher that
  **blocks**, started with `Start-Process`. That is why `re-desktop`,
  `run-target` and `ghidra-mcp-start` all block.

  **This does not apply through the MCP server.** `lab_mcp.py` is itself a
  long-lived process inside the lab, so a `setsid` child spawned from
  `lab_exec` outlives the call:

  ```
  setsid env DISPLAY=:10 some-gui-app >/tmp/app.log 2>&1 < /dev/null &
  ```

  Prefer that over `Start-Process` when the MCP is available — it is one call
  instead of a launcher script, and there is no quoting to get wrong.
- **Run GUI targets on `:10`, not `:0`.** Under WSLg a window reports 1x1
  geometry and screenshots come back blank — it is a proxy for a real Windows
  window. Xephyr behaves normally.
- **`pkill -f` matches the shell running it.** The pattern is in that shell's
  own argv, so the call kills the caller and returns exit `-15` with no output -
  which reads as the lab dying rather than a self-match. Bracket the first
  character: `pkill -f '[N]ame'`. `lab_kill` does this for you.
- **CRLF kills shebangs.** These files live on an NTFS share; reinstall with
  `tr -d '\r'` (what `install.sh` does) or you get a confusing "not found".
- **Never reposition the desktop window from Windows.** WSLg tracks where it
  thinks the window is and translates pointer events against it; moving it
  behind its back leaves clicks landing in the wrong place.
