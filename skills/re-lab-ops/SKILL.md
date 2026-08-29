---
name: re-lab-ops
description: Operating the isolated Kali reverse-engineering lab on this machine - launching the desktop, driving GUI apps with re-ctl, snapshot and rollback discipline, moving files across the Windows/Linux boundary, and what must never be executed where. Use whenever working in the RE lab, running Ghidra or Wine in it, or when a lab command behaves oddly.
---

# RE Lab operations

An isolated Kali Linux WSL2 instance for reverse engineering. This skill covers
driving it; `ghidra-mcp-usage` covers analysing binaries once loaded.

## Layout

| Path | What |
|---|---|
| `D:\re-lab\` | Windows-side scripts and snapshots |
| `D:\re-lab-share\` | The **only** shared folder. Appears in Linux as `/mnt/share` |
| distro `kali-linux` | The lab. User `oddity`, passwordless sudo |
| `/opt/ghidra_12.1.3_PUBLIC` | Ghidra with our GhidraMCP build |
| `/opt/ghidra-mcp/` | MCP bridge and its venv |

Windows drives are **not** mounted inside the lab and the Windows PATH is not
injected. Only `/mnt/share` crosses the boundary. To give the lab a file from
Windows, copy it into `D:\re-lab-share\` and reference it as
`/mnt/share/<name>`.

## Isolation: what it does and does not buy

It protects against **accidents** — a wrong path, a bad `rm`, a package that
misbehaves cannot reach the Windows filesystem.

It is **not a malware boundary**. The lab shares the network and WSL2 is not
built to contain hostile code. Static analysis, unpacking and scripting are
fine. To *execute* something of unknown provenance, use a Hyper-V VM with
checkpoints and networking off, not this lab.

Wine is installed with 32-bit support, so Windows PE crackmes will run. That is
a deliberate, accepted risk for challenges from a known source. It is the wrong
tool for an unknown binary.

## Running commands

Always through PowerShell, never Git Bash:

```powershell
wsl -d kali-linux -- <command>          # as oddity
wsl -d kali-linux -u root -- <command>  # as root
```

**Git Bash mangles Linux paths.** It rewrites anything resembling a Unix path
(`/mnt`, `/tmp`, `/opt`, `/proc`) into a Windows path, and it eats `$variables`
inside nested quotes. This has silently corrupted commands and produced
convincing-but-false "it's broken" diagnoses. If a command returns empty output
or a path like `C:/Program Files/Git/opt/...`, that is the cause.

## The desktop

Launch: **RE Lab - Desktop** shortcut, or `re-desktop` inside the lab. Stop it
with `re-desktop-stop`.

XFCE runs inside Xephyr, a nested X server; WSLg presents it as one Windows
window. Individual Linux GUI apps also appear in the Start menu under
**kali-linux** and open as their own windows.

**Never reposition the desktop window with `SetWindowPos` from Windows.** WSLg
tracks where it thinks the window is and uses that to translate pointer events.
Moving it behind WSLg's back leaves that stale, so clicks land in the wrong
place and the mouse appears "uncalibrated". Drag it by its title bar instead.

If GUI apps stop opening, run `wsl --shutdown` and reopen. That rebuilds the
WSLg system distro. A plain `wsl --terminate` is **not** enough.

## Driving the GUI: re-ctl

`re-ctl` is the control surface. Every subcommand takes plain positional
arguments so nothing needs escaping.

```
re-ctl shot [name]        screenshot -> /mnt/share/<name>.png
re-ctl shotwin <match>    screenshot one window
re-ctl windows            list windows
re-ctl click <x> <y>      also rclick / dblclick
re-ctl type <text...>     type into focused window
re-ctl key <keys>         Return, ctrl+s, alt+F4
re-ctl focus <match>      raise and focus by title substring
re-ctl run <cmd...>       launch a GUI program
re-ctl geom <match>       window geometry
re-ctl ps                 what is running
```

`DISP=:0` switches to apps in their own Windows windows; default `:10` is the
nested desktop.

**Look at the screenshot.** A process list proves a program started, not that it
works or that anything is visible. Take a shot and read it before concluding
something works — a desktop rendering solid black still has every process
running.

## Lab commands

Installed in the lab, all on PATH:

| Command | What |
|---|---|
| `ghidra-mcp-start` | Cold start of the whole Ghidra MCP stack. Blocks; launch it detached from Windows |
| `re-triage <file>` | Everything worth knowing before opening a disassembler |
| `re-run <file.exe>` | Run a Windows PE under Wine, arch-correct prefix chosen automatically |
| `run-target <file.exe> [display]` | Same, but **blocks** - use for GUI targets that must stay alive |
| `dump-wine-image <name> <base> <size> <out>` | Dump a PE image out of a running Wine process |
| `fix-dump.py <dump> <out>` | Repair a memory dump's section headers so a disassembler maps it |
| `mem-strings <name> [len] [filter]` | UTF-16 strings from a live process, with addresses |
| `catch-vbastrcmp <name>` | Break on msvbvm60 string compare and log both arguments |
| `vbinfo.py <fixed-dump>` | VB6 header: native vs P-code, object table |
| `disas.py <file> <va> <len>` | Disassemble a fixed-up dump where file offset == RVA |
| `re-desktop` / `re-desktop-stop` | The XFCE desktop window |
| `re-ctl` | GUI control surface (above) |

## The re-lab MCP is the normal way in

`re-lab` runs inside the lab and is called from Windows, so it sidesteps the
Git Bash path mangling and the PowerShell quoting traps below entirely. Prefer
it over `wsl.exe` for anything beyond a one-line check.

| Group | Tools |
|---|---|
| Shell | `lab_exec`, `lab_exec_root`, `lab_kill` |
| RE toolchain | `lab_triage`, `lab_strings`, `lab_r2`, `lab_disas`, `lab_hexdump`, `lab_wine_run`, `lab_python` |
| VB6 | `lab_vbinfo`, `lab_pcode_dis`, `lab_fetch_pcode_table` |
| Live process | `lab_run_target`, `lab_mem_strings`, `lab_dump_memory`, `lab_fix_dump` |
| GUI | `lab_windows`, `lab_window_tree`, `lab_screenshot`, `lab_click`, `lab_type`, `lab_key`, `lab_focus` |

`lab_wine_run` is for **console** PEs - it waits for exit, which a GUI target
never does; use `lab_run_target` for those. `lab_python` runs a snippet inside
the lab with capstone, pefile and lief available, which is where a keygen
belongs: written and checked against the binary rather than asserted.

If a `.py`-backed tool returns "No such file or directory", the lab is missing
its install rather than the tool being broken - run `install.sh` from
`re-lab-tools`.

## Processes started from Windows die immediately

**The single most time-wasting trap in this lab.** A process started by a
one-shot `wsl.exe` call is killed when that call returns. `nohup`, `&` and
`setsid` do **not** save it. Symptoms: the program appears to start, then
`pgrep` finds nothing seconds later, with an empty log.

Anything that must keep running needs a launcher that **blocks**, started
detached from Windows:

```powershell
Start-Process wsl.exe -ArgumentList '-d','kali-linux','--','run-target','/path/app.exe',':10'
```

That is why `re-desktop`, `ghidra-mcp-start` and `run-target` all block rather
than backgrounding their work.

**Exception: the `re-lab` MCP.** Its server process lives inside the lab for
the whole session, so a `setsid` child spawned from `lab_exec` survives the
call and needs no blocking launcher:

```
setsid env DISPLAY=:10 some-gui-app >/tmp/app.log 2>&1 < /dev/null &
```

Reach for this first when the MCP is available.

**`pkill -f` / `pgrep -f` match the shell running them.** The pattern sits in
that shell's own argv, so `pkill -f Nicohogtag` kills the caller. The symptom is
exit `-15` with no output, which reads as "the lab died", not as a self-match.
Bracket the first character - the regex is unchanged, but the literal in argv no
longer matches it:

```bash
pkill -f '[N]icohogtag'
```

`lab_kill` now does this itself. The bracket only helps if the plain literal
appears nowhere else in the same command line, so do not spawn the victim and
kill it in one call.

Two related traps:

- **`Start-Process -ArgumentList` re-quotes long command strings**, which
  silently broke a `cd ... && wine ...` one-liner into "File not found". Put the
  logic in a script in the lab and pass simple arguments.
- **Shell variables get eaten** on the PowerShell → `wsl.exe` → bash path.
  `$f`, `$PID`, `$W` repeatedly arrived empty, producing errors like
  `BadWindow ... 0x0`. Use explicit values, `xdotool` command chaining
  (`xdotool search --name X getwindowgeometry %@`), or do the work in Python.

## Driving GUI targets

Run GUI targets on the **nested desktop** (`:10`), not WSLg (`:0`). Under WSLg
a window reports 1x1 geometry and screenshots come back blank, because it is a
proxy for a real Windows window. Xephyr gives a normal X server where geometry,
clicks and `import` all behave.

Find the real window - VB6 and similar create several hidden 1x1 toplevels:

```bash
DISPLAY=:10 xwininfo -root -tree | grep -v '1x1'
```

## Building and testing in the lab

It is a development machine as well as an analysis one.

| Purpose | Tools |
|---|---|
| Build | `cmake`, `ninja`, `make`, `gcc`/`g++`, `clang`, `lld`, `ccache`, `pkg-config` |
| Cross-build to Windows | `mingw-w64` — PE32+ output, run it with `re-run` |
| Libraries | SDL2, OpenSSL, epoxy, GL, ALSA dev headers |
| Source control | `git`, `git-lfs`, `gh` |

Cross-compiling on Linux and running the result under Wine keeps the whole
write-build-test loop inside the lab, which is the point for anything targeting
a Windows binary.

**GPU: OpenGL is real, Vulkan is not.** Inside the desktop OpenGL reports
`D3D12 (<your GPU>)` with direct rendering, but the `dzn` ICD that maps Vulkan
onto D3D12 is not installed, so Vulkan falls back to `lavapipe` in software.
Do not assume the desktop can host Vulkan work.

`gh auth login` has to be run by a human - nothing here scripts credentials.

## Snapshots

```powershell
D:\re-lab\snapshot.ps1 -Name "before-unpacking-thing"
D:\re-lab\restore.ps1
```

Snapshot **before** the risky thing. Restore lists snapshots newest-first and
requires typing `RESTORE`. It destroys everything in the lab since that
snapshot, so anything worth keeping belongs in `D:\re-lab-share`, which lives on
Windows and is untouched by a restore.

## Launching processes that must survive

`wsl.exe` tears down its session's processes when it returns. A program that
forks and exits (Ghidra's `ghidraRun` uses `launch.sh bg`) gets killed seconds
later. Either keep the launching process alive in the foreground, or use a
wrapper that execs the foreground form — `ghidra-mcp-run` does this for Ghidra.

`nohup` and `setsid` are **not** sufficient on their own.
