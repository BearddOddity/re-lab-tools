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
