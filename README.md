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

## solutions/

Per-target keygens, kept as worked examples.

| Script | Target |
|---|---|
| `keygen01.py` | `crackme01` — self-authored pipeline test |
| `solve_prime.py` | `prime.exe` (crackmes.one) — inverts `pow(129, char, 251)` then XOR |
| `keygen_bfcrackme40.py` | `BFCrackMe40` (crackmes.one) — VB6 P-code; string-range check |

## Things that will bite

- **Processes started from Windows die immediately.** A process launched by a
  one-shot `wsl.exe` call is killed when that call returns; `nohup`, `&` and
  `setsid` do not save it. Anything that must survive needs a launcher that
  **blocks**, started with `Start-Process`. That is why `re-desktop`,
  `run-target` and `ghidra-mcp-start` all block.
- **Run GUI targets on `:10`, not `:0`.** Under WSLg a window reports 1x1
  geometry and screenshots come back blank — it is a proxy for a real Windows
  window. Xephyr behaves normally.
- **CRLF kills shebangs.** These files live on an NTFS share; reinstall with
  `tr -d '\r'` (what `install.sh` does) or you get a confusing "not found".
- **Never reposition the desktop window from Windows.** WSLg tracks where it
  thinks the window is and translates pointer events against it; moving it
  behind its back leaves clicks landing in the wrong place.
