---
name: ghidra-mcp-usage
description: Driving Ghidra through the ghidra MCP server - loading a binary, choosing the right tool for a question, and annotating as you go so analysis compounds. Use whenever reverse engineering a binary with the ghidra MCP tools, or when those tools return "No program loaded" or stop responding.
---

# Using the Ghidra MCP

The `ghidra` MCP server drives a real Ghidra instance in the RE lab. It is our
own build of GhidraMCP (LaurieWired), rebuilt against Ghidra 12.1.3 with extra
tools added. Source: `~/src/GhidraMCP` in the lab.

## Getting a running server

One command brings the whole stack up from cold - desktop, Ghidra, CodeBrowser,
port - and blocks to keep it alive:

```powershell
Start-Process wsl.exe -ArgumentList '-d','kali-linux','--','bash','-c','ghidra-mcp-start > /mnt/share/boot.log 2>&1'
```

Watch `D:\re-lab-share\boot.log`; it ends in `READY` or `FAILED`. On failure it
writes a screenshot to `/mnt/share/ghidra-boot-fail.png` and leaves Ghidra
running so the state can be inspected — a blocking dialog or a mis-clicked
coordinate is obvious from the picture.

Ghidra must NOT be started with `ghidraRun` from Windows: it uses
`launch.sh bg`, which forks the JVM and exits, so WSL reaps the orphan seconds
later. `ghidra-mcp-start` uses the foreground launcher.

The HTTP server lives inside the **CodeBrowser tool**, not the project window,
and **exactly one** CodeBrowser may exist — a second cannot bind 8080, and
closing either stops the server.

Check readiness by calling the server, never by looking at the socket. During a
restart the dying instance can still hold port 8080:

```powershell
wsl -d kali-linux -- bash -c 'curl -s -m 5 http://127.0.0.1:8080/program_info'
```

**Exactly one CodeBrowser.** Each instance tries to bind port 8080; a second one
fails with `BindException` and closing either can stop the server. If tools go
dead, check for duplicates before anything else:

```powershell
wsl -d kali-linux -- bash -c 'grep -i ghidramcp ~/.config/ghidra/ghidra_12.1.3_PUBLIC/application.log | tail'
```

## Starting a target

```
import_binary(path="/mnt/share/crackme01.exe", analyze=True)
```

The path resolves **inside Linux**. Copy Windows files to `D:\re-lab-share\`
first and load them from `/mnt/share/`.

Then orient before diving in:

```
get_program_info()     # arch, image base, entry points, compiler, hashes
list_strings(filter=…) # almost always the fastest first lead
list_imports()         # what the binary can actually do
```

## Choosing a tool

| Question | Tool |
|---|---|
| What is this binary? | `get_program_info` |
| Where is the interesting code? | `list_strings`, `list_imports`, `search_functions_by_name` |
| What does this function do? | `decompile_function` (by name) or `decompile_function_by_address` |
| What calls this? | `get_callers`, or `get_xrefs_to` for finer detail |
| What does it call? | `get_callees` |
| What are the actual bytes? | `read_bytes` |
| Where else does this pattern appear? | `search_bytes` |
| Exact instructions | `disassemble_function` |

`search_bytes` accepts `??` as a wildcard byte: `48??8b` matches `48 xx 8b`.
Useful for signatures that must tolerate a varying register or a relocated
operand. Results include the containing function where known.

## Annotate as you go

The single highest-value habit. Every time a name or type is worked out, write
it back:

```
rename_function(old_name="FUN_00401230", new_name="check_serial")
rename_variable(function_name="check_serial", old_name="local_1c", new_name="user_len")
set_function_prototype(function_address="0x401230", prototype="bool check_serial(char *name, char *serial)")
set_decompiler_comment(address="0x401256", comment="XOR key derived from username length")
```

Decompiler output improves markedly once prototypes and types are correct. Most
unreadable decompilation is a wrong type, not obfuscation — fixing one struct
pointer can collapse twenty lines of casts into a field access.

Call `save_program()` at the end, or the annotations die with the session.

## Patching

```
patch_bytes(address="0x401256", bytes_hex="9090")   # returns the original bytes
export_program(path="/mnt/share/patched.exe", format="binary")
```

`patch_bytes` edits the analysis database, not the file on disk — `export_program`
writes it out. Keep the returned "before" bytes; that is how a patch is reversed.

`format="binary"` writes raw memory including patches; `format="original"`
writes the file as originally imported.

## When something looks wrong

- **"No program loaded"** — nothing imported yet, or CodeBrowser has no program open.
- **All tools time out** — a modal dialog is blocking Ghidra's thread. Screenshot
  the desktop (`re-ctl shot`) and look. Ghidra's "Analyze?" prompt on program
  open is the usual culprit; answer "No (Don't ask again)".
- **Tools vanish** — the MCP server is registered at Claude Code startup. After
  changing the bridge, restart Claude Code.

## Extending it

The plugin is one Java file; the bridge is one Python file.

```
~/src/GhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java   # HTTP endpoints
/opt/ghidra-mcp/bridge_mcp_ghidra.py                                # MCP tool wrappers
```

Rebuild and reinstall:

```powershell
wsl -d kali-linux -- bash -c 'cd ~/src/GhidraMCP && mvn -q -B clean package'
wsl -d kali-linux -- unzip -o -q ~/src/GhidraMCP/target/GhidraMCP-1.0-SNAPSHOT.zip -d ~/.config/ghidra/ghidra_12.1.3_PUBLIC/Extensions
wsl -d kali-linux -- bash -c "printf '' > ~/.config/ghidra/ghidra_12.1.3_PUBLIC/Extensions/GhidraMCP/Module.manifest"
```

Two things that will bite:

- Extensions install to `~/.config/ghidra/<version>/Extensions`, **not** the
  legacy `~/.ghidra/.ghidra_<version>/`.
- `Module.manifest` must be **empty** or use `KEY: value`. GhidraMCP ships
  `GHIDRA_MODULE_NAME=...`, which Ghidra 12 rejects — and it rejects the whole
  module silently, so the extension simply never appears.

Verify API signatures with `javap` before writing against them; Ghidra's Java
API shifts between versions.

```powershell
wsl -d kali-linux -- bash -c "cd ~/src/GhidraMCP/lib && javap -cp 'Base.jar:SoftwareModeling.jar:Generic.jar:Project.jar:Utility.jar' ghidra.program.model.mem.Memory | grep findBytes"
```
