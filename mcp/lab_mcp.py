#!/usr/bin/env python3
"""re-lab MCP server - the lab's tools, callable directly.

Runs *inside* the Kali lab, so commands never cross the PowerShell -> wsl.exe ->
bash boundary that silently rewrites Unix paths into Windows ones and eats
shell variables. That boundary caused a long run of false diagnoses, and this
server exists mainly to remove it.

Register with:
  claude mcp add re-lab --scope user -- wsl.exe -d kali-linux -- /opt/re-lab-mcp/venv/bin/python /opt/re-lab-mcp/lab_mcp.py
"""
import os
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("re-lab")

SHARE = "/mnt/share"
DEFAULT_DISPLAY = ":10"


def run(cmd, timeout=120, display=None):
    """Run a command in the lab and return combined output."""
    env = dict(os.environ)
    if display:
        env["DISPLAY"] = display
        env.pop("WAYLAND_DISPLAY", None)
        env["GDK_BACKEND"] = "x11"
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                           text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return f"(timed out after {timeout}s)"
    out = (p.stdout or "") + (p.stderr or "")
    return out.strip() or f"(no output, exit {p.returncode})"


# ---------------------------------------------------------------- shell

@mcp.tool()
def lab_exec(command: str, timeout: int = 120) -> str:
    """
    Run a shell command inside the RE lab as the 'oddity' user and return its
    output. Paths are Linux paths and are NOT rewritten.

    Use this instead of driving the lab through PowerShell: that path mangles
    /mnt, /tmp and /opt into Windows paths and drops shell variables.

    Args:
        command: shell command, e.g. "ls -l /home/oddity/targets"
        timeout: seconds before giving up
    """
    return run(command, timeout=timeout)


@mcp.tool()
def lab_exec_root(command: str, timeout: int = 120) -> str:
    """
    Run a shell command in the lab as root (passwordless sudo).

    Needed for reading another process's memory (/proc/<pid>/mem) and for
    attaching a debugger, since root has CAP_SYS_PTRACE and the kernel's
    yama ptrace_scope is deliberately left at its default.
    """
    return run(["sudo", "-n", "bash", "-lc", command], timeout=timeout)


# ---------------------------------------------------------------- triage

@mcp.tool()
def lab_triage(path: str) -> str:
    """
    Full pre-analysis report on a binary: hashes, entropy, PE header, section
    entropy with packer detection, notable imports, APIs named only in strings
    (dynamically resolved), and likely-interesting strings.
    """
    return run(["re-triage", path], timeout=180)


@mcp.tool()
def lab_vbinfo(path: str) -> str:
    """
    Read a VB5/VB6 header: whether the binary is native or P-code, the code
    range and the object table. Run this before disassembling a VB6 target -
    P-code read as x86 produces convincing nonsense.
    """
    return run(["python3", "/usr/local/bin/vbinfo.py", path], timeout=120)


# ---------------------------------------------------------------- running

@mcp.tool()
def lab_run_target(path: str, display: str = DEFAULT_DISPLAY) -> str:
    """
    Launch a Windows target under Wine on the nested desktop, detached so it
    keeps running.

    Use the nested desktop (:10), not WSLg (:0): under WSLg a window reports
    1x1 geometry and screenshots come back blank.
    """
    subprocess.Popen(
        ["setsid", "run-target", path, display],
        stdout=open("/tmp/lab-run.log", "wb"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return f"launched {path} on {display}; check with lab_windows()"


@mcp.tool()
def lab_kill(pattern: str) -> str:
    """
    Kill processes whose command line matches `pattern`, and report how many
    survived.

    The pattern's first character is wrapped in a bracket expression before use.
    Without that, pkill matches the shell running it - the pattern is sitting in
    that shell's own argv - so the call kills itself, returns signal 15 and no
    output, and looks like the lab died rather than like a self-match. Bracketing
    leaves the regex meaning unchanged while making the literal in argv differ
    from what the regex accepts.
    """
    if not pattern:
        return "refusing to kill on an empty pattern"
    safe = f"[{pattern[0]}]{pattern[1:]}"
    return run(["bash", "-lc",
                f"pkill -f '{safe}'; sleep 1; "
                # pgrep -c prints 0 AND exits non-zero when nothing matches, so
                # a `|| echo 0` fallback prints the count twice.
                f"echo \"survivors: $(pgrep -cf '{safe}' | head -1)\""])


# ---------------------------------------------------------------- gui

@mcp.tool()
def lab_windows(display: str = DEFAULT_DISPLAY) -> str:
    """List window titles on the given display."""
    return run(["bash", "-lc",
                "xdotool search --name . getwindowname %@ 2>/dev/null | grep -v '^$'"],
               display=display)


@mcp.tool()
def lab_window_tree(display: str = DEFAULT_DISPLAY) -> str:
    """
    Full X window tree with geometry. Use this to find a program's real window:
    VB6 and similar create several hidden 1x1 toplevels alongside the real form.
    """
    return run(["bash", "-lc", "xwininfo -root -tree 2>/dev/null | grep -v '1x1'"],
               display=display)


@mcp.tool()
def lab_screenshot(name: str = "shot", display: str = DEFAULT_DISPLAY,
                   window: str = "") -> str:
    """
    Screenshot the desktop, or one window if `window` is given (an X window id
    like 0x4000004, or a title substring). Returns the file path; read it to
    see the result.

    Look at the pixels. A process list proves a program started, not that it
    works or that anything is visible.
    """
    out = f"{SHARE}/{name}.png"
    if window:
        if window.startswith("0x"):
            cmd = f"import -window {window} {out}"
        else:
            cmd = (f"import -window $(xdotool search --name '{window}' | tail -1) {out}")
    else:
        cmd = f"import -window root {out}"
    res = run(["bash", "-lc", cmd], display=display)
    return out if os.path.exists(out) else f"capture failed: {res}"


@mcp.tool()
def lab_click(x: int, y: int, button: int = 1, double: bool = False,
              display: str = DEFAULT_DISPLAY) -> str:
    """Click at screen coordinates on the given display."""
    rep = "--repeat 2 --delay 80 " if double else ""
    return run(["bash", "-lc", f"xdotool mousemove {x} {y} click {rep}{button}"],
               display=display) or f"clicked {x},{y}"


@mcp.tool()
def lab_type(text: str, display: str = DEFAULT_DISPLAY) -> str:
    """Type text into the focused window."""
    return run(["xdotool", "type", "--delay", "25", "--", text],
               display=display) or f"typed {len(text)} chars"


@mcp.tool()
def lab_key(keys: str, repeat: int = 1, display: str = DEFAULT_DISPLAY) -> str:
    """
    Press a key, optionally repeatedly. e.g. "Return", "ctrl+s", "BackSpace".

    Clearing a text field: many old VB6 forms ignore ctrl+a, so send End then
    BackSpace with a repeat count rather than trying to select-all.
    """
    return run(["bash", "-lc",
                f"for i in $(seq 1 {repeat}); do xdotool key -- {keys}; done"],
               display=display) or f"pressed {keys} x{repeat}"


@mcp.tool()
def lab_focus(match: str, display: str = DEFAULT_DISPLAY) -> str:
    """Raise and focus a window by title substring."""
    return run(["bash", "-lc",
                f"xdotool search --name '{match}' windowactivate --sync %@ 2>/dev/null "
                f"|| xdotool search --name '{match}' windowraise %@"],
               display=display) or f"focused {match}"


# ---------------------------------------------------------------- RE tools

@mcp.tool()
def lab_strings(path: str, min_len: int = 6, encoding: str = "ascii",
                filter: str = "", limit: int = 200) -> str:
    """
    Strings from a file on disk.

    Args:
        path: file to scan
        min_len: minimum run length
        encoding: "ascii", "utf16" (Windows binaries keep most text as UTF-16),
                  or "both"
        filter: only lines containing this (case-insensitive)
        limit: maximum lines returned
    """
    parts = []
    if encoding in ("ascii", "both"):
        parts.append(f"strings -n {min_len} '{path}'")
    if encoding in ("utf16", "both"):
        parts.append(f"strings -el -n {min_len} '{path}'")
    cmd = "{ " + "; ".join(parts) + "; }"
    if filter:
        cmd += f" | grep -i -- '{filter}'"
    cmd += f" | head -{limit}"
    return run(["bash", "-lc", cmd], timeout=180)


@mcp.tool()
def lab_r2(path: str, commands: str, analyse: bool = True) -> str:
    """
    Run radare2 in batch mode against a file and return its output.

    Args:
        path: binary to open
        commands: r2 commands separated by ';' e.g. "afl" (list functions),
                  "pdf @ main" (disassemble), "iz" (strings), "ii" (imports)
        analyse: run 'aaa' first so functions exist (slower on big binaries)
    """
    script = ("aaa;" if analyse else "") + commands
    # scr.color=0 strips ANSI. The rest of the noise - "Analyze all flags",
    # "Function already defined" once per function - is on stderr and is not
    # gated by log.level, so drop stderr and keep stdout, which is just the
    # answer. Merging the two buries a five-line result in three hundred lines
    # of commentary. stderr is still the fallback: r2 reports a bad path there
    # and exits with an empty stdout, which would otherwise read as "no results".
    cmd = (f"r2 -q -e scr.color=0 -c \"{script}\" '{path}' 2>/tmp/r2.err")
    return run(["bash", "-lc",
                f'out=$({cmd}); '
                f'if [ -n "$out" ]; then printf "%s\n" "$out" | head -300; '
                f'else echo "(no stdout; r2 stderr follows)"; head -20 /tmp/r2.err; fi'],
               timeout=600)


@mcp.tool()
def lab_pcode_dis(path: str, proc_va: str, imagebase: str = "0x400000",
                  constpool: str = "0") -> str:
    """
    Disassemble VB6 P-code for one procedure of a fixed-up dump.

    `proc_va` is the address from an ObjectInfo method array - it points at the
    ProcDscInfo, and the P-code stream sits immediately BEFORE it. The tool
    handles that; decoding forward from the descriptor reads cleanup tables and
    filler instead.

    Needs the opcode table at /home/oddity/targets/opcodes.csv - see
    lab_fetch_pcode_table().
    """
    return run(["python3", "/usr/local/bin/pcode-dis.py", path, proc_va,
                imagebase, constpool], timeout=180)


@mcp.tool()
def lab_fetch_pcode_table() -> str:
    """
    Fetch the VB6 P-code opcode table (1536 entries with verified instruction
    sizes and operand formats) that lab_pcode_dis needs.

    Source: the `visualbasic` crate. Original P-code research by MrUnleaded,
    Moogman and Napalm.
    """
    cmd = (
        "set -e; mkdir -p /home/oddity/targets; "
        "if [ -s /home/oddity/targets/opcodes.csv ]; then "
        "  echo 'already present'; exit 0; fi; "
        "curl -sL -o /tmp/vb.crate "
        "https://static.crates.io/crates/visualbasic/visualbasic-0.1.0.crate; "
        "tar xzf /tmp/vb.crate -C /tmp; "
        "cp /tmp/visualbasic-0.1.0/data/opcodes.csv /home/oddity/targets/opcodes.csv; "
        "wc -l /home/oddity/targets/opcodes.csv"
    )
    return run(["bash", "-lc", cmd], timeout=300)


@mcp.tool()
def lab_wine_run(path: str, args: str = "", stdin_text: str = "",
                 timeout: int = 120) -> str:
    """
    Run a console Windows PE under Wine and capture its output. The 32- or
    64-bit prefix is chosen from the PE header.

    For GUI targets use lab_run_target instead - this waits for the program to
    exit, which a GUI app will not do.

    Args:
        path: the .exe
        args: command line arguments
        stdin_text: text piped to the program's stdin
    """
    import shlex
    inp = f"printf '%s' {shlex.quote(stdin_text)} | " if stdin_text else ""
    return run(["bash", "-lc",
                f"{inp}timeout {timeout} re-run '{path}' {args} 2>&1 | tail -40"],
               timeout=timeout + 60)


@mcp.tool()
def lab_python(code: str, timeout: int = 120) -> str:
    """
    Run a Python snippet inside the lab and return its output.

    For keygens and one-off analysis: pefile, capstone, lief and the standard
    library are available. Writing the algorithm here and checking it against
    the binary is the way to confirm a keygen rather than assume it.
    """
    import base64
    blob = base64.b64encode(code.encode()).decode()
    return run(["bash", "-lc",
                f"echo {blob} | base64 -d | python3 -"], timeout=timeout)


# ---------------------------------------------------------------- memory

@mcp.tool()
def lab_mem_strings(process: str, min_len: int = 6, filter: str = "") -> str:
    """
    UTF-16LE strings from a live process, with addresses. VB6 keeps everything
    as BSTRs, so inputs and computed values are readable text.

    Beware: every keystroke you send leaves its own BSTR, so the heap fills
    with prefixes of your own input. Before dumping, set fields to values that
    share no characters with any plausible answer.
    """
    cmd = f"mem-strings {process} {min_len}"
    if filter:
        cmd += f" {filter}"
    return run(["sudo", "-n", "bash", "-lc", cmd], timeout=300)


@mcp.tool()
def lab_dump_memory(process: str, base: str = "0x400000", size: str = "0xC000",
                    out: str = "/mnt/share/dump.bin") -> str:
    """
    Dump a memory range from a running process. The usual way past a packer you
    cannot decompress offline: let the program unpack itself, then read it.
    """
    return run(["sudo", "-n", "dump-wine-image", process, base, size, out],
               timeout=300)


@mcp.tool()
def lab_fix_dump(dump: str, out: str) -> str:
    """
    Repair a memory dump's PE section headers (PointerToRawData = VirtualAddress)
    so a disassembler maps it correctly. Without this every section lands at the
    wrong offset and the disassembly looks like obfuscation.
    """
    return run(["python3", "/usr/local/bin/fix-dump.py", dump, out], timeout=120)


@mcp.tool()
def lab_disas(path: str, address: str, length: int = 128,
              imagebase: str = "0x400000") -> str:
    """Disassemble x86-32 at a virtual address in a fixed-up dump."""
    return run(["python3", "/usr/local/bin/disas.py", path, address,
                str(length), imagebase], timeout=120)


@mcp.tool()
def lab_hexdump(path: str, offset: str = "0", length: int = 256) -> str:
    """Hex dump a file region (offset may be decimal or 0x-prefixed)."""
    off = int(offset, 0)
    return run(["bash", "-lc",
                f"xxd -s {off} -l {length} '{path}'"], timeout=60)


if __name__ == "__main__":
    mcp.run()
