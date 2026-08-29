#!/bin/bash
# Install the lab tooling into /usr/local/bin. Run inside the lab as root:
#
#   sudo ./install.sh [source-dir]
#
# Strips carriage returns on the way in. These files normally arrive over an
# NTFS share, and a stray \r in the shebang makes the kernel report "not
# found" for a script that is plainly there.
set -eu

SRC="${1:-$(cd "$(dirname "$0")" && pwd)}"
DEST=/usr/local/bin

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (sudo ./install.sh)" >&2
    exit 1
fi

install_one() {
    local src="$1" name
    name=$(basename "$src")
    tr -d '\r' < "$src" > "$DEST/$name"
    chmod +x "$DEST/$name"
    printf '  %s\n' "$name"
}

echo "installing lab scripts:"
for f in "$SRC"/lab/*; do [ -f "$f" ] && install_one "$f"; done

echo "installing analysis scripts:"
for f in "$SRC"/analysis/*; do [ -f "$f" ] && install_one "$f"; done

# re-desktop-stop is generated rather than stored: it is three lines and must
# stay in step with the display re-desktop uses.
cat > "$DEST/re-desktop-stop" <<'EOF'
#!/bin/bash
pkill -f "xfce4-session" 2>/dev/null
pkill -f "Xephyr :10" 2>/dev/null
sleep 1
# Both must go: the lock is what makes X refuse to start again, and it
# survives any unclean kill.
rm -f /tmp/.X11-unix/X10 /tmp/.X10-lock
echo stopped
EOF
chmod +x "$DEST/re-desktop-stop"
echo "  re-desktop-stop (generated)"

echo
echo "MCP server:"
mkdir -p /opt/re-lab-mcp
tr -d '\r' < "$SRC/mcp/lab_mcp.py" > /opt/re-lab-mcp/lab_mcp.py
if [ ! -d /opt/re-lab-mcp/venv ]; then
    python3 -m venv /opt/re-lab-mcp/venv
    # FastMCP was renamed in mcp 2.x; this server targets the 1.x API.
    /opt/re-lab-mcp/venv/bin/pip install -q 'mcp<2'
fi
chown -R oddity:oddity /opt/re-lab-mcp
echo "  /opt/re-lab-mcp/lab_mcp.py"

echo
echo "done. P-code disassembly also needs the opcode table:"
echo "  see README.md -> pcode-dis.py needs the opcode table"
