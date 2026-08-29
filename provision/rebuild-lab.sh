#!/bin/bash
# rebuild-lab.sh - recreate the RE lab from a stock Kali WSL image.
#
# Run INSIDE a fresh kali-linux distro as root:
#
#   wsl --install kali-linux --no-launch
#   wsl -d kali-linux -u root -- bash /mnt/share/provision/rebuild-lab.sh
#
# This exists instead of an image backup because the lab snapshot is ~13 GB -
# far past GitHub's 100 MB per-file limit. A rebuild script is also portable to
# a different machine and shows what actually changed, which a tarball does not.
#
# For a same-machine restore, the snapshot is still faster:
#   D:\re-lab\restore.ps1
set -eu

USER_NAME=oddity
SHARE_WIN='D:/re-lab-share'
GHIDRA_VER=12.1.3
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_20260817.zip"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

say() { printf '\n=== %s\n' "$*"; }

# ---------------------------------------------------------------- user
say "user $USER_NAME"
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo "$USER_NAME"
    passwd -d "$USER_NAME"
    echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-$USER_NAME
    chmod 440 /etc/sudoers.d/90-$USER_NAME
fi
# A password is NOT set here on purpose. Set your own if you ever need one:
#   wsl -d kali-linux -- sudo passwd oddity

# ---------------------------------------------------------------- isolation
say "wsl.conf and fstab"
# No automount: Windows drives are not visible inside the lab. Only the single
# share folder crosses, via fstab. Keeps an accident in here off the host disk.
cp "$SRC_DIR/provision/wsl.conf" /etc/wsl.conf
cp "$SRC_DIR/provision/fstab" /etc/fstab
mkdir -p /mnt/share

# wsl.conf turns systemd on, which needs a full `wsl --shutdown` to take effect
# - it changes PID 1, so a restart of the distro alone will not do it. Until
# then systemctl reports "offline" and nothing below that touches a unit works.

# ---------------------------------------------------------------- github cli
# gh is not in Debian or Kali, so it comes from GitHub's own repository. Needed
# for the lab to be a place work actually lives rather than a scratch machine:
# cloning, pushing and opening PRs without crossing back to Windows.
say "github cli"
install -d -m 0755 /etc/apt/keyrings
if curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg         -o /etc/apt/keyrings/githubcli-archive-keyring.gpg; then
    chmod 0644 /etc/apt/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main"         > /etc/apt/sources.list.d/github-cli.list
    apt-get update -qq && apt-get install -y -qq gh || true
fi

# Git identity, so commits made in here are attributed rather than anonymous.
# Authentication is deliberately NOT scripted - run `gh auth login` yourself.
sudo -u "$USER_NAME" bash -lc '
    git config --global user.name  "BearddOddity"
    git config --global user.email "saintlyendless@gmail.com"
    git config --global init.defaultBranch main
    git config --global core.autocrlf input
    git config --global credential.helper store
    git-lfs install --skip-repo >/dev/null 2>&1 || true
' || true

# ---------------------------------------------------------------- task manager
# Task Manager TMOG (Plummer's Software) replaces xfce4-taskmanager as the
# desktop's task manager. It is not in Debian or Kali, so the .deb has to be
# supplied - drop it in the source directory or /mnt/share and this picks it up.
#   https://github.com/PlummersSoftwareLLC/TMOG
TMOG_DEB=$(ls "$SRC_DIR"/TMOG-*.deb /mnt/share/TMOG-*.deb 2>/dev/null | head -1)
if [ -n "$TMOG_DEB" ]; then
    say "task manager (TMOG)"
    # The package under-declares its dependencies: it lists only libc6, libgcc,
    # libstdc++ and libsystemd, but links against Qt6 Multimedia for its splash
    # video and will not start without it.
    apt-get install -y -qq "$TMOG_DEB" libqt6multimedia6 || true

    # Desktop-entry override pointing at the wrapper, in /usr/local/share so a
    # package upgrade cannot overwrite it. That path outranks /usr/share in
    # XDG_DATA_DIRS.
    mkdir -p /usr/local/share/applications
    if [ -f /usr/share/applications/com.tmog.taskmanager.desktop ]; then
        sed 's|^Exec=tmog-task-manager|Exec=/usr/local/bin/tmog|'             /usr/share/applications/com.tmog.taskmanager.desktop             > /usr/local/share/applications/com.tmog.taskmanager.desktop
    fi

    # xfce4-taskmanager cannot be removed - kali-desktop-xfce depends on it, and
    # removing it takes the desktop metapackage with it. Hide its launcher
    # instead: the dependency stays satisfied and TMOG is the only task manager
    # the menu offers.
    if [ -f /usr/share/applications/xfce4-taskmanager.desktop ]; then
        { sed 's|^NoDisplay=.*||' /usr/share/applications/xfce4-taskmanager.desktop
          echo 'NoDisplay=true'; } > /usr/local/share/applications/xfce4-taskmanager.desktop
    fi
    update-desktop-database /usr/local/share/applications 2>/dev/null || true

    # Ctrl+Shift+Escape, by absolute path - xfsettingsd spawns with its own PATH
    # and a bare command name silently does nothing.
    sudo -u "$USER_NAME" bash -lc         "xfconf-query -c xfce4-keyboard-shortcuts -p '/commands/custom/<Primary><Shift>Escape' -s '/usr/local/bin/tmog' -n -t string"         2>/dev/null || true
else
    say "task manager (TMOG) - no TMOG-*.deb found, skipping"
fi

# ---------------------------------------------------------------- services
# Only reachable once systemd is PID 1 (see wsl.conf above). Skipped rather than
# failed when it is not, so a first pass before `wsl --shutdown` still completes.
if [ "$(systemctl is-system-running 2>/dev/null)" != "offline" ]; then
    say "services"
    # tpm-udev fails on every boot because WSL passes no TPM through, and one
    # failed unit is enough to make systemctl report the whole system as
    # "degraded" - which hides real failures behind permanent noise.
    systemctl mask tpm-udev.path tpm-udev.service >/dev/null 2>&1 || true
    # accounts-daemon cannot start either: it needs /run/systemd/seats, and
    # logind creates no seats under WSL because there is no session hardware.
    # It serves display-manager greeters, and this desktop launches XFCE
    # directly, so nothing here wants it.
    systemctl mask accounts-daemon.service >/dev/null 2>&1 || true
    systemctl enable --now cron >/dev/null 2>&1 || true
    systemctl reset-failed >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------- packages
say "packages"
export DEBIAN_FRONTEND=noninteractive
dpkg --add-architecture i386
apt-get update -qq
# Desktop, RE toolset, Wine with 32-bit support (most crackmes are 32-bit),
# and the build chain for the GhidraMCP fork.
apt-get install -y -qq \
    xfce4 xfce4-terminal thunar dbus-x11 xserver-xephyr x11-utils xdotool imagemagick \
    ghidra radare2 gdb gdb-multiarch binwalk upx-ucl ltrace strace hexedit yara \
    python3-pefile python3-capstone python3-lief python3-unicorn python3-pip python3-venv patchelf vim-common \n    git-lfs ninja-build pkg-config ccache clang lld gdb mingw-w64 \n    libsdl2-dev libssl-dev libepoxy-dev libgl1-mesa-dev libasound2-dev \
    wine wine32:i386 wine64 cmake maven git cabextract curl unzip

# ---------------------------------------------------------------- ghidra
say "ghidra $GHIDRA_VER"
if [ ! -d "/opt/ghidra_${GHIDRA_VER}_PUBLIC" ]; then
    tmp=$(mktemp -d)
    curl -sL -o "$tmp/ghidra.zip" "$GHIDRA_URL"
    unzip -q -o "$tmp/ghidra.zip" -d /opt/
    rm -rf "$tmp"
fi

# ---------------------------------------------------------------- ghidramcp fork
say "GhidraMCP fork"
# Upstream plus our patch: adds import_binary, read_bytes, search_bytes,
# get_program_info, get_callers/callees, patch_bytes, export_program,
# analyze_program, save_program. Forked at 27f316f.
sudo -u "$USER_NAME" bash <<EOF
set -eu
mkdir -p ~/src && cd ~/src
[ -d GhidraMCP ] || git clone -q https://github.com/LaurieWired/GhidraMCP.git
cd GhidraMCP
git checkout -q 27f316f80139e2d5dec882519a1bdf4aa46ac04c 2>/dev/null || true
git apply --check "$SRC_DIR/ghidra-mcp/ghidramcp-relab.patch" && \
  git apply "$SRC_DIR/ghidra-mcp/ghidramcp-relab.patch" || echo "patch already applied"
mkdir -p lib
for j in Generic SoftwareModeling Project Docking Decompiler Utility Base Gui; do
    f=\$(find /opt/ghidra_${GHIDRA_VER}_PUBLIC -name "\$j.jar" | head -1)
    [ -n "\$f" ] && cp "\$f" lib/
done
mvn -q -B clean package
EOF

EXT=/home/$USER_NAME/.config/ghidra/ghidra_${GHIDRA_VER}_PUBLIC/Extensions
mkdir -p "$EXT"
unzip -q -o "/home/$USER_NAME/src/GhidraMCP/target/GhidraMCP-1.0-SNAPSHOT.zip" -d "$EXT"
# Ghidra 12 rejects the upstream Module.manifest format outright - and rejects
# the whole module silently, so the extension simply never appears.
printf '' > "$EXT/GhidraMCP/Module.manifest"
chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.config/ghidra"

# ---------------------------------------------------------------- mcp bridges
say "MCP bridges"
mkdir -p /opt/ghidra-mcp
cp "/home/$USER_NAME/src/GhidraMCP/bridge_mcp_ghidra.py" /opt/ghidra-mcp/ 2>/dev/null || \
  cp "$SRC_DIR/ghidra-mcp/bridge_mcp_ghidra.py" /opt/ghidra-mcp/ 2>/dev/null || true
patch -p0 -d /opt/ghidra-mcp -i "$SRC_DIR/ghidra-mcp/bridge-relab.patch" 2>/dev/null || \
  echo "bridge patch skipped (already applied or bridge missing)"
python3 -m venv /opt/ghidra-mcp/venv
# FastMCP was renamed in mcp 2.x; these bridges target the 1.x API.
/opt/ghidra-mcp/venv/bin/pip install -q 'mcp<2' requests
chown -R "$USER_NAME:$USER_NAME" /opt/ghidra-mcp

# ---------------------------------------------------------------- tools
say "lab tooling"
bash "$SRC_DIR/install.sh" "$SRC_DIR"

# ---------------------------------------------------------------- wine prefixes
say "wine prefixes (32-bit first, most crackmes are 32-bit)"
sudo -u "$USER_NAME" env WINEARCH=win32 WINEPREFIX="/home/$USER_NAME/.wine32" \
    WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=-all wineboot -u >/dev/null 2>&1 || true

cat <<'EOF'

=== done

Remaining manual steps:

1.  wsl --shutdown          (on Windows - required, --terminate is not enough:
                             only a full shutdown rebuilds the WSLg sockets)

2.  Register the MCP servers:
      claude mcp add re-lab --scope user -- wsl.exe -d kali-linux -- \
        /opt/re-lab-mcp/venv/bin/python /opt/re-lab-mcp/lab_mcp.py
      claude mcp add ghidra --scope user -- wsl.exe -d kali-linux -- \
        /opt/ghidra-mcp/venv/bin/python /opt/ghidra-mcp/bridge_mcp_ghidra.py

3.  First Ghidra run: create a project, open ONE CodeBrowser, enable
    GhidraMCPPlugin via File > Configure > Developer, then File > Save Tool.
    Saving the tool is what makes every later CodeBrowser start the server
    without any dialogs.

4.  Optional, for VB6 P-code work - fetch the opcode table:
      curl -sL -o /tmp/vb.crate \
        https://static.crates.io/crates/visualbasic/visualbasic-0.1.0.crate
      tar xzf /tmp/vb.crate -C /tmp
      cp /tmp/visualbasic-0.1.0/data/opcodes.csv ~/targets/opcodes.csv

5.  Optional, for VB6 targets - the VB6 runtime:
      winetricks -q vb6run
EOF
