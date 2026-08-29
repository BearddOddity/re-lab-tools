Kali RE Lab - Windows app
=========================

A Kali Linux desktop that behaves like an ordinary Windows application: it has a
Start-menu entry, its own icon, and a line in Apps & features. Underneath it is
a WSL2 distro running XFCE inside a nested X server, presented by WSLg as one
Windows window.


Install
-------

Right-click Install.ps1 -> Run with PowerShell.

Or from a PowerShell prompt:

    .\Install.ps1

No administrator rights are needed - everything is per-user.

Useful options:

    .\Install.ps1 -InstallDir 'D:\re-lab'
        Install somewhere other than %LOCALAPPDATA%\Programs\RE Lab.

    .\Install.ps1 -SnapshotDir 'D:\re-lab\snapshots'
        Put snapshots on a roomier drive. One snapshot of a provisioned lab is
        about 16 GB, so this matters if the install directory is on a small
        disk.

    .\Install.ps1 -LinkDistro
        Move the lab's virtual disk inside the app folder, so the app owns the
        machine rather than pointing at one registered elsewhere. Back up that
        folder and you have backed up the lab. Moving between drives copies
        every byte, so allow time.

If Windows blocks the scripts because they came from the internet, unblock them
first:

    Get-ChildItem *.ps1 | Unblock-File


What it needs first
-------------------

The Windows app is a launcher. The lab itself must exist:

    wsl --install kali-linux --no-launch
    wsl -d kali-linux -u root -- bash provision/rebuild-lab.sh
    wsl --shutdown

The installer checks for the distro and refuses to install shortcuts that would
open nothing, telling you exactly what is missing.

The `wsl --shutdown` is not optional. The lab runs systemd as PID 1, and that is
only picked up on a full shutdown - restarting the distro alone leaves systemd
"offline" and no services running.


What you get
------------

  Kali RE Lab                 the desktop in a window
  Kali RE Lab (Fullscreen)    no title bar; the closest thing to a real screen
  Kali RE Lab (Portrait)      1080x1920, for a rotated monitor
  Ghidra (RE Lab)             Ghidra on its own, as a normal Windows window
  RE Lab - Terminal           a Kali shell
  RE Lab - Snapshot           save a rollback point
  RE Lab - Restore            roll back (destroys the current lab, asks first)
  RE Lab - Shared Folder      the one folder shared with Windows

Inside: XFCE, GPU-accelerated through d3d12, sound via WSLg, a dark theme, and
a shared clipboard with Windows. systemd runs, so cron, timers and other
services work as they would on a normal machine.


Uninstall
---------

Apps & features -> Kali RE Lab, or run Uninstall.ps1 from the install folder.

It removes the shortcuts, the registry entry and the installed scripts. It does
NOT delete your snapshots or the WSL distro - both are reported so you can
remove them deliberately. To remove the lab itself:

    wsl --unregister kali-linux

Note that a shortcut is only deleted if it belongs to this install: the
uninstaller checks where each one points before touching it, so a second copy
of the app elsewhere is left alone.


Known behaviour
---------------

Do not move the desktop window with a script. WSLg tracks where it believes the
window is and translates pointer events against that; moving it behind WSLg's
back leaves clicks landing in the wrong place. Dragging it by the title bar is
fine.

The window's title bar cannot be themed dark. It is drawn by msrdc.exe, which
paints its own caption and ignores the usual DWM attributes. Use the Fullscreen
shortcut, which has no caption at all.

If GUI apps stop opening, run `wsl --shutdown` and start the app again. That
rebuilds WSLg's own system distro. A `wsl --terminate` is not enough.
