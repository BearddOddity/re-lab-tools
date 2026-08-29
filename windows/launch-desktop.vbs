' Opens the Kali desktop window with no console window of its own.
' The desktop is a nested X server (Xephyr) inside the lab; WSLg presents it to
' Windows as an ordinary window.
'
' Note: do NOT reposition this window with SetWindowPos from Windows. WSLg keeps
' its own idea of where the window sits and uses it to translate pointer events.
' Moving the window behind its back leaves that mapping stale, and every click
' then lands at the wrong place inside the desktop. Drag the window by its title
' bar instead - that keeps WSLg in sync.
Dim shell, size
size = "1400x900"
If WScript.Arguments.Count > 0 Then size = WScript.Arguments(0)
Set shell = CreateObject("WScript.Shell")
shell.Run "wsl.exe -d kali-linux -- re-desktop " & size, 0, False
