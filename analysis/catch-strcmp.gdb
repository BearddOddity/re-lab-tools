set pagination off
set confirm off
set logging file /mnt/share/strcmp.log
set logging overwrite on
set logging enabled on

# __vbaStrCmp(BSTR a, BSTR b) - stdcall, so the two BSTR pointers are at
# [esp+4] and [esp+8] on entry. A BSTR points at UTF-16 data with its byte
# length stored in the 4 bytes just before it.
break *0x735093da

commands
silent
printf "=== __vbaStrCmp hit\n"
set $a = *(unsigned int *)($esp + 4)
set $b = *(unsigned int *)($esp + 8)
printf "arg1 ptr = 0x%08x  len = %d bytes\n", $a, *(unsigned int *)($a - 4)
printf "arg2 ptr = 0x%08x  len = %d bytes\n", $b, *(unsigned int *)($b - 4)
printf "arg1 utf16:\n"
x/32hx $a
printf "arg2 utf16:\n"
x/32hx $b
continue
end

continue
