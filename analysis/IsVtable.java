import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

/**
 * Is this address inside an MSVC vtable, and if so whose?
 *
 * MSVC puts an RTTICompleteObjectLocator pointer immediately before a vtable.
 * The locator holds a TypeDescriptor pointer at +0x0C, and the type name sits at
 * TypeDescriptor+8. Walking that chain backwards from a candidate table start
 * names the class - or proves the table is not a vtable at all.
 *
 * args: <hexAddr> [maxSlotsBack]
 */
public class IsVtable extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long v = Long.parseLong(a[0].replace("0x", ""), 16);
        int back = a.length > 1 ? Integer.parseInt(a[1]) : 128;
        Memory mem = currentProgram.getMemory();

        for (int i = 0; i <= back; i++) {
            Address cand = toAddr(v - i * 4L);          // candidate vtable start
            Address colPtr = cand.subtract(4);
            int colV;
            try { colV = mem.getInt(colPtr); } catch (Exception e) { continue; }
            Address col = toAddr(colV & 0xFFFFFFFFL);
            if (col == null || !mem.contains(col)) continue;
            int sig;
            try { sig = mem.getInt(col); } catch (Exception e) { continue; }
            if (sig != 0) continue;                     // COL signature must be 0
            int tdV;
            try { tdV = mem.getInt(col.add(0x0C)); } catch (Exception e) { continue; }
            Address td = toAddr(tdV & 0xFFFFFFFFL);
            if (td == null || !mem.contains(td)) continue;
            StringBuilder nm = new StringBuilder();
            for (int k = 0; k < 160; k++) {
                byte b;
                try { b = mem.getByte(td.add(8 + k)); } catch (Exception e) { break; }
                if (b == 0) break;
                nm.append((char) (b & 0xFF));
            }
            if (nm.length() > 3 && nm.charAt(0) == '.') {
                println("VT vtable_start=" + cand);
                println("VT slot_of_query=" + i);
                println("VT class=" + nm);
                return;
            }
        }
        println("VT no vtable found within " + back + " slots - not a vtable");
    }
}
