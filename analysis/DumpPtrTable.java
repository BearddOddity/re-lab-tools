import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Dump the pointer table around an address, walking outwards until the entries
 * stop looking like code pointers.
 *
 * args: <hexAddr> [maxEntriesEachWay]
 *
 * A function reached only by a DATA reference lives in a table. Knowing where
 * that table starts and ends, and what else is in it, is what turns "something
 * points here" into "this is the Nth entry of an init list".
 */
public class DumpPtrTable extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long v = Long.parseLong(a[0].replace("0x", ""), 16);
        int max = a.length > 1 ? Integer.parseInt(a[1]) : 40;
        Address at = toAddr(v);

        MemoryBlock b = currentProgram.getMemory().getBlock(at);
        println("PT addr=" + at + " block=" + (b == null ? "?" : b.getName()));

        // Walk back while entries still point at code.
        Address start = at;
        for (int i = 0; i < max; i++) {
            Address p = start.subtract(4);
            if (!looksLikeCodePtr(p)) break;
            start = p;
        }
        Address end = at;
        for (int i = 0; i < max; i++) {
            Address p = end.add(4);
            if (!looksLikeCodePtr(p)) break;
            end = p;
        }
        long entries = (end.subtract(start) / 4) + 1;
        println("PT table_start=" + start + " table_end=" + end + " entries=" + entries);

        Address p = start;
        for (int i = 0; i < entries && i < 64; i++, p = p.add(4)) {
            int val = getInt(p);
            Address t = toAddr(val & 0xFFFFFFFFL);
            Function f = t == null ? null : getFunctionAt(t);
            String mark = p.equals(at) ? "  <== the reference we followed" : "";
            println(String.format("PT  [%2d] %s -> %s  %s%s", i, p, t,
                    f == null ? "(no function)" : f.getName(), mark));
        }

        println("PT --- who references the table start ---");
        for (ghidra.program.model.symbol.Reference r : getReferencesTo(start)) {
            Function f = getFunctionContaining(r.getFromAddress());
            println("PT   from=" + r.getFromAddress() + " type=" + r.getReferenceType()
                    + " in=" + (f == null ? "ORPHAN" : f.getName()));
        }
    }

    private boolean looksLikeCodePtr(Address p) {
        try {
            int v = getInt(p);
            Address t = toAddr(v & 0xFFFFFFFFL);
            if (t == null) return false;
            MemoryBlock b = currentProgram.getMemory().getBlock(t);
            if (b == null || !b.isExecute()) return false;
            return getInstructionAt(t) != null || getFunctionAt(t) != null;
        } catch (Exception e) { return false; }
    }
}
