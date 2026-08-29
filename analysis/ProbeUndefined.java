import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

/**
 * What surrounds an address that has instructions but no function?
 *
 * A recompiler lifts functions. Code the analyser never promoted to a function
 * is invisible to it, so a table written only from there looks unwritten - which
 * is a very different problem from a table nobody writes.
 *
 * args: <hexAddr> [contextInstructions]
 */
public class ProbeUndefined extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long v = Long.parseLong(a[0].replace("0x", ""), 16);
        int ctx = a.length > 1 ? Integer.parseInt(a[1]) : 20;
        Address at = toAddr(v);

        Function f = getFunctionContaining(at);
        println("PU addr=" + at + " function=" + (f == null ? "NONE" : f.getName()));

        // Walk back to the start of the contiguous instruction run.
        Instruction ins = getInstructionAt(at);
        if (ins == null) { println("PU no instruction here - it is data"); return; }
        Instruction first = ins;
        for (int i = 0; i < 400; i++) {
            Instruction p = first.getPrevious();
            if (p == null || !p.getMaxAddress().add(1).equals(first.getAddress())) break;
            first = p;
        }
        println("PU contiguous_code_starts=" + first.getAddress()
                + "  in_function=" + (getFunctionContaining(first.getAddress()) != null));
        println("PU  entry-point references to that start: "
                + getReferencesTo(first.getAddress()).length);

        println("PU --- context ---");
        Instruction cur = first;
        for (int i = 0; i < ctx && cur != null; i++) {
            Function cf = getFunctionContaining(cur.getAddress());
            println(String.format("PU  %s %-42s %s", cur.getAddress(), cur.toString(),
                    cf == null ? "" : "[" + cf.getName() + "]"));
            cur = cur.getNext();
        }
    }
}
