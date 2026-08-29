import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.util.*;

/**
 * How much disassembled code sits outside every function?
 *
 * A recompiler lifts functions, so instructions the analyser never attributed to
 * one are invisible to it. If a table looks unwritten, this is the first thing to
 * check: the writer may exist and simply never have been lifted.
 *
 * args: [apply]   - with "apply", create functions at the runs that look like
 *                   real entry points (a prologue and something referencing them)
 */
public class OrphanCode extends GhidraScript {
    @Override
    public void run() throws Exception {
        boolean apply = getScriptArgs().length > 0 && getScriptArgs()[0].equals("apply");

        long orphanInstrs = 0;
        List<Address> runStarts = new ArrayList<>();
        Address runStart = null;
        Address prevEnd = null;

        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            boolean orphan = getFunctionContaining(ins.getAddress()) == null;
            if (orphan) {
                orphanInstrs++;
                if (runStart == null || prevEnd == null
                        || !prevEnd.add(1).equals(ins.getAddress())) {
                    if (runStart != null) runStarts.add(runStart);
                    runStart = ins.getAddress();
                }
                prevEnd = ins.getMaxAddress();
            } else if (runStart != null) {
                runStarts.add(runStart);
                runStart = null; prevEnd = null;
            }
        }
        if (runStart != null) runStarts.add(runStart);

        println("ORPHAN instructions_outside_any_function=" + orphanInstrs);
        println("ORPHAN contiguous_runs=" + runStarts.size());

        // Which runs look like genuine function entries: something references
        // them, and they open with a recognisable prologue.
        int candidates = 0, created = 0;
        for (Address s : runStarts) {
            if (getReferencesTo(s).length == 0) continue;
            Instruction i0 = getInstructionAt(s);
            if (i0 == null) continue;
            String m = i0.toString();
            boolean prologue = m.startsWith("PUSH EBP") || m.startsWith("SUB ESP")
                            || m.startsWith("PUSH EBX") || m.startsWith("PUSH ESI")
                            || m.startsWith("MOV EDI,EDI");
            if (!prologue) continue;
            candidates++;
            if (apply && createFunction(s, null) != null) created++;
        }
        println("ORPHAN referenced_runs_with_a_prologue=" + candidates);
        println("ORPHAN functions_created=" + created);
    }
}
