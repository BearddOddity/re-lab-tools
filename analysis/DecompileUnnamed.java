import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

import java.io.PrintWriter;
import java.util.*;

/**
 * Decompile the largest still-unnamed functions to a text file.
 *
 * args: <output> [count] [minCodeUnits]
 *
 * Reading one function at a time through an interactive tool is the slow way to
 * do this. The point of a batch dump is that the expensive part - decompiling -
 * happens once, unattended, and what comes back can be read and named in bulk.
 *
 * Each entry carries the callers and callees too. A function's neighbours in the
 * call graph are usually what identifies it: "called by CCamera::vfunc12 and
 * calls sqrtf" narrows things far faster than the body alone.
 *
 * Skips inferred names (near_, helper_) - those are affiliation, not
 * identification, so their functions still deserve a real look.
 */
public class DecompileUnnamed extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("DEC need an output path"); return; }
        int want = a.length > 1 ? Integer.parseInt(a[1]) : 25;
        int minUnits = a.length > 2 ? Integer.parseInt(a[2]) : 0;

        List<Function> cands = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String n = f.getName();
            boolean unknown = n.startsWith("FUN_") || n.contains("::near_") || n.contains("::helper_");
            if (!unknown) continue;
            long units = f.getBody().getNumAddresses();
            if (units < minUnits) continue;
            cands.add(f);
        }
        cands.sort((x, y) -> Long.compare(y.getBody().getNumAddresses(), x.getBody().getNumAddresses()));
        println("DEC candidates=" + cands.size());

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        PrintWriter w = new PrintWriter(a[0]);
        int done = 0;
        for (Function f : cands) {
            if (done >= want || monitor.isCancelled()) break;
            DecompileResults res = di.decompileFunction(f, 90, monitor);
            if (res == null || !res.decompileCompleted()) continue;

            w.println("================================================================");
            w.printf("FUNCTION %s  %s  (%d bytes)%n", f.getEntryPoint(), f.getName(),
                     f.getBody().getNumAddresses());

            Set<String> callers = new TreeSet<>();
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                Function c = getFunctionContaining(r.getFromAddress());
                if (c != null && !c.equals(f)) callers.add(c.getName());
            }
            Set<String> callees = new TreeSet<>();
            for (Function c : f.getCalledFunctions(monitor)) callees.add(c.getName());

            w.println("CALLERS: " + (callers.isEmpty() ? "(none found)" : String.join(", ", trim(callers))));
            w.println("CALLS  : " + (callees.isEmpty() ? "(none)" : String.join(", ", trim(callees))));
            w.println("----------------------------------------------------------------");
            w.println(res.getDecompiledFunction().getC());
            done++;
        }
        w.close();
        di.dispose();
        println("DEC decompiled=" + done + " -> " + a[0]);
    }

    private static List<String> trim(Set<String> s) {
        List<String> l = new ArrayList<>(s);
        return l.size() > 14 ? l.subList(0, 14) : l;
    }
}
