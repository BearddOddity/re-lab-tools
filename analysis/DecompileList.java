import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.*;

/** Decompile exactly the addresses listed in a file, with call context. */
public class DecompileList extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 2) { println("DL need <addrlist> <output>"); return; }
        List<Address> want = new ArrayList<>();
        BufferedReader r = new BufferedReader(new FileReader(a[0]));
        String line;
        while ((line = r.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            Address ad = toAddr(line);
            if (ad != null) want.add(ad);
        }
        r.close();

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        PrintWriter w = new PrintWriter(a[1]);
        int done = 0;
        for (Address ad : want) {
            if (monitor.isCancelled()) break;
            Function f = getFunctionAt(ad);
            if (f == null) continue;
            DecompileResults res = di.decompileFunction(f, 90, monitor);
            if (res == null || !res.decompileCompleted()) continue;
            w.println("================================================================");
            w.printf("FUNCTION %s  %s  (%d bytes)%n", f.getEntryPoint(), f.getName(),
                     f.getBody().getNumAddresses());
            Set<String> callers = new TreeSet<>();
            for (Reference rf : getReferencesTo(f.getEntryPoint())) {
                Function c = getFunctionContaining(rf.getFromAddress());
                if (c != null && !c.equals(f)) callers.add(c.getName());
            }
            Set<String> callees = new TreeSet<>();
            for (Function c : f.getCalledFunctions(monitor)) callees.add(c.getName());
            w.println("CALLERS: " + String.join(", ", cap(callers)));
            w.println("CALLS  : " + String.join(", ", cap(callees)));
            w.println("----------------------------------------------------------------");
            w.println(res.getDecompiledFunction().getC());
            done++;
        }
        w.close(); di.dispose();
        println("DL decompiled=" + done + " -> " + a[1]);
    }
    private static List<String> cap(Set<String> s) {
        List<String> l = new ArrayList<>(s);
        return l.size() > 16 ? l.subList(0, 16) : l;
    }
}
