import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.PrintWriter;

/**
 * Dump every function as "fullHash specificHash codeUnits address name".
 *
 * args: <output file>
 *
 * Raw bytes cannot be compared across two binaries - the same library function
 * links at different addresses, so every absolute operand differs. FID's hash
 * exists precisely to mask the varying operands, which makes it the right tool
 * for asking "is this the same function as that one" across images.
 */
public class DumpFunctionHashes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("DUMP need an output path"); return; }
        FidService svc = new FidService();
        PrintWriter w = new PrintWriter(a[0]);
        int n = 0, unhashable = 0;
        FunctionIterator it = currentProgram.getListing().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            FidHashQuad q;
            try { q = svc.hashFunction(f); } catch (Exception e) { unhashable++; continue; }
            if (q == null) { unhashable++; continue; }
            w.printf("%016x %016x %d %s %s%n",
                     q.getFullHash(), q.getSpecificHash(), q.getCodeUnitSize(),
                     f.getEntryPoint(), f.getName());
            n++;
        }
        w.close();
        println("DUMP program=" + currentProgram.getName() + " hashed=" + n + " unhashable=" + unhashable);
    }
}
