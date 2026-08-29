import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

import java.io.PrintWriter;

/**
 * Export the analysis as text so it can live in git instead of a 465 MB
 * database.
 *
 * args: <output file>
 *
 * A Ghidra project is an opaque binary: it cannot be diffed, reviewed in a pull
 * request, or merged when two people work at once, and it is regenerable from
 * the original executable plus the scripts that produced it. The names, labels
 * and prototypes are the part worth versioning, and they are under a megabyte.
 *
 * Format, one record per line, tab separated:
 *   F <addr> <name> <callingConvention> <prototype>
 *   L <addr> <name>            (labels: data, vtables, RTTI structures)
 *
 * Re-apply with ApplyAnalysis.java against a freshly imported program.
 */
public class ExportAnalysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("EXPORT need an output path"); return; }
        PrintWriter w = new PrintWriter(a[0]);
        w.printf("# program=%s%n", currentProgram.getName());
        w.printf("# imagebase=%s%n", currentProgram.getImageBase());
        w.printf("# sha256=%s%n", currentProgram.getExecutableSHA256());

        int funcs = 0, labels = 0;
        FunctionIterator fit = currentProgram.getListing().getFunctions(true);
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            String n = f.getName();
            if (n.startsWith("FUN_") || n.startsWith("thunk_FUN_")) continue;
            String proto = f.getSignature() == null ? "" :
                    f.getSignature().getPrototypeString().replace('\t', ' ').replace('\n', ' ');
            w.printf("F\t%s\t%s\t%s\t%s%n", f.getEntryPoint(), n,
                     f.getCallingConventionName(), proto);
            funcs++;
        }

        // Labels carry the data-side work: vtables, RTTI structures, the
        // D3DRS_* render-state globals. Names alone would lose all of it.
        SymbolIterator sit = currentProgram.getSymbolTable().getAllSymbols(false);
        while (sit.hasNext() && !monitor.isCancelled()) {
            Symbol s = sit.next();
            if (s.getSymbolType() != SymbolType.LABEL) continue;
            if (s.getSource() == ghidra.program.model.symbol.SourceType.DEFAULT) continue;
            w.printf("L\t%s\t%s%n", s.getAddress(), s.getName());
            labels++;
        }
        w.close();
        println("EXPORT functions=" + funcs + " labels=" + labels + " -> " + a[0]);
    }
}
