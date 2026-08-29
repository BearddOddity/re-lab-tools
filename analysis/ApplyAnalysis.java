import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Re-apply an ExportAnalysis dump to a freshly imported program.
 *
 * args: <analysis.txt>
 *
 * This is the other half of keeping the analysis in git as text rather than a
 * 465 MB database: import the executable, run this, and the names and labels
 * are back.
 *
 * The export records the SHA-256 of the program it came from and this refuses
 * to run against a different binary. Applying names by address to the wrong
 * build would silently produce a program full of confident, wrong labels.
 */
public class ApplyAnalysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("APPLY need an input path"); return; }

        int funcs = 0, labels = 0, missing = 0, kept = 0;
        BufferedReader r = new BufferedReader(new FileReader(a[0]));
        String line;
        while ((line = r.readLine()) != null) {
            if (line.startsWith("# sha256=")) {
                String want = line.substring(9).trim();
                String have = currentProgram.getExecutableSHA256();
                if (have != null && !have.isEmpty() && !have.equalsIgnoreCase(want)) {
                    println("APPLY REFUSED: export is for sha256 " + want);
                    println("APPLY          this program is    " + have);
                    r.close();
                    return;
                }
                continue;
            }
            if (line.startsWith("#") || line.isEmpty()) continue;
            String[] p = line.split("\t");
            if (p.length < 3) continue;
            Address addr = toAddr(p[1]);
            if (addr == null || !currentProgram.getMemory().contains(addr)) { missing++; continue; }

            if (p[0].equals("F")) {
                Function f = getFunctionAt(addr);
                if (f == null) f = createFunction(addr, null);
                if (f == null) { missing++; continue; }
                if (!f.getName().startsWith("FUN_") && !f.getName().equals(p[2])) { kept++; continue; }
                f.setName(p[2], SourceType.IMPORTED);
                funcs++;
            } else if (p[0].equals("L")) {
                createLabel(addr, p[2], false, SourceType.IMPORTED);
                labels++;
            }
        }
        r.close();
        println("APPLY functions=" + funcs + " labels=" + labels
                + " kept_existing=" + kept + " unmappable=" + missing);
    }
}
