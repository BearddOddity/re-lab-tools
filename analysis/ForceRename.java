import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Rename functions unconditionally, and drop stray labels at the same address.
 *
 * ApplyXbSymbols refuses to overwrite a non-default name on purpose, which is
 * right for importing but wrong for correcting a name that should not be there.
 * Backing out a bad name needs a tool that will actually overwrite one.
 *
 * args: <file of "NewName = 0xADDR">
 */
public class ForceRename extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("FR need a file"); return; }
        int done = 0, cleared = 0;
        BufferedReader r = new BufferedReader(new FileReader(a[0]));
        String line;
        while ((line = r.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#") || !line.contains("=")) continue;
            String[] p = line.split("=", 2);
            String want = p[0].trim();
            Address addr = toAddr(p[1].trim());
            if (addr == null) continue;
            Function f = getFunctionAt(addr);
            if (f == null) continue;
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(addr)) {
                if (!s.isPrimary() && s.getSource() != SourceType.DEFAULT) { s.delete(); cleared++; }
            }
            // A default name is expressed by clearing the name, not by setting
            // the FUN_ text - setting it literally leaves a user-defined symbol
            // that merely looks default.
            if (want.startsWith("FUN_")) f.setName(null, SourceType.DEFAULT);
            else                          f.setName(want, SourceType.USER_DEFINED);
            done++;
            println("FR " + addr + " -> " + f.getName());
        }
        r.close();
        println("FR renamed=" + done + " stray_labels_cleared=" + cleared);
    }
}
