import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Apply XbSymbolDatabase output ("NAME = 0xADDR" per line) to the current program.
 *
 * A name that was assigned by a person is worth more than a signature match, so
 * a function that already carries a non-default name keeps it and gains the SDK
 * name as a secondary label instead of being overwritten.
 */
public class ApplyXbSymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("XBSYM need a symbols file"); return; }

        int renamed = 0, labelled = 0, kept = 0, already = 0, bad = 0;
        BufferedReader r = new BufferedReader(new FileReader(args[0]));
        String line;
        while ((line = r.readLine()) != null) {
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            String name = line.substring(0, eq).trim();
            String as = line.substring(eq + 1).trim();
            if (name.isEmpty() || !as.startsWith("0x")) continue;
            Address addr;
            try { addr = toAddr(Long.parseLong(as.substring(2), 16)); }
            catch (Exception e) { bad++; continue; }
            if (addr == null || !currentProgram.getMemory().contains(addr)) { bad++; continue; }

            boolean exists = false;
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(addr)) {
                if (s.getName().equals(name)) { exists = true; break; }
            }
            if (exists) { already++; continue; }

            Function f = getFunctionAt(addr);
            if (f != null) {
                if (f.getName().startsWith("FUN_")) {
                    f.setName(name, SourceType.IMPORTED);
                    renamed++;
                } else {
                    createLabel(addr, name, false, SourceType.IMPORTED);
                    kept++;
                }
            } else {
                createLabel(addr, name, true, SourceType.IMPORTED);
                labelled++;
            }
        }
        r.close();
        println("XBSYM renamed_functions=" + renamed);
        println("XBSYM new_data_labels=" + labelled);
        println("XBSYM kept_existing_name_added_label=" + kept);
        println("XBSYM already_present=" + already);
        println("XBSYM unmappable=" + bad);
    }
}
