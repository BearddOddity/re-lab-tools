import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.*;

/**
 * Name functions from the string constants they reference.
 *
 * args: <map file> [apply]
 *
 * Map file, one rule per line:   <name><TAB><literal string>
 *
 * This reaches what RTTI and proximity cannot: non-virtual, non-member code with
 * no useful neighbours. It works whenever a binary statically links a library
 * whose diagnostic strings are public - zlib's "invalid literal/length code"
 * only ever appears in inflate's code path, so whatever references it IS that
 * function.
 *
 * A string referenced from several functions names none of them: the reference
 * would not say which one owns it. Those are reported instead of guessed.
 */
public class NameByStringXref extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("SX need a map file"); return; }
        boolean apply = a.length > 1 && a[1].equals("apply");

        List<String[]> rules = new ArrayList<>();
        BufferedReader r = new BufferedReader(new FileReader(a[0]));
        String line;
        while ((line = r.readLine()) != null) {
            if (line.startsWith("#") || line.trim().isEmpty()) continue;
            String[] p = line.split("\t", 2);
            if (p.length == 2) rules.add(p);
        }
        r.close();
        println("SX rules=" + rules.size());

        int named = 0, ambiguous = 0, notFound = 0, kept = 0;
        for (String[] rule : rules) {
            String want = rule[0], lit = rule[1];
            Set<Function> refs = new LinkedHashSet<>();
            Address cur = currentProgram.getMinAddress();
            while (cur != null && !monitor.isCancelled()) {
                Address hit = find(cur, lit.getBytes());
                if (hit == null) break;
                cur = hit.add(1);
                for (Reference rf : getReferencesTo(hit)) {
                    Function f = getFunctionContaining(rf.getFromAddress());
                    if (f != null) refs.add(f);
                }
            }
            if (refs.isEmpty()) { notFound++; println("SX  none: " + want); continue; }
            if (refs.size() > 1) {
                ambiguous++;
                println("SX  ambiguous: " + want + " referenced by " + refs.size() + " functions");
                continue;
            }
            Function f = refs.iterator().next();
            if (!f.getName().startsWith("FUN_") && !f.getName().contains("::near_")
                    && !f.getName().contains("::helper_")) {
                kept++;
                println("SX  kept: " + want + " -> already " + f.getName());
                continue;
            }
            if (apply) f.setName(want, SourceType.IMPORTED);
            named++;
            println("SX  " + want + " @ " + f.getEntryPoint());
        }
        println("SX mode=" + (apply ? "APPLIED" : "measure-only"));
        println("SX named=" + named + " ambiguous=" + ambiguous
                + " string_not_found=" + notFound + " already_named=" + kept);
    }
}
