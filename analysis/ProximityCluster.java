import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

/**
 * Infer class membership for unnamed functions from their neighbours.
 *
 * A compiler emits one class's methods together, so an unnamed function sitting
 * between two functions of the same class very probably belongs to it. This is
 * AFFILIATION, not identification: it says which class, never which method, so
 * the name it assigns says exactly that.
 *
 * args: [apply]     - measures only unless the word "apply" is passed
 *
 * Conservative on purpose:
 *  - both neighbours must belong to the same class
 *  - the gap must not span more than MAX_GAP bytes on either side
 *  - template placeholder classes are skipped; they are containers instantiated
 *    all over the binary and their neighbours mean nothing
 */
public class ProximityCluster extends GhidraScript {
    private static final long MAX_GAP = 0x400;

    private static String classOf(String n) {
        int i = n.indexOf("::");
        if (i <= 0) return null;
        String c = n.substring(0, i);
        if (c.startsWith("tmpl_")) return null;
        return c;
    }

    @Override
    public void run() throws Exception {
        boolean apply = getScriptArgs().length > 0 && getScriptArgs()[0].equals("apply");

        List<Function> fns = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) fns.add(f);
        fns.sort(Comparator.comparing(Function::getEntryPoint));

        int assigned = 0, disagreed = 0, tooFar = 0, noAnchor = 0;
        Map<String, Integer> perClass = new HashMap<>();
        List<String> examples = new ArrayList<>();

        for (int i = 0; i < fns.size(); i++) {
            Function f = fns.get(i);
            if (!f.getName().startsWith("FUN_")) continue;

            String before = null, after = null;
            long dBefore = 0, dAfter = 0;
            for (int j = i - 1; j >= 0; j--) {
                String c = classOf(fns.get(j).getName());
                if (c != null) {
                    before = c;
                    dBefore = f.getEntryPoint().subtract(fns.get(j).getEntryPoint());
                    break;
                }
                if (!fns.get(j).getName().startsWith("FUN_")) break;   // a non-class name breaks the run
            }
            for (int j = i + 1; j < fns.size(); j++) {
                String c = classOf(fns.get(j).getName());
                if (c != null) {
                    after = c;
                    dAfter = fns.get(j).getEntryPoint().subtract(f.getEntryPoint());
                    break;
                }
                if (!fns.get(j).getName().startsWith("FUN_")) break;
            }

            if (before == null || after == null) { noAnchor++; continue; }
            if (!before.equals(after))           { disagreed++; continue; }
            if (dBefore > MAX_GAP || dAfter > MAX_GAP) { tooFar++; continue; }

            if (apply) {
                f.setName(before + "::near_" + f.getEntryPoint(), SourceType.ANALYSIS);
            }
            assigned++;
            perClass.merge(before, 1, Integer::sum);
            if (examples.size() < 6) examples.add(before + "::near_" + f.getEntryPoint());
        }

        println("PROX mode=" + (apply ? "APPLIED" : "measure-only"));
        println("PROX assigned=" + assigned);
        println("PROX rejected_neighbours_disagree=" + disagreed);
        println("PROX rejected_gap_too_large=" + tooFar);
        println("PROX rejected_no_class_anchor=" + noAnchor);
        perClass.entrySet().stream()
                .sorted((x, y) -> y.getValue() - x.getValue()).limit(8)
                .forEach(e -> println("PROX  " + e.getKey() + " -> " + e.getValue()));
        for (String x : examples) println("PROX example: " + x);
    }
}
