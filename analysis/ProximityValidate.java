import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

import java.util.*;

/**
 * How often is the proximity heuristic right?
 *
 * Take functions whose class IS known, pretend it is unknown, and see whether
 * the neighbours on either side predict it. Same rules as ProximityCluster.
 * Without this the 649 assignments it offers are an unmeasured guess.
 */
public class ProximityValidate extends GhidraScript {
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
        List<Function> fns = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) fns.add(f);
        fns.sort(Comparator.comparing(Function::getEntryPoint));

        int tested = 0, correct = 0, wrong = 0;
        List<String> misses = new ArrayList<>();

        for (int i = 0; i < fns.size(); i++) {
            String truth = classOf(fns.get(i).getName());
            if (truth == null) continue;

            // Neighbours, skipping the function under test.
            String before = null, after = null;
            long dB = 0, dA = 0;
            for (int j = i - 1; j >= 0; j--) {
                String c = classOf(fns.get(j).getName());
                if (c != null) { before = c; dB = fns.get(i).getEntryPoint().subtract(fns.get(j).getEntryPoint()); break; }
                if (!fns.get(j).getName().startsWith("FUN_")) break;
            }
            for (int j = i + 1; j < fns.size(); j++) {
                String c = classOf(fns.get(j).getName());
                if (c != null) { after = c; dA = fns.get(j).getEntryPoint().subtract(fns.get(i).getEntryPoint()); break; }
                if (!fns.get(j).getName().startsWith("FUN_")) break;
            }
            if (before == null || after == null) continue;
            if (!before.equals(after)) continue;
            if (dB > MAX_GAP || dA > MAX_GAP) continue;

            tested++;
            if (before.equals(truth)) correct++;
            else { wrong++; if (misses.size() < 6) misses.add(before + " predicted, actually " + truth); }
        }
        println("VALID tested=" + tested);
        println("VALID correct=" + correct);
        println("VALID wrong=" + wrong);
        if (tested > 0) println("VALID accuracy=" + (correct * 100 / tested) + "%");
        for (String m : misses) println("VALID miss: " + m);
    }
}
