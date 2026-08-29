import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.*;

/** Same rule as CallGraphAffiliate, tested against functions whose class is known. */
public class CallGraphValidate extends GhidraScript {
    private static final int MIN_CALLERS = 4;
    private static String classOf(String n) {
        int i = n.indexOf("::");
        if (i <= 0) return null;
        String c = n.substring(0, i);
        return c.startsWith("tmpl_") ? null : c;
    }
    @Override
    public void run() throws Exception {
        int tested = 0, correct = 0;
        List<String> misses = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String truth = classOf(f.getName());
            if (truth == null) continue;
            // Only judge on truly independent evidence: skip callers of the same
            // class name we are trying to predict is trivially circular? No -
            // the prediction IS "callers agree", so use them as-is; what matters
            // is whether unanimous callers actually imply the callee's class.
            Set<String> classes = new HashSet<>();
            int namedCallers = 0;
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                Function c = getFunctionContaining(r.getFromAddress());
                if (c == null || c.equals(f)) continue;
                String cls = classOf(c.getName());
                if (cls == null) continue;
                classes.add(cls); namedCallers++;
            }
            if (namedCallers < MIN_CALLERS || classes.size() != 1) continue;
            tested++;
            String pred = classes.iterator().next();
            if (pred.equals(truth)) correct++;
            else if (misses.size() < 6) misses.add(pred + " predicted, actually " + truth);
        }
        println("CGV tested=" + tested + " correct=" + correct
                + " accuracy=" + (tested > 0 ? correct * 100 / tested : 0) + "%");
        for (String m : misses) println("CGV miss: " + m);
    }
}
