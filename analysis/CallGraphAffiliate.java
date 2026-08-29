import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

/**
 * Infer class affiliation from callers.
 *
 * A helper called only from one class's methods almost certainly belongs to it.
 * Like proximity this gives affiliation, never a method name, so the name says
 * so - and unlike proximity it works on functions with no near neighbours,
 * which is where proximity gave up (7,825 had no class anchor at all).
 *
 * args: [apply]
 *
 * Requires UNANIMITY among callers, and at least MIN_CALLERS of them: one
 * caller is a coincidence, and a helper called by three different classes is a
 * shared utility that would be mislabelled by picking a winner.
 */
public class CallGraphAffiliate extends GhidraScript {
    private static final int MIN_CALLERS = 4;

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
        int named = 0, mixed = 0, tooFew = 0, noNamedCaller = 0;
        Map<String, Integer> per = new HashMap<>();
        List<String> examples = new ArrayList<>();

        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!f.getName().startsWith("FUN_")) continue;
            Set<String> classes = new HashSet<>();
            int namedCallers = 0;
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                Function c = getFunctionContaining(r.getFromAddress());
                if (c == null || c.equals(f)) continue;
                String cls = classOf(c.getName());
                if (cls == null) continue;
                classes.add(cls);
                namedCallers++;
            }
            if (namedCallers == 0)          { noNamedCaller++; continue; }
            if (namedCallers < MIN_CALLERS) { tooFew++; continue; }
            if (classes.size() != 1)        { mixed++; continue; }

            String cls = classes.iterator().next();
            if (apply) f.setName(cls + "::helper_" + f.getEntryPoint(), SourceType.ANALYSIS);
            named++;
            per.merge(cls, 1, Integer::sum);
            if (examples.size() < 6) examples.add(cls + "::helper_" + f.getEntryPoint());
        }
        println("CG mode=" + (apply ? "APPLIED" : "measure-only"));
        println("CG assigned=" + named);
        println("CG rejected_callers_from_several_classes=" + mixed);
        println("CG rejected_too_few_named_callers=" + tooFew);
        println("CG rejected_no_named_caller=" + noNamedCaller);
        per.entrySet().stream().sorted((a,b)->b.getValue()-a.getValue()).limit(8)
           .forEach(e -> println("CG  " + e.getKey() + " -> " + e.getValue()));
        for (String x : examples) println("CG example: " + x);
    }
}
