import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

/**
 * Name the functions that write a class vtable pointer into an object.
 *
 * MSVC constructors and destructors do `mov [ecx], offset SomeClass::vftable`.
 * Those functions are NOT virtual, so walking RTTI never reaches them - which is
 * exactly where naming stalls once the vtables are done.
 *
 * WHICH CLASS, WHEN A FUNCTION STORES SEVERAL
 * A derived constructor often has its base constructors inlined, so several
 * vtables get stored in one function: base first, then the class's own, last.
 * The store at the HIGHEST instruction address therefore names the function.
 *
 * WHY NOT "ctor"
 * A function storing a vtable may be a constructor, a destructor, or a factory,
 * and MSVC frequently shares code between constructor and destructor. Calling it
 * a constructor would be a guess presented as a fact, so it is named
 * ctor_or_dtor - accurate about what is known and about what is not.
 */
public class NameVtableStorers extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Map every vtable slot address to the class that owns it, using the
        // vfunc names the RTTI walk produced.
        Map<Address, String> slotOwner = new HashMap<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String n = f.getName();
            int i = n.indexOf("::vfunc");
            if (i <= 0) continue;
            String cls = n.substring(0, i);
            for (Reference r : getReferencesTo(f.getEntryPoint()))
                slotOwner.put(r.getFromAddress(), cls);
        }
        println("VTS vtable_slots=" + slotOwner.size());

        // For each function, remember the last vtable store by address.
        Map<Function, Address> lastAddr = new HashMap<>();
        Map<Function, String> lastCls = new HashMap<>();
        Map<Function, Set<String>> allCls = new HashMap<>();

        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (int op = 0; op < ins.getNumOperands(); op++) {
                for (Object o : ins.getOpObjects(op)) {
                    if (!(o instanceof Scalar)) continue;
                    Address a = toAddr(((Scalar) o).getUnsignedValue());
                    if (a == null) continue;
                    String cls = slotOwner.get(a);
                    if (cls == null) continue;
                    Function f = getFunctionContaining(ins.getAddress());
                    if (f == null) continue;
                    allCls.computeIfAbsent(f, k -> new HashSet<>()).add(cls);
                    Address prev = lastAddr.get(f);
                    if (prev == null || ins.getAddress().compareTo(prev) > 0) {
                        lastAddr.put(f, ins.getAddress());
                        lastCls.put(f, cls);
                    }
                }
            }
        }

        // Several functions per class is normal (ctor, dtor, vector variants),
        // so disambiguate with the entry address rather than a counter - stable
        // across runs and greppable back to the listing.
        int named = 0, kept = 0, multi = 0;
        List<String> examples = new ArrayList<>();
        for (Map.Entry<Function, String> e : lastCls.entrySet()) {
            Function f = e.getKey();
            if (!f.getName().startsWith("FUN_")) { kept++; continue; }
            String cls = e.getValue();
            if (allCls.get(f).size() > 1) multi++;
            String nm = cls + "::ctor_or_dtor_" + f.getEntryPoint();
            f.setName(nm, SourceType.ANALYSIS);
            named++;
            if (examples.size() < 8) examples.add(nm);
        }
        println("VTS functions_named=" + named);
        println("VTS already_named_kept=" + kept);
        println("VTS  (of the named, stored >1 vtable: " + multi + " - inlined base ctors)");
        for (String x : examples) println("VTS example: " + x);
    }
}
