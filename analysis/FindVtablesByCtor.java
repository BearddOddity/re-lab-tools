import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

/**
 * Find vtables the RTTI walk cannot see, by the way constructors assign them.
 *
 * WalkMsvcRtti starts from type descriptors, so it only ever finds classes the
 * compiler emitted RTTI for. A class built without it is completely invisible to
 * that method - and one such class is why the subsystem table at 0x005BB700 is
 * never written: its registrar is virtual slot 40 of an RTTI-less vtable.
 *
 * A constructor assigns the vptr with `mov [reg], <address>` where the address
 * begins an array of code pointers. That store is evidence RTTI cannot give and
 * needs no type information at all.
 *
 * args: [apply]
 *
 * Guards against naming ordinary data:
 *  - the target must begin at least MIN_SLOTS consecutive pointers to code
 *  - the store must be to [reg] or a small positive displacement, which is where
 *    a vptr lives; a large offset is some other member being initialised
 *  - vtables the RTTI walk already named are left alone
 */
public class FindVtablesByCtor extends GhidraScript {
    private static final int MIN_SLOTS = 4;
    private static final int MAX_DISP = 0x40;

    private boolean codePtrAt(Address p) {
        try {
            Address t = toAddr(getInt(p) & 0xFFFFFFFFL);
            if (t == null) return false;
            MemoryBlock b = currentProgram.getMemory().getBlock(t);
            return b != null && b.isExecute()
                   && (getInstructionAt(t) != null || getFunctionAt(t) != null);
        } catch (Exception e) { return false; }
    }

    private int slotCount(Address start) {
        int n = 0;
        Address p = start;
        while (n < 512 && codePtrAt(p)) { n++; p = p.add(4); }
        return n;
    }

    @Override
    public void run() throws Exception {
        boolean apply = getScriptArgs().length > 0 && getScriptArgs()[0].equals("apply");
        Memory mem = currentProgram.getMemory();

        Map<Address, Set<Function>> vtables = new LinkedHashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            if (!ins.getMnemonicString().startsWith("MOV")) continue;
            if (ins.getNumOperands() < 2) continue;
            String dst = ins.getDefaultOperandRepresentation(0);
            if (!dst.contains("[")) continue;              // a store: "dword ptr [ESI]"
            // [reg] or [reg + small]: where a vptr sits.
            if (dst.contains("+")) {
                try {
                    String tail = dst.substring(dst.indexOf('+') + 1).replace("]", "").trim();
                    long d = Long.decode(tail.startsWith("0x") ? tail : "0x" + tail);
                    if (d > MAX_DISP) continue;
                } catch (Exception e) { continue; }
            }
            for (Object o : ins.getOpObjects(1)) {
                if (!(o instanceof Scalar)) continue;
                Address t = toAddr(((Scalar) o).getUnsignedValue());
                if (t == null || !mem.contains(t)) continue;
                // Section flags cannot be used here: this XBE marks .rdata
                // executable, so isExecute() is true for the vtables too. What
                // separates a table from code is that the target is not itself
                // an instruction.
                MemoryBlock b = mem.getBlock(t);
                if (b == null || getInstructionAt(t) != null) continue;
                if (slotCount(t) < MIN_SLOTS) continue;
                Function ctor = getFunctionContaining(ins.getAddress());
                vtables.computeIfAbsent(t, k -> new LinkedHashSet<>());
                if (ctor != null) vtables.get(t).add(ctor);
            }
        }
        println("VC candidate_vtables=" + vtables.size());

        int known = 0, fresh = 0, namedFns = 0, namedCtors = 0;
        for (Map.Entry<Address, Set<Function>> e : vtables.entrySet()) {
            Address vt = e.getKey();
            int slots = slotCount(vt);
            // Already covered by the RTTI walk? Its slot functions carry ::vfunc.
            boolean rttiKnown = false;
            for (int i = 0; i < Math.min(slots, 8); i++) {
                Function f = getFunctionAt(toAddr(getInt(vt.add(i * 4L)) & 0xFFFFFFFFL));
                if (f != null && f.getName().contains("::vfunc")) { rttiKnown = true; break; }
            }
            if (rttiKnown) { known++; continue; }
            fresh++;
            String tag = "vt_" + vt;
            if (!apply) continue;
            for (int i = 0; i < slots; i++) {
                Address t = toAddr(getInt(vt.add(i * 4L)) & 0xFFFFFFFFL);
                Function f = getFunctionAt(t);
                if (f == null) f = createFunction(t, null);
                if (f == null) continue;
                if (f.getName().startsWith("FUN_")) {
                    f.setName(tag + "::vfunc" + i, SourceType.ANALYSIS);
                    namedFns++;
                }
            }
            for (Function c : e.getValue())
                if (c.getName().startsWith("FUN_")) {
                    c.setName(tag + "::ctor_" + c.getEntryPoint(), SourceType.ANALYSIS);
                    namedCtors++;
                }
        }
        println("VC already_known_from_rtti=" + known);
        println("VC NEW_vtables_rtti_missed=" + fresh);
        println("VC mode=" + (apply ? "APPLIED" : "measure-only"));
        println("VC functions_named=" + namedFns + " ctors_named=" + namedCtors);
    }
}
