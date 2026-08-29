import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

/**
 * Print exactly what each predicate sees at a known-good vptr store, so a filter
 * that returns nothing can be debugged against a case that must match rather
 * than by guessing at string formats.
 */
public class DebugVptrMatch extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String s : new String[]{"0020de39", "00216196"}) {
            Address at = toAddr(Long.parseLong(s, 16));
            Instruction ins = getInstructionAt(at);
            println("DV --- " + at);
            if (ins == null) { println("DV   no instruction"); continue; }
            println("DV   toString      = " + ins);
            println("DV   mnemonic      = '" + ins.getMnemonicString() + "'");
            println("DV   numOperands   = " + ins.getNumOperands());
            for (int i = 0; i < ins.getNumOperands(); i++) {
                println("DV   op[" + i + "] repr   = '" + ins.getDefaultOperandRepresentation(i) + "'");
                Object[] objs = ins.getOpObjects(i);
                for (Object o : objs)
                    println("DV     opObject    = " + o.getClass().getSimpleName() + " : " + o);
            }
            // what the scalar resolves to
            for (int i = 0; i < ins.getNumOperands(); i++)
                for (Object o : ins.getOpObjects(i))
                    if (o instanceof Scalar) {
                        Address t = toAddr(((Scalar) o).getUnsignedValue());
                        MemoryBlock b = t == null ? null : currentProgram.getMemory().getBlock(t);
                        println("DV     scalar->addr = " + t + " block="
                                + (b == null ? "null" : b.getName() + " exec=" + b.isExecute()));
                    }
        }
    }
}
