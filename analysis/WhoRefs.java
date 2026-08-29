import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

/** Every reference to an address, saying whether the referrer is itself lifted. */
public class WhoRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address t = toAddr(Long.parseLong(getScriptArgs()[0].replace("0x",""),16));
        Reference[] rs = getReferencesTo(t);
        println("WR target=" + t + " references=" + rs.length);
        for (Reference r : rs) {
            Address from = r.getFromAddress();
            Function f = getFunctionContaining(from);
            Instruction i = getInstructionAt(from);
            println("WR  from=" + from
                    + "  type=" + r.getReferenceType()
                    + "  in=" + (f == null ? "ORPHAN (not lifted)" : f.getName())
                    + "  insn=" + (i == null ? "(data)" : i.toString()));
        }
    }
}
