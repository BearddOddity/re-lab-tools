import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.InstructionIterator;

import java.util.*;

/**
 * Everything known about one address: which block it lives in, whether the file
 * initialises it, and every instruction that mentions it or the region around it.
 *
 * args: <hexAddr> [spanBytes]
 *
 * A table nothing appears to write is usually one of two things: written through
 * a base pointer the search never sees, or initialised by code the lift missed.
 * Distinguishing those needs the reads AND the writes, and the block's
 * initialised flag.
 */
public class ProbeAddress extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("PA need an address"); return; }
        long base = Long.parseLong(a[0].replace("0x", ""), 16);
        long span = 0x400;
        if (a.length > 1) {
            String sp = a[1].toLowerCase();
            // accept 0x400 as well as 1024 - passing hex here is the natural thing
            span = sp.startsWith("0x") ? Long.parseLong(sp.substring(2), 16)
                                       : Long.parseLong(sp);
        }
        Address at = toAddr(base);

        MemoryBlock blk = currentProgram.getMemory().getBlock(at);
        println("PA address=" + at);
        if (blk == null) { println("PA NOT MAPPED"); return; }
        println("PA block=" + blk.getName() + " " + blk.getStart() + "-" + blk.getEnd()
                + " initialized=" + blk.isInitialized()
                + " r=" + blk.isRead() + " w=" + blk.isWrite() + " x=" + blk.isExecute());

        if (blk.isInitialized()) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 32; i++) sb.append(String.format("%02x ", getByte(at.add(i))));
            println("PA first32=" + sb);
        }

        // Any instruction whose operand lands in [base, base+span)
        int reads = 0, writes = 0;
        Map<String, Integer> byFunc = new LinkedHashMap<>();
        List<String> writeSites = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            boolean touches = false;
            for (int op = 0; op < ins.getNumOperands(); op++)
                for (Object o : ins.getOpObjects(op))
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v >= base && v < base + span) touches = true;
                    }
            if (!touches) continue;
            Function f = getFunctionContaining(ins.getAddress());
            String fn = f == null ? "(no function)" : f.getName();
            byFunc.merge(fn, 1, Integer::sum);
            // Operand 0 being the destination means a write on x86 in Ghidra's
            // normalised form; good enough to separate readers from writers.
            String m = ins.getMnemonicString();
            boolean isWrite = m.startsWith("MOV") && ins.getNumOperands() > 1
                              && ins.getDefaultOperandRepresentation(0).contains("[");
            if (isWrite) { writes++; writeSites.add(ins.getAddress() + "  " + ins + "   in " + fn); }
            else reads++;
        }
        println("PA touching_instructions reads=" + reads + " writes=" + writes);
        println("PA functions_touching=" + byFunc.size());
        int n = 0;
        for (Map.Entry<String, Integer> e : byFunc.entrySet()) {
            println("PA  " + e.getKey() + " x" + e.getValue());
            if (++n >= 12) break;
        }
        for (String w : writeSites.subList(0, Math.min(10, writeSites.size())))
            println("PA WRITE " + w);
    }
}
