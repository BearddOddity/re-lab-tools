import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Give the Xbox SDK functions their real prototypes.
 *
 * XbSymbolDatabase says WHICH function at an address is, say,
 * D3DDevice_SetRenderState_FillMode. The parsed SDK headers say what its
 * arguments and return type are. Neither is much use alone: a name without a
 * signature still decompiles as undefined4 params, and a signature with no
 * address has nothing to attach to. This joins them.
 *
 * args: <symbols file from XbSymbolDatabaseCLI>
 */
public class ApplyXboxSignatures extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("XBSIG need a symbols file"); return; }
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        int applied = 0, noFunc = 0, noSig = 0, failed = 0;
        List<String> missing = new ArrayList<>();

        BufferedReader r = new BufferedReader(new FileReader(a[0]));
        String line;
        while ((line = r.readLine()) != null) {
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            String full = line.substring(0, eq).trim();
            String as = line.substring(eq + 1).trim();
            if (!as.startsWith("0x")) continue;

            // "D3D8__D3DDevice_SetRenderState_FillMode" -> the header's own name
            int sep = full.indexOf("__");
            String plain = sep >= 0 ? full.substring(sep + 2) : full;

            Address addr;
            try { addr = toAddr(Long.parseLong(as.substring(2), 16)); }
            catch (Exception e) { continue; }
            if (addr == null || !currentProgram.getMemory().contains(addr)) continue;

            Function f = getFunctionAt(addr);
            if (f == null) { noFunc++; continue; }

            List<DataType> hits = new ArrayList<>();
            dtm.findDataTypes(plain, hits);
            FunctionDefinition def = null;
            for (DataType dt : hits) {
                if (dt instanceof FunctionDefinition) { def = (FunctionDefinition) dt; break; }
            }
            if (def == null) { noSig++; if (missing.size() < 8) missing.add(plain); continue; }

            ApplyFunctionSignatureCmd cmd =
                new ApplyFunctionSignatureCmd(addr, def, SourceType.IMPORTED);
            if (cmd.applyTo(currentProgram, monitor)) applied++; else failed++;
        }
        r.close();

        println("XBSIG applied=" + applied);
        println("XBSIG no_function_at_address=" + noFunc);
        println("XBSIG no_signature_in_headers=" + noSig);
        println("XBSIG apply_failed=" + failed);
        for (String m : missing) println("XBSIG missing_sig_example: " + m);
    }
}
