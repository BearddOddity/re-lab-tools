import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;

/**
 * Parse the flattened Xbox SDK header into Ghidra data types.
 *
 * args: <xbox.h> [<output.gdt>]
 *
 * The header must already be preprocessed (gcc -E -P). Ghidra's C parser is not
 * a full preprocessor, and feeding it the original headers means fighting
 * include paths and macros for no gain when the project's own Makefile already
 * produces a flat file.
 *
 * Writes a reusable .gdt archive AND parses into the open program, because a
 * .gdt alone does nothing for the decompiler until its types are in the
 * program's own manager.
 */
public class ParseXboxHeaders extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("XBOXDT need a header path"); return; }
        String header = a[0];
        String[] filenames = { header };
        String[] parseArgs = { };          // already preprocessed: no -I, no -D

        if (a.length > 1) {
            FileDataTypeManager fdtm = CParserUtils.parseHeaderFiles(
                    new DataTypeManager[0], filenames, parseArgs, a[1], monitor);
            if (fdtm != null) {
                println("XBOXDT archive=" + a[1] + " types=" + fdtm.getDataTypeCount(true));
                fdtm.save();
                fdtm.close();
            }
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int before = dtm.getDataTypeCount(true);
        CParseResults res = CParserUtils.parseHeaderFiles(
                new DataTypeManager[] { dtm }, filenames, parseArgs, dtm, monitor);
        int after = dtm.getDataTypeCount(true);

        println("XBOXDT successful=" + (res != null && res.successful()));
        println("XBOXDT program_types_before=" + before);
        println("XBOXDT program_types_after=" + after);
        println("XBOXDT added=" + (after - before));
        if (res != null && !res.successful()) {
            String m = res.cParseMessages();
            if (m != null && !m.isEmpty()) {
                String[] lines = m.split("\n");
                for (int i = 0; i < Math.min(6, lines.length); i++) println("XBOXDT err: " + lines[i]);
            }
        }
    }
}
