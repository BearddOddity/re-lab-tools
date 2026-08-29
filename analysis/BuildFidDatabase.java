import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;

/**
 * Build a Function ID database from the named functions of the open program.
 *
 * args: <output.fidb> <libraryName> <version> <variant>
 *
 * Ghidra ships the FunctionID engine but no .fidb data, and the normal way to
 * populate one is a GUI dialog. FidServiceLibraryIngest, which that dialog
 * drives, is package-private and unreachable from a script - so this uses the
 * public FidDB API directly. That is not a workaround so much as an improvement:
 * it makes the ingest filter explicit rather than accepting whatever the dialog
 * decides.
 *
 * Only functions with a real name are ingested. FUN_/thunk_ entries carry no
 * information to transfer, and including them would inflate the database with
 * hashes that can never usefully name anything.
 */
public class BuildFidDatabase extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { println("FID need an output path"); return; }
        File out = new File(a[0]);
        String libName = a.length > 1 ? a[1] : currentProgram.getName();
        String version = a.length > 2 ? a[2] : "1.0";
        String variant = a.length > 3 ? a[3] : "default";

        FidFileManager mgr = FidFileManager.getInstance();
        if (out.exists()) out.delete();
        mgr.createNewFidDatabase(out);
        FidFile fidFile = mgr.addUserFidFile(out);
        FidDB db = fidFile.getFidDB(true);

        FidService svc = new FidService();
        LibraryRecord lib = db.createNewLibrary(libName, version, variant,
                ghidra.framework.Application.getApplicationVersion(),
                currentProgram.getLanguageID(), 1, 0,
                currentProgram.getCompilerSpec().getCompilerSpecID());

        int ingested = 0, skippedDefault = 0, tooSmall = 0;
        FunctionIterator it = currentProgram.getListing().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            String n = f.getName();
            if (n.startsWith("FUN_") || n.startsWith("thunk_FUN_")) { skippedDefault++; continue; }
            FidHashQuad q;
            try { q = svc.hashFunction(f); }
            catch (Exception e) { tooSmall++; continue; }
            // Functions below the hash's minimum instruction count return null;
            // they are too short to identify safely and would only ever produce
            // false matches.
            if (q == null) { tooSmall++; continue; }
            db.createNewFunction(lib, q, n, f.getEntryPoint().getOffset(),
                    currentProgram.getDomainFile().getPathname(), false);
            ingested++;
        }

        db.saveDatabase("built by BuildFidDatabase", monitor);
        db.close();

        println("FID output=" + out.getAbsolutePath());
        println("FID library=" + libName + " " + version + " " + variant);
        println("FID ingested=" + ingested);
        println("FID skipped_default_names=" + skippedDefault);
        println("FID skipped_too_small_or_unhashable=" + tooSmall);
    }
}
