import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Walk MSVC RTTI and name virtual functions from vtables.
 *
 * Ghidra's RTTI analyzer is tied to PE, so on an XBE it never runs. The layout
 * is fixed and documented:
 *
 *   TypeDescriptor            +0x00 vftable, +0x04 spare, +0x08 ".?AVFoo@@"
 *   RTTICompleteObjectLocator +0x00 signature(0), +0x0C TypeDescriptor*
 *   vtable                    the COL pointer sits at vtable[-1]
 *
 * The first version of this scanned all of memory once per class to find
 * pointers, then again per locator. With ~900 classes that is quadratic and it
 * had produced nothing after two minutes. This builds ONE index of every
 * 4-byte-aligned dword whose value lands inside the image, then answers every
 * "what points here" in constant time. Only pointer-looking values are indexed,
 * which keeps the map small.
 *
 * Only functions still carrying a default name are renamed: a name a person
 * chose says more than "slot 7 of this vtable".
 */
public class WalkMsvcRtti extends GhidraScript {

    /** True for a name this script previously mangled by mis-splitting a template. */
    static boolean isBadTemplateName(String n) {
        return n.contains("?$") || n.startsWith("$");
    }

    private static String demangle(String raw) {
        String s = raw;
        if (s.startsWith(".?AV") || s.startsWith(".?AU")) s = s.substring(4);

        // Templates encode nested types, and reversing on '@' turns
        // ".?AV?$handle_str@...@ratl@@" into "$0A::V?$handle_str::?$map_vs" -
        // a name that looks demangled and is not. A wrong-but-plausible name is
        // worse than an ugly one, because later work trusts it. So templates
        // keep their raw mangled form, sanitised into a legal identifier: it is
        // unique, greppable, and obviously not a tidy class name.
        if (s.contains("?$")) {
            String t = raw.replaceAll("[^A-Za-z0-9_]", "_").replaceAll("_+", "_");
            if (t.length() > 96) t = t.substring(0, 96);
            return "tmpl_" + t;
        }

        int at = s.indexOf("@@");
        if (at >= 0) s = s.substring(0, at);
        StringBuilder sb = new StringBuilder();
        String[] parts = s.split("@");
        for (int i = parts.length - 1; i >= 0; i--) {
            if (parts[i].isEmpty()) continue;
            if (sb.length() > 0) sb.append("::");
            sb.append(parts[i]);
        }
        return sb.length() == 0 ? "UnknownClass" : sb.toString();
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        AddressSetView init = mem.getLoadedAndInitializedAddressSet();
        long lo = currentProgram.getMinAddress().getOffset();
        long hi = currentProgram.getMaxAddress().getOffset();

        // ---- one pass: index every aligned dword that looks like a pointer
        monitor.setMessage("indexing pointers");
        Map<Integer, List<Address>> ptrIndex = new HashMap<>(1 << 20);
        for (MemoryBlock blk : mem.getBlocks()) {
            if (!blk.isInitialized()) continue;
            long start = blk.getStart().getOffset(), end = blk.getEnd().getOffset();
            byte[] buf = new byte[(int) Math.min(end - start + 1, 1 << 24)];
            mem.getBytes(blk.getStart(), buf);
            for (int off = 0; off + 4 <= buf.length; off += 4) {
                int v = (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8)
                      | ((buf[off + 2] & 0xFF) << 16) | ((buf[off + 3] & 0xFF) << 24);
                long uv = v & 0xFFFFFFFFL;
                if (uv < lo || uv > hi) continue;
                ptrIndex.computeIfAbsent(v, k -> new ArrayList<>(2))
                        .add(blk.getStart().add(off));
            }
            if (monitor.isCancelled()) return;
        }
        println("RTTI indexed_pointer_slots=" + ptrIndex.size());

        int classes = 0, vtables = 0, renamed = 0, kept = 0, slots = 0;
        Set<Address> seenVtables = new HashSet<>();
        List<String> examples = new ArrayList<>();

        Address cur = currentProgram.getMinAddress();
        while (cur != null && !monitor.isCancelled()) {
            Address hit = find(cur, ".?A".getBytes());
            if (hit == null) break;
            cur = hit.add(1);

            StringBuilder nm = new StringBuilder();
            for (int i = 0; i < 192; i++) {
                byte b;
                try { b = mem.getByte(hit.add(i)); } catch (Exception e) { break; }
                if (b == 0) break;
                nm.append((char) (b & 0xFF));
            }
            String raw = nm.toString();
            if (!(raw.startsWith(".?AV") || raw.startsWith(".?AU"))) continue;
            String cls = demangle(raw);
            classes++;

            Address typeDesc = hit.subtract(8);
            List<Address> tdRefs = ptrIndex.get((int) typeDesc.getOffset());
            if (tdRefs == null) continue;

            for (Address tdRef : tdRefs) {
                Address col = tdRef.subtract(0x0C);
                try { if (mem.getInt(col) != 0) continue; } catch (Exception e) { continue; }

                List<Address> colRefs = ptrIndex.get((int) col.getOffset());
                if (colRefs == null) continue;

                for (Address colRef : colRefs) {
                    Address vt = colRef.add(4);
                    if (!seenVtables.add(vt)) continue;
                    vtables++;
                    for (int slot = 0; slot < 512; slot++) {
                        Address slotAddr = vt.add(slot * 4L);
                        if (!init.contains(slotAddr)) break;
                        int fp;
                        try { fp = mem.getInt(slotAddr); } catch (Exception e) { break; }
                        Address target = toAddr(fp & 0xFFFFFFFFL);
                        if (target == null || !init.contains(target)) break;
                        Function f = getFunctionAt(target);
                        if (f == null) f = createFunction(target, null);
                        if (f == null) break;
                        slots++;
                        if (f.getName().startsWith("FUN_") || isBadTemplateName(f.getName())) {
                            f.setName(cls + "::vfunc" + slot, SourceType.ANALYSIS);
                            renamed++;
                            if (examples.size() < 10) examples.add(cls + "::vfunc" + slot + " @ " + target);
                        } else {
                            kept++;
                        }
                    }
                }
            }
        }

        println("RTTI classes_found=" + classes);
        println("RTTI vtables_found=" + vtables);
        println("RTTI vtable_slots_walked=" + slots);
        println("RTTI functions_renamed=" + renamed);
        println("RTTI kept_existing_name=" + kept);
        for (String e : examples) println("RTTI example: " + e);
    }
}
