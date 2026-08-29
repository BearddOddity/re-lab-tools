import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.*;

/**
 * Does Alchemy's ig* type registration lead anywhere?
 *
 * The engine keeps ~693 class names as plain strings in one blob. If each is
 * referenced by a metaclass record, and that record holds function pointers,
 * those functions are factories and initialisers - non-virtual, so RTTI never
 * reached them. This measures whether the structure is there before writing a
 * namer for it.
 */
public class ProbeAlchemyMeta extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        long lo = currentProgram.getMinAddress().getOffset();
        long hi = currentProgram.getMaxAddress().getOffset();

        // Index pointer-valued dwords once (the same trick that made the RTTI
        // walk finish in a minute instead of never).
        Map<Integer, List<Address>> idx = new HashMap<>(1 << 20);
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) continue;
            int len = (int) Math.min(b.getEnd().subtract(b.getStart()) + 1, 1 << 24);
            byte[] buf = new byte[len];
            mem.getBytes(b.getStart(), buf);
            for (int o = 0; o + 4 <= len; o += 4) {
                int v = (buf[o]&0xFF)|((buf[o+1]&0xFF)<<8)|((buf[o+2]&0xFF)<<16)|((buf[o+3]&0xFF)<<24);
                long uv = v & 0xFFFFFFFFL;
                if (uv < lo || uv > hi) continue;
                idx.computeIfAbsent(v, k -> new ArrayList<>(2)).add(b.getStart().add(o));
            }
        }

        int names = 0, referenced = 0, withNearbyFunc = 0;
        Map<String, Integer> hits = new LinkedHashMap<>();
        Address cur = currentProgram.getMinAddress();
        while (cur != null && !monitor.isCancelled()) {
            Address at = find(cur, "ig".getBytes());
            if (at == null) break;
            cur = at.add(1);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 64; i++) {
                byte b;
                try { b = mem.getByte(at.add(i)); } catch (Exception e) { break; }
                if (b == 0) break;
                if (b < 0x20 || b > 0x7E) { sb.setLength(0); break; }
                sb.append((char) b);
            }
            String s = sb.toString();
            if (s.length() < 5 || !Character.isUpperCase(s.charAt(2))) continue;
            names++;
            List<Address> refs = idx.get((int) at.getOffset());
            if (refs == null) continue;
            referenced++;
            // Does the record holding the name pointer also hold code pointers?
            for (Address r : refs) {
                for (int slot = -8; slot <= 8; slot++) {
                    Address p = r.add(slot * 4L);
                    int v;
                    try { v = mem.getInt(p); } catch (Exception e) { continue; }
                    Address t = toAddr(v & 0xFFFFFFFFL);
                    if (t == null) continue;
                    Function f = getFunctionAt(t);
                    if (f != null) {
                        withNearbyFunc++;
                        hits.merge(s + (f.getName().startsWith("FUN_") ? " -> UNNAMED" : " -> named"), 1, Integer::sum);
                        slot = 99;
                        break;
                    }
                }
            }
        }
        println("ALC ig_name_strings=" + names);
        println("ALC referenced_by_a_pointer=" + referenced);
        println("ALC records_with_a_function_pointer_nearby=" + withNearbyFunc);
        int shown = 0;
        for (Map.Entry<String, Integer> e : hits.entrySet()) {
            println("ALC  " + e.getKey() + " x" + e.getValue());
            if (++shown >= 10) break;
        }
    }
}
