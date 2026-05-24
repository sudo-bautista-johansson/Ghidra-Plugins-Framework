//AIB Pointer Chain Helper — Recursive XREF Pointer Chain Mapper
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.GameAnalysis
//@keybinding
//@menupath Tools.AIB.Pointer Chain Helper
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB POINTER CHAIN HELPER
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 *
 * Given a target memory address, recursively traces cross-references (XREFs)
 * backwards to construct a pointer chain map leading from static base addresses.
 *
 * Useful for game hacking (identifying static pointers for Cheat Engine/ReClass).
 *
 * Actions:
 *   - Prompts for target address (defaults to cursor location)
 *   - Traces data references (pointers in memory blocks)
 *   - Traces code references (instructions loading/offsets)
 *   - Reconstructs offset chains: [[base + offset] + offset]
 *   - Outputs hierarchical ASCII tree
 *   - Exports results to JSON
 *
 * Language: Bilingual EN/ES
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_PointerChainHelper extends GhidraScript {

    private boolean useSpanish = false;
    private String t(String en, String es) { return useSpanish ? es : en; }

    // ========================================================================
    // DATA STRUCTURES
    // ========================================================================

    private static class ChainNode {
        Address address;
        String type; // "DATA", "INSTRUCTION", "UNKNOWN"
        String label;
        String functionName;
        long offset; // detected offset in instruction/struct
        String instrString;
        List<ChainNode> parents;
        boolean isBase;

        ChainNode(Address address, String type) {
            this.address = address;
            this.type = type;
            this.label = "";
            this.functionName = "";
            this.offset = 0;
            this.instrString = "";
            this.parents = new ArrayList<>();
            this.isBase = false;
        }

        Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("address", "0x" + address.toString());
            map.put("type", type);
            map.put("label", label);
            map.put("function", functionName);
            map.put("offset", offset);
            map.put("offset_hex", String.format("0x%X", offset));
            map.put("instruction", instrString);
            map.put("is_base", isBase);
            List<Map<String, Object>> parentMaps = new ArrayList<>();
            for (ChainNode p : parents) {
                parentMaps.add(p.toMap());
            }
            map.put("parents", parentMaps);
            return map;
        }
    }

    private int maxDepth = 5;
    private Set<Address> visited = new HashSet<>();
    private List<ChainNode> rootChains = new ArrayList<>();
    private int totalChainsFound = 0;

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        // Language selection
        String langChoice = askChoice(
            "AIB Pointer Chain Helper — Language / Idioma",
            "Select language / Seleccione idioma:",
            Arrays.asList("English", "Español"), "English");
        useSpanish = "Español".equals(langChoice);

        String caseId = askString(
            t("AIB — Case ID", "AIB — ID de Caso"),
            t("Enter Case ID:", "Ingrese ID de Caso:"), "CASE_001");

        // Address selection
        Address defaultAddr = currentAddress;
        if (defaultAddr == null) {
            defaultAddr = currentProgram.getMinAddress();
        }

        String addrStr = askString(
            t("AIB — Target Address", "AIB — Dirección Destino"),
            t("Enter target address (hex):", "Ingrese dirección de destino (hex):"),
            "0x" + defaultAddr.toString()
        );

        Address targetAddr = parseAddressHex(addrStr);
        if (targetAddr == null) {
            printerr(t("Invalid address entered.", "Dirección ingresada inválida."));
            return;
        }

        // Depth selection
        String depthStr = askChoice(
            t("AIB — Max Search Depth", "AIB — Profundidad Máxima"),
            t("Select max recursion depth:", "Seleccione profundidad máxima de recursión:"),
            Arrays.asList("3", "5", "8", "10"), "5"
        );
        maxDepth = Integer.parseInt(depthStr);

        printBanner(targetAddr);

        println("  [*] " + t("Tracing pointer chains back from target 0x", 
            "Rastreando cadenas de punteros desde el destino 0x") + targetAddr.toString() + "...");

        visited.clear();
        rootChains.clear();
        totalChainsFound = 0;

        ChainNode targetNode = new ChainNode(targetAddr, "TARGET");
        targetNode.label = getAddressLabel(targetAddr);
        
        buildChainTree(targetNode, 0);

        printResults(targetNode);

        if (totalChainsFound > 0) {
            // Bookmark
            BookmarkManager bmMgr = currentProgram.getBookmarkManager();
            bmMgr.setBookmark(targetAddr, "AIB_POINTER", "ChainTarget", 
                "[POINTER] Target address for pointer chain analysis");

            // Export
            exportResults(targetNode, caseId);
        }

        printFooter();
    }

    // ========================================================================
    // RECURSIVE CHAIN RECONSTRUCTION
    // ========================================================================

    private void buildChainTree(ChainNode node, int depth) {
        if (depth >= maxDepth) return;
        if (visited.contains(node.address)) {
            // Cycle detected
            return;
        }
        visited.add(node.address);

        // Check if current node is in a static base/global block (e.g. .data, .rdata, .bss)
        if (isStaticBase(node.address)) {
            node.isBase = true;
            totalChainsFound++;
            visited.remove(node.address);
            return;
        }

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(node.address);
        List<Reference> refList = new ArrayList<>();
        while (refs.hasNext()) {
            refList.add(refs.next());
        }

        for (Reference ref : refList) {
            Address fromAddr = ref.getFromAddress();
            
            // Check if fromAddr is inside memory blocks
            MemoryBlock block = currentProgram.getMemory().getBlock(fromAddr);
            if (block == null) continue;

            ChainNode parent = null;
            if (ref.getReferenceType().isData()) {
                parent = new ChainNode(fromAddr, "DATA");
                parent.label = getAddressLabel(fromAddr);
            } else if (currentProgram.getListing().getInstructionAt(fromAddr) != null) {
                parent = new ChainNode(fromAddr, "INSTRUCTION");
                // Get instruction information
                Instruction instr = currentProgram.getListing().getInstructionAt(fromAddr);
                if (instr != null) {
                    parent.instrString = instr.toString();
                    parent.offset = extractOffsetFromInstruction(instr);
                }
                Function func = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
                if (func != null) {
                    parent.functionName = func.getName();
                }
            } else {
                parent = new ChainNode(fromAddr, "UNKNOWN");
            }

            node.parents.add(parent);
            buildChainTree(parent, depth + 1);
        }

        visited.remove(node.address);
    }

    // ========================================================================
    // UTILITIES & PARSING
    // ========================================================================

    private Address parseAddressHex(String addrStr) {
        addrStr = addrStr.trim();
        if (addrStr.toLowerCase().startsWith("0x")) {
            addrStr = addrStr.substring(2);
        }
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrStr, true);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isStaticBase(Address addr) {
        MemoryBlock block = currentProgram.getMemory().getBlock(addr);
        if (block == null) return false;
        
        // A static base is located in a writable or read-only global data block,
        // but typically not in the stack, heap, or code segments.
        String name = block.getName().toLowerCase();
        return name.contains("data") || name.contains("rdata") || name.contains("bss") || name.contains("const");
    }

    private String getAddressLabel(Address addr) {
        Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(addr);
        return sym != null ? sym.getName() : "";
    }

    private long extractOffsetFromInstruction(Instruction instr) {
        // Look for Scalars inside operands
        int numOps = instr.getNumOperands();
        for (int i = 0; i < numOps; i++) {
            Object[] objs = instr.getOpObjects(i);
            for (Object obj : objs) {
                if (obj instanceof Scalar) {
                    Scalar scalar = (Scalar) obj;
                    long val = scalar.getValue();
                    // Generally, offsets in structures are small positive integers,
                    // e.g. 0 to 0x10000. Filter out huge values which could be memory addresses
                    if (val > 0 && val < 0x100000) {
                        return val;
                    }
                }
            }
        }
        
        // Fallback: Parse string representation for offsets
        String instrStr = instr.toString().toLowerCase();
        if (instrStr.contains("+") || instrStr.contains("-")) {
            try {
                // Find hex patterns like +0x18 or +24
                int plusIdx = instrStr.indexOf('+');
                int minusIdx = instrStr.indexOf('-');
                int idx = (plusIdx != -1) ? plusIdx : minusIdx;
                
                String part = instrStr.substring(idx + 1).trim();
                // strip bracket
                int bracketIdx = part.indexOf(']');
                if (bracketIdx != -1) {
                    part = part.substring(0, bracketIdx).trim();
                }
                
                long val = 0;
                if (part.startsWith("0x")) {
                    val = Long.parseLong(part.substring(2), 16);
                } else {
                    val = Long.parseLong(part);
                }
                
                if (minusIdx != -1) val = -val;
                return val;
            } catch (Exception e) {
                // Parse failure
            }
        }
        return 0;
    }

    // ========================================================================
    // CONSOLE AND OUTPUT RENDERING
    // ========================================================================

    private void printResults(ChainNode targetNode) {
        println("\n══════════════════════════════════════════════════════════════");
        println("  " + t("POINTER CHAINS FOUND", "CADENAS DE PUNTEROS ENCONTRADAS") + ": " + totalChainsFound);
        println("══════════════════════════════════════════════════════════════");

        if (totalChainsFound == 0) {
            println("  [!] " + t("No pointer chains could be traced back to static data blocks.",
                "No se pudieron rastrear cadenas de punteros hasta bloques de datos estáticos."));
            return;
        }

        // Print tree
        printNodeTree(targetNode, "", true);

        // Print copy-pasteable Cheat Engine pointer formulas for base chains
        println("\n──── " + t("Pointer Notation Formulas", "Fórmulas de Notación de Punteros") + " ──────────────────");
        List<String> formulas = new ArrayList<>();
        generateFormulas(targetNode, new ArrayList<>(), formulas);
        for (String formula : formulas) {
            println("  ◆ " + formula);
        }
    }

    private void printNodeTree(ChainNode node, String indent, boolean isLast) {
        String nodeInfo = "0x" + node.address.toString();
        if (!node.label.isEmpty()) {
            nodeInfo += " (" + node.label + ")";
        }
        if (node.isBase) {
            nodeInfo += " [BASE STATIC]";
        }
        if (!node.functionName.isEmpty()) {
            nodeInfo += " in " + node.functionName + "()";
        }
        if (node.offset > 0) {
            nodeInfo += " [Offset: +0x" + Long.toHexString(node.offset).toUpperCase() + "]";
        }
        if (!node.instrString.isEmpty()) {
            nodeInfo += " -> \"" + node.instrString + "\"";
        }

        String marker = isLast ? "└── " : "├── ";
        println("  " + indent + marker + nodeInfo);

        String childIndent = indent + (isLast ? "    " : "│   ");
        for (int i = 0; i < node.parents.size(); i++) {
            printNodeTree(node.parents.get(i), childIndent, i == node.parents.size() - 1);
        }
    }

    private void generateFormulas(ChainNode node, List<Long> offsets, List<String> formulas) {
        if (node.isBase) {
            // We found a base node. Build the formula string.
            StringBuilder sb = new StringBuilder();
            String baseLabel = node.label.isEmpty() ? "base" : node.label;
            sb.append("0x").append(node.address.toString()).append(" (").append(baseLabel).append(")");
            
            // Build the offsets list in reverse order (since we traced backward)
            List<Long> revOffsets = new ArrayList<>(offsets);
            Collections.reverse(revOffsets);

            String formula = "";
            if (revOffsets.isEmpty()) {
                formula = "[" + sb.toString() + "]";
            } else {
                formula = sb.toString();
                for (long offset : revOffsets) {
                    formula = "[" + formula + " + 0x" + Long.toHexString(offset).toUpperCase() + "]";
                }
            }
            formulas.add(formula);
            return;
        }

        for (ChainNode parent : node.parents) {
            List<Long> newOffsets = new ArrayList<>(offsets);
            newOffsets.add(node.offset);
            generateFormulas(parent, newOffsets, formulas);
        }
    }

    // ========================================================================
    // EXPORT TO JSON
    // ========================================================================

    private void exportResults(ChainNode targetNode, String caseId) throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File outputDir = new File(desktop + File.separator + "AIB_Cases" + File.separator +
            caseId + File.separator + "exports");
        if (!outputDir.exists()) outputDir.mkdirs();

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "pointer_chains_" + timestamp + ".json";

        Map<String, Object> data = new LinkedHashMap<>();
        
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("tool", "AIB Pointer Chain Helper");
        meta.put("version", "1.0.0");
        meta.put("organization", "Arcy Intelligence Bureau");
        meta.put("case_id", caseId);
        meta.put("binary", currentProgram.getName());
        meta.put("target_address", "0x" + targetNode.address.toString());
        meta.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()));
        data.put("metadata", meta);

        data.put("tree", targetNode.toMap());

        List<String> formulas = new ArrayList<>();
        generateFormulas(targetNode, new ArrayList<>(), formulas);
        data.put("pointer_formulas", formulas);
        data.put("total_chains", totalChainsFound);

        // Serialize manually to avoid dependency issues
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(jsonPath), StandardCharsets.UTF_8))) {
            writer.write(toJSON(data, 0));
        }

        println("  [✓] " + t("JSON exported", "JSON exportado") + ": " + jsonPath);
    }

    @SuppressWarnings("unchecked")
    private String toJSON(Object obj, int indent) {
        if (obj == null) return "null";
        String indentStr = repeat("  ", indent);
        String innerIndent = repeat("  ", indent + 1);

        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            if (map.isEmpty()) return "{}";
            StringBuilder sb = new StringBuilder("{\n");
            Iterator<Map.Entry<String, Object>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Object> entry = it.next();
                sb.append(innerIndent).append("\"").append(esc(entry.getKey())).append("\": ");
                sb.append(toJSON(entry.getValue(), indent + 1));
                if (it.hasNext()) sb.append(",");
                sb.append("\n");
            }
            sb.append(indentStr).append("}");
            return sb.toString();
        }
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            if (list.isEmpty()) return "[]";
            StringBuilder sb = new StringBuilder("[\n");
            for (int i = 0; i < list.size(); i++) {
                sb.append(innerIndent).append(toJSON(list.get(i), indent + 1));
                if (i < list.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append(indentStr).append("]");
            return sb.toString();
        }
        if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        }
        return "\"" + esc(obj.toString()) + "\"";
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }

    // ========================================================================
    // CONSOLE HEADER
    // ========================================================================

    private void printBanner(Address targetAddr) {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║         AIB POINTER CHAIN HELPER — " +
            t("XREF Tracing", "Rastreo XREF") + "        ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: 0x" + targetAddr.toString());
        println("  Depth:  " + maxDepth);
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB Pointer Chain Helper — " + t("Complete", "Completado"));
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }
}
