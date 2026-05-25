//AIB RTTI & Vtable Identifier — C++ Class Hierarchy Reconstruction
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.GameAnalysis
//@keybinding
//@menupath Tools.AIB.RTTI Vtable Identifier
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB RTTI & VTABLE IDENTIFIER
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 *
 * Scans for C++ RTTI (Run-Time Type Information) structures and
 * reconstructs class hierarchies with virtual function tables.
 *
 * Supported compilers:
 *   - MSVC (Windows): .?AVClassName@@ patterns
 *   - GCC/Clang (Linux/Android): _ZTV/_ZTI/_ZTS symbols
 *
 * Actions:
 *   - Parses RTTI type descriptors to extract class names
 *   - Reconstructs vtable function lists
 *   - Renames virtual functions as ClassName::vfunc_N
 *   - Builds inheritance tree from RTTI hierarchy data
 *   - Creates Ghidra namespaces matching the class tree
 *   - Exports full class hierarchy as JSON
 *
 * Language: Bilingual EN/ES
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_RTTIVtableIdentifier extends GhidraScript {

    private boolean useSpanish = false;
    private String t(String en, String es) { return useSpanish ? es : en; }

    // ========================================================================
    // DATA STRUCTURES
    // ========================================================================

    private static class ClassInfo {
        String className;
        String mangledName;
        Address typeDescriptorAddr;
        Address vtableAddr;
        List<Address> virtualFunctions;
        List<String> baseClasses;
        boolean isAbstract;

        ClassInfo(String className, String mangledName, Address typeDescAddr) {
            this.className = className;
            this.mangledName = mangledName;
            this.typeDescriptorAddr = typeDescAddr;
            this.virtualFunctions = new ArrayList<>();
            this.baseClasses = new ArrayList<>();
            this.isAbstract = false;
        }
    }

    private List<ClassInfo> classes = new ArrayList<>();
    private Map<String, ClassInfo> classByName = new LinkedHashMap<>();

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        // Language selection
        String langChoice = askChoice(
            "AIB RTTI/Vtable Identifier — Language / Idioma",
            "Select language / Seleccione idioma:",
            Arrays.asList("English", "Español"), "English");
        useSpanish = "Español".equals(langChoice);

        String caseId = askString(
            t("AIB — Case ID", "AIB — ID de Caso"),
            t("Enter Case ID:", "Ingrese ID de Caso:"), "CASE_001");

        caseId = normalizeCaseId(caseId);
        printBanner();
        classes.clear();
        classByName.clear();

        // Detect compiler
        boolean isMSVC = detectMSVC();
        boolean isGCC = detectGCC();

        if (!isMSVC && !isGCC) {
            println("  [!] " + t("No RTTI detected. Attempting heuristic vtable scan...",
                "No se detectó RTTI. Intentando escaneo heurístico de vtables..."));
            scanHeuristicVtables();
        } else {
            if (isMSVC) {
                println("  [*] " + t("MSVC RTTI detected — scanning...",
                    "RTTI MSVC detectado — escaneando..."));
                scanMSVCRTTI();
            }
            if (isGCC) {
                println("  [*] " + t("GCC/Clang RTTI detected — scanning...",
                    "RTTI GCC/Clang detectado — escaneando..."));
                scanGCCRTTI();
            }
        }

        println("\n  [✓] " + t("Found", "Encontradas") + " " + classes.size() + " " +
            t("C++ classes", "clases C++"));

        if (!classes.isEmpty()) {
            // Scan vtables
            println("  [*] " + t("Reconstructing virtual function tables...",
                "Reconstruyendo tablas de funciones virtuales..."));
            reconstructVtables();

            // Rename functions
            println("  [*] " + t("Renaming virtual functions...",
                "Renombrando funciones virtuales..."));
            int renamed = renameVirtualFunctions();
            println("  [✓] " + t("Renamed", "Renombradas") + " " + renamed + " " +
                t("virtual functions", "funciones virtuales"));

            // Create namespaces
            println("  [*] " + t("Creating class namespaces...",
                "Creando espacios de nombres de clase..."));
            createNamespaces();

            // Print hierarchy
            printClassHierarchy();

            // Bookmark
            createBookmarks();

            // Export
            exportResults(caseId);
        }

        printFooter();
    }

    // ========================================================================
    // MSVC RTTI DETECTION
    // ========================================================================

    private boolean detectMSVC() {
        // Search for ".?AV" pattern which indicates MSVC RTTI type descriptors
        Memory memory = currentProgram.getMemory();
        byte[] pattern = ".?AV".getBytes(StandardCharsets.US_ASCII);
        try {
            Address found = memory.findBytes(currentProgram.getMinAddress(),
                currentProgram.getMaxAddress(), pattern, null, true, monitor);
            return found != null;
        } catch (Exception e) {
            return false;
        }
    }

    private void scanMSVCRTTI() throws Exception {
        Memory memory = currentProgram.getMemory();
        byte[] pattern = ".?AV".getBytes(StandardCharsets.US_ASCII);

        Address searchAddr = currentProgram.getMinAddress();
        Address maxAddr = currentProgram.getMaxAddress();
        int count = 0;

        while (searchAddr != null && searchAddr.compareTo(maxAddr) < 0 && !monitor.isCancelled()) {
            Address found = memory.findBytes(searchAddr, maxAddr, pattern, null, true, monitor);
            if (found == null) break;

            try {
                // Read the full type descriptor string (null-terminated)
                byte[] nameBytes = new byte[256];
                memory.getBytes(found, nameBytes);
                
                // Find null terminator
                int nameLen = 0;
                for (int i = 0; i < nameBytes.length; i++) {
                    if (nameBytes[i] == 0) {
                        nameLen = i;
                        break;
                    }
                }

                if (nameLen > 4) {
                    String mangledName = new String(nameBytes, 0, nameLen, StandardCharsets.US_ASCII);
                    String className = demangleMSVC(mangledName);

                    if (className != null && !className.isEmpty() && !classByName.containsKey(className)) {
                        // The type descriptor starts before the .?AV string
                        // In MSVC, TypeDescriptor has: vtable_ptr (ptr), spare (ptr), name (char[])
                        int ptrSize = currentProgram.getDefaultPointerSize();
                        Address typeDescStart = found.subtract(ptrSize * 2);

                        ClassInfo ci = new ClassInfo(className, mangledName, typeDescStart);
                        classes.add(ci);
                        classByName.put(className, ci);
                        count++;

                        if (count % 50 == 0) {
                            println("    ... " + t("found", "encontradas") + " " + count + " " +
                                t("classes", "clases"));
                        }
                    }
                }
            } catch (Exception e) {
                // Skip malformed entries
            }

            searchAddr = found.add(1);
        }

        println("  [✓] " + t("MSVC scan complete", "Escaneo MSVC completado") + 
            ": " + count + " " + t("classes", "clases"));
    }

    // ========================================================================
    // GCC RTTI DETECTION
    // ========================================================================

    private boolean detectGCC() {
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            if (name.startsWith("_ZTV") || name.startsWith("_ZTI") || name.startsWith("_ZTS")) {
                return true;
            }
        }
        return false;
    }

    private void scanGCCRTTI() throws Exception {
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getAllSymbols(true);
        int count = 0;

        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();

            // _ZTS = typeinfo name string
            if (name.startsWith("_ZTS")) {
                String className = demangleGCC(name);
                if (className != null && !classByName.containsKey(className)) {
                    ClassInfo ci = new ClassInfo(className, name, sym.getAddress());
                    classes.add(ci);
                    classByName.put(className, ci);
                    count++;
                }
            }
            // _ZTV = vtable — associate with class
            else if (name.startsWith("_ZTV")) {
                String className = demangleGCC(name.replace("_ZTV", "_ZTS"));
                if (classByName.containsKey(className)) {
                    classByName.get(className).vtableAddr = sym.getAddress();
                }
            }
        }

        println("  [✓] " + t("GCC scan complete", "Escaneo GCC completado") + 
            ": " + count + " " + t("classes", "clases"));
    }

    // ========================================================================
    // HEURISTIC VTABLE SCAN (no RTTI)
    // ========================================================================

    private void scanHeuristicVtables() throws Exception {
        // Look for arrays of function pointers in data sections
        Memory memory = currentProgram.getMemory();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int ptrSize = currentProgram.getDefaultPointerSize();
        int count = 0;

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.isExecute()) continue;
            if (block.getSize() > 100 * 1024 * 1024) continue;

            String blockName = block.getName().toLowerCase();
            // Focus on data sections likely to contain vtables
            if (!blockName.contains("data") && !blockName.contains("rdata") && 
                !blockName.contains("rodata") && !blockName.contains("const")) continue;

            byte[] data = new byte[(int) block.getSize()];
            block.getBytes(block.getStart(), data);

            for (int i = 0; i <= data.length - ptrSize * 3; i += ptrSize) {
                // Check if we have a sequence of at least 3 valid code pointers
                int consecutiveCodePtrs = 0;
                List<Address> potentialVfuncs = new ArrayList<>();

                for (int j = 0; j < 50; j++) { // Max 50 virtual functions
                    int offset = i + j * ptrSize;
                    if (offset + ptrSize > data.length) break;

                    long ptrValue = readPointer(data, offset, ptrSize);
                    Address ptrAddr = currentProgram.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(ptrValue);

                    if (isCodeAddress(ptrAddr)) {
                        consecutiveCodePtrs++;
                        potentialVfuncs.add(ptrAddr);
                    } else {
                        break;
                    }
                }

                if (consecutiveCodePtrs >= 3) {
                    Address vtableAddr = block.getStart().add(i);
                    String className = "UnknownClass_" + String.format("%08X", vtableAddr.getOffset());
                    
                    ClassInfo ci = new ClassInfo(className, "", vtableAddr);
                    ci.vtableAddr = vtableAddr;
                    ci.virtualFunctions = potentialVfuncs;
                    classes.add(ci);
                    classByName.put(className, ci);
                    count++;

                    // Skip past this vtable
                    i += consecutiveCodePtrs * ptrSize;
                }
            }
        }

        println("  [✓] " + t("Heuristic scan complete", "Escaneo heurístico completado") + 
            ": " + count + " " + t("potential vtables", "vtables potenciales"));
    }

    // ========================================================================
    // VTABLE RECONSTRUCTION
    // ========================================================================

    private void reconstructVtables() throws Exception {
        Memory memory = currentProgram.getMemory();
        int ptrSize = currentProgram.getDefaultPointerSize();
        int reconstructed = 0;

        for (ClassInfo ci : classes) {
            if (ci.vtableAddr != null && ci.virtualFunctions.isEmpty()) {
                try {
                    // Read vtable entries — skip first 2 entries (RTTI ptr + offset-to-top for GCC,
                    // or start at the vtable pointer for MSVC)
                    Address readAddr = ci.vtableAddr;

                    for (int i = 0; i < 100; i++) { // Max 100 virtual functions
                        Address ptrAddr = readAddr.add(i * ptrSize);
                        byte[] ptrBytes = new byte[ptrSize];
                        memory.getBytes(ptrAddr, ptrBytes);

                        long ptrValue = readPointer(ptrBytes, 0, ptrSize);
                        Address targetAddr = currentProgram.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(ptrValue);

                        if (isCodeAddress(targetAddr)) {
                            ci.virtualFunctions.add(targetAddr);
                        } else {
                            break; // End of vtable
                        }
                    }

                    if (!ci.virtualFunctions.isEmpty()) {
                        reconstructed++;
                    }
                } catch (Exception e) {
                    // Skip on error
                }
            }
        }

        println("  [✓] " + t("Reconstructed", "Reconstruidas") + " " + reconstructed + " " +
            t("vtables", "vtables") + " (" + countTotalVfuncs() + " " +
            t("total virtual functions", "funciones virtuales totales") + ")");
    }

    private int countTotalVfuncs() {
        int total = 0;
        for (ClassInfo ci : classes) total += ci.virtualFunctions.size();
        return total;
    }

    // ========================================================================
    // FUNCTION RENAMING
    // ========================================================================

    private int renameVirtualFunctions() throws Exception {
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int renamed = 0;

        for (ClassInfo ci : classes) {
            for (int i = 0; i < ci.virtualFunctions.size(); i++) {
                Address vfuncAddr = ci.virtualFunctions.get(i);
                Function func = funcMgr.getFunctionAt(vfuncAddr);
                
                if (func == null) {
                    // Try to create function
                    func = createFunction(vfuncAddr, null);
                }

                if (func != null) {
                    String currentName = func.getName();
                    // Only rename if still has a default name
                    if (currentName.startsWith("FUN_") || currentName.startsWith("SUB_") ||
                        currentName.startsWith("LAB_")) {
                        try {
                            String newName = ci.className + "::vfunc_" + i;
                            // Sanitize name for Ghidra
                            newName = newName.replace("::", "__");
                            func.setName(newName, SourceType.ANALYSIS);

                            // Add plate comment
                            String comment = "══ AIB RTTI IDENTIFIER ══\n" +
                                "Class: " + ci.className + "\n" +
                                "Virtual Function Index: " + i + "\n" +
                                "Vtable Address: 0x" + 
                                (ci.vtableAddr != null ? ci.vtableAddr.toString() : "unknown") + "\n" +
                                "═════════════════════════";
                            func.setComment(comment);
                            renamed++;
                        } catch (Exception e) {
                            // Name conflict — try with suffix
                            try {
                                String altName = ci.className.replace("::", "__") + 
                                    "__vfunc_" + i + "_" + vfuncAddr.toString();
                                func.setName(altName, SourceType.ANALYSIS);
                                renamed++;
                            } catch (Exception e2) {
                                // Give up on this one
                            }
                        }
                    }
                }
            }
        }

        return renamed;
    }

    // ========================================================================
    // NAMESPACE CREATION
    // ========================================================================

    private void createNamespaces() throws Exception {
        SymbolTable symTable = currentProgram.getSymbolTable();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int nsCreated = 0;

        for (ClassInfo ci : classes) {
            try {
                // Parse namespace hierarchy from class name (e.g., Game::Player::Component)
                String[] parts = ci.className.split("::");
                Namespace parent = currentProgram.getGlobalNamespace();

                for (String part : parts) {
                    if (part.isEmpty()) continue;
                    Namespace existing = symTable.getNamespace(part, parent);
                    if (existing == null) {
                        parent = symTable.createNameSpace(parent, part, SourceType.ANALYSIS);
                        nsCreated++;
                    } else {
                        parent = existing;
                    }
                }

                // Move virtual functions into namespace
                for (Address vfuncAddr : ci.virtualFunctions) {
                    Function func = funcMgr.getFunctionAt(vfuncAddr);
                    if (func != null) {
                        try {
                            func.setParentNamespace(parent);
                        } catch (Exception e) {
                            // Namespace conflict
                        }
                    }
                }
            } catch (Exception e) {
                // Skip on error
            }
        }

        println("  [✓] " + t("Created", "Creados") + " " + nsCreated + " " +
            t("namespaces", "espacios de nombres"));
    }

    // ========================================================================
    // BOOKMARKS
    // ========================================================================

    private void createBookmarks() {
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        int count = 0;

        for (ClassInfo ci : classes) {
            if (ci.vtableAddr != null) {
                String note = "[CLASS] " + ci.className + " (" + ci.virtualFunctions.size() + " vfuncs)";
                if (!ci.baseClasses.isEmpty()) {
                    note += " extends " + String.join(", ", ci.baseClasses);
                }
                bmMgr.setBookmark(ci.vtableAddr, "AIB_RTTI", "Vtable", note);
                count++;
            }
            if (ci.typeDescriptorAddr != null) {
                bmMgr.setBookmark(ci.typeDescriptorAddr, "AIB_RTTI", "TypeInfo",
                    "[TYPEINFO] " + ci.className);
                count++;
            }
        }

        println("  [✓] " + t("Created", "Creados") + " " + count + " " +
            t("bookmarks", "marcadores") + " (AIB_RTTI)");
    }

    // ========================================================================
    // CLASS HIERARCHY PRINT
    // ========================================================================

    private void printClassHierarchy() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  " + t("CLASS HIERARCHY", "JERARQUÍA DE CLASES"));
        println("══════════════════════════════════════════════════════════════");

        // Find root classes (no base classes)
        List<ClassInfo> roots = new ArrayList<>();
        Set<String> childNames = new HashSet<>();
        for (ClassInfo ci : classes) {
            childNames.addAll(ci.baseClasses);
        }

        for (ClassInfo ci : classes) {
            if (ci.baseClasses.isEmpty()) {
                roots.add(ci);
            }
        }

        // Sort by name
        roots.sort((a, b) -> a.className.compareTo(b.className));

        if (roots.isEmpty()) {
            // No hierarchy info, just list all classes
            for (ClassInfo ci : classes) {
                printClassNode(ci, 0);
            }
        } else {
            for (ClassInfo root : roots) {
                printClassTree(root, 0, new HashSet<>());
            }
        }

        // Statistics
        println("\n──── " + t("Statistics", "Estadísticas") + " ──────────────────────────────────────────");
        println("  " + t("Total classes", "Total de clases") + ": " + classes.size());
        println("  " + t("Total virtual functions", "Total funciones virtuales") + ": " + countTotalVfuncs());
        int withVtable = 0;
        for (ClassInfo ci : classes) {
            if (!ci.virtualFunctions.isEmpty()) withVtable++;
        }
        println("  " + t("Classes with vtables", "Clases con vtables") + ": " + withVtable);
    }

    private void printClassTree(ClassInfo ci, int depth, Set<String> visited) {
        if (visited.contains(ci.className)) return;
        visited.add(ci.className);

        printClassNode(ci, depth);

        // Find children
        for (ClassInfo child : classes) {
            if (child.baseClasses.contains(ci.className)) {
                printClassTree(child, depth + 1, visited);
            }
        }
    }

    private void printClassNode(ClassInfo ci, int depth) {
        String indent = repeat("  ", depth);
        String prefix = depth > 0 ? "├─ " : "◆ ";
        println("  " + indent + prefix + ci.className);
        if (!ci.virtualFunctions.isEmpty()) {
            println("  " + indent + "   " + t("Vtable", "Vtable") + ": " +
                (ci.vtableAddr != null ? "0x" + ci.vtableAddr.toString() : "?") +
                " (" + ci.virtualFunctions.size() + " " + t("functions", "funciones") + ")");
        }
    }

    // ========================================================================
    // EXPORT
    // ========================================================================

    private void exportResults(String caseId) throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File outputDir = new File(desktop + File.separator + "AIB_Cases" + File.separator +
            caseId + File.separator + "exports");
        if (!outputDir.exists()) outputDir.mkdirs();

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "rtti_vtables_" + timestamp + ".json";

        try (BufferedWriter w = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(jsonPath), StandardCharsets.UTF_8))) {
            w.write("{\n");
            w.write("  \"metadata\": {\n");
            w.write("    \"tool\": \"AIB RTTI/Vtable Identifier\",\n");
            w.write("    \"version\": \"1.0.0\",\n");
            w.write("    \"organization\": \"Arcy Intelligence Bureau\",\n");
            w.write("    \"case_id\": \"" + escJSON(caseId) + "\",\n");
            w.write("    \"binary\": \"" + escJSON(currentProgram.getName()) + "\",\n");
            w.write("    \"timestamp\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()) + "\"\n");
            w.write("  },\n");

            w.write("  \"classes\": [\n");
            for (int i = 0; i < classes.size(); i++) {
                ClassInfo ci = classes.get(i);
                w.write("    {\n");
                w.write("      \"name\": \"" + escJSON(ci.className) + "\",\n");
                w.write("      \"mangled_name\": \"" + escJSON(ci.mangledName) + "\",\n");
                w.write("      \"type_descriptor\": \"" +
                    (ci.typeDescriptorAddr != null ? "0x" + ci.typeDescriptorAddr.toString() : "null") + "\",\n");
                w.write("      \"vtable_address\": \"" +
                    (ci.vtableAddr != null ? "0x" + ci.vtableAddr.toString() : "null") + "\",\n");
                w.write("      \"base_classes\": [");
                for (int j = 0; j < ci.baseClasses.size(); j++) {
                    w.write("\"" + escJSON(ci.baseClasses.get(j)) + "\"");
                    if (j < ci.baseClasses.size() - 1) w.write(", ");
                }
                w.write("],\n");
                w.write("      \"virtual_functions\": [\n");
                FunctionManager funcMgr = currentProgram.getFunctionManager();
                for (int j = 0; j < ci.virtualFunctions.size(); j++) {
                    Address vfAddr = ci.virtualFunctions.get(j);
                    Function func = funcMgr.getFunctionAt(vfAddr);
                    String funcName = func != null ? func.getName() : "unknown";
                    w.write("        {\"index\": " + j + ", \"address\": \"0x" + vfAddr.toString() +
                        "\", \"name\": \"" + escJSON(funcName) + "\"}");
                    if (j < ci.virtualFunctions.size() - 1) w.write(",");
                    w.write("\n");
                }
                w.write("      ]\n");
                w.write("    }");
                if (i < classes.size() - 1) w.write(",");
                w.write("\n");
            }
            w.write("  ],\n");
            w.write("  \"total_classes\": " + classes.size() + ",\n");
            w.write("  \"total_virtual_functions\": " + countTotalVfuncs() + "\n");
            w.write("}\n");
        }

        println("  [✓] " + t("JSON exported", "JSON exportado") + ": " + jsonPath);
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    private String demangleMSVC(String mangled) {
        if (mangled == null) return null;
        if (mangled.startsWith(".?AV") && mangled.endsWith("@@")) {
            String inner = mangled.substring(4, mangled.length() - 2);
            return inner.replace("@", "::");
        }
        if (mangled.startsWith(".?AU") && mangled.endsWith("@@")) {
            String inner = mangled.substring(4, mangled.length() - 2);
            return inner.replace("@", "::");
        }
        // Try to extract any class name
        if (mangled.startsWith(".?A")) {
            int end = mangled.indexOf("@@");
            if (end > 4) {
                return mangled.substring(4, end).replace("@", "::");
            }
        }
        return mangled;
    }

    private String demangleGCC(String mangled) {
        if (mangled == null) return null;
        String s = mangled;
        if (s.startsWith("_ZTS")) s = s.substring(4);
        else if (s.startsWith("_ZTI")) s = s.substring(4);
        else if (s.startsWith("_ZTV")) s = s.substring(4);
        else return mangled;

        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < s.length()) {
            if (Character.isDigit(s.charAt(i))) {
                int lenStart = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                int len = Integer.parseInt(s.substring(lenStart, i));
                if (i + len <= s.length()) {
                    if (result.length() > 0) result.append("::");
                    result.append(s.substring(i, i + len));
                    i += len;
                } else break;
            } else {
                i++; // skip qualifiers
            }
        }
        return result.length() > 0 ? result.toString() : mangled;
    }

    private boolean isCodeAddress(Address addr) {
        if (addr == null) return false;
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(addr);
            return block != null && block.isExecute();
        } catch (Exception e) {
            return false;
        }
    }

    private long readPointer(byte[] data, int offset, int ptrSize) {
        long val = 0;
        for (int i = 0; i < ptrSize; i++) {
            val |= ((long)(data[offset + i] & 0xFF)) << (i * 8);
        }
        return val;
    }

    private String escJSON(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    private String normalizeCaseId(String input) {
        if (input == null) return "CASE_001";
        String normalized = input.trim().replaceAll("[^a-zA-Z0-9._\\-]", "_");
        return normalized.isEmpty() ? "CASE_001" : normalized;
    }

    private String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }

    // ========================================================================
    // CONSOLE
    // ========================================================================

    private void printBanner() {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║      AIB RTTI & VTABLE IDENTIFIER — " +
            t("Class Recovery", "Recuperación de Clases") + "     ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: " + currentProgram.getName());
        println("  Arch:   " + currentProgram.getLanguage());
        println("  Ptr:    " + currentProgram.getDefaultPointerSize() + " bytes");
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB RTTI/Vtable Identifier — " + t("Complete", "Completado"));
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }
}
