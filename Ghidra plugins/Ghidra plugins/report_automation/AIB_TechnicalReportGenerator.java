//AIB Technical Report Generator — One-Click Markdown Analysis Reporter
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.ReportAutomation
//@keybinding
//@menupath Tools.AIB.Technical Report Generator
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB TECHNICAL REPORT GENERATOR
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 *
 * Compiles analyst annotations, renamed functions, comments, bookmarks,
 * and program metadata to generate a comprehensive markdown-formatted
 * technical report and companion JSON archive.
 *
 * Gathered Information:
 *   - Program Metadata (Name, MD5/SHA256, Architecture, Compiler)
 *   - Labeled Functions (excluding default FUN_ and thunks)
 *   - Comments (Plate, Pre, Post, EOL, and Repeatable)
 *   - Bookmarks (grouped by category)
 *   - Custom data structures created during analysis
 *   - Reference map of key indicators of interest
 *
 * Language: Bilingual EN/ES
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_TechnicalReportGenerator extends GhidraScript {

    private boolean useSpanish = false;
    private String t(String en, String es) { return useSpanish ? es : en; }

    // ========================================================================
    // REPORT STRUCTURE
    // ========================================================================

    private static class CommentEntry {
        Address address;
        String type;
        String content;
        String context; // Function name or symbol

        CommentEntry(Address address, String type, String content, String context) {
            this.address = address;
            this.type = type;
            this.content = content;
            this.context = context;
        }
    }

    private static class FunctionEntry {
        Address address;
        String name;
        String comments;
        int callCount;
        int callerCount;

        FunctionEntry(Address address, String name) {
            this.address = address;
            this.name = name;
            this.comments = "";
            this.callCount = 0;
            this.callerCount = 0;
        }
    }

    private static class BookmarkEntry {
        Address address;
        String category;
        String comment;

        BookmarkEntry(Address address, String category, String comment) {
            this.address = address;
            this.category = category;
            this.comment = comment;
        }
    }

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        // Language selection
        String langChoice = askChoice(
            "AIB Technical Report Generator — Language / Idioma",
            "Select language / Seleccione idioma:",
            Arrays.asList("English", "Español"), "English");
        useSpanish = "Español".equals(langChoice);

        String caseId = askString(
            t("AIB — Case ID", "AIB — ID de Caso"),
            t("Enter Case ID:", "Ingrese ID de Caso:"), "CASE_001");
        caseId = normalizeCaseId(caseId);

        printBanner();

        println("  [*] " + t("Gathering program metadata...", "Recopilando metadatos del programa..."));
        String hash = computeProgramHash();

        // 1. Gather Labeled Functions
        println("  [*] " + t("Extracting renamed functions...", "Extrayendo funciones renombradas..."));
        List<FunctionEntry> renamedFunctions = gatherRenamedFunctions();

        // 2. Gather Comments
        println("  [*] " + t("Extracting analyst comments...", "Extrayendo comentarios del analista..."));
        List<CommentEntry> commentsList = gatherComments();

        // 3. Gather Bookmarks
        println("  [*] " + t("Extracting bookmarks...", "Extrayendo marcadores..."));
        List<BookmarkEntry> bookmarksList = gatherBookmarks();

        // 4. Gather Custom Data Structures
        println("  [*] " + t("Extracting custom data structures...", "Extrayendo estructuras de datos personalizadas..."));
        List<String> structList = gatherCustomStructures();

        // 5. Generate Report
        println("  [*] " + t("Formatting report documents...", "Dando formato a los documentos de reporte..."));
        
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File outputDir = new File(desktop + File.separator + "AIB_Cases" + File.separator +
            caseId + File.separator + "exports");
        if (!outputDir.exists()) outputDir.mkdirs();

        String mdPath = outputDir.getAbsolutePath() + File.separator +
            "technical_report_" + timestamp + ".md";
        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "technical_report_" + timestamp + ".json";

        writeMarkdownReport(mdPath, hash, renamedFunctions, commentsList, bookmarksList, structList, caseId);
        writeJSONReport(jsonPath, hash, renamedFunctions, commentsList, bookmarksList, structList, caseId);

        println("\n══════════════════════════════════════════════════════════════");
        println("  [✓] " + t("Markdown Report Generated", "Reporte Markdown Generado") + ":");
        println("      " + mdPath);
        println("  [✓] " + t("JSON Archive Generated", "Archivo JSON Generado") + ":");
        println("      " + jsonPath);

        printFooter();
    }

    // ========================================================================
    // DATA GATHERING
    // ========================================================================

    private String computeProgramHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            Memory memory = currentProgram.getMemory();
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isInitialized()) {
                    byte[] bytes = new byte[(int) block.getSize()];
                    block.getBytes(block.getStart(), bytes);
                    digest.update(bytes);
                }
            }
            byte[] hashBytes = digest.digest();
            StringBuilder hex = new StringBuilder();
            for (byte b : hashBytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString().toUpperCase();
        } catch (Exception e) {
            return "UNKNOWN_HASH";
        }
    }

    private List<FunctionEntry> gatherRenamedFunctions() {
        List<FunctionEntry> list = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function func = iterator.next();
            String name = func.getName();
            
            // Check if name is non-default and not a compiler helper
            if (!name.startsWith("FUN_") && !name.startsWith("SUB_") && 
                !name.startsWith("LAB_") && !func.isThunk()) {
                FunctionEntry entry = new FunctionEntry(func.getEntryPoint(), name);
                
                // Get calls info
                entry.callCount = func.getCalledFunctions(monitor).size();
                entry.callerCount = func.getCallingFunctions(monitor).size();
                
                // Get comments
                String comment = func.getComment();
                if (comment != null) {
                    entry.comments = comment.replace("\n", " ");
                }
                
                list.add(entry);
            }
        }
        // Sort by address
        list.sort((a, b) -> a.address.compareTo(b.address));
        return list;
    }

    private List<CommentEntry> gatherComments() {
        List<CommentEntry> list = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        
        // Scan all defined code units (instructions and data)
        CodeUnitIterator it = listing.getCodeUnits(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = it.next();
            
            // Collect various comment types
            checkAndAddComment(list, cu, CodeUnit.PLATE_COMMENT, "PLATE");
            checkAndAddComment(list, cu, CodeUnit.PRE_COMMENT, "PRE");
            checkAndAddComment(list, cu, CodeUnit.POST_COMMENT, "POST");
            checkAndAddComment(list, cu, CodeUnit.EOL_COMMENT, "EOL");
            checkAndAddComment(list, cu, CodeUnit.REPEATABLE_COMMENT, "REPEATABLE");
        }
        return list;
    }

    private void checkAndAddComment(List<CommentEntry> list, CodeUnit cu, int commentType, String typeStr) {
        String comment = cu.getComment(commentType);
        if (comment != null && !comment.trim().isEmpty()) {
            // Find context (containing function)
            Function func = currentProgram.getFunctionManager().getFunctionContaining(cu.getMinAddress());
            String context = func != null ? func.getName() + "()" : "GLOBAL/DATA";
            list.add(new CommentEntry(cu.getMinAddress(), typeStr, comment, context));
        }
    }

    private List<BookmarkEntry> gatherBookmarks() {
        List<BookmarkEntry> list = new ArrayList<>();
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        Iterator<Bookmark> it = bmMgr.getBookmarksIterator();
        while (it.hasNext()) {
            Bookmark bm = it.next();
            list.add(new BookmarkEntry(bm.getAddress(), bm.getCategory(), bm.getComment()));
        }
        return list;
    }

    private List<String> gatherCustomStructures() {
        List<String> list = new ArrayList<>();
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        
        // Locate all composite types (structs and unions)
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (dt instanceof Structure || dt instanceof Union) {
                // Focus on categories like user-created or AIB structures
                String cat = dt.getCategoryPath().toString();
                if (cat.contains("AIB_Structures") || cat.contains("User") || cat.startsWith("/Class")) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("### Struct: ").append(dt.getName()).append(" (Category: ").append(cat).append(")\n");
                    sb.append("| Offset | Name | Type | Description |\n");
                    sb.append("| :--- | :--- | :--- | :--- |\n");
                    
                    if (dt instanceof Structure) {
                        Structure struct = (Structure) dt;
                        for (DataTypeComponent comp : struct.getComponents()) {
                            sb.append(String.format("| 0x%X | %s | %s | %s |\n",
                                comp.getOffset(),
                                comp.getFieldName() != null ? comp.getFieldName() : "",
                                comp.getDataType().getName(),
                                comp.getComment() != null ? comp.getComment() : ""
                            ));
                        }
                    }
                    list.add(sb.toString());
                }
            }
        }
        return list;
    }

    // ========================================================================
    // REPORT GENERATION (MARKDOWN)
    // ========================================================================

    private void writeMarkdownReport(String path, String hash, List<FunctionEntry> functions,
                                     List<CommentEntry> comments, List<BookmarkEntry> bookmarks,
                                     List<String> structures, String caseId) throws Exception {
        
        try (BufferedWriter w = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(path), StandardCharsets.UTF_8))) {
            
            // Header
            w.write("# " + t("AIB Technical Analysis Report", "AIB Reporte de Análisis Técnico") + "\n\n");
            
            // Metadata Block
            w.write("## " + t("Case & Binary Metadata", "Metadatos del Caso y Binario") + "\n");
            w.write(String.format("- **%-15s** %s\n", t("Case ID:", "ID del Caso:"), caseId));
            w.write(String.format("- **%-15s** %s\n", t("Target Binary:", "Binario Objetivo:"), currentProgram.getName()));
            w.write(String.format("- **%-15s** %s\n", t("SHA-256 Hash:", "Hash SHA-256:"), hash));
            w.write(String.format("- **%-15s** %s\n", t("Architecture:", "Arquitectura:"), currentProgram.getLanguage().toString()));
            w.write(String.format("- **%-15s** %s\n", t("Compiler:", "Compilador:"), currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
            w.write(String.format("- **%-15s** %s\n", t("Analyst:", "Analista:"), System.getProperty("user.name")));
            w.write(String.format("- **%-15s** %s\n", t("Date Generated:", "Fecha de Generación:"), new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())));
            w.write("\n---\n\n");

            // Executive Summary
            w.write("## " + t("Executive Summary", "Resumen Ejecutivo") + "\n");
            w.write(t(
                "This document summarizes the technical findings recovered from static analysis. The code annotations and structures have been extracted directly from the analyst's workspace database.\n\n",
                "Este documento resume los hallazgos técnicos recuperados del análisis estático. Las anotaciones de código y estructuras han sido extraídas directamente de la base de datos de trabajo del analista.\n\n"
            ));
            w.write("| " + t("Metric", "Métrica") + " | " + t("Value", "Valor") + " |\n");
            w.write("| :--- | :--- |\n");
            w.write(String.format("| %s | %d |\n", t("Renamed Functions", "Funciones Renombradas"), functions.size()));
            w.write(String.format("| %s | %d |\n", t("Total Comments", "Comentarios Totales"), comments.size()));
            w.write(String.format("| %s | %d |\n", t("Bookmarks Set", "Marcadores Establecidos"), bookmarks.size()));
            w.write(String.format("| %s | %d |\n", t("Custom Data Types", "Tipos de Datos Personalizados"), structures.size()));
            w.write("\n---\n\n");

            // Labeled Functions of Interest
            w.write("## " + t("Identified Functions of Interest", "Funciones de Interés Identificadas") + "\n");
            w.write("| " + t("Address", "Dirección") + " | " + t("Function Name", "Nombre de Función") + " | " + t("Call/Caller", "Llama/Llamado por") + " | " + t("Analyst Note / Auto comment", "Nota del Analista") + " |\n");
            w.write("| :--- | :--- | :--- | :--- |\n");
            for (FunctionEntry entry : functions) {
                w.write(String.format("| `0x%s` | **%s** | %d / %d | %s |\n",
                    entry.address.toString(),
                    entry.name,
                    entry.callCount,
                    entry.callerCount,
                    entry.comments.isEmpty() ? "-" : entry.comments
                ));
            }
            w.write("\n---\n\n");

            // Analyst Comments
            w.write("## " + t("Detailed Code Comments", "Comentarios de Código Detallados") + "\n");
            w.write("| " + t("Address", "Dirección") + " | " + t("Location/Context", "Ubicación/Contexto") + " | " + t("Type", "Tipo") + " | " + t("Comment", "Comentario") + " |\n");
            w.write("| :--- | :--- | :--- | :--- |\n");
            for (CommentEntry entry : comments) {
                w.write(String.format("| `0x%s` | %s | _%s_ | %s |\n",
                    entry.address.toString(),
                    entry.context,
                    entry.type,
                    entry.content.replace("\n", "<br>")
                ));
            }
            w.write("\n---\n\n");

            // Custom Structures
            w.write("## " + t("Reconstructed Data Structures", "Estructuras de Datos Reconstruidas") + "\n");
            if (structures.isEmpty()) {
                w.write("*" + t("No custom structures extracted.", "No se extrajeron estructuras personalizadas.") + "*\n");
            } else {
                for (String structMd : structures) {
                    w.write(structMd);
                    w.write("\n");
                }
            }
            w.write("\n---\n\n");

            // Appendix: Bookmarks
            w.write("## " + t("Appendix: Analysis Bookmarks", "Apéndice: Marcadores de Análisis") + "\n");
            w.write("| " + t("Address", "Dirección") + " | " + t("Category", "Categoría") + " | " + t("Description", "Descripción") + " |\n");
            w.write("| :--- | :--- | :--- |\n");
            for (BookmarkEntry entry : bookmarks) {
                w.write(String.format("| `0x%s` | **%s** | %s |\n",
                    entry.address.toString(),
                    entry.category,
                    entry.comment
                ));
            }
            w.write("\n");
        }
    }

    // ========================================================================
    // REPORT GENERATION (JSON)
    // ========================================================================

    private void writeJSONReport(String path, String hash, List<FunctionEntry> functions,
                                  List<CommentEntry> comments, List<BookmarkEntry> bookmarks,
                                  List<String> structures, String caseId) throws Exception {
        
        Map<String, Object> root = new LinkedHashMap<>();
        
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("case_id", caseId);
        meta.put("binary", currentProgram.getName());
        meta.put("sha256", hash);
        meta.put("architecture", currentProgram.getLanguage().toString());
        meta.put("analyst", System.getProperty("user.name"));
        meta.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()));
        root.put("metadata", meta);

        List<Map<String, Object>> funList = new ArrayList<>();
        for (FunctionEntry f : functions) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", "0x" + f.address.toString());
            m.put("name", f.name);
            m.put("comment", f.comments);
            m.put("calls", f.callCount);
            m.put("called_by", f.callerCount);
            funList.add(m);
        }
        root.put("renamed_functions", funList);

        List<Map<String, Object>> commentList = new ArrayList<>();
        for (CommentEntry c : comments) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", "0x" + c.address.toString());
            m.put("context", c.context);
            m.put("type", c.type);
            m.put("comment", c.content);
            commentList.add(m);
        }
        root.put("comments", commentList);

        List<Map<String, Object>> bmList = new ArrayList<>();
        for (BookmarkEntry b : bookmarks) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", "0x" + b.address.toString());
            m.put("category", b.category);
            m.put("comment", b.comment);
            bmList.add(m);
        }
        root.put("bookmarks", bmList);

        root.put("custom_structures_count", structures.size());

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(path), StandardCharsets.UTF_8))) {
            writer.write(toJSON(root, 0));
        }
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
    // CONSOLE HEADER
    // ========================================================================

    private void printBanner() {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║      AIB TECHNICAL REPORT GENERATOR — " +
            t("Automated Report", "Reporte Automático") + "     ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: " + currentProgram.getName());
        println("  Arch:   " + currentProgram.getLanguage());
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB Technical Report Generator — " + t("Complete", "Completado"));
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }
}
