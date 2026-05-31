//AIB Audit Trail Logger — Analyst Modification History & Diff Logger
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.ReportAutomation
//@keybinding
//@menupath Tools.AIB.Audit Trail Logger
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB AUDIT TRAIL LOGGER
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 *
 * Captures historical snapshots of analyst modifications (renamed symbols,
 * comments, bookmarks) and generates comparison diff reports.
 *
 * Output:
 *   - audit_trail_<case>_<timestamp>.json (complete state snapshot)
 *   - audit_diff_<case>_<timestamp>.md (human-readable change log)
 *
 * Features:
 *   - Multi-analyst tracing (captures OS username)
 *   - Auto-detection of prior snapshots for comparison
 *   - Compact regex-based JSON parsing (dependency-free)
 *
 * Language: Bilingual EN/ES
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_AuditTrailLogger extends GhidraScript {

    private boolean useSpanish = false;
    private String t(String en, String es) { return useSpanish ? es : en; }

    // ========================================================================
    // STATE STRUCTURES
    // ========================================================================

    private Map<String, String> currentSymbols = new LinkedHashMap<>();
    private Map<String, String> currentComments = new LinkedHashMap<>();
    private Map<String, String> currentBookmarks = new LinkedHashMap<>();

    private Map<String, String> prevSymbols = new LinkedHashMap<>();
    private Map<String, String> prevComments = new LinkedHashMap<>();
    private Map<String, String> prevBookmarks = new LinkedHashMap<>();

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        // Language selection
        String langChoice = askChoice(
            "AIB Audit Trail Logger — Language / Idioma",
            "Select language / Seleccione idioma:",
            Arrays.asList("English", "Español"), "English");
        useSpanish = "Español".equals(langChoice);

        String caseId = askString(
            t("AIB — Case ID", "AIB — ID de Caso"),
            t("Enter Case ID:", "Ingrese ID de Caso:"), "CASE_001");
        caseId = normalizeCaseId(caseId);

        printBanner();

        // Setup paths
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File auditDir = new File(desktop + File.separator + "AIB_Cases" + File.separator +
            caseId + File.separator + "exports" + File.separator + "audit");
        if (!auditDir.exists()) auditDir.mkdirs();

        // 1. Find latest previous snapshot before taking new one
        File latestPrevFile = findLatestSnapshot(auditDir);
        if (latestPrevFile != null) {
            println("  [*] " + t("Found prior snapshot", "Se encontró un snapshot previo") + ": " + latestPrevFile.getName());
            println("  [*] " + t("Parsing prior snapshot...", "Analizando snapshot previo..."));
            parseSnapshot(latestPrevFile);
        } else {
            println("  [*] " + t("No prior snapshot found. First run of Audit Trail.", 
                "No se encontró un snapshot previo. Primera ejecución de la Bitácora de Auditoría."));
        }

        // 2. Capture current state
        println("  [*] " + t("Capturing current project state...", "Capturando el estado actual del proyecto..."));
        captureCurrentState();

        // 3. Write new snapshot
        String snapshotPath = auditDir.getAbsolutePath() + File.separator + "audit_trail_" + timestamp + ".json";
        writeSnapshot(snapshotPath);
        println("  [✓] " + t("Snapshot captured", "Snapshot capturado") + ": " + snapshotPath);

        // 4. Generate and save diff
        if (latestPrevFile != null) {
            println("  [*] " + t("Generating change logs...", "Generando registros de cambios..."));
            String diffPath = auditDir.getAbsolutePath() + File.separator + "audit_diff_" + timestamp + ".md";
            generateDiffReport(diffPath, latestPrevFile.getName());
            println("  [✓] " + t("Audit Diff Report saved", "Reporte de Cambios Guardado") + ": " + diffPath);
        }

        printFooter();
    }

    // ========================================================================
    // STATE CAPTURE
    // ========================================================================

    private void captureCurrentState() {
        // Capture Symbols
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            // Exclude default symbols to keep logs clean
            if (!name.startsWith("FUN_") && !name.startsWith("SUB_") && 
                !name.startsWith("LAB_") && !name.startsWith("DAT_") && 
                !name.startsWith("PTR_")) {
                currentSymbols.put("0x" + sym.getAddress().toString(), name);
            }
        }

        // Capture Comments
        Listing listing = currentProgram.getListing();
        CodeUnitIterator units = listing.getCodeUnits(true);
        while (units.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = units.next();
            Address addr = cu.getMinAddress();
            String addrStr = "0x" + addr.toString();

            checkComment(cu, CommentType.PLATE, addrStr + ":PLATE");
            checkComment(cu, CommentType.PRE, addrStr + ":PRE");
            checkComment(cu, CommentType.POST, addrStr + ":POST");
            checkComment(cu, CommentType.EOL, addrStr + ":EOL");
            checkComment(cu, CommentType.REPEATABLE, addrStr + ":REPEATABLE");
        }

        // Capture Bookmarks
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        Iterator<Bookmark> it = bmMgr.getBookmarksIterator();
        while (it.hasNext()) {
            Bookmark bm = it.next();
            currentBookmarks.put("0x" + bm.getAddress().toString() + ":" + bm.getCategory(), bm.getComment());
        }
    }

    private void checkComment(CodeUnit cu, CommentType commentType, String key) {
        String comment = cu.getComment(commentType);
        if (comment != null && !comment.trim().isEmpty()) {
            currentComments.put(key, comment);
        }
    }

    // ========================================================================
    // SNAPSHOT IO
    // ========================================================================

    private File findLatestSnapshot(File auditDir) {
        File[] files = auditDir.listFiles((dir, name) -> name.startsWith("audit_trail_") && name.endsWith(".json"));
        if (files == null || files.length == 0) return null;
        Arrays.sort(files, (a, b) -> b.getName().compareTo(a.getName())); // Sort descending (newest first)
        return files[0];
    }

    private void writeSnapshot(String filepath) throws Exception {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            writer.write("{\n");
            writer.write("  \"metadata\": {\n");
            writer.write("    \"analyst\": \"" + esc(System.getProperty("user.name")) + "\",\n");
            writer.write("    \"timestamp\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()) + "\"\n");
            writer.write("  },\n");

            // Write Symbols
            writer.write("  \"symbols\": [\n");
            writeMapEntries(writer, currentSymbols);
            writer.write("  ],\n");

            // Write Comments
            writer.write("  \"comments\": [\n");
            writeMapEntries(writer, currentComments);
            writer.write("  ],\n");

            // Write Bookmarks
            writer.write("  \"bookmarks\": [\n");
            writeMapEntries(writer, currentBookmarks);
            writer.write("  ]\n");

            writer.write("}\n");
        }
    }

    private void writeMapEntries(BufferedWriter w, Map<String, String> map) throws IOException {
        List<Map.Entry<String, String>> entries = new ArrayList<>(map.entrySet());
        for (int i = 0; i < entries.size(); i++) {
            Map.Entry<String, String> entry = entries.get(i);
            w.write("    {\"key\": \"" + esc(entry.getKey()) + "\", \"value\": \"" + esc(entry.getValue()) + "\"}");
            if (i < entries.size() - 1) w.write(",");
            w.write("\n");
        }
    }

    private void parseSnapshot(File file) throws Exception {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            
            String line;
            String currentSection = "";
            Pattern entryPattern = Pattern.compile("\\{\"key\":\\s*\"([^\"]+)\",\\s*\"value\":\\s*\"([^\"]*)\"\\}");

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("\"symbols\"")) {
                    currentSection = "symbols";
                } else if (line.startsWith("\"comments\"")) {
                    currentSection = "comments";
                } else if (line.startsWith("\"bookmarks\"")) {
                    currentSection = "bookmarks";
                }
                
                Matcher m = entryPattern.matcher(line);
                if (m.find()) {
                    String key = m.group(1).replace("\\\\", "\\").replace("\\\"", "\"");
                    String val = m.group(2).replace("\\\\", "\\").replace("\\\"", "\"").replace("\\n", "\n");
                    
                    if ("symbols".equals(currentSection)) {
                        prevSymbols.put(key, val);
                    } else if ("comments".equals(currentSection)) {
                        prevComments.put(key, val);
                    } else if ("bookmarks".equals(currentSection)) {
                        prevBookmarks.put(key, val);
                    }
                }
            }
        }
    }

    // ========================================================================
    // DIFF GENERATION
    // ========================================================================

    private void generateDiffReport(String outputPath, String prevFileName) throws Exception {
        List<String> symLogs = new ArrayList<>();
        List<String> commentLogs = new ArrayList<>();
        List<String> bookmarkLogs = new ArrayList<>();

        // Diff Symbols
        for (Map.Entry<String, String> entry : currentSymbols.entrySet()) {
            String addr = entry.getKey();
            String curName = entry.getValue();
            if (!prevSymbols.containsKey(addr)) {
                symLogs.add(String.format("| `%-12s` | %s | [NEW] `%s` |", addr, "-", curName));
            } else if (!prevSymbols.get(addr).equals(curName)) {
                symLogs.add(String.format("| `%-12s` | `%s` | [MOD] `%s` |", addr, prevSymbols.get(addr), curName));
            }
        }
        for (String addr : prevSymbols.keySet()) {
            if (!currentSymbols.containsKey(addr)) {
                symLogs.add(String.format("| `%-12s` | `%s` | [DEL] - |", addr, prevSymbols.get(addr)));
            }
        }

        // Diff Comments
        for (Map.Entry<String, String> entry : currentComments.entrySet()) {
            String key = entry.getKey();
            String curComment = entry.getValue();
            int colonIdx = key.indexOf(':');
            String addr = key.substring(0, colonIdx);
            String type = key.substring(colonIdx + 1);

            String displayComment = curComment.replace("\n", "<br>");
            if (!prevComments.containsKey(key)) {
                commentLogs.add(String.format("| `%-12s` | %s | [NEW] _%s_ | %s |", addr, type, "-", displayComment));
            } else if (!prevComments.get(key).equals(curComment)) {
                commentLogs.add(String.format("| `%-12s` | %s | [MOD] _%s_ | %s |", addr, type, prevComments.get(key).replace("\n", "<br>"), displayComment));
            }
        }
        for (String key : prevComments.keySet()) {
            if (!currentComments.containsKey(key)) {
                int colonIdx = key.indexOf(':');
                String addr = key.substring(0, colonIdx);
                String type = key.substring(colonIdx + 1);
                commentLogs.add(String.format("| `%-12s` | %s | [DEL] _%s_ | - |", addr, type, prevComments.get(key).replace("\n", "<br>")));
            }
        }

        // Diff Bookmarks
        for (Map.Entry<String, String> entry : currentBookmarks.entrySet()) {
            String key = entry.getKey();
            String curBm = entry.getValue();
            int colonIdx = key.indexOf(':');
            String addr = key.substring(0, colonIdx);
            String cat = key.substring(colonIdx + 1);

            if (!prevBookmarks.containsKey(key)) {
                bookmarkLogs.add(String.format("| `%-12s` | %s | [NEW] %s |", addr, cat, curBm));
            }
        }
        for (String key : prevBookmarks.keySet()) {
            if (!currentBookmarks.containsKey(key)) {
                int colonIdx = key.indexOf(':');
                String addr = key.substring(0, colonIdx);
                String cat = key.substring(colonIdx + 1);
                bookmarkLogs.add(String.format("| `%-12s` | %s | [DEL] %s |", addr, cat, prevBookmarks.get(key)));
            }
        }

        // Write Markdown Diff File
        try (BufferedWriter w = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8))) {
            
            w.write("# " + t("AIB Audit Diff Report", "Reporte de Cambios de Auditoría AIB") + "\n\n");
            w.write("- **" + t("Project Name:", "Nombre del Proyecto:") + "** " + currentProgram.getName() + "\n");
            w.write("- **" + t("Prior Snapshot:", "Snapshot Previo:") + "** " + prevFileName + "\n");
            w.write("- **" + t("Current Snapshot:", "Snapshot Actual:") + "** " + new File(outputPath).getName().replace("audit_diff_", "audit_trail_").replace(".md", ".json") + "\n");
            w.write("- **" + t("Analyst:", "Analista:") + "** " + System.getProperty("user.name") + "\n");
            w.write("- **" + t("Date:", "Fecha:") + "** " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) + "\n\n");
            w.write("---\n\n");

            // Symbols Diff
            w.write("## " + t("Symbol Modifications", "Modificaciones de Símbolos") + "\n");
            if (symLogs.isEmpty()) {
                w.write("*" + t("No symbols changed.", "No hubo cambios en los símbolos.") + "*\n\n");
            } else {
                w.write("| " + t("Address", "Dirección") + " | " + t("Previous Value", "Valor Previo") + " | " + t("Current Value", "Valor Actual") + " |\n");
                w.write("| :--- | :--- | :--- |\n");
                for (String log : symLogs) w.write(log + "\n");
                w.write("\n");
            }

            // Comments Diff
            w.write("## " + t("Comment Modifications", "Modificaciones de Comentarios") + "\n");
            if (commentLogs.isEmpty()) {
                w.write("*" + t("No comments changed.", "No hubo cambios en los comentarios.") + "*\n\n");
            } else {
                w.write("| " + t("Address", "Dirección") + " | " + t("Type", "Tipo") + " | " + t("Previous Comment", "Comentario Previo") + " | " + t("Current Comment", "Comentario Actual") + " |\n");
                w.write("| :--- | :--- | :--- | :--- |\n");
                for (String log : commentLogs) w.write(log + "\n");
                w.write("\n");
            }

            // Bookmarks Diff
            w.write("## " + t("Bookmark Modifications", "Modificaciones de Marcadores") + "\n");
            if (bookmarkLogs.isEmpty()) {
                w.write("*" + t("No bookmarks changed.", "No hubo cambios en los marcadores.") + "*\n\n");
            } else {
                w.write("| " + t("Address", "Dirección") + " | " + t("Category", "Categoría") + " | " + t("Details", "Detalles") + " |\n");
                w.write("| :--- | :--- | :--- |\n");
                for (String log : bookmarkLogs) w.write(log + "\n");
                w.write("\n");
            }
        }

        // Print summary to Ghidra console
        println("\n──── " + t("CHANGES SINCE LAST SNAPSHOT", "CAMBIOS DESDE EL ÚLTIMO SNAPSHOT") + " ──────────────────");
        println("  " + t("Symbol Changes", "Cambios en Símbolos") + ":   " + symLogs.size());
        println("  " + t("Comment Changes", "Cambios en Comentarios") + ":  " + commentLogs.size());
        println("  " + t("Bookmark Changes", "Cambios en Marcadores") + ": " + bookmarkLogs.size());
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

    // ========================================================================
    // CONSOLE HEADER
    // ========================================================================

    private void printBanner() {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║        AIB AUDIT TRAIL LOGGER — " +
            t("Session Diffing", "Comparación de Sesión") + "      ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: " + currentProgram.getName());
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("  User:   " + System.getProperty("user.name"));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB Audit Trail Logger — " + t("Complete", "Completado"));
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }
}
