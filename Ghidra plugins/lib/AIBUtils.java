//AIB Shared Utility Library
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * AIBUtils — Shared utility functions for the AIB Ghidra Plugin Suite.
 * 
 * This class provides common helpers used across all AIB plugins:
 * - JSON/CSV/Markdown export
 * - SHA-256 hashing
 * - Address validation
 * - Timestamp formatting
 * - AIB branded console output
 * 
 * Usage: Place this file alongside other AIB scripts in ghidra_scripts/.
 * Other scripts can reference these utilities by importing this class.
 * 
 * Since GhidraScripts are compiled in the same classloader context,
 * static methods from this class are accessible to all AIB scripts.
 */
public class AIBUtils extends GhidraScript {

    // ========================================================================
    // CONSTANTS
    // ========================================================================

    public static final String AIB_VERSION = "2.0.0";
    public static final String AIB_ORG = "Arcy Intelligence Bureau";
    public static final String AIB_DIVISION = "Dirección General";

    private static final String BANNER = 
        "╔══════════════════════════════════════════════════════════════╗\n" +
        "║          ARCY INTELLIGENCE BUREAU — GHIDRA SUITE           ║\n" +
        "║               Dirección General — v" + AIB_VERSION + "                  ║\n" +
        "╚══════════════════════════════════════════════════════════════╝";

    // ========================================================================
    // JSON EXPORT
    // ========================================================================

    /**
     * Exports a Map structure to a JSON file.
     * Supports nested Maps, Lists, arrays, and primitive types.
     */
    public static void exportToJSON(Map<String, Object> data, String filepath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            writer.write(toJSON(data, 0));
            writer.newLine();
        }
    }

    /**
     * Exports a List of Maps to a JSON array file.
     */
    public static void exportToJSONArray(List<Map<String, Object>> dataList, String filepath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            writer.write(listToJSON(dataList, 0));
            writer.newLine();
        }
    }

    @SuppressWarnings("unchecked")
    private static String toJSON(Object obj, int indent) {
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
                sb.append(innerIndent).append("\"").append(escapeJSON(entry.getKey())).append("\": ");
                sb.append(toJSON(entry.getValue(), indent + 1));
                if (it.hasNext()) sb.append(",");
                sb.append("\n");
            }
            sb.append(indentStr).append("}");
            return sb.toString();
        }
        
        if (obj instanceof List) {
            return listToJSON((List<?>) obj, indent);
        }
        
        if (obj instanceof Object[]) {
            return listToJSON(Arrays.asList((Object[]) obj), indent);
        }
        
        if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        }
        
        return "\"" + escapeJSON(obj.toString()) + "\"";
    }

    private static String listToJSON(List<?> list, int indent) {
        if (list.isEmpty()) return "[]";
        
        String indentStr = repeat("  ", indent);
        String innerIndent = repeat("  ", indent + 1);
        
        StringBuilder sb = new StringBuilder("[\n");
        for (int i = 0; i < list.size(); i++) {
            sb.append(innerIndent).append(toJSON(list.get(i), indent + 1));
            if (i < list.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append(indentStr).append("]");
        return sb.toString();
    }

    private static String escapeJSON(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\b", "\\b")
                .replace("\f", "\\f");
    }

    // ========================================================================
    // CSV EXPORT
    // ========================================================================

    /**
     * Exports tabular data to CSV.
     * @param headers Column headers
     * @param rows Data rows (each row is a String array)
     * @param filepath Output file path
     */
    public static void exportToCSV(String[] headers, List<String[]> rows, String filepath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            // UTF-8 BOM for Excel compatibility
            writer.write('\uFEFF');
            writer.write(csvLine(headers));
            writer.newLine();
            for (String[] row : rows) {
                writer.write(csvLine(row));
                writer.newLine();
            }
        }
    }

    private static String csvLine(String[] fields) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) sb.append(",");
            String field = fields[i] != null ? fields[i] : "";
            if (field.contains(",") || field.contains("\"") || field.contains("\n")) {
                sb.append("\"").append(field.replace("\"", "\"\"")).append("\"");
            } else {
                sb.append(field);
            }
        }
        return sb.toString();
    }

    // ========================================================================
    // MARKDOWN EXPORT
    // ========================================================================

    /**
     * Writes content to a Markdown file.
     */
    public static void exportToMarkdown(String content, String filepath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            writer.write(content);
        }
    }

    // ========================================================================
    // SHA-256 HASHING
    // ========================================================================

    /**
     * Computes SHA-256 hash of a byte array.
     */
    public static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return "ERROR_SHA256_UNAVAILABLE";
        }
    }

    /**
     * Computes SHA-256 of the loaded program's bytes.
     */
    public static String computeProgramHash(Program program) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.isInitialized()) {
                    byte[] bytes = new byte[(int) block.getSize()];
                    block.getBytes(block.getStart(), bytes);
                    digest.update(bytes);
                }
            }
            byte[] hash = digest.digest();
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            return "HASH_COMPUTATION_FAILED";
        }
    }

    // ========================================================================
    // ADDRESS UTILITIES
    // ========================================================================

    /**
     * Checks if an address points to executable code.
     */
    public static boolean isCodeAddress(Program program, Address addr) {
        if (addr == null) return false;
        MemoryBlock block = program.getMemory().getBlock(addr);
        return block != null && block.isExecute();
    }

    /**
     * Formats an address with 0x prefix.
     */
    public static String formatAddress(Address addr) {
        if (addr == null) return "0x????????";
        return "0x" + addr.toString();
    }

    /**
     * Formats an address range.
     */
    public static String formatAddressRange(Address start, Address end) {
        return formatAddress(start) + " - " + formatAddress(end);
    }

    // ========================================================================
    // TIMESTAMP & FORMATTING
    // ========================================================================

    /**
     * Returns current timestamp in ISO 8601 format.
     */
    public static String getTimestamp() {
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date());
    }

    /**
     * Returns a timestamp suitable for filenames.
     */
    public static String getFileTimestamp() {
        return new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
    }

    /**
     * Sanitizes a string for use as a filename.
     */
    public static String sanitizeFilename(String name) {
        if (name == null) return "unnamed";
        return name.replaceAll("[^a-zA-Z0-9._-]", "_").replaceAll("_+", "_");
    }

    /**
     * Repeats a string N times.
     */
    public static String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    // ========================================================================
    // C++ NAME DEMANGLING
    // ========================================================================

    /**
     * Attempts to demangle a MSVC-style mangled name.
     * Extracts the class name from patterns like .?AVClassName@@
     */
    public static String demangleMSVC(String mangled) {
        if (mangled == null) return null;
        // Pattern: .?AVClassName@Namespace@@
        if (mangled.startsWith(".?AV") && mangled.endsWith("@@")) {
            String inner = mangled.substring(4, mangled.length() - 2);
            // Replace @ with :: for nested namespaces
            return inner.replace("@", "::");
        }
        // Pattern: .?AUStructName@@
        if (mangled.startsWith(".?AU") && mangled.endsWith("@@")) {
            String inner = mangled.substring(4, mangled.length() - 2);
            return inner.replace("@", "::");
        }
        return mangled;
    }

    /**
     * Attempts to demangle a GCC-style mangled name.
     * Basic extraction — handles simple _ZN...E patterns.
     */
    public static String demangleGCC(String mangled) {
        if (mangled == null) return null;
        // _ZTV = vtable, _ZTI = typeinfo, _ZTS = typeinfo name string
        if (mangled.startsWith("_ZTS")) {
            return extractGCCName(mangled.substring(4));
        }
        if (mangled.startsWith("_ZTI") || mangled.startsWith("_ZTV")) {
            return extractGCCName(mangled.substring(4));
        }
        if (mangled.startsWith("_ZN")) {
            return extractGCCNestedName(mangled.substring(3));
        }
        return mangled;
    }

    private static String extractGCCName(String s) {
        // Format: <length><name> e.g. "6Player" → "Player"
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < s.length() && Character.isDigit(s.charAt(i))) {
            int lenStart = i;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            int len = Integer.parseInt(s.substring(lenStart, i));
            if (i + len <= s.length()) {
                if (result.length() > 0) result.append("::");
                result.append(s.substring(i, i + len));
                i += len;
            } else {
                break;
            }
        }
        return result.length() > 0 ? result.toString() : s;
    }

    private static String extractGCCNestedName(String s) {
        // Format: <length><name><length><name>...E
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < s.length() && s.charAt(i) != 'E') {
            if (Character.isDigit(s.charAt(i))) {
                int lenStart = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                int len = Integer.parseInt(s.substring(lenStart, i));
                if (i + len <= s.length()) {
                    if (result.length() > 0) result.append("::");
                    result.append(s.substring(i, i + len));
                    i += len;
                } else {
                    break;
                }
            } else {
                i++; // skip qualifiers like 'K', 'V', etc.
            }
        }
        return result.length() > 0 ? result.toString() : s;
    }

    // ========================================================================
    // OUTPUT DIRECTORY MANAGEMENT
    // ========================================================================

    public static String normalizeCaseId(String input) {
        if (input == null) return "CASE_001";
        String normalized = input.trim().replaceAll("[^a-zA-Z0-9._-]", "_").replaceAll("_+", "_");
        return normalized.isEmpty() ? "CASE_001" : normalized;
    }

    public static File getGlobalDirectory() {
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File dir = new File(desktop + File.separator + "AIB_Cases" + File.separator + "_global");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getConfigDirectory() {
        File dir = new File(getGlobalDirectory(), "config");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getCaseDirectory(String caseId) {
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File dir = new File(desktop + File.separator + "AIB_Cases" + File.separator + normalizeCaseId(caseId));
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getCaseExportDirectory(String caseId) {
        File dir = new File(getCaseDirectory(caseId), "exports");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getToolOutputDirectory(GhidraScript script, String caseId, String toolName) throws Exception {
        String safeToolName = sanitizeFilename(toolName);
        String progName = sanitizeFilename(script.getCurrentProgram().getName());
        File outputDir = new File(getCaseExportDirectory(caseId), safeToolName + File.separator + progName);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        return outputDir;
    }

    /**
     * Gets or creates the default AIB output directory for the current program.
     * Structure: Desktop/AIB_Cases/CASE_001/exports/general/<program_name>/
     */
    public static File getOutputDirectory(GhidraScript script) throws Exception {
        return getToolOutputDirectory(script, "CASE_001", "general");
    }

    /**
     * Creates a file path within the AIB output directory.
     */
    public static String getOutputPath(GhidraScript script, String filename) throws Exception {
        File dir = getOutputDirectory(script);
        return dir.getAbsolutePath() + File.separator + filename;
    }

    // ========================================================================
    // CONSOLE OUTPUT (AIB BRANDING)
    // ========================================================================

    /**
     * Prints the AIB branded banner.
     */
    public static void printBanner(GhidraScript script) {
        script.println(BANNER);
    }

    /**
     * Prints a plugin header.
     */
    public static void printPluginHeader(GhidraScript script, String pluginName) {
        script.println(BANNER);
        script.println("  Plugin: " + pluginName);
        script.println("  Target: " + script.getCurrentProgram().getName());
        script.println("  Time:   " + getTimestamp());
        script.println("══════════════════════════════════════════════════════════════");
    }

    /**
     * Prints a section divider.
     */
    public static void printSection(GhidraScript script, String title) {
        script.println("\n──── " + title + " " + repeat("─", Math.max(0, 50 - title.length())));
    }

    /**
     * Prints a result summary line.
     */
    public static void printResult(GhidraScript script, String label, Object value) {
        script.println("  [✓] " + label + ": " + value);
    }

    /**
     * Prints a warning line.
     */
    public static void printWarning(GhidraScript script, String message) {
        script.println("  [!] WARNING: " + message);
    }

    /**
     * Prints a completion footer.
     */
    public static void printFooter(GhidraScript script, String pluginName) {
        script.println("\n══════════════════════════════════════════════════════════════");
        script.println("  " + pluginName + " — Complete");
        script.println("  " + getTimestamp());
        script.println("══════════════════════════════════════════════════════════════\n");
    }

    // ========================================================================
    // BYTE UTILITIES
    // ========================================================================

    /**
     * Converts a byte array to hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Converts a byte array to hex string with spaces.
     */
    public static String bytesToHexSpaced(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(" ");
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }

    /**
     * Converts a hex string to byte array.
     */
    public static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    // ========================================================================
    // TABLE FORMATTING
    // ========================================================================

    /**
     * Formats data as an ASCII table for console output.
     */
    public static String formatTable(String[] headers, List<String[]> rows) {
        int cols = headers.length;
        int[] widths = new int[cols];

        // Calculate column widths
        for (int i = 0; i < cols; i++) {
            widths[i] = headers[i].length();
        }
        for (String[] row : rows) {
            for (int i = 0; i < Math.min(cols, row.length); i++) {
                if (row[i] != null) {
                    widths[i] = Math.max(widths[i], row[i].length());
                }
            }
        }

        // Build table
        StringBuilder sb = new StringBuilder();
        
        // Header
        sb.append("  │");
        for (int i = 0; i < cols; i++) {
            sb.append(" ").append(padRight(headers[i], widths[i])).append(" │");
        }
        sb.append("\n");

        // Separator
        sb.append("  ├");
        for (int i = 0; i < cols; i++) {
            sb.append(repeat("─", widths[i] + 2)).append("┤");
        }
        sb.append("\n");

        // Rows
        for (String[] row : rows) {
            sb.append("  │");
            for (int i = 0; i < cols; i++) {
                String val = (i < row.length && row[i] != null) ? row[i] : "";
                sb.append(" ").append(padRight(val, widths[i])).append(" │");
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) return s;
        return s + repeat(" ", width - s.length());
    }

    // ========================================================================
    // HTTP CLIENT MODULE (Phase 2)
    // ========================================================================

    /**
     * Sends an HTTP POST request and returns the response body.
     * Used by AIB_SentinelAI for LLM API calls.
     */
    public static String httpPost(String urlStr, Map<String, String> headers, String body) throws IOException {
        java.net.URL url = new java.net.URL(urlStr);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(120000);
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        if (headers != null) {
            for (Map.Entry<String, String> h : headers.entrySet()) {
                conn.setRequestProperty(h.getKey(), h.getValue());
            }
        }
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        if (is == null) throw new IOException("HTTP " + code + " — no response body");
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
        }
        if (code < 200 || code >= 300) {
            throw new IOException("HTTP " + code + ": " + sb.toString().trim());
        }
        return sb.toString().trim();
    }

    /**
     * Sends an HTTP GET request and returns the response body.
     */
    public static String httpGet(String urlStr, Map<String, String> headers) throws IOException {
        java.net.URL url = new java.net.URL(urlStr);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(60000);
        if (headers != null) {
            for (Map.Entry<String, String> h : headers.entrySet()) {
                conn.setRequestProperty(h.getKey(), h.getValue());
            }
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        if (is == null) throw new IOException("HTTP " + code + " — no response body");
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
        }
        return sb.toString().trim();
    }

    // ========================================================================
    // API CONFIGURATION (Phase 2)
    // ========================================================================

    private static final String CONFIG_FILENAME = ".aib_config.json";

    /**
     * Loads the AIB API configuration from the exports directory.
     * Returns a map with keys: gemini_key, claude_key, preferred_provider, daily_limit, usage_today, usage_date
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> loadAPIConfig() {
        Map<String, String> config = new LinkedHashMap<>();
        File configFile = new File(getConfigDirectory(), CONFIG_FILENAME);
        if (configFile.exists()) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(new FileInputStream(configFile), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
                String json = sb.toString().trim();
                // Simple JSON parser for flat key-value config
                json = json.replaceAll("[{}]", "").trim();
                for (String pair : json.split(",")) {
                    String[] kv = pair.split(":", 2);
                    if (kv.length == 2) {
                        String key = kv[0].trim().replaceAll("\"", "");
                        String val = kv[1].trim().replaceAll("\"", "");
                        config.put(key, val);
                    }
                }
            } catch (Exception e) {
                // Return empty config on error
            }
        }
        return config;
    }

    /**
     * Saves the AIB API configuration.
     */
    public static void saveAPIConfig(Map<String, String> config) throws IOException {
        File dir = getConfigDirectory();
        File configFile = new File(dir, CONFIG_FILENAME);
        Map<String, Object> wrapped = new LinkedHashMap<>(config);
        exportToJSON(wrapped, configFile.getAbsolutePath());
    }

    /**
     * Increments the daily API usage counter. Returns the new count.
     */
    public static int incrementAPIUsage() {
        Map<String, String> config = loadAPIConfig();
        String today = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        String lastDate = config.getOrDefault("usage_date", "");
        int count;
        if (today.equals(lastDate)) {
            count = Integer.parseInt(config.getOrDefault("usage_today", "0")) + 1;
        } else {
            count = 1;
        }
        config.put("usage_date", today);
        config.put("usage_today", String.valueOf(count));
        try {
            saveAPIConfig(config);
        } catch (IOException e) {
            // Non-fatal
        }
        return count;
    }

    /**
     * Gets the current daily API usage count.
     */
    public static int getAPIUsageToday() {
        Map<String, String> config = loadAPIConfig();
        String today = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        String lastDate = config.getOrDefault("usage_date", "");
        if (today.equals(lastDate)) {
            return Integer.parseInt(config.getOrDefault("usage_today", "0"));
        }
        return 0;
    }

    // ========================================================================
    // ENTROPY FUNCTIONS (Phase 2)
    // ========================================================================

    /**
     * Computes Shannon entropy of a byte array.
     * Returns value between 0.0 (uniform) and 8.0 (maximum randomness).
     */
    public static double shannonEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int[] freq = new int[256];
        for (byte b : data) freq[b & 0xFF]++;
        double entropy = 0.0;
        double len = data.length;
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                entropy -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return entropy;
    }

    /**
     * Computes entropy using a sliding window across the data.
     * Returns an array of entropy values, one per window position.
     */
    public static double[] slidingWindowEntropy(byte[] data, int windowSize, int step) {
        if (data == null || data.length < windowSize) return new double[0];
        int count = (data.length - windowSize) / step + 1;
        double[] result = new double[count];
        for (int i = 0; i < count; i++) {
            byte[] window = new byte[windowSize];
            System.arraycopy(data, i * step, window, 0, windowSize);
            result[i] = shannonEntropy(window);
        }
        return result;
    }

    /**
     * Computes byte frequency distribution.
     * Returns int[256] with count of each byte value.
     */
    public static int[] byteFrequency(byte[] data) {
        int[] freq = new int[256];
        if (data != null) {
            for (byte b : data) freq[b & 0xFF]++;
        }
        return freq;
    }

    /**
     * Computes the ratio of printable ASCII bytes (0x20-0x7E, plus 0x09, 0x0A, 0x0D).
     */
    public static double asciiRatio(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int printable = 0;
        for (byte b : data) {
            int v = b & 0xFF;
            if ((v >= 0x20 && v <= 0x7E) || v == 0x09 || v == 0x0A || v == 0x0D) {
                printable++;
            }
        }
        return (double) printable / data.length;
    }

    /**
     * Classifies entropy level as a human-readable string.
     */
    public static String classifyEntropy(double entropy) {
        if (entropy >= 7.5) return "ENCRYPTED";
        if (entropy >= 7.0) return "PACKED/COMPRESSED";
        if (entropy >= 6.0) return "POSSIBLY_OBFUSCATED";
        if (entropy >= 4.5) return "MIXED_CONTENT";
        if (entropy >= 3.0) return "TEXT/CODE";
        return "LOW_ENTROPY_DATA";
    }

    // ========================================================================
    // DOT GRAPH BUILDER (Phase 2)
    // ========================================================================

    /**
     * Simple DOT graph builder for CyberFlow visualization.
     */
    public static class DotGraphBuilder {
        private String graphName;
        private List<String> nodes = new ArrayList<>();
        private List<String> edges = new ArrayList<>();
        private List<String> subgraphs = new ArrayList<>();
        private Map<String, String> graphAttrs = new LinkedHashMap<>();

        public DotGraphBuilder(String name) {
            this.graphName = name;
            graphAttrs.put("rankdir", "TB");
            graphAttrs.put("fontname", "Helvetica");
            graphAttrs.put("bgcolor", "\"#1a1a2e\"");
        }

        public DotGraphBuilder addNode(String id, String label, String fillColor, String shape, String fontColor) {
            nodes.add(String.format("  \"%s\" [label=\"%s\", shape=%s, style=filled, fillcolor=\"%s\", fontcolor=\"%s\", fontname=\"Helvetica\"];",
                id, escapeJSON(label), shape, fillColor, fontColor));
            return this;
        }

        public DotGraphBuilder addEdge(String fromId, String toId, String label, String color, String style) {
            String attrs = String.format("color=\"%s\", style=%s, fontcolor=\"%s\", fontname=\"Helvetica\", fontsize=9",
                color, style, color);
            if (label != null && !label.isEmpty()) {
                attrs += String.format(", label=\"%s\"", escapeJSON(label));
            }
            edges.add(String.format("  \"%s\" -> \"%s\" [%s];", fromId, toId, attrs));
            return this;
        }

        public DotGraphBuilder addSubgraph(String name, String label, String color, List<String> nodeIds) {
            StringBuilder sg = new StringBuilder();
            sg.append("  subgraph \"cluster_").append(name).append("\" {\n");
            sg.append("    label=\"").append(escapeJSON(label)).append("\";\n");
            sg.append("    style=dashed; color=\"").append(color).append("\"; fontcolor=\"").append(color).append("\";\n");
            for (String nid : nodeIds) {
                sg.append("    \"").append(nid).append("\";\n");
            }
            sg.append("  }");
            subgraphs.add(sg.toString());
            return this;
        }

        public String toDOT() {
            StringBuilder sb = new StringBuilder();
            sb.append("digraph \"").append(graphName).append("\" {\n");
            for (Map.Entry<String, String> a : graphAttrs.entrySet()) {
                sb.append("  ").append(a.getKey()).append("=").append(a.getValue()).append(";\n");
            }
            sb.append("  node [shape=box, style=filled, fontname=\"Helvetica\", fontsize=10];\n");
            sb.append("  edge [fontname=\"Helvetica\", fontsize=9];\n\n");
            for (String sg : subgraphs) {
                sb.append(sg).append("\n\n");
            }
            for (String n : nodes) {
                sb.append(n).append("\n");
            }
            sb.append("\n");
            for (String e : edges) {
                sb.append(e).append("\n");
            }
            sb.append("}\n");
            return sb.toString();
        }

        /**
         * Generates a self-contained interactive HTML visualization.
         * Uses vis.js from CDN for network graph rendering.
         */
        public String toHTML(String title, List<Map<String, Object>> nodeData, List<Map<String, Object>> edgeData) {
            StringBuilder sb = new StringBuilder();
            sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
            sb.append("<meta charset=\"UTF-8\">\n");
            sb.append("<title>").append(escapeJSON(title)).append("</title>\n");
            sb.append("<script src=\"https://unpkg.com/vis-network/standalone/umd/vis-network.min.js\"></script>\n");
            sb.append("<style>\n");
            sb.append("body { margin:0; background:#0f0f23; color:#e0e0e0; font-family:'Segoe UI',Arial,sans-serif; }\n");
            sb.append("#header { background:linear-gradient(135deg,#1a1a2e,#16213e); padding:15px 25px; ");
            sb.append("border-bottom:2px solid #e94560; display:flex; justify-content:space-between; align-items:center; }\n");
            sb.append("#header h1 { margin:0; font-size:18px; color:#e94560; }\n");
            sb.append("#header span { font-size:12px; color:#888; }\n");
            sb.append("#controls { background:#1a1a2e; padding:10px 25px; border-bottom:1px solid #333; display:flex; gap:10px; flex-wrap:wrap; }\n");
            sb.append(".btn { padding:6px 14px; border:1px solid #444; background:#16213e; color:#ccc; cursor:pointer; ");
            sb.append("border-radius:4px; font-size:12px; } .btn:hover { background:#e94560; color:#fff; border-color:#e94560; }\n");
            sb.append(".btn.active { background:#e94560; color:#fff; border-color:#e94560; }\n");
            sb.append("#search { padding:6px 12px; background:#0f0f23; border:1px solid #444; color:#e0e0e0; border-radius:4px; font-size:12px; width:200px; }\n");
            sb.append("#network { width:100%; height:calc(100vh - 120px); }\n");
            sb.append("#legend { position:absolute; bottom:20px; right:20px; background:rgba(26,26,46,0.9); ");
            sb.append("padding:12px 16px; border-radius:8px; border:1px solid #333; font-size:11px; }\n");
            sb.append(".legend-item { display:flex; align-items:center; gap:8px; margin:4px 0; }\n");
            sb.append(".legend-dot { width:12px; height:12px; border-radius:50%; }\n");
            sb.append("#details { position:absolute; top:120px; right:20px; background:rgba(26,26,46,0.95); ");
            sb.append("padding:15px; border-radius:8px; border:1px solid #e94560; max-width:350px; display:none; font-size:12px; }\n");
            sb.append("#details h3 { margin:0 0 8px 0; color:#e94560; font-size:14px; }\n");
            sb.append("#details .close { position:absolute; top:8px; right:12px; cursor:pointer; color:#888; }\n");
            sb.append("</style>\n</head>\n<body>\n");
            sb.append("<div id=\"header\"><h1>⚡ AIB CyberFlow — ").append(escapeJSON(title)).append("</h1>");
            sb.append("<span>Arcy Intelligence Bureau — Dirección General</span></div>\n");
            sb.append("<div id=\"controls\">\n");
            sb.append("<input id=\"search\" type=\"text\" placeholder=\"Search function...\">\n");
            sb.append("<button class=\"btn active\" onclick=\"toggleFilter('all')\">All</button>\n");
            sb.append("<button class=\"btn\" onclick=\"toggleFilter('MALICIOUS')\">🔴 Malicious</button>\n");
            sb.append("<button class=\"btn\" onclick=\"toggleFilter('SUSPICIOUS')\">🟡 Suspicious</button>\n");
            sb.append("<button class=\"btn\" onclick=\"toggleFilter('CRYPTO')\">🔵 Crypto</button>\n");
            sb.append("<button class=\"btn\" onclick=\"toggleFilter('NETWORK')\">🟣 Network</button>\n");
            sb.append("<button class=\"btn\" onclick=\"toggleFilter('BENIGN')\">🟢 Benign</button>\n");
            sb.append("</div>\n");
            sb.append("<div id=\"network\"></div>\n");
            sb.append("<div id=\"legend\">\n");
            sb.append("<div class=\"legend-item\"><div class=\"legend-dot\" style=\"background:#ff4444\"></div>Malicious</div>\n");
            sb.append("<div class=\"legend-item\"><div class=\"legend-dot\" style=\"background:#ffaa00\"></div>Suspicious</div>\n");
            sb.append("<div class=\"legend-item\"><div class=\"legend-dot\" style=\"background:#44ff44\"></div>Benign</div>\n");
            sb.append("<div class=\"legend-item\"><div class=\"legend-dot\" style=\"background:#4488ff\"></div>Crypto</div>\n");
            sb.append("<div class=\"legend-item\"><div class=\"legend-dot\" style=\"background:#aa44ff\"></div>Network</div>\n");
            sb.append("<div class=\"legend-item\"><div class=\"legend-dot\" style=\"background:#888888\"></div>Unknown</div>\n");
            sb.append("</div>\n");
            sb.append("<div id=\"details\"><span class=\"close\" onclick=\"document.getElementById('details').style.display='none'\">✕</span>");
            sb.append("<h3 id=\"detTitle\"></h3><div id=\"detBody\"></div></div>\n");
            sb.append("<script>\n");
            sb.append("var allNodes = ").append(toJSON(new ArrayList<Object>(nodeData), 0)).append(";\n");
            sb.append("var allEdges = ").append(toJSON(new ArrayList<Object>(edgeData), 0)).append(";\n");
            sb.append("var nodes = new vis.DataSet(allNodes);\n");
            sb.append("var edges = new vis.DataSet(allEdges);\n");
            sb.append("var container = document.getElementById('network');\n");
            sb.append("var data = {nodes: nodes, edges: edges};\n");
            sb.append("var options = {\n");
            sb.append("  physics:{barnesHut:{gravitationalConstant:-3000,springLength:150}},\n");
            sb.append("  nodes:{font:{color:'#e0e0e0',size:11}},\n");
            sb.append("  edges:{arrows:'to',smooth:{type:'cubicBezier'}},\n");
            sb.append("  interaction:{hover:true,tooltipDelay:200}\n");
            sb.append("};\n");
            sb.append("var network = new vis.Network(container, data, options);\n");
            sb.append("network.on('click',function(p){\n");
            sb.append("  if(p.nodes.length>0){var n=nodes.get(p.nodes[0]);\n");
            sb.append("  document.getElementById('detTitle').textContent=n.label;\n");
            sb.append("  document.getElementById('detBody').innerHTML='<p>'+( n.title||'No details')+'</p>';\n");
            sb.append("  document.getElementById('details').style.display='block';}\n");
            sb.append("});\n");
            sb.append("function toggleFilter(cat){\n");
            sb.append("  document.querySelectorAll('.btn').forEach(b=>b.classList.remove('active'));\n");
            sb.append("  event.target.classList.add('active');\n");
            sb.append("  if(cat==='all'){nodes.update(allNodes.map(n=>({id:n.id,hidden:false})));}\n");
            sb.append("  else{nodes.update(allNodes.map(n=>({id:n.id,hidden:n.group!==cat})));}\n");
            sb.append("}\n");
            sb.append("document.getElementById('search').addEventListener('input',function(){\n");
            sb.append("  var q=this.value.toLowerCase();\n");
            sb.append("  if(!q){nodes.update(allNodes.map(n=>({id:n.id,hidden:false})));return;}\n");
            sb.append("  nodes.update(allNodes.map(n=>({id:n.id,hidden:!n.label.toLowerCase().includes(q)})));\n");
            sb.append("});\n");
            sb.append("</script>\n</body>\n</html>");
            return sb.toString();
        }
    }

    // ========================================================================
    // SIMPLE JSON VALUE EXTRACTOR (Phase 2)
    // ========================================================================

    /**
     * Extracts a string value from a JSON object string by key.
     * Simple parser — works for flat or single-level nesting.
     */
    public static String extractJSONValue(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colonIdx = json.indexOf(':', idx + search.length());
        if (colonIdx < 0) return null;
        int start = colonIdx + 1;
        // Skip whitespace
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length()) return null;
        char c = json.charAt(start);
        if (c == '"') {
            // String value
            int end = json.indexOf('"', start + 1);
            // Handle escaped quotes
            while (end > 0 && json.charAt(end - 1) == '\\') end = json.indexOf('"', end + 1);
            return (end > start) ? json.substring(start + 1, end) : null;
        } else if (c == '[' || c == '{') {
            // Array or object — find matching bracket
            char open = c, close = (c == '[') ? ']' : '}';
            int depth = 1;
            int pos = start + 1;
            while (pos < json.length() && depth > 0) {
                char ch = json.charAt(pos);
                if (ch == open) depth++;
                else if (ch == close) depth--;
                pos++;
            }
            return json.substring(start, pos);
        } else {
            // Number, boolean, null
            int end = start;
            while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}' && json.charAt(end) != ']') end++;
            return json.substring(start, end).trim();
        }
    }

    /**
     * Extracts the "text" content from a Gemini API response.
     */
    public static String extractGeminiResponseText(String responseJson) {
        // Navigate: candidates[0].content.parts[0].text
        String candidates = extractJSONValue(responseJson, "candidates");
        if (candidates == null) return null;
        String content = extractJSONValue(candidates, "content");
        if (content == null) return null;
        String parts = extractJSONValue(content, "parts");
        if (parts == null) return null;
        String text = extractJSONValue(parts, "text");
        return text;
    }

    /**
     * Extracts the text content from a Claude API response.
     */
    public static String extractClaudeResponseText(String responseJson) {
        // Navigate: content[0].text
        String content = extractJSONValue(responseJson, "content");
        if (content == null) return null;
        String text = extractJSONValue(content, "text");
        return text;
    }

    // ========================================================================
    // GHIDRA SCRIPT ENTRY (required but this is a library)
    // ========================================================================

    @Override
    protected void run() throws Exception {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║          ARCY INTELLIGENCE BUREAU — GHIDRA SUITE           ║");
        println("║               Dirección General — v" + AIB_VERSION + "                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("");
        println("AIBUtils is a shared library. It provides utility functions");
        println("used by all other AIB plugins. You don't need to run this");
        println("script directly.");
        println("");
        println("Available AIB Plugins (Phase 1 — Core):");
        println("  1.  AIB_NetworkArtifactExtractor  — IoC/Network data extraction");
        println("  2.  AIB_CryptoDetector            — Cryptography identification");
        println("  3.  AIB_FileStructureParser        — Embedded file format parser");
        println("  4.  AIB_RTTIVtableIdentifier       — C++ RTTI/Vtable reconstruction");
        println("  5.  AIB_PointerChainHelper         — Pointer chain tracing");
        println("  6.  AIB_GameEngineFilter           — Game engine noise filter");
        println("  7.  AIB_TechnicalReportGenerator   — Markdown report generation");
        println("  8.  AIB_AuditTrailLogger           — Analysis audit trail");
        println("");
        println("Available AIB Plugins (Phase 2 — Mega OP):");
        println("  9.  AIB_SentinelAI                — LLM-powered binary analysis");
        println("  10. AIB_EntropyShield             — Entropy & anti-analysis detection");
        println("  11. AIB_GhostDecrypter            — Emulation-based string decryption");
        println("  12. AIB_CyberFlow                 — Behavior graph visualization");
        println("");
        println("All exports are saved under: Desktop/AIB_Cases/<Case_ID>/exports/");
    }
}
