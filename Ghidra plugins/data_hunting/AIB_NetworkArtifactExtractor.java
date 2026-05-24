//AIB Network Artifact Extractor — OSINT IoC Extraction
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.DataHunting
//@keybinding
//@menupath Tools.AIB.Network Artifact Extractor
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB NETWORK ARTIFACT EXTRACTOR
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 * 
 * Scans the loaded binary for network-related Indicators of Compromise (IoCs):
 *   - IPv4 and IPv6 addresses
 *   - URLs (HTTP/HTTPS/FTP)
 *   - Domain names
 *   - Email addresses
 *   - User-Agent strings
 *   - File paths (Windows/Unix)
 *   - Registry key references
 * 
 * Results are:
 *   - Printed to console with cross-reference information
 *   - Bookmarked in Ghidra for quick navigation
 *   - Exported as JSON (for OSINT tool ingestion)
 *   - Exported as CSV (for Documentation Officer)
 * 
 * Output: Desktop/AIB_Exports/<program_name>/
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_NetworkArtifactExtractor extends GhidraScript {

    // ========================================================================
    // REGEX PATTERNS
    // ========================================================================

    // IPv4 — validates octets 0-255
    private static final String IPV4_REGEX =
        "\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\.){3}" +
        "(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\b";

    // IPv4 with port
    private static final String IPV4_PORT_REGEX =
        "\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\.){3}" +
        "(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d):\\d{1,5}\\b";

    // IPv6 — simplified pattern for common formats
    private static final String IPV6_REGEX =
        "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|" +
        "(?:[0-9a-fA-F]{1,4}:){1,7}:|" +
        "::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|" +
        "(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}";

    // URLs — HTTP, HTTPS, FTP
    private static final String URL_REGEX =
        "(?:https?|ftp)://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+";

    // Domain names — with TLD validation
    private static final String DOMAIN_REGEX =
        "\\b[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?" +
        "(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*" +
        "\\.(?:com|net|org|edu|gov|mil|int|io|co|info|biz|name|pro|" +
        "aero|museum|coop|travel|jobs|mobi|cat|asia|tel|xxx|" +
        "uk|us|ca|de|fr|es|it|nl|be|at|ch|ru|cn|jp|kr|au|br|mx|" +
        "ar|cl|pe|ve|ec|bo|py|uy|onion|bit|i2p|xyz|top|club|" +
        "online|site|store|tech|space|fun|website|app|dev|" +
        "tk|ml|ga|cf|gq)\\b";

    // Email addresses
    private static final String EMAIL_REGEX =
        "\\b[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}\\b";

    // User-Agent strings
    private static final String USERAGENT_REGEX =
        "(?:Mozilla/[0-9.]+|curl/[0-9.]+|Wget/[0-9.]+|" +
        "Python-urllib/[0-9.]+|python-requests/[0-9.]+|" +
        "Java/[0-9._]+|Go-http-client/[0-9.]+|" +
        "libwww-perl/[0-9.]+|PHP/[0-9.]+|" +
        "\\bBot\\b|\\bSpider\\b|\\bCrawler\\b)" +
        "[^\\x00-\\x1F]*";

    // Windows file paths
    private static final String WIN_PATH_REGEX =
        "[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\x00-\\x1F]+\\\\)*[^\\\\/:*?\"<>|\\x00-\\x1F]+";

    // Unix file paths
    private static final String UNIX_PATH_REGEX =
        "(?:/(?:etc|usr|var|tmp|home|opt|bin|sbin|lib|dev|proc|sys|mnt|root)" +
        "(?:/[a-zA-Z0-9._\\-]+)+)";

    // Windows Registry keys
    private static final String REGISTRY_REGEX =
        "(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)" +
        "|HKLM|HKCU|HKCR|HKU|HKCC)" +
        "\\\\[^\\s\"<>]+";

    // Network configuration strings (ports, protocols)
    private static final String NET_CONFIG_REGEX =
        "\\b(?:SOCKS[45]?|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|" +
        "proxy_host|proxy_port|connect_timeout|" +
        "bind_address|listen_port|server_port)\\b";

    // Compiled pattern map
    private Map<String, Pattern> patterns;

    // ========================================================================
    // RESULTS STORAGE
    // ========================================================================

    private static class Artifact {
        String category;
        String value;
        Address address;
        String containingFunction;
        List<String> references;

        Artifact(String category, String value, Address address) {
            this.category = category;
            this.value = value;
            this.address = address;
            this.containingFunction = "";
            this.references = new ArrayList<>();
        }
    }

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        printBanner();

        // Initialize regex patterns
        initPatterns();

        // Collect artifacts
        Map<String, List<Artifact>> artifactsByCategory = new LinkedHashMap<>();
        artifactsByCategory.put("IPv4", new ArrayList<>());
        artifactsByCategory.put("IPv4+Port", new ArrayList<>());
        artifactsByCategory.put("IPv6", new ArrayList<>());
        artifactsByCategory.put("URL", new ArrayList<>());
        artifactsByCategory.put("Domain", new ArrayList<>());
        artifactsByCategory.put("Email", new ArrayList<>());
        artifactsByCategory.put("User-Agent", new ArrayList<>());
        artifactsByCategory.put("WinPath", new ArrayList<>());
        artifactsByCategory.put("UnixPath", new ArrayList<>());
        artifactsByCategory.put("Registry", new ArrayList<>());
        artifactsByCategory.put("NetConfig", new ArrayList<>());

        println("  [*] Scanning defined strings...");
        int definedCount = scanDefinedStrings(artifactsByCategory);
        println("  [✓] Scanned " + definedCount + " defined strings");

        println("  [*] Scanning raw memory blocks...");
        int rawCount = scanRawMemory(artifactsByCategory);
        println("  [✓] Scanned " + rawCount + " memory bytes");

        // Deduplicate
        deduplicateArtifacts(artifactsByCategory);

        // Enrich with function context
        enrichWithContext(artifactsByCategory);

        // Count total artifacts
        int totalArtifacts = 0;
        for (List<Artifact> list : artifactsByCategory.values()) {
            totalArtifacts += list.size();
        }

        println("\n══════════════════════════════════════════════════════════════");
        println("  RESULTS: " + totalArtifacts + " network artifacts identified");
        println("══════════════════════════════════════════════════════════════");

        if (totalArtifacts == 0) {
            println("  [!] No network artifacts found in this binary.");
            println("      This may indicate the binary doesn't contain");
            println("      network-related strings, or they may be obfuscated/encrypted.");
            printFooter();
            return;
        }

        // Print results by category
        for (Map.Entry<String, List<Artifact>> entry : artifactsByCategory.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                printSection(entry.getKey());
                for (Artifact art : entry.getValue()) {
                    println("  [" + formatAddr(art.address) + "] " + art.value);
                    if (!art.containingFunction.isEmpty()) {
                        println("    └─ Function: " + art.containingFunction);
                    }
                    if (!art.references.isEmpty()) {
                        println("    └─ XREFs: " + String.join(", ", art.references));
                    }
                }
            }
        }

        // Create bookmarks in Ghidra
        println("\n  [*] Creating Ghidra bookmarks...");
        int bookmarkCount = createBookmarks(artifactsByCategory);
        println("  [✓] Created " + bookmarkCount + " bookmarks (category: AIB_NET)");

        // Export files
        String progName = sanitizeFilename(currentProgram.getName());
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File outputDir = new File(desktop + File.separator + "AIB_Exports" + File.separator + progName);
        if (!outputDir.exists()) outputDir.mkdirs();

        // Export JSON
        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "network_artifacts_" + timestamp + ".json";
        exportJSON(artifactsByCategory, jsonPath);
        println("  [✓] JSON exported: " + jsonPath);

        // Export CSV
        String csvPath = outputDir.getAbsolutePath() + File.separator +
            "network_artifacts_" + timestamp + ".csv";
        exportCSV(artifactsByCategory, csvPath);
        println("  [✓] CSV exported: " + csvPath);

        printFooter();
    }

    // ========================================================================
    // PATTERN INITIALIZATION
    // ========================================================================

    private void initPatterns() {
        patterns = new LinkedHashMap<>();
        patterns.put("IPv4+Port", Pattern.compile(IPV4_PORT_REGEX));
        patterns.put("IPv4", Pattern.compile(IPV4_REGEX));
        patterns.put("IPv6", Pattern.compile(IPV6_REGEX, Pattern.CASE_INSENSITIVE));
        patterns.put("URL", Pattern.compile(URL_REGEX, Pattern.CASE_INSENSITIVE));
        patterns.put("Domain", Pattern.compile(DOMAIN_REGEX, Pattern.CASE_INSENSITIVE));
        patterns.put("Email", Pattern.compile(EMAIL_REGEX, Pattern.CASE_INSENSITIVE));
        patterns.put("User-Agent", Pattern.compile(USERAGENT_REGEX));
        patterns.put("WinPath", Pattern.compile(WIN_PATH_REGEX));
        patterns.put("UnixPath", Pattern.compile(UNIX_PATH_REGEX));
        patterns.put("Registry", Pattern.compile(REGISTRY_REGEX, Pattern.CASE_INSENSITIVE));
        patterns.put("NetConfig", Pattern.compile(NET_CONFIG_REGEX, Pattern.CASE_INSENSITIVE));
    }

    // ========================================================================
    // SCANNING — DEFINED STRINGS
    // ========================================================================

    private int scanDefinedStrings(Map<String, List<Artifact>> results) {
        int count = 0;
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data.getValue() instanceof String) {
                count++;
                String value = (String) data.getValue();
                if (value == null || value.length() < 4) continue;

                Address addr = data.getAddress();
                matchAndStore(value, addr, results);

                if (count % 5000 == 0) {
                    println("    ... processed " + count + " strings");
                }
            }
        }
        return count;
    }

    // ========================================================================
    // SCANNING — RAW MEMORY
    // ========================================================================

    private int scanRawMemory(Map<String, List<Artifact>> results) throws Exception {
        int totalBytes = 0;
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            // Skip executable blocks (code) — focus on data sections
            // But include them if they might contain embedded strings
            
            long blockSize = block.getSize();
            if (blockSize > 100 * 1024 * 1024) { // Skip blocks > 100MB
                println("    [!] Skipping large block: " + block.getName() + " (" + blockSize + " bytes)");
                continue;
            }

            byte[] bytes = new byte[(int) blockSize];
            block.getBytes(block.getStart(), bytes);
            totalBytes += bytes.length;

            // Extract printable ASCII strings (min length 6)
            StringBuilder currentString = new StringBuilder();
            int stringStart = 0;
            
            for (int i = 0; i < bytes.length; i++) {
                byte b = bytes[i];
                if (b >= 0x20 && b <= 0x7E) {
                    if (currentString.length() == 0) stringStart = i;
                    currentString.append((char) b);
                } else {
                    if (currentString.length() >= 6) {
                        String s = currentString.toString();
                        Address addr = block.getStart().add(stringStart);
                        matchAndStore(s, addr, results);
                    }
                    currentString.setLength(0);
                }
            }
            // Handle string at end of block
            if (currentString.length() >= 6) {
                String s = currentString.toString();
                Address addr = block.getStart().add(stringStart);
                matchAndStore(s, addr, results);
            }
        }
        return totalBytes;
    }

    // ========================================================================
    // PATTERN MATCHING
    // ========================================================================

    private void matchAndStore(String text, Address addr, Map<String, List<Artifact>> results) {
        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            String category = entry.getKey();
            Pattern pattern = entry.getValue();
            Matcher matcher = pattern.matcher(text);

            while (matcher.find()) {
                String matched = matcher.group();
                
                // Filter false positives
                if (isFilteredOut(category, matched)) continue;

                results.get(category).add(new Artifact(category, matched, addr));
            }
        }
    }

    /**
     * Filters out common false positives.
     */
    private boolean isFilteredOut(String category, String value) {
        if ("IPv4".equals(category) || "IPv4+Port".equals(category)) {
            // Filter version numbers (0.0.0.0 patterns without port)
            if (value.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                String[] octets = value.split("\\.");
                // Likely version number: all octets < 10 or known versions
                boolean allSmall = true;
                for (String o : octets) {
                    if (Integer.parseInt(o) > 10) allSmall = false;
                }
                // 0.0.0.0 is a valid network addr — keep it
                if (allSmall && !value.equals("0.0.0.0")) {
                    // Could be version like 1.0.0.1 — only filter pure versions
                    if (value.matches("[0-3]\\.[0-9]\\.[0-9]\\.[0-9]")) return true;
                }
            }
            // Filter loopback unless analysis needs it
            // Keep 127.0.0.1 as it's still informative
        }

        if ("Domain".equals(category)) {
            // Filter common library/compiler artifacts
            if (value.endsWith(".dll") || value.endsWith(".exe") || 
                value.endsWith(".sys") || value.endsWith(".obj") ||
                value.endsWith(".lib") || value.endsWith(".pdb")) {
                return true;
            }
            // Filter file extensions that look like domains
            if (value.length() < 5) return true;
        }

        if ("Email".equals(category)) {
            // Filter file paths that look like emails
            if (value.contains("\\") || value.contains("/")) return true;
        }

        return false;
    }

    // ========================================================================
    // DEDUPLICATION
    // ========================================================================

    private void deduplicateArtifacts(Map<String, List<Artifact>> results) {
        for (Map.Entry<String, List<Artifact>> entry : results.entrySet()) {
            List<Artifact> list = entry.getValue();
            Map<String, Artifact> seen = new LinkedHashMap<>();
            for (Artifact art : list) {
                if (!seen.containsKey(art.value)) {
                    seen.put(art.value, art);
                }
            }
            entry.setValue(new ArrayList<>(seen.values()));
        }

        // Remove IPv4 entries that are already captured as IPv4+Port
        Set<String> ipsWithPorts = new HashSet<>();
        for (Artifact art : results.get("IPv4+Port")) {
            String ip = art.value.substring(0, art.value.lastIndexOf(':'));
            ipsWithPorts.add(ip);
        }
        results.get("IPv4").removeIf(art -> ipsWithPorts.contains(art.value));

        // Remove domains that are already part of URLs
        Set<String> urlDomains = new HashSet<>();
        Pattern domainInUrl = Pattern.compile("://([^/:]+)");
        for (Artifact art : results.get("URL")) {
            Matcher m = domainInUrl.matcher(art.value);
            if (m.find()) {
                urlDomains.add(m.group(1).toLowerCase());
            }
        }
        results.get("Domain").removeIf(art -> urlDomains.contains(art.value.toLowerCase()));
    }

    // ========================================================================
    // CONTEXT ENRICHMENT
    // ========================================================================

    private void enrichWithContext(Map<String, List<Artifact>> results) {
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        for (List<Artifact> list : results.values()) {
            for (Artifact art : list) {
                // Find containing function
                Function func = funcMgr.getFunctionContaining(art.address);
                if (func != null) {
                    art.containingFunction = func.getName();
                }

                // Find cross-references
                ReferenceIterator refs = refMgr.getReferencesTo(art.address);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address fromAddr = ref.getFromAddress();
                    Function refFunc = funcMgr.getFunctionContaining(fromAddr);
                    String refName = refFunc != null ? refFunc.getName() : formatAddr(fromAddr);
                    if (!art.references.contains(refName)) {
                        art.references.add(refName);
                    }
                    if (art.references.size() >= 10) break; // Cap references
                }
            }
        }
    }

    // ========================================================================
    // BOOKMARKS
    // ========================================================================

    private int createBookmarks(Map<String, List<Artifact>> results) {
        int count = 0;
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();

        for (Map.Entry<String, List<Artifact>> entry : results.entrySet()) {
            for (Artifact art : entry.getValue()) {
                bmMgr.setBookmark(art.address, "AIB_NET", art.category,
                    "[" + art.category + "] " + art.value);
                count++;
            }
        }
        return count;
    }

    // ========================================================================
    // JSON EXPORT
    // ========================================================================

    private void exportJSON(Map<String, List<Artifact>> results, String filepath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            writer.write("{\n");
            writer.write("  \"metadata\": {\n");
            writer.write("    \"tool\": \"AIB Network Artifact Extractor\",\n");
            writer.write("    \"version\": \"1.0.0\",\n");
            writer.write("    \"organization\": \"Arcy Intelligence Bureau\",\n");
            writer.write("    \"binary\": \"" + escJSON(currentProgram.getName()) + "\",\n");
            writer.write("    \"architecture\": \"" + escJSON(currentProgram.getLanguage().toString()) + "\",\n");
            writer.write("    \"timestamp\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()) + "\",\n");
            
            // Compute hash
            String hash = computeHash();
            writer.write("    \"sha256\": \"" + hash + "\"\n");
            writer.write("  },\n");

            writer.write("  \"artifacts\": {\n");
            Iterator<Map.Entry<String, List<Artifact>>> catIt = results.entrySet().iterator();
            while (catIt.hasNext()) {
                Map.Entry<String, List<Artifact>> entry = catIt.next();
                if (entry.getValue().isEmpty()) {
                    if (catIt.hasNext()) continue;
                    else continue;
                }
                writer.write("    \"" + entry.getKey() + "\": [\n");
                for (int i = 0; i < entry.getValue().size(); i++) {
                    Artifact art = entry.getValue().get(i);
                    writer.write("      {\n");
                    writer.write("        \"value\": \"" + escJSON(art.value) + "\",\n");
                    writer.write("        \"address\": \"" + formatAddr(art.address) + "\",\n");
                    writer.write("        \"function\": \"" + escJSON(art.containingFunction) + "\",\n");
                    writer.write("        \"xrefs\": [");
                    for (int j = 0; j < art.references.size(); j++) {
                        writer.write("\"" + escJSON(art.references.get(j)) + "\"");
                        if (j < art.references.size() - 1) writer.write(", ");
                    }
                    writer.write("]\n");
                    writer.write("      }");
                    if (i < entry.getValue().size() - 1) writer.write(",");
                    writer.write("\n");
                }
                writer.write("    ]");
                // Check if there are more non-empty categories
                boolean hasMore = false;
                while (catIt.hasNext()) {
                    Map.Entry<String, List<Artifact>> next = catIt.next();
                    if (!next.getValue().isEmpty()) {
                        writer.write(",\n");
                        // Process this entry
                        entry = next;
                        writer.write("    \"" + entry.getKey() + "\": [\n");
                        for (int i = 0; i < entry.getValue().size(); i++) {
                            Artifact art = entry.getValue().get(i);
                            writer.write("      {\n");
                            writer.write("        \"value\": \"" + escJSON(art.value) + "\",\n");
                            writer.write("        \"address\": \"" + formatAddr(art.address) + "\",\n");
                            writer.write("        \"function\": \"" + escJSON(art.containingFunction) + "\",\n");
                            writer.write("        \"xrefs\": [");
                            for (int j = 0; j < art.references.size(); j++) {
                                writer.write("\"" + escJSON(art.references.get(j)) + "\"");
                                if (j < art.references.size() - 1) writer.write(", ");
                            }
                            writer.write("]\n");
                            writer.write("      }");
                            if (i < entry.getValue().size() - 1) writer.write(",");
                            writer.write("\n");
                        }
                        writer.write("    ]");
                        hasMore = true;
                    }
                }
                if (!hasMore) writer.write("\n");
            }
            writer.write("  },\n");

            // Summary counts
            writer.write("  \"summary\": {\n");
            int total = 0;
            Iterator<Map.Entry<String, List<Artifact>>> sumIt = results.entrySet().iterator();
            while (sumIt.hasNext()) {
                Map.Entry<String, List<Artifact>> e = sumIt.next();
                int size = e.getValue().size();
                total += size;
                writer.write("    \"" + e.getKey() + "\": " + size);
                if (sumIt.hasNext()) writer.write(",");
                writer.write("\n");
            }
            writer.write("  },\n");
            writer.write("  \"total_artifacts\": " + total + "\n");
            writer.write("}\n");
        }
    }

    // ========================================================================
    // CSV EXPORT
    // ========================================================================

    private void exportCSV(Map<String, List<Artifact>> results, String filepath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            // UTF-8 BOM
            writer.write('\uFEFF');
            writer.write("Category,Value,Address,Function,Cross-References\n");

            for (Map.Entry<String, List<Artifact>> entry : results.entrySet()) {
                for (Artifact art : entry.getValue()) {
                    writer.write(csvField(art.category) + ",");
                    writer.write(csvField(art.value) + ",");
                    writer.write(csvField(formatAddr(art.address)) + ",");
                    writer.write(csvField(art.containingFunction) + ",");
                    writer.write(csvField(String.join("; ", art.references)));
                    writer.write("\n");
                }
            }
        }
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    private String formatAddr(Address addr) {
        return addr != null ? "0x" + addr.toString() : "0x????????";
    }

    private String escJSON(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private String csvField(String s) {
        if (s == null) s = "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private String sanitizeFilename(String name) {
        return name.replaceAll("[^a-zA-Z0-9._\\-]", "_");
    }

    private String computeHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (block.isInitialized()) {
                    byte[] bytes = new byte[(int) Math.min(block.getSize(), 10 * 1024 * 1024)];
                    block.getBytes(block.getStart(), bytes);
                    digest.update(bytes);
                }
            }
            byte[] hash = digest.digest();
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            return "UNAVAILABLE";
        }
    }

    // ========================================================================
    // CONSOLE OUTPUT
    // ========================================================================

    private void printBanner() {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║       AIB NETWORK ARTIFACT EXTRACTOR — OSINT Edition       ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: " + currentProgram.getName());
        println("  Arch:   " + currentProgram.getLanguage());
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printSection(String title) {
        println("\n──── " + title + " " + repeat("─", Math.max(0, 50 - title.length())));
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB Network Artifact Extractor — Complete");
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }

    private String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }
}
