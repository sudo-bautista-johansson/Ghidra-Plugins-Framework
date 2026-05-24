//AIB CyberFlow — Behavior Graph Visualization
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * AIB_CyberFlow — Phase 2 Mega OP Plugin #4
 *
 * Constructs a high-level behavior graph of the binary, mapping function-to-function
 * call relationships, system API usage, data flows, and suspicious behavior chains
 * into an interactive visual map.
 *
 * Features:
 * - Function classification by behavior (Malicious, Suspicious, Benign, Crypto, Network)
 * - Behavior chain detection (injection, persistence, exfiltration, etc.)
 * - MITRE ATT&CK technique mapping (~200 APIs categorized)
 * - Interactive HTML visualization with vis.js
 * - DOT (Graphviz) export
 * - Integration with other AIB plugins via bookmarks
 * - Console-based ASCII call graph
 */
public class AIB_CyberFlow extends GhidraScript {

    // ========================================================================
    // DATA STRUCTURES
    // ========================================================================

    private static class FuncNode {
        String name;
        String address;
        String category; // MALICIOUS, SUSPICIOUS, BENIGN, CRYPTO, NETWORK, UNKNOWN
        List<String> apis = new ArrayList<>();
        List<String> callers = new ArrayList<>();
        List<String> callees = new ArrayList<>();
        List<String> mitreTechniques = new ArrayList<>();
        String details = "";
        int callCount = 0;
    }

    private static class BehaviorChain {
        String name;
        String mitre;
        String description;
        List<String> requiredAPIs;
        List<String> foundFunctions = new ArrayList<>();
        String severity; // CRITICAL, HIGH, MEDIUM
    }

    // ========================================================================
    // CONSTANTS — API Categories (~200 APIs)
    // ========================================================================

    private static final Map<String, String[]> API_CATEGORIES = new LinkedHashMap<>();
    static {
        // Process manipulation
        API_CATEGORIES.put("PROCESS_CREATE", new String[]{
            "CreateProcessA", "CreateProcessW", "CreateProcessInternalA", "CreateProcessInternalW",
            "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
            "WinExec", "system", "_popen", "NtCreateProcess", "NtCreateProcessEx",
            "RtlCreateUserProcess", "ZwCreateProcess"
        });
        API_CATEGORIES.put("PROCESS_INJECT", new String[]{
            "VirtualAllocEx", "NtAllocateVirtualMemory", "WriteProcessMemory",
            "NtWriteVirtualMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
            "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
            "NtQueueApcThread", "SetThreadContext", "NtSetContextThread"
        });
        API_CATEGORIES.put("PROCESS_HOLLOW", new String[]{
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtMapViewOfSection"
        });
        API_CATEGORIES.put("PROCESS_QUERY", new String[]{
            "OpenProcess", "NtOpenProcess", "GetCurrentProcessId",
            "EnumProcesses", "CreateToolhelp32Snapshot", "Process32First",
            "Process32Next", "NtQueryInformationProcess"
        });

        // File operations
        API_CATEGORIES.put("FILE_WRITE", new String[]{
            "CreateFileA", "CreateFileW", "WriteFile", "NtWriteFile",
            "fwrite", "fputs", "fprintf", "DeleteFileA", "DeleteFileW",
            "MoveFileA", "MoveFileW", "CopyFileA", "CopyFileW",
            "NtCreateFile", "NtDeleteFile"
        });
        API_CATEGORIES.put("FILE_READ", new String[]{
            "ReadFile", "NtReadFile", "fread", "fgets",
            "GetFileSize", "GetFileSizeEx", "FindFirstFileA", "FindFirstFileW"
        });

        // Registry
        API_CATEGORIES.put("REGISTRY", new String[]{
            "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
            "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteKeyA", "RegDeleteKeyW",
            "RegDeleteValueA", "RegDeleteValueW", "RegQueryValueExA", "RegQueryValueExW",
            "NtOpenKey", "NtSetValueKey", "NtCreateKey", "NtDeleteKey"
        });

        // Network
        API_CATEGORIES.put("NETWORK_SOCKET", new String[]{
            "socket", "WSASocketA", "WSASocketW", "connect", "WSAConnect",
            "bind", "listen", "accept", "send", "sendto", "WSASend",
            "recv", "recvfrom", "WSARecv", "closesocket", "shutdown",
            "select", "gethostbyname", "getaddrinfo", "inet_addr",
            "htons", "ntohs"
        });
        API_CATEGORIES.put("NETWORK_HTTP", new String[]{
            "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
            "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
            "InternetReadFile", "InternetWriteFile", "InternetOpenUrlA", "InternetOpenUrlW",
            "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA",
            "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
            "WinHttpReceiveResponse", "WinHttpReadData"
        });

        // Crypto
        API_CATEGORIES.put("CRYPTO", new String[]{
            "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData",
            "CryptDeriveKey", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
            "BCryptOpenAlgorithmProvider", "BCryptCreateHash", "BCryptHashData"
        });

        // Memory
        API_CATEGORIES.put("MEMORY", new String[]{
            "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
            "VirtualProtectEx", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
            "HeapCreate", "HeapAlloc", "HeapFree", "MapViewOfFile",
            "CreateFileMappingA", "CreateFileMappingW"
        });

        // Service control
        API_CATEGORIES.put("SERVICE", new String[]{
            "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
            "OpenServiceA", "OpenServiceW", "StartServiceA", "StartServiceW",
            "ControlService", "DeleteService", "ChangeServiceConfigA", "ChangeServiceConfigW"
        });

        // Privilege escalation
        API_CATEGORIES.put("PRIVILEGE", new String[]{
            "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
            "LookupPrivilegeValueW", "ImpersonateLoggedOnUser", "DuplicateToken",
            "DuplicateTokenEx", "SetTokenInformation", "NtSetInformationToken"
        });

        // Credentials
        API_CATEGORIES.put("CREDENTIAL", new String[]{
            "CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW",
            "LsaRetrievePrivateData", "SamQueryInformationUser",
            "NetUserEnum", "NetUserGetInfo", "LogonUserA", "LogonUserW"
        });

        // Anti-analysis (linking to EntropyShield)
        API_CATEGORIES.put("ANTI_ANALYSIS", new String[]{
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "GetTickCount", "GetTickCount64",
            "QueryPerformanceCounter", "OutputDebugStringA", "Sleep",
            "GetCursorPos", "GetSystemMetrics"
        });

        // Hooking
        API_CATEGORIES.put("HOOKING", new String[]{
            "SetWindowsHookExA", "SetWindowsHookExW", "UnhookWindowsHookEx",
            "SetWinEventHook", "GetAsyncKeyState", "GetKeyState",
            "RegisterHotKey", "GetClipboardData", "OpenClipboard"
        });

        // DLL injection
        API_CATEGORIES.put("DLL_LOAD", new String[]{
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
            "LdrLoadDll", "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW"
        });
    }

    // ========================================================================
    // CONSTANTS — Behavior Chains
    // ========================================================================

    private List<BehaviorChain> defineBehaviorChains() {
        List<BehaviorChain> chains = new ArrayList<>();

        BehaviorChain injection = new BehaviorChain();
        injection.name = "Process Injection";
        injection.mitre = "T1055";
        injection.description = "Classic DLL/code injection: allocate remote memory, write payload, execute";
        injection.requiredAPIs = Arrays.asList("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread");
        injection.severity = "CRITICAL";
        chains.add(injection);

        BehaviorChain hollowing = new BehaviorChain();
        hollowing.name = "Process Hollowing";
        hollowing.mitre = "T1055.012";
        hollowing.description = "Hollow out legitimate process and replace with malicious code";
        hollowing.requiredAPIs = Arrays.asList("CreateProcessA", "NtUnmapViewOfSection", "WriteProcessMemory");
        chains.add(hollowing);
        hollowing.severity = "CRITICAL";

        BehaviorChain persistence = new BehaviorChain();
        persistence.name = "Registry Persistence";
        persistence.mitre = "T1547.001";
        persistence.description = "Establish persistence via registry Run keys";
        persistence.requiredAPIs = Arrays.asList("RegOpenKeyExA", "RegSetValueExA");
        persistence.severity = "HIGH";
        chains.add(persistence);

        BehaviorChain servicePersist = new BehaviorChain();
        servicePersist.name = "Service Persistence";
        servicePersist.mitre = "T1543.003";
        servicePersist.description = "Create or modify Windows services for persistence";
        servicePersist.requiredAPIs = Arrays.asList("OpenSCManagerA", "CreateServiceA");
        servicePersist.severity = "HIGH";
        chains.add(servicePersist);

        BehaviorChain exfil = new BehaviorChain();
        exfil.name = "Data Exfiltration";
        exfil.mitre = "T1041";
        exfil.description = "Read files and send data over network";
        exfil.requiredAPIs = Arrays.asList("ReadFile", "send");
        exfil.severity = "HIGH";
        chains.add(exfil);

        BehaviorChain httpExfil = new BehaviorChain();
        httpExfil.name = "HTTP Exfiltration";
        httpExfil.mitre = "T1071.001";
        httpExfil.description = "Exfiltrate data via HTTP requests";
        httpExfil.requiredAPIs = Arrays.asList("InternetOpenA", "HttpSendRequestA");
        httpExfil.severity = "HIGH";
        chains.add(httpExfil);

        BehaviorChain keylog = new BehaviorChain();
        keylog.name = "Keylogging";
        keylog.mitre = "T1056.001";
        keylog.description = "Input capture via Windows hooks or key state queries";
        keylog.requiredAPIs = Arrays.asList("SetWindowsHookExA", "GetAsyncKeyState");
        keylog.severity = "HIGH";
        chains.add(keylog);

        BehaviorChain privesc = new BehaviorChain();
        privesc.name = "Privilege Escalation";
        privesc.mitre = "T1134";
        privesc.description = "Token manipulation for privilege escalation";
        privesc.requiredAPIs = Arrays.asList("OpenProcessToken", "AdjustTokenPrivileges");
        privesc.severity = "HIGH";
        chains.add(privesc);

        BehaviorChain credTheft = new BehaviorChain();
        credTheft.name = "Credential Theft";
        credTheft.mitre = "T1003";
        credTheft.description = "OS credential dumping";
        credTheft.requiredAPIs = Arrays.asList("LsaRetrievePrivateData");
        credTheft.severity = "CRITICAL";
        chains.add(credTheft);

        BehaviorChain download = new BehaviorChain();
        download.name = "File Download";
        download.mitre = "T1105";
        download.description = "Download files from internet";
        download.requiredAPIs = Arrays.asList("URLDownloadToFileA");
        download.severity = "HIGH";
        chains.add(download);

        return chains;
    }

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        AIBUtils.printPluginHeader(this, "AIB CyberFlow — Behavior Graph Visualization");

        String[] modes = {
            "Full Analysis + HTML Graph + DOT Export",
            "Console Report Only (No File Export)",
            "HTML Graph Only",
            "DOT Graph Only"
        };
        String choice = askChoice("AIB CyberFlow — Output Mode",
            "Select output format:", Arrays.asList(modes), modes[0]);

        boolean doHTML = choice.equals(modes[0]) || choice.equals(modes[2]);
        boolean doDOT = choice.equals(modes[0]) || choice.equals(modes[3]);
        boolean doConsole = choice.equals(modes[0]) || choice.equals(modes[1]);

        // Phase 1: Build function graph
        AIBUtils.printSection(this, "BUILDING FUNCTION GRAPH");
        Map<String, FuncNode> graph = buildFunctionGraph();

        // Phase 2: Classify functions
        AIBUtils.printSection(this, "CLASSIFYING FUNCTIONS");
        classifyFunctions(graph);

        // Phase 3: Detect behavior chains
        AIBUtils.printSection(this, "DETECTING BEHAVIOR CHAINS");
        List<BehaviorChain> chains = detectBehaviorChains(graph);

        // Phase 4: Integrate with other AIB plugins
        AIBUtils.printSection(this, "INTEGRATING AIB BOOKMARKS");
        integrateBookmarks(graph);

        // Phase 5: Output
        if (doConsole) {
            printConsoleReport(graph, chains);
        }

        // Phase 6: Export
        if (doHTML || doDOT) {
            AIBUtils.printSection(this, "GENERATING VISUALIZATIONS");
            exportGraph(graph, chains, doHTML, doDOT);
        }

        // JSON export always
        exportJSON(graph, chains);

        AIBUtils.printFooter(this, "AIB CyberFlow");
    }

    // ========================================================================
    // GRAPH CONSTRUCTION
    // ========================================================================

    private Map<String, FuncNode> buildFunctionGraph() throws Exception {
        Map<String, FuncNode> graph = new LinkedHashMap<>();
        Listing listing = currentProgram.getListing();
        FunctionIterator funcIter = listing.getFunctions(true);
        int count = 0;

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            String name = func.getName();
            String addr = AIBUtils.formatAddress(func.getEntryPoint());

            FuncNode node = new FuncNode();
            node.name = name;
            node.address = addr;
            node.category = "UNKNOWN";

            // Collect called functions (callees)
            Set<Function> calledFuncs = func.getCalledFunctions(monitor);
            for (Function called : calledFuncs) {
                node.callees.add(called.getName());
            }

            // Collect calling functions (callers)
            Set<Function> callingFuncs = func.getCallingFunctions(monitor);
            for (Function caller : callingFuncs) {
                node.callers.add(caller.getName());
            }

            node.callCount = node.callers.size();
            graph.put(name, node);
            count++;
        }

        println(String.format("  Built graph with %d function nodes", count));
        return graph;
    }

    // ========================================================================
    // FUNCTION CLASSIFICATION
    // ========================================================================

    private void classifyFunctions(Map<String, FuncNode> graph) {
        int malicious = 0, suspicious = 0, benign = 0, crypto = 0, network = 0;

        // Build reverse lookup: API name → category
        Map<String, String> apiToCategory = new HashMap<>();
        for (Map.Entry<String, String[]> entry : API_CATEGORIES.entrySet()) {
            for (String api : entry.getValue()) {
                apiToCategory.put(api.toLowerCase(), entry.getKey());
            }
        }

        for (FuncNode node : graph.values()) {
            Set<String> categories = new HashSet<>();

            // Check if this function IS a known API (external/import)
            String nameLower = node.name.toLowerCase();
            if (apiToCategory.containsKey(nameLower)) {
                String cat = apiToCategory.get(nameLower);
                categories.add(cat);
                node.apis.add(node.name);
            }

            // Check callees for known APIs
            for (String callee : node.callees) {
                String calleeLower = callee.toLowerCase();
                if (apiToCategory.containsKey(calleeLower)) {
                    categories.add(apiToCategory.get(calleeLower));
                    node.apis.add(callee);
                }
            }

            // Classify based on API categories found
            if (categories.contains("PROCESS_INJECT") || categories.contains("PROCESS_HOLLOW") ||
                categories.contains("CREDENTIAL")) {
                node.category = "MALICIOUS";
                malicious++;
            } else if (categories.contains("NETWORK_SOCKET") || categories.contains("NETWORK_HTTP")) {
                node.category = "NETWORK";
                network++;
            } else if (categories.contains("CRYPTO")) {
                node.category = "CRYPTO";
                crypto++;
            } else if (categories.contains("ANTI_ANALYSIS") || categories.contains("HOOKING") ||
                       categories.contains("PRIVILEGE") || categories.contains("SERVICE") ||
                       categories.contains("REGISTRY")) {
                node.category = "SUSPICIOUS";
                suspicious++;
            } else if (categories.contains("FILE_READ") || categories.contains("FILE_WRITE") ||
                       categories.contains("DLL_LOAD") || categories.contains("MEMORY") ||
                       categories.contains("PROCESS_CREATE") || categories.contains("PROCESS_QUERY")) {
                node.category = "BENIGN";
                benign++;
            }
            // Else remains UNKNOWN

            // Build details string
            if (!node.apis.isEmpty()) {
                node.details = "APIs: " + String.join(", ", node.apis);
            }
        }

        println(String.format("  🔴 Malicious: %d  🟡 Suspicious: %d  🟢 Benign: %d  🔵 Crypto: %d  🟣 Network: %d",
            malicious, suspicious, benign, crypto, network));
    }

    // ========================================================================
    // BEHAVIOR CHAIN DETECTION
    // ========================================================================

    private List<BehaviorChain> detectBehaviorChains(Map<String, FuncNode> graph) {
        List<BehaviorChain> defined = defineBehaviorChains();
        List<BehaviorChain> detected = new ArrayList<>();

        // Build set of all APIs used in the binary
        Set<String> allAPIs = new HashSet<>();
        Map<String, List<String>> apiToFunctions = new HashMap<>();

        for (FuncNode node : graph.values()) {
            for (String api : node.apis) {
                allAPIs.add(api);
                apiToFunctions.computeIfAbsent(api, k -> new ArrayList<>()).add(node.name);
            }
            // Also check function names themselves (for imported functions)
            allAPIs.add(node.name);
        }

        for (BehaviorChain chain : defined) {
            boolean allFound = true;
            List<String> involvedFunctions = new ArrayList<>();

            for (String requiredAPI : chain.requiredAPIs) {
                boolean found = false;
                for (String api : allAPIs) {
                    if (api.toLowerCase().startsWith(requiredAPI.toLowerCase()) ||
                        api.equalsIgnoreCase(requiredAPI)) {
                        found = true;
                        List<String> funcs = apiToFunctions.getOrDefault(api, Collections.emptyList());
                        involvedFunctions.addAll(funcs);
                        break;
                    }
                }
                if (!found) {
                    // Check with W suffix for wide variants
                    String wideAPI = requiredAPI.replace("A", "W");
                    for (String api : allAPIs) {
                        if (api.equalsIgnoreCase(wideAPI)) {
                            found = true;
                            List<String> funcs = apiToFunctions.getOrDefault(api, Collections.emptyList());
                            involvedFunctions.addAll(funcs);
                            break;
                        }
                    }
                }
                if (!found) {
                    allFound = false;
                    break;
                }
            }

            if (allFound) {
                chain.foundFunctions = involvedFunctions;
                detected.add(chain);

                String icon = chain.severity.equals("CRITICAL") ? "🔴" :
                              chain.severity.equals("HIGH") ? "🟠" : "🟡";
                println(String.format("  %s [%s] %s (%s) — %s",
                    icon, chain.mitre, chain.name, chain.severity, chain.description));
                println(String.format("       Functions: %s", String.join(", ", involvedFunctions)));

                // Update involved function nodes to MALICIOUS if chain is critical
                for (String funcName : involvedFunctions) {
                    FuncNode node = graph.get(funcName);
                    if (node != null) {
                        if (chain.severity.equals("CRITICAL")) {
                            node.category = "MALICIOUS";
                        }
                        node.mitreTechniques.add(chain.mitre + " " + chain.name);
                    }
                }
            }
        }

        if (detected.isEmpty()) {
            println("  🟢 No known behavior chains detected.");
        }

        return detected;
    }

    // ========================================================================
    // BOOKMARK INTEGRATION
    // ========================================================================

    private void integrateBookmarks(Map<String, FuncNode> graph) {
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        int integrated = 0;

        Iterator<Bookmark> bookmarks = bmMgr.getBookmarksIterator();
        while (bookmarks.hasNext()) {
            Bookmark bm = bookmarks.next();
            String comment = bm.getComment();
            if (comment == null) continue;

            Address addr = bm.getAddress();
            Function func = getFunctionContaining(addr);
            if (func == null) continue;

            FuncNode node = graph.get(func.getName());
            if (node == null) continue;

            // Integrate tags from other AIB plugins
            if (comment.contains("[CRYPTO]")) {
                if (!node.category.equals("MALICIOUS")) node.category = "CRYPTO";
                node.details += " | CryptoDetector: " + comment;
                integrated++;
            }
            if (comment.contains("[NET]") || comment.contains("[NETWORK]")) {
                if (!node.category.equals("MALICIOUS") && !node.category.equals("CRYPTO")) {
                    node.category = "NETWORK";
                }
                node.details += " | NetworkExtractor: " + comment;
                integrated++;
            }
            if (comment.contains("[ANTI-DBG]") || comment.contains("[ANTI-VM]") || comment.contains("[ANTI-SANDBOX]")) {
                if (node.category.equals("UNKNOWN") || node.category.equals("BENIGN")) {
                    node.category = "SUSPICIOUS";
                }
                node.details += " | EntropyShield: " + comment;
                integrated++;
            }
            if (comment.contains("[DECRYPTED]")) {
                node.details += " | GhostDecrypter: " + comment;
                integrated++;
            }
            if (comment.contains("[PACKED]")) {
                node.details += " | EntropyShield: Packed section";
                integrated++;
            }
        }

        println(String.format("  Integrated %d bookmarks from other AIB plugins", integrated));
    }

    // ========================================================================
    // CONSOLE REPORT
    // ========================================================================

    private void printConsoleReport(Map<String, FuncNode> graph, List<BehaviorChain> chains) {
        AIBUtils.printSection(this, "FUNCTION CLASSIFICATION SUMMARY");

        // Count by category
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("MALICIOUS", 0);
        counts.put("SUSPICIOUS", 0);
        counts.put("NETWORK", 0);
        counts.put("CRYPTO", 0);
        counts.put("BENIGN", 0);
        counts.put("UNKNOWN", 0);

        for (FuncNode node : graph.values()) {
            counts.merge(node.category, 1, Integer::sum);
        }

        String[] headers = {"Category", "Count", "Icon"};
        List<String[]> rows = new ArrayList<>();
        rows.add(new String[]{"MALICIOUS", String.valueOf(counts.get("MALICIOUS")), "🔴"});
        rows.add(new String[]{"SUSPICIOUS", String.valueOf(counts.get("SUSPICIOUS")), "🟡"});
        rows.add(new String[]{"NETWORK", String.valueOf(counts.get("NETWORK")), "🟣"});
        rows.add(new String[]{"CRYPTO", String.valueOf(counts.get("CRYPTO")), "🔵"});
        rows.add(new String[]{"BENIGN", String.valueOf(counts.get("BENIGN")), "🟢"});
        rows.add(new String[]{"UNKNOWN", String.valueOf(counts.get("UNKNOWN")), "⚪"});
        println(AIBUtils.formatTable(headers, rows));

        // MITRE ATT&CK Summary
        if (!chains.isEmpty()) {
            AIBUtils.printSection(this, "MITRE ATT&CK MAPPING");
            String[] mitreHeaders = {"Technique", "Name", "Severity", "Functions"};
            List<String[]> mitreRows = new ArrayList<>();
            for (BehaviorChain chain : chains) {
                mitreRows.add(new String[]{
                    chain.mitre, chain.name, chain.severity,
                    String.join(", ", chain.foundFunctions)
                });
            }
            println(AIBUtils.formatTable(mitreHeaders, mitreRows));
        }

        // Top interesting functions
        AIBUtils.printSection(this, "TOP FUNCTIONS OF INTEREST");
        List<FuncNode> interesting = new ArrayList<>();
        for (FuncNode node : graph.values()) {
            if (!node.category.equals("UNKNOWN") && !node.category.equals("BENIGN") && !node.apis.isEmpty()) {
                interesting.add(node);
            }
        }
        interesting.sort((a, b) -> {
            int catOrder = getCategoryOrder(a.category) - getCategoryOrder(b.category);
            if (catOrder != 0) return catOrder;
            return b.apis.size() - a.apis.size();
        });

        int shown = 0;
        for (FuncNode node : interesting) {
            if (shown >= 25) break;
            String icon;
            switch (node.category) {
                case "MALICIOUS": icon = "🔴"; break;
                case "SUSPICIOUS": icon = "🟡"; break;
                case "NETWORK": icon = "🟣"; break;
                case "CRYPTO": icon = "🔵"; break;
                default: icon = "⚪"; break;
            }
            println(String.format("  %s %-35s  [%s]  APIs: %s",
                icon, node.name, node.category,
                String.join(", ", node.apis)));
            shown++;
        }

        if (shown == 0) {
            println("  (No classified functions with API usage found)");
        }
    }

    private int getCategoryOrder(String category) {
        switch (category) {
            case "MALICIOUS": return 0;
            case "SUSPICIOUS": return 1;
            case "NETWORK": return 2;
            case "CRYPTO": return 3;
            case "BENIGN": return 4;
            default: return 5;
        }
    }

    // ========================================================================
    // GRAPH EXPORT — DOT & HTML
    // ========================================================================

    private void exportGraph(Map<String, FuncNode> graph, List<BehaviorChain> chains,
            boolean doHTML, boolean doDOT) throws Exception {
        File outputDir = AIBUtils.getOutputDirectory(this);
        String timestamp = AIBUtils.getFileTimestamp();

        // Filter: only include classified functions and their direct connections
        Set<String> relevantFuncs = new HashSet<>();
        for (FuncNode node : graph.values()) {
            if (!node.category.equals("UNKNOWN")) {
                relevantFuncs.add(node.name);
                relevantFuncs.addAll(node.callees);
                relevantFuncs.addAll(node.callers);
            }
        }

        // Cap at 200 nodes for performance
        if (relevantFuncs.size() > 200) {
            // Prioritize non-UNKNOWN
            Set<String> prioritized = new LinkedHashSet<>();
            for (String name : relevantFuncs) {
                FuncNode node = graph.get(name);
                if (node != null && !node.category.equals("UNKNOWN")) {
                    prioritized.add(name);
                }
            }
            relevantFuncs = prioritized;
        }

        // DOT Export
        if (doDOT) {
            AIBUtils.DotGraphBuilder dot = new AIBUtils.DotGraphBuilder("AIB_CyberFlow");

            for (String name : relevantFuncs) {
                FuncNode node = graph.get(name);
                if (node == null) continue;
                String[] style = getNodeStyle(node != null ? node.category : "UNKNOWN");
                dot.addNode(name, name, style[0], "box", style[1]);
            }

            for (String name : relevantFuncs) {
                FuncNode node = graph.get(name);
                if (node == null) continue;
                for (String callee : node.callees) {
                    if (relevantFuncs.contains(callee)) {
                        String edgeColor = getEdgeColor(node.category);
                        dot.addEdge(name, callee, null, edgeColor, "solid");
                    }
                }
            }

            // Add subgraphs for behavior chains
            for (BehaviorChain chain : chains) {
                List<String> chainNodes = new ArrayList<>();
                for (String f : chain.foundFunctions) {
                    if (relevantFuncs.contains(f)) chainNodes.add(f);
                }
                if (!chainNodes.isEmpty()) {
                    String color = chain.severity.equals("CRITICAL") ? "#ff4444" : "#ffaa00";
                    dot.addSubgraph(chain.mitre, chain.mitre + " " + chain.name, color, chainNodes);
                }
            }

            String dotPath = outputDir.getAbsolutePath() + File.separator +
                "cyberflow_" + timestamp + ".dot";
            AIBUtils.exportToMarkdown(dot.toDOT(), dotPath);
            AIBUtils.printResult(this, "DOT graph exported", dotPath);
        }

        // HTML Export
        if (doHTML) {
            List<Map<String, Object>> nodeData = new ArrayList<>();
            List<Map<String, Object>> edgeData = new ArrayList<>();
            int edgeId = 0;

            for (String name : relevantFuncs) {
                FuncNode node = graph.get(name);
                Map<String, Object> nData = new LinkedHashMap<>();
                nData.put("id", name);
                nData.put("label", name);
                String cat = (node != null) ? node.category : "UNKNOWN";
                nData.put("group", cat);
                nData.put("color", getHTMLNodeColor(cat));
                nData.put("title", (node != null && !node.details.isEmpty()) ? node.details :
                    "Category: " + cat);
                nodeData.add(nData);
            }

            for (String name : relevantFuncs) {
                FuncNode node = graph.get(name);
                if (node == null) continue;
                for (String callee : node.callees) {
                    if (relevantFuncs.contains(callee)) {
                        Map<String, Object> eData = new LinkedHashMap<>();
                        eData.put("id", "e" + (edgeId++));
                        eData.put("from", name);
                        eData.put("to", callee);
                        eData.put("color", getEdgeColor(node.category));
                        edgeData.add(eData);
                    }
                }
            }

            AIBUtils.DotGraphBuilder builder = new AIBUtils.DotGraphBuilder("CyberFlow");
            String htmlContent = builder.toHTML(currentProgram.getName(), nodeData, edgeData);

            String htmlPath = outputDir.getAbsolutePath() + File.separator +
                "cyberflow_" + timestamp + ".html";
            AIBUtils.exportToMarkdown(htmlContent, htmlPath);
            AIBUtils.printResult(this, "Interactive HTML graph exported", htmlPath);
            println("  💡 Open the HTML file in a web browser for interactive exploration!");
        }
    }

    // ========================================================================
    // JSON EXPORT
    // ========================================================================

    private void exportJSON(Map<String, FuncNode> graph, List<BehaviorChain> chains) throws Exception {
        File outputDir = AIBUtils.getOutputDirectory(this);
        String timestamp = AIBUtils.getFileTimestamp();

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("plugin", "AIB_CyberFlow");
        report.put("version", AIBUtils.AIB_VERSION);
        report.put("timestamp", AIBUtils.getTimestamp());
        report.put("program", currentProgram.getName());

        // Function nodes
        List<Map<String, Object>> funcList = new ArrayList<>();
        for (FuncNode node : graph.values()) {
            if (node.category.equals("UNKNOWN") && node.apis.isEmpty()) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", node.name);
            m.put("address", node.address);
            m.put("category", node.category);
            m.put("apis", node.apis);
            m.put("callers_count", node.callers.size());
            m.put("callees_count", node.callees.size());
            if (!node.mitreTechniques.isEmpty()) {
                m.put("mitre_techniques", node.mitreTechniques);
            }
            funcList.add(m);
        }
        report.put("classified_functions", funcList);

        // Behavior chains
        List<Map<String, Object>> chainList = new ArrayList<>();
        for (BehaviorChain chain : chains) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", chain.name);
            m.put("mitre", chain.mitre);
            m.put("severity", chain.severity);
            m.put("description", chain.description);
            m.put("required_apis", chain.requiredAPIs);
            m.put("involved_functions", chain.foundFunctions);
            chainList.add(m);
        }
        report.put("behavior_chains", chainList);

        // Summary
        Map<String, Object> summary = new LinkedHashMap<>();
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (FuncNode node : graph.values()) {
            counts.merge(node.category, 1, Integer::sum);
        }
        summary.put("total_functions", graph.size());
        summary.put("classification_counts", counts);
        summary.put("behavior_chains_detected", chains.size());
        report.put("summary", summary);

        // MITRE report
        if (!chains.isEmpty()) {
            StringBuilder mitreMd = new StringBuilder();
            mitreMd.append("# AIB CyberFlow — MITRE ATT&CK Mapping\n\n");
            mitreMd.append("| Technique | Name | Severity | Description | Functions |\n");
            mitreMd.append("|-----------|------|----------|-------------|----------|\n");
            for (BehaviorChain chain : chains) {
                mitreMd.append(String.format("| %s | %s | %s | %s | %s |\n",
                    chain.mitre, chain.name, chain.severity, chain.description,
                    String.join(", ", chain.foundFunctions)));
            }
            String mitrePath = outputDir.getAbsolutePath() + File.separator +
                "cyberflow_mitre_" + timestamp + ".md";
            AIBUtils.exportToMarkdown(mitreMd.toString(), mitrePath);
            AIBUtils.printResult(this, "MITRE ATT&CK report exported", mitrePath);
        }

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "cyberflow_" + timestamp + ".json";
        AIBUtils.exportToJSON(report, jsonPath);
        AIBUtils.printResult(this, "JSON graph data exported", jsonPath);
    }

    // ========================================================================
    // STYLE HELPERS
    // ========================================================================

    private String[] getNodeStyle(String category) {
        switch (category) {
            case "MALICIOUS":  return new String[]{"#ff4444", "#ffffff"};
            case "SUSPICIOUS": return new String[]{"#ffaa00", "#000000"};
            case "BENIGN":     return new String[]{"#44ff44", "#000000"};
            case "CRYPTO":     return new String[]{"#4488ff", "#ffffff"};
            case "NETWORK":    return new String[]{"#aa44ff", "#ffffff"};
            default:           return new String[]{"#888888", "#ffffff"};
        }
    }

    private String getEdgeColor(String category) {
        switch (category) {
            case "MALICIOUS":  return "#ff6666";
            case "SUSPICIOUS": return "#ffcc44";
            case "NETWORK":    return "#cc88ff";
            case "CRYPTO":     return "#66aaff";
            default:           return "#666666";
        }
    }

    private String getHTMLNodeColor(String category) {
        switch (category) {
            case "MALICIOUS":  return "#ff4444";
            case "SUSPICIOUS": return "#ffaa00";
            case "BENIGN":     return "#44ff44";
            case "CRYPTO":     return "#4488ff";
            case "NETWORK":    return "#aa44ff";
            default:           return "#888888";
        }
    }
}
