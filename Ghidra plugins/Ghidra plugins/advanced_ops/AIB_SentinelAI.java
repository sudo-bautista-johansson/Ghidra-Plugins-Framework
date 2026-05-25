//AIB SentinelAI â€” LLM-Powered Binary Analysis
//@author Arcy Intelligence Bureau (AIB) â€” DirecciÃ³n General
//@category AIB
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.BookmarkManager;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * AIB_SentinelAI â€” Phase 2 Mega OP Plugin #1
 *
 * Bridges the gap between Ghidra's decompiler output and cloud LLMs (Gemini / Claude)
 * to provide AI-powered reverse engineering assistance:
 * 
 * 1. ðŸ§  Explain Function: Decompiles the current function and generates a highly detailed
 *    Markdown explanation of its logic, purpose, and potential context.
 * 2. âœï¸ Auto-Rename Variables: Renames meaningless variables (e.g. uVar1, local_18) and
 *    the function itself based on semantic analysis.
 * 3. ðŸ¦  Malware Classification: Scans binary features (imported APIs, network IoCs, high-entropy)
 *    and generates a threat intelligence assessment mapping capabilities to MITRE ATT&CK.
 * 4. ðŸ”“ Vulnerability Scanner: Heuristically reviews decompiled C code for common
 *    vulnerabilities (buffer overflows, logic bugs, weak cryptography) and bookmarks them.
 * 5. ðŸŒ Full Binary Summary: Performs a batch overview of the binary's architecture and capabilities.
 */
public class AIB_SentinelAI extends GhidraScript {

    private static final String GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent";
    private static final String CLAUDE_API_URL = "https://api.anthropic.com/v1/messages";

    private String preferredProvider = "gemini";
    private String apiKey = "";
    private int rateLimit = 250;
    private String currentCaseId = "CASE_001";
    private boolean safeEnrichmentEnabled = true;
    private boolean safeOnlineEnrichmentEnabled = false;

    private static class LocalHeuristicFinding {
        String id;
        String severity;
        String title;
        String evidence;
        String rationale;
        String analystNote;
    }

    @Override
    protected void run() throws Exception {
        AIBUtils.printPluginHeader(this, "AIB SentinelAI â€” LLM-Powered Binary Analysis");

        // Load or prompt API configuration
        if (!setupAPIConfig()) {
            AIBUtils.printWarning(this, "API configuration was cancelled or is missing a valid API key.");
            return;
        }

        // Check if a program is active
        if (currentProgram == null) {
            printerr("No active program loaded in Ghidra.");
            return;
        }

        currentCaseId = AIBUtils.normalizeCaseId(askString(
            "AIB SentinelAI - Case ID",
            "Enter Case ID for exports:",
            currentCaseId
        ));

        // Show main menu
        List<String> menuChoices = new ArrayList<>();
        menuChoices.add("ðŸ§  Explain Selected Function");
        menuChoices.add("âœ ï¸  Auto-Rename Selected Function & Variables");
        menuChoices.add("ðŸ¦  Malware & Threat Classification (Global)");
        menuChoices.add("ðŸ”“ Scan Selected Function for Vulnerabilities (Advanced CoT)");
        menuChoices.add("ðŸ§ª Research Disclosed Vulnerability (Safe)");
        menuChoices.add("ðŸŒ  Generate Full Binary Intelligence Briefing");
        menuChoices.add("ðŸ¡ï¸  Generate Defensive PoC Skeleton");
        menuChoices.add("ðŸ”Ž Deep 0-Day Sweep");

        String selectedOption = askChoice("AIB SentinelAI â€” AI Analysis Suite",
            "Select an AI-assisted analysis operation:", menuChoices, menuChoices.get(0));

        if (selectedOption.contains("Explain Selected Function")) {
            explainCurrentFunction();
        } else if (selectedOption.contains("Auto-Rename Selected Function")) {
            autoRenameCurrentFunction();
        } else if (selectedOption.contains("Threat Classification")) {
            classifyMalwareGlobal();
        } else if (selectedOption.contains("Scan Selected Function for Vulnerabilities")) {
            scanFunctionVulnerabilitiesAdvanced();
        } else if (selectedOption.contains("Research Disclosed Vulnerability")) {
            researchDisclosedVulnerability();
        } else if (selectedOption.contains("Generate Full Binary Intelligence Briefing")) {
            generateGlobalBriefing();
        } else if (selectedOption.contains("Defensive PoC Skeleton")) {
            generateDefensivePoc();
        } else if (selectedOption.contains("Deep 0-Day Sweep")) {
            deep0DaySweep();
        }

        AIBUtils.printFooter(this, "AIB SentinelAI");
    }

    // ========================================================================
    // API CONFIGURATION SETUP
    // ========================================================================

    private boolean setupAPIConfig() throws Exception {
        Map<String, String> config = AIBUtils.loadAPIConfig();
        
        // Resolve preferred provider
        preferredProvider = config.getOrDefault("preferred_provider", "gemini").toLowerCase();
        if (!preferredProvider.equals("gemini") && !preferredProvider.equals("claude")) {
            preferredProvider = "gemini";
        }

        // Fetch corresponding API key
        if (preferredProvider.equals("gemini")) {
            apiKey = config.getOrDefault("gemini_key", "");
        } else {
            apiKey = config.getOrDefault("claude_key", "");
        }

        // Check rate limits
        try {
            rateLimit = Integer.parseInt(config.getOrDefault("daily_limit", "250"));
        } catch (NumberFormatException e) {
            rateLimit = 250;
        }
        safeEnrichmentEnabled = "true".equalsIgnoreCase(config.getOrDefault("safe_enrichment_enabled", "true"));
        safeOnlineEnrichmentEnabled = "true".equalsIgnoreCase(config.getOrDefault("safe_online_enrichment_enabled", "false"));

        // Prompt for configuration if key is missing
        if (apiKey == null || apiKey.trim().isEmpty()) {
            String choice = askChoice("AIB SentinelAI â€” Choose LLM Provider",
                "Choose your preferred LLM provider for analysis:",
                Arrays.asList("Gemini 2.5 Flash (250 req/day free)", "Claude 3.5 Sonnet"),
                preferredProvider.equals("gemini") ? "Gemini 2.5 Flash (250 req/day free)" : "Claude 3.5 Sonnet");

            if (choice.contains("Gemini")) {
                preferredProvider = "gemini";
                apiKey = askString("AIB SentinelAI â€” Gemini API Key", "Enter your Gemini API key:");
            } else {
                preferredProvider = "claude";
                apiKey = askString("AIB SentinelAI â€” Claude API Key", "Enter your Anthropic Claude API key:");
            }

            if (apiKey == null || apiKey.trim().isEmpty()) {
                return false;
            }

            // Save configuration
            config.put("preferred_provider", preferredProvider);
            if (preferredProvider.equals("gemini")) {
                config.put("gemini_key", apiKey);
            } else {
                config.put("claude_key", apiKey);
            }
            config.put("daily_limit", String.valueOf(rateLimit));
            config.put("safe_enrichment_enabled", String.valueOf(safeEnrichmentEnabled));
            config.put("safe_online_enrichment_enabled", String.valueOf(safeOnlineEnrichmentEnabled));
            AIBUtils.saveAPIConfig(config);
            AIBUtils.printResult(this, "API configuration saved", "Desktop/AIB_Cases/_global/config/.aib_config.json");
        }

        // Verify daily usage does not exceed limit
        int todayUsage = AIBUtils.getAPIUsageToday();
        if (todayUsage >= rateLimit) {
            boolean proceed = askYesNo("AIB SentinelAI â€” Rate Limit Warning", 
                "You have reached your daily limit of " + rateLimit + " API requests.\nDo you want to proceed anyway?");
            if (!proceed) return false;
        } else {
            println("  [i] API Usage Today: " + todayUsage + " / " + rateLimit + " requests.");
        }

        return true;
    }

    // ========================================================================
    // DECOMPILATION HELPER
    // ========================================================================

    private String decompileFunction(Function func) {
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {
                DecompiledFunction decompFunc = results.getDecompiledFunction();
                if (decompFunc != null) {
                    return decompFunc.getC();
                }
            }
        } catch (Exception e) {
            printerr("Error decompiling function " + func.getName() + ": " + e.getMessage());
        } finally {
            decomp.dispose();
        }
        return null;
    }

    // ========================================================================
    // ðŸ§  1. EXPLAIN SELECTED FUNCTION
    // ========================================================================

    private void explainCurrentFunction() throws Exception {
        Function currentFunc = getFunctionContaining(currentAddress);
        if (currentFunc == null) {
            printerr("No function selected. Please place your cursor inside a function.");
            return;
        }

        println("  [ðŸ§ ] Analyzing and explaining function: " + currentFunc.getName() + "...");
        String cCode = decompileFunction(currentFunc);
        if (cCode == null || cCode.trim().isEmpty()) {
            printerr("Could not retrieve decompiler output for: " + currentFunc.getName());
            return;
        }

        String prompt = "Analyze this decompiled C function and explain its purpose, identify any algorithms used, "
            + "note any security implications or suspicious activities, and suggest a better name for the function "
            + "and its parameters/variables. Use the local heuristic dossier below as grounding context, clearly "
            + "separate observed facts from hypotheses, and output your findings as a well-structured markdown document:\n\n"
            + buildDeepFunctionContext(currentFunc, cCode) + "\n"
            + "If external knowledge is ever referenced, restrict it to globally recognized defensive sources such as NVD/CVE, CISA KEV, GitHub Security Advisories, OSV, CWE/CAPEC, and MITRE ATT&CK.\n\n"
            + "```c\n" + cCode + "\n```";

        String response = sendLLMRequest(prompt);
        if (response == null) {
            printerr("LLM API returned an empty or invalid response.");
            return;
        }

        // Log and print explanation
        AIBUtils.printSection(this, "AI ANALYSIS FOR: " + currentFunc.getName());
        println(response);

        // Save report to file
        File outputDir = getSentinelOutputDirectory();
        
        String cleanFuncName = AIBUtils.sanitizeFilename(currentFunc.getName());
        File reportFile = new File(outputDir, "explain_" + cleanFuncName + "_" + AIBUtils.getFileTimestamp() + ".md");
        try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(reportFile), StandardCharsets.UTF_8))) {
            bw.write("# SentinelAI Explanation Report â€” " + currentFunc.getName() + "\n");
            bw.write("Date: " + AIBUtils.getTimestamp() + "\n\n");
            bw.write(response);
        }
        AIBUtils.printResult(this, "Explanation report saved", reportFile.getAbsolutePath());

        // Add plate comment to the function
        try {
            currentProgram.getListing().setComment(currentFunc.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "âš¡ AIB SentinelAI Analysis:\n" + truncateForComment(response));
            AIBUtils.printResult(this, "Plate comment added to function start", AIBUtils.formatAddress(currentFunc.getEntryPoint()));
        } catch (Exception e) {
            AIBUtils.printWarning(this, "Failed to apply plate comment: " + e.getMessage());
        }
    }

    private String truncateForComment(String response) {
        if (response == null) return "";
        // Strip markdown blocks for cleaner plate comments
        String clean = response.replaceAll("```[a-zA-Z]*", "").replaceAll("`", "");
        if (clean.length() > 1000) {
            return clean.substring(0, 997) + "... [Truncated, see exported markdown for full details]";
        }
        return clean;
    }

    // ========================================================================
    // âœï¸ 2. AUTO-RENAME SELECTED FUNCTION & VARIABLES
    // ========================================================================

    private void autoRenameCurrentFunction() throws Exception {
        Function currentFunc = getFunctionContaining(currentAddress);
        if (currentFunc == null) {
            printerr("No function selected. Please place your cursor inside a function.");
            return;
        }

        println("  [âœï¸] Generating renaming suggestions for: " + currentFunc.getName() + "...");
        String cCode = decompileFunction(currentFunc);
        if (cCode == null || cCode.trim().isEmpty()) {
            printerr("Could not retrieve decompiler output.");
            return;
        }

        String prompt = "Review this decompiled function and suggest meaningful names for: \n"
            + "1. The function itself\n"
            + "2. Any local variables (e.g. uVar1, local_18)\n"
            + "3. Any parameters (e.g. param_1, param_2)\n\n"
            + "Use this local heuristic dossier to infer semantics before renaming:\n"
            + buildDeepFunctionContext(currentFunc, cCode) + "\n"
            + "If you reference outside knowledge, constrain it to globally recognized defensive sources only.\n"
            + "You MUST respond strictly with a valid, parsable JSON object in this exact format, with no extra text or markdown formatting outside the JSON:\n"
            + "{\n"
            + "  \"function_name\": \"suggested_better_name\",\n"
            + "  \"variables\": {\n"
            + "    \"uVar1\": \"bytes_written\",\n"
            + "    \"local_18\": \"buffer_ptr\"\n"
            + "  },\n"
            + "  \"parameters\": {\n"
            + "    \"param_1\": \"target_addr\",\n"
            + "    \"param_2\": \"max_len\"\n"
            + "  }\n"
            + "}\n\n"
            + "Function C Code:\n"
            + "```c\n" + cCode + "\n```";

        String jsonResponse = sendLLMRequest(prompt);
        if (jsonResponse == null) return;

        // Clean JSON response (strip markdown wrappers)
        jsonResponse = cleanJSONResponse(jsonResponse);

        AIBUtils.printSection(this, "AI RENAMING SUGGESTIONS");
        println(jsonResponse);

        // Prompt user before applying renames
        boolean apply = askYesNo("AIB SentinelAI â€” Apply Renames?", 
            "Do you want to automatically apply the AI's variable and function renaming suggestions in Ghidra?");
        
        if (!apply) {
            println("Renaming suggestions discarded by user.");
            return;
        }

        // Apply suggestions to Ghidra Database
        int renameCheck = 0;
        int transaction = currentProgram.startTransaction("AIB_SentinelAI_AutoRename");
        try {
            // 1. Rename function itself
            String suggestedFuncName = AIBUtils.extractJSONValue(jsonResponse, "function_name");
            if (suggestedFuncName != null && !suggestedFuncName.trim().isEmpty() && !suggestedFuncName.equals(currentFunc.getName())) {
                String oldName = currentFunc.getName();
                currentFunc.setName(suggestedFuncName.trim(), SourceType.USER_DEFINED);
                AIBUtils.printResult(this, "Renamed Function", oldName + " â†’ " + suggestedFuncName);
                renameCheck++;
            }

            // 2. Parse variables map
            String varsJSON = AIBUtils.extractJSONValue(jsonResponse, "variables");
            if (varsJSON != null) {
                Map<String, String> varMap = parseSimpleJSONMap(varsJSON);
                for (Variable var : currentFunc.getLocalVariables()) {
                    String oldVarName = var.getName();
                    if (varMap.containsKey(oldVarName)) {
                        String newVarName = varMap.get(oldVarName);
                        var.setName(newVarName, SourceType.USER_DEFINED);
                        AIBUtils.printResult(this, "Renamed Local Variable", oldVarName + " â†’ " + newVarName);
                        renameCheck++;
                    }
                }
            }

            // 3. Parse parameters map
            String paramsJSON = AIBUtils.extractJSONValue(jsonResponse, "parameters");
            if (paramsJSON != null) {
                Map<String, String> paramMap = parseSimpleJSONMap(paramsJSON);
                for (Parameter param : currentFunc.getParameters()) {
                    String oldParamName = param.getName();
                    if (paramMap.containsKey(oldParamName)) {
                        String newParamName = paramMap.get(oldParamName);
                        param.setName(newParamName, SourceType.USER_DEFINED);
                        AIBUtils.printResult(this, "Renamed Parameter", oldParamName + " â†’ " + newParamName);
                        renameCheck++;
                    }
                }
            }

            currentProgram.endTransaction(transaction, true);
            println("\n  [âœ“] Applied " + renameCheck + " renaming changes successfully!");
        } catch (Exception e) {
            currentProgram.endTransaction(transaction, false);
            printerr("Error applying renaming suggestions: " + e.getMessage());
        }
    }

    private String cleanJSONResponse(String raw) {
        String clean = raw.trim();
        if (clean.startsWith("```json")) {
            clean = clean.substring(7);
        } else if (clean.startsWith("```")) {
            clean = clean.substring(3);
        }
        if (clean.endsWith("```")) {
            clean = clean.substring(0, clean.length() - 3);
        }
        return clean.trim();
    }

    private Map<String, String> parseSimpleJSONMap(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        String inner = json.replaceAll("[{}]", "").trim();
        if (inner.isEmpty()) return map;

        for (String pair : inner.split(",")) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) {
                String key = kv[0].trim().replaceAll("\"", "");
                String val = kv[1].trim().replaceAll("\"", "");
                map.put(key, val);
            }
        }
        return map;
    }

    // ========================================================================
    // ðŸ¦  3. MALWARE & THREAT CLASSIFICATION (GLOBAL)
    // ========================================================================

    private void classifyMalwareGlobal() throws Exception {
        println("  [ðŸ¦ ] Gathering comprehensive global binary characteristics...");
        
        // Accumulate high-value context
        List<String> suspiciousAPIs = new ArrayList<>();
        List<String> suspiciousStrings = new ArrayList<>();
        List<String> bookmarks = new ArrayList<>();

        // 1. Scan bookmarks (gather bookmarks from other AIB plugins)
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        int bmCount = 0;
        Iterator<ghidra.program.model.listing.Bookmark> bmIter = bmMgr.getBookmarksIterator();
        while (bmIter.hasNext() && bmCount < 50) {
            ghidra.program.model.listing.Bookmark bm = bmIter.next();
            bookmarks.add(String.format("[%s] at %s: %s", bm.getType(), bm.getAddress().toString(), bm.getComment()));
            bmCount++;
        }

        // 2. Scan imported/referenced APIs
        int apiCount = 0;
        Iterator<ghidra.program.model.symbol.Symbol> symIter = currentProgram.getSymbolTable().getExternalSymbols();
        while (symIter.hasNext() && apiCount < 60) {
            ghidra.program.model.symbol.Symbol sym = symIter.next();
            suspiciousAPIs.add(sym.getName());
            apiCount++;
        }

        // 3. Scan some strings
        int strCount = 0;
        Iterator<ghidra.program.model.listing.Data> dataIter = currentProgram.getListing().getDefinedData(true);
        while (dataIter.hasNext() && strCount < 40) {
            ghidra.program.model.listing.Data d = dataIter.next();
            if (d.hasStringValue()) {
                String val = d.getDefaultValueRepresentation();
                if (val != null && val.length() > 5) {
                    suspiciousStrings.add(val.replaceAll("\"", ""));
                    strCount++;
                }
            }
        }

        println("  [i] Collected " + suspiciousAPIs.size() + " APIs, " + suspiciousStrings.size() + " strings, and " + bookmarks.size() + " bookmarks.");

        String prompt = "You are a senior threat intelligence analyst. Review these characteristics of a compiled binary "
            + "and perform a comprehensive threat classification report. Specifically:\n"
            + "1. Estimate the binary's potential capabilities (network activity, exfiltration, persistence, injection).\n"
            + "2. Identify any possible malware families, campaign links, or APT affiliations.\n"
            + "3. Map findings to the MITRE ATT&CK enterprise matrix.\n"
            + "4. Assess overall sophistication (low, moderate, high, advanced/nation-state).\n\n"
            + "--- BINARY METADATA ---\n"
            + "Name: " + currentProgram.getName() + "\n"
            + "Language: " + currentProgram.getLanguage().getLanguageID().toString() + "\n"
            + "Compiler: " + currentProgram.getCompiler() + "\n"
            + "--- DETECTED IMPORTED APIS ---\n"
            + String.join(", ", suspiciousAPIs) + "\n\n"
            + "--- DEFINED STRINGS ---\n"
            + String.join("\n", suspiciousStrings.size() > 20 ? suspiciousStrings.subList(0, 20) : suspiciousStrings) + "\n\n"
            + "--- EXISTING ANALYSIS BOOKMARKS ---\n"
            + String.join("\n", bookmarks) + "\n\n"
            + "--- ANALYST CONSTRAINTS ---\n"
            + "Distinguish direct evidence from inference. Avoid overclaiming attribution, campaign linkage, or confidence.\n\n"
            + "--- APPROVED EXTERNAL SOURCES ---\n"
            + "If you rely on outside knowledge, restrict it to NVD/CVE, CISA KEV, GitHub Security Advisories, OSV, CWE/CAPEC, and MITRE ATT&CK.\n\n"
            + "Output a professional, exhaustive Threat intelligence report in Markdown format:";

        String response = sendLLMRequest(prompt);
        if (response == null) return;

        AIBUtils.printSection(this, "MALWARE THREAT ASSESSMENT REPORT");
        println(response);

        // Export report
        File outputDir = getSentinelOutputDirectory();
        File reportFile = new File(outputDir, "threat_assessment_" + AIBUtils.getFileTimestamp() + ".md");
        try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(reportFile), StandardCharsets.UTF_8))) {
            bw.write("# AIB SentinelAI Threat Classification Assessment\n");
            bw.write("Target: " + currentProgram.getName() + "\n");
            bw.write("Date: " + AIBUtils.getTimestamp() + "\n\n");
            bw.write(response);
        }
        AIBUtils.printResult(this, "Threat Intelligence report exported", reportFile.getAbsolutePath());
    }

    // ========================================================================
    // ðŸ”“ 4. SCAN SELECTED FUNCTION FOR VULNERABILITIES
    // ========================================================================

    private void scanFunctionVulnerabilities() throws Exception {
        Function currentFunc = getFunctionContaining(currentAddress);
        if (currentFunc == null) {
            printerr("No function selected. Please place your cursor inside a function.");
            return;
        }

        println("  [ðŸ”“] Scanning function for vulnerabilities: " + currentFunc.getName() + "...");
        String cCode = decompileFunction(currentFunc);
        if (cCode == null || cCode.trim().isEmpty()) {
            printerr("Could not decompile function.");
            return;
        }
        List<LocalHeuristicFinding> localFindings = collectLocalHeuristicFindings(currentFunc, cCode);
        int candidateScore = calculateCandidateScore(currentFunc, cCode, localFindings);
        println("  [i] Candidate score: " + candidateScore + "/100 (" + candidateBand(candidateScore) + ")");

        String prompt = "Analyze this decompiled C function for potential software vulnerabilities. "
            + "Look for buffer overflows, integer overflows, format string vulnerabilities, logic bugs, race conditions, "
            + "unsafe string/memory copy usage (e.g. strcpy, memcpy without bounds checking), or weak custom encryption. "
            + "Use the local heuristic dossier below to reason step by step. Treat this as defensive triage and do not "
            + "claim certainty about a true 0-day unless the code itself strongly supports it.\n"
            + buildDeepFunctionContext(currentFunc, cCode) + "\n"
            + "If you rely on outside knowledge, restrict it to NVD/CVE, CISA KEV, GitHub Security Advisories, OSV, CWE/CAPEC, and MITRE ATT&CK.\n"
            + "Output your findings as a parsable JSON object matching this exact structure:\n"
            + "{\n"
            + "  \"vulnerabilities_found\": true,\n"
            + "  \"severity\": \"HIGH\", // or MEDIUM, LOW, NONE\n"
            + "  \"details\": \"A concise description of what is vulnerable and why...\",\n"
            + "  \"cvss_score\": 7.5,\n"
            + "  \"confidence\": \"MEDIUM\",\n"
            + "  \"suggested_remediation\": \"How to fix the code...\"\n"
            + "}\n\n"
            + "Function C Code:\n"
            + "```c\n" + cCode + "\n```";

        String jsonResponse = sendLLMRequest(prompt);
        if (jsonResponse == null) return;

        jsonResponse = cleanJSONResponse(jsonResponse);
        AIBUtils.printSection(this, "VULNERABILITY SCAN RESULTS");
        println(jsonResponse);

        // Bookmark findings if a vulnerability is detected
        String foundStr = AIBUtils.extractJSONValue(jsonResponse, "vulnerabilities_found");
        boolean found = "true".equalsIgnoreCase(foundStr);
        if (found) {
            String severity = AIBUtils.extractJSONValue(jsonResponse, "severity");
            String details = AIBUtils.extractJSONValue(jsonResponse, "details");
            
            Address entry = currentFunc.getEntryPoint();
            currentProgram.getBookmarkManager().setBookmark(entry, "Analysis", "VULNERABILITY",
                String.format("[VULN_%s] %s: %s", severity, currentFunc.getName(), details));

            // Prefix function name for quick identification
            if (!currentFunc.getName().startsWith("[VULN_")) {
                int transaction = currentProgram.startTransaction("AIB_SentinelAI_TagVuln");
                try {
                    currentFunc.setName("[VULN_" + severity + "]_" + currentFunc.getName(), SourceType.USER_DEFINED);
                    currentProgram.endTransaction(transaction, true);
                    AIBUtils.printResult(this, "Tagged function entry point with Bookmark & Renamed", currentFunc.getName());
                } catch (Exception e) {
                    currentProgram.endTransaction(transaction, false);
                }
            }
        } else {
            println("  [ðŸŸ¢] No vulnerabilities identified in this function.");
        }
    }

    // ========================================================================
    // ðŸŒ 5. GENERATE GLOBAL BRIEFING
    // ========================================================================

    private void generateGlobalBriefing() throws Exception {
        println("  [ðŸŒ] Generating global binary intelligence briefing (this may take a moment)...");

        // Iterate over functions of interest (max 15 high-value functions)
        FunctionIterator funcIter = currentProgram.getListing().getFunctions(true);
        List<String> functionSummaries = new ArrayList<>();
        int count = 0;

        while (funcIter.hasNext() && count < 15 && !monitor.isCancelled()) {
            Function func = funcIter.next();
            // Skip small helper / library functions
            if (func.isThunk() || func.getBody().getNumAddresses() < 50) continue;

            String name = func.getName();
            // Only select user-renamed functions or functions categorized by other AIB tools
            if (name.startsWith("FUN_") || name.startsWith("SUB_") || name.startsWith("md5_") || name.startsWith("sha1_")) continue;

            String cCode = decompileFunction(func);
            if (cCode != null) {
                // Keep brief decompilation
                String lines[] = cCode.split("\n");
                int capLines = Math.min(lines.length, 30);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < capLines; i++) sb.append(lines[i]).append("\n");
                if (lines.length > 30) sb.append("// ... [Code truncated for briefing] ...\n");

                functionSummaries.add("### Function: " + name + " (" + AIBUtils.formatAddress(func.getEntryPoint()) + ")\n"
                    + "```c\n" + sb.toString() + "```\n");
                count++;
            }
        }

        if (functionSummaries.isEmpty()) {
            AIBUtils.printWarning(this, "No interesting/renamed functions found to summarize. Please rename a few critical functions first.");
            return;
        }

        String prompt = "Review these compiled function definitions from a binary under analysis. "
            + "Provide a high-level executive intelligence briefing of the overall system layout, architecture, and "
            + "functional flows. What does this application do as a cohesive unit? Summarize structural behaviors "
            + "clearly in professional intelligence style. Distinguish direct evidence, strong hypotheses, and unknowns:\n\n"
            + "If you rely on outside knowledge, restrict it to NVD/CVE, CISA KEV, GitHub Security Advisories, OSV, CWE/CAPEC, and MITRE ATT&CK.\n\n"
            + String.join("\n", functionSummaries);

        String response = sendLLMRequest(prompt);
        if (response == null) return;

        AIBUtils.printSection(this, "EXECUTIVE INTELLIGENCE BRIEFING");
        println(response);

        // Export brief
        File outputDir = getSentinelOutputDirectory();
        File briefFile = new File(outputDir, "executive_briefing_" + AIBUtils.getFileTimestamp() + ".md");
        try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(briefFile), StandardCharsets.UTF_8))) {
            bw.write("# AIB SentinelAI Executive Intelligence Briefing\n");
            bw.write("Program: " + currentProgram.getName() + "\n");
            bw.write("Date: " + AIBUtils.getTimestamp() + "\n\n");
            bw.write(response);
        }
        AIBUtils.printResult(this, "Executive Briefing exported", briefFile.getAbsolutePath());
    }

    // ========================================================================
    // SAFE VULNERABILITY RESEARCH
    // ========================================================================

    private void researchDisclosedVulnerability() throws Exception {
        String pluginName = askString("AIB SentinelAI â€” Plugin / Target",
            "Enter the Ghidra plugin, extension, script, or component you are reviewing:");
        if (pluginName == null || pluginName.trim().isEmpty()) {
            printerr("No target component was provided.");
            return;
        }

        String advisoryId = askString("AIB SentinelAI â€” Advisory Reference",
            "Enter a CVE, GHSA, disclosure title, or internal tracking ID:");
        if (advisoryId == null || advisoryId.trim().isEmpty()) {
            advisoryId = "UNSPECIFIED_DISCLOSURE";
        }

        String advisorySummary = askString("AIB SentinelAI â€” Advisory Summary",
            "Paste a short summary of the disclosed issue and affected behavior:");
        if (advisorySummary == null || advisorySummary.trim().isEmpty()) {
            printerr("A vulnerability summary is required for safe research mode.");
            return;
        }

        Function currentFunc = getFunctionContaining(currentAddress);
        String cCode = null;
        if (currentFunc != null) {
            cCode = decompileFunction(currentFunc);
        }

        StringBuilder prompt = new StringBuilder();
        prompt.append("You are assisting a defensive reverse-engineering workflow for a disclosed vulnerability in a Ghidra plugin or extension. ")
            .append("Do NOT provide exploit code, weaponized payloads, shell commands for compromise, bypass steps, or instructions that enable unauthorized access. ")
            .append("Produce a practical markdown report with these sections:\n")
            .append("1. Vulnerability synopsis\n")
            .append("2. Likely root cause patterns to inspect in code\n")
            .append("3. Static analysis checklist for Ghidra review\n")
            .append("4. Safe validation steps for an isolated lab\n")
            .append("5. Expected benign observations that would confirm the bug exists\n")
            .append("6. Remediation guidance and secure coding fixes\n")
            .append("7. Regression tests or harness ideas that verify the fix\n")
            .append("8. Responsible disclosure and evidence collection notes\n\n")
            .append("If outside knowledge is referenced, restrict it to NVD/CVE, CISA KEV, GitHub Security Advisories, OSV, CWE/CAPEC, and MITRE ATT&CK.\n\n")
            .append("Target component: ").append(pluginName).append("\n")
            .append("Reference: ").append(advisoryId).append("\n")
            .append("Disclosed issue summary: ").append(advisorySummary).append("\n");

        if (currentFunc != null && cCode != null && !cCode.trim().isEmpty()) {
            prompt.append("\nSelected function for context: ").append(currentFunc.getName())
                .append(" at ").append(AIBUtils.formatAddress(currentFunc.getEntryPoint())).append("\n")
                .append("```c\n").append(cCode).append("\n```\n")
                .append("Use this code only to focus the review and point out suspicious patterns to inspect.\n");
        }

        String response = sendLLMRequest(prompt.toString());
        if (response == null || response.trim().isEmpty()) {
            printerr("LLM API returned an empty or invalid response.");
            return;
        }

        AIBUtils.printSection(this, "SAFE VULNERABILITY RESEARCH");
        println(response);

        File outputDir = getSentinelOutputDirectory();

        String safeTarget = AIBUtils.sanitizeFilename(pluginName);
        String safeRef = AIBUtils.sanitizeFilename(advisoryId);
        File reportFile = new File(outputDir,
            "safe_vuln_research_" + safeTarget + "_" + safeRef + "_" + AIBUtils.getFileTimestamp() + ".md");
        try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(reportFile), StandardCharsets.UTF_8))) {
            bw.write("# AIB SentinelAI Safe Vulnerability Research\n");
            bw.write("Target: " + pluginName + "\n");
            bw.write("Reference: " + advisoryId + "\n");
            bw.write("Date: " + AIBUtils.getTimestamp() + "\n\n");
            bw.write(response);
        }
        AIBUtils.printResult(this, "Safe research report exported", reportFile.getAbsolutePath());
    }
    // ========================================================================
    // NETWORK / HTTP REQUEST DISPATCHER
    // ========================================================================

    private String sendLLMRequest(String prompt) {
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            String body = "";
            String url = "";

            if (preferredProvider.equals("gemini")) {
                url = GEMINI_API_URL + "?key=" + apiKey;
                body = "{\n"
                    + "  \"contents\": [\n"
                    + "    {\n"
                    + "      \"parts\": [\n"
                    + "        {\n"
                    + "          \"text\": \"" + escapeStringLiteral(prompt) + "\"\n"
                    + "        }\n"
                    + "      ]\n"
                    + "    }\n"
                    + "  ]\n"
                    + "}";
            } else {
                url = CLAUDE_API_URL;
                headers.put("x-api-key", apiKey);
                headers.put("anthropic-version", "2023-06-01");
                body = "{\n"
                    + "  \"model\": \"claude-3-5-sonnet-20241022\",\n"
                    + "  \"max_tokens\": 4000,\n"
                    + "  \"messages\": [\n"
                    + "    {\n"
                    + "      \"role\": \"user\",\n"
                    + "      \"content\": \"" + escapeStringLiteral(prompt) + "\"\n"
                    + "    }\n"
                    + "  ]\n"
                    + "}";
            }

            // Increment usage limit locally
            AIBUtils.incrementAPIUsage();

            println("  [~] Contacting " + preferredProvider + " API...");
            String rawResponse = AIBUtils.httpPost(url, headers, body);
            
            // Extract response text using standard library helpers
            String extracted = null;
            if (preferredProvider.equals("gemini")) {
                extracted = AIBUtils.extractGeminiResponseText(rawResponse);
            } else {
                extracted = AIBUtils.extractClaudeResponseText(rawResponse);
            }

            if (extracted != null) {
                // Correct escaped newlines or formatting
                return unescapeJSONString(extracted);
            }
            return rawResponse;

        } catch (Exception e) {
            printerr("API connection error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private String escapeStringLiteral(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }

    private String unescapeJSONString(String input) {
        if (input == null) return "";
        return input.replace("\\n", "\n")
                    .replace("\\r", "\r")
                    .replace("\\t", "\t")
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\");
    }

    private File getSentinelOutputDirectory() throws Exception {
        return AIBUtils.getToolOutputDirectory(this, currentCaseId, "sentinel_ai");
    }

    private String buildDeepFunctionContext(Function func, String cCode) {
        List<String> observations = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        List<LocalHeuristicFinding> findings = collectLocalHeuristicFindings(func, cCode);
        int candidateScore = calculateCandidateScore(func, cCode, findings);

        if (func != null) {
            observations.add("Function: " + func.getName() + " at " + AIBUtils.formatAddress(func.getEntryPoint()));
            observations.add("Parameter count: " + func.getParameterCount());
            observations.add("Local variable count: " + func.getLocalVariables().length);
        }

        addIfContains(lower, observations, "memcpy", "Potential raw memory copy usage");
        addIfContains(lower, observations, "strcpy", "Unbounded string copy pattern");
        addIfContains(lower, observations, "strncpy", "Length-limited copy requires boundary review");
        addIfContains(lower, observations, "sprintf", "Potential format-string or buffer sizing issue");
        addIfContains(lower, observations, "snprintf", "Formatted output present; review truncation handling");
        addIfContains(lower, observations, "recv", "Inbound network data handling path");
        addIfContains(lower, observations, "send", "Outbound network transmission path");
        addIfContains(lower, observations, "read(", "External input ingestion path");
        addIfContains(lower, observations, "write(", "External output path");
        addIfContains(lower, observations, "virtualalloc", "Dynamic allocation or code staging indicator");
        addIfContains(lower, observations, "createprocess", "Process creation behavior");
        addIfContains(lower, observations, "crypt", "Cryptographic or obfuscation-related token");
        addIfContains(lower, observations, "xor", "Potential simple obfuscation or decryption logic");

        observations.add("Estimated branch density: " + (countOccurrences(lower, "if (") + countOccurrences(lower, "switch")));
        observations.add("Estimated loop density: " + (countOccurrences(lower, "for (") + countOccurrences(lower, "while")));
        observations.add("Pointer-manipulation hints: " + (countOccurrences(lower, "->") + countOccurrences(lower, "*")));
        observations.add("Candidate score: " + candidateScore + "/100 (" + candidateBand(candidateScore) + ")");

        StringBuilder sb = new StringBuilder();
        sb.append("--- LOCAL HEURISTIC DOSSIER ---\n");
        for (String observation : observations) {
            sb.append("- ").append(observation).append("\n");
        }
        if (!findings.isEmpty()) {
            sb.append("--- STRUCTURED LOCAL FINDINGS ---\n");
            for (LocalHeuristicFinding finding : findings) {
                sb.append("- [").append(finding.severity).append("] ").append(finding.title).append("\n");
                sb.append("  Evidence: ").append(finding.evidence).append("\n");
                sb.append("  Why it matters: ").append(finding.rationale).append("\n");
                sb.append("  Analyst note: ").append(finding.analystNote).append("\n");
            }
        }
        appendSection(sb, "VARIANT ANALYSIS", buildVariantAnalysis(func, cCode));
        appendSection(sb, "INVARIANT CHECKING", buildInvariantChecks(func, cCode));
        appendSection(sb, "SOURCE TO SINK CORRELATION", buildSourceSinkCorrelation(func, cCode));
        appendSection(sb, "STATE MACHINE REVIEW", buildStateMachineReview(cCode));
        appendSection(sb, "KNOWN-SAFE PATTERN DIFF", buildKnownSafePatternDiff(cCode));
        appendSection(sb, "CROSS-PLUGIN CORRELATION", buildCrossPluginCorrelation(func));
        appendSection(sb, "TEMPORAL SAFETY", buildTemporalSafetyAnalysis(cCode));
        appendSection(sb, "ANTICHEAT SURFACE", buildAnticheatAttackSurfaceAnalysis(cCode));
        appendSection(sb, "TAINT ANALYSIS", buildCrossFunctionTaintAnalysis(func, cCode));
        if (safeEnrichmentEnabled) {
            appendSection(sb, "SAFE ENRICHMENT", buildSafeEnrichment(findings, candidateScore));
            appendSection(sb, "APPROVED EXTERNAL KNOWLEDGE SOURCES", buildTrustedSourcePolicy());
        }
        sb.append("--- END DOSSIER ---\n");
        return sb.toString();
    }

    private List<LocalHeuristicFinding> collectLocalHeuristicFindings(Function func, String cCode) {
        List<LocalHeuristicFinding> findings = new ArrayList<>();
        if (func == null) {
            return findings;
        }

        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        Set<String> callees = new LinkedHashSet<>();
        try {
            for (Function called : func.getCalledFunctions(monitor)) {
                if (called != null && called.getName() != null) {
                    callees.add(called.getName().toLowerCase(Locale.ROOT));
                }
            }
        } catch (Exception e) {
            // Best-effort only.
        }

        // Add core standard call findings
        addCallFinding(findings, callees, "dangerous_call", "HIGH", "Potentially unsafe call", "strcpy", "Uses strcpy", "Historically associated with unbounded copies and overflow review.", "Trace source length and destination capacity.");
        addCallFinding(findings, callees, "dangerous_call", "HIGH", "Potentially unsafe call", "gets", "Uses gets", "Directly consumes input without a bound parameter.", "Treat as a top-priority review path.");
        addCallFinding(findings, callees, "dangerous_call", "MEDIUM", "Potentially unsafe call", "memcpy", "Uses memcpy", "Copy length and destination sizing may diverge if attacker-controlled.", "Review size provenance and integer conversions.");
        addCallFinding(findings, callees, "dangerous_call", "MEDIUM", "Potentially unsafe call", "recv", "Uses recv", "Externally influenced data may flow into parser or copy logic.", "Pair with boundary and state validation review.");
        addCallFinding(findings, callees, "dangerous_call", "MEDIUM", "Potentially unsafe call", "read", "Uses read", "Input boundary handling may be coupled to caller-controlled lengths.", "Exercise short reads, truncation, and overlong payloads.");
        addCallFinding(findings, callees, "dangerous_call", "MEDIUM", "Potentially unsafe call", "sprintf", "Uses sprintf", "Formatted writes can exceed the destination buffer if sizing is implicit.", "Review all format and destination combinations.");

        if (containsAny(callees, "malloc", "calloc", "realloc") && containsAny(callees, "memcpy", "memmove", "strcpy", "strncpy")) {
            findings.add(makeFinding(
                "memory_pattern", "HIGH", "Allocation followed by copy operations",
                "Calls allocation APIs and copy primitives in the same function",
                "Heap size math and subsequent writes are a common source of corruption bugs.",
                "Mutate size fields, counts, and copy lengths that influence both steps."
            ));
        }

        if ((lower.contains("memcpy(") || lower.contains("memmove(")) && !containsAnyText(lower, "sizeof(", "min(", "if (")) {
            findings.add(makeFinding(
                "memory_pattern", "MEDIUM", "Copy operation without obvious nearby guard",
                "Pseudocode shows raw copy usage without an obvious local guard",
                "Length or offset metadata may be trusted too early.",
                "Review negative-to-large conversions, desynced sizes, and truncated headers."
            ));
        }

        boolean parserShape = containsAny(callees, "read", "recv", "fread", "scanf", "sscanf")
            || containsAnyText(lower, "parse", "header", "length", "offset", "magic");
        if (parserShape && (countOccurrences(lower, "if (") + countOccurrences(lower, "switch")) > 12) {
            findings.add(makeFinding(
                "parser_shape", "MEDIUM", "Complex parser-like control flow",
                "Input-oriented tokens plus high branch density",
                "State divergence and inconsistent bounds checks often hide in parser-heavy code.",
                "Fuzz truncated records, overlapping offsets, recursive containers, and contradictory lengths."
            ));
        }

        if (containsAnyText(lower, "switch", "default:", "break;")) {
            findings.add(makeFinding(
                "dispatch_pattern", "LOW", "Dispatch table worth fail-closed review",
                "Switch-based selector logic is present",
                "Default behavior can accidentally accept unsupported states.",
                "Probe invalid selectors and malformed record types."
            ));
        }

        if (containsAny(callees, "md5", "sha1", "rc4", "des", "rand", "srand") || containsAnyText(lower, "md5", "sha1", "rc4", "des", "seed")) {
            findings.add(makeFinding(
                "weak_crypto", "MEDIUM", "Potential weak cryptography or weak randomness",
                "Legacy crypto or predictable randomness indicators detected",
                "Security-sensitive use of weak primitives can create downgrade or predictability issues.",
                "Inspect key derivation, nonce reuse, and any trust decisions tied to these primitives."
            ));
        }

        if (containsAnyText(lower, "xor", "^") && containsAnyText(lower, "for", "while")) {
            findings.add(makeFinding(
                "weak_crypto", "LOW", "Custom obfuscation or home-grown crypto pattern",
                "Looping XOR-style transformation pattern detected",
                "Ad hoc transformations are often reversible and can hide brittle parsing or trust logic.",
                "Review key reuse, block handling, and malformed input behavior."
            ));
        }

        boolean inputFacing = containsAny(callees, "recv", "read", "fread", "accept", "socket")
            || containsAnyText(lower, "http", "json", "xml", "protobuf", "packet", "request")
            || containsAnyText(lower, "length", "header", "opcode", "request", "response");
        if (inputFacing && estimateInstructionCount(cCode) > 40) {
            findings.add(makeFinding(
                "fuzz_surface", "MEDIUM", "High-value fuzzing surface",
                "Input-facing behavior combined with meaningful complexity",
                "Externally influenced parsers and handlers are common bug concentration points.",
                "Prioritize structure-aware mutations for tags, lengths, opcodes, and nested records."
            ));
        }

        boolean authContext = containsAnyText(lower, "auth", "login", "token", "password", "session", "role", "permission");
        if (authContext && (lower.contains("strcmp(") || lower.contains("strncmp(") || containsAny(callees, "strcmp", "strncmp"))) {
            findings.add(makeFinding(
                "auth_logic", "MEDIUM", "Authentication comparison path",
                "String-based auth or authorization comparisons detected",
                "Canonicalization, truncation, or inconsistent normalization can create bypass paths.",
                "Test casing, Unicode normalization, null bytes, whitespace, and prefix collisions."
            ));
        }

        if (authContext && countOccurrences(lower, "if (") <= 4 && (lower.contains("return 1;") || lower.contains("return true;"))) {
            findings.add(makeFinding(
                "auth_logic", "LOW", "Small auth gate merits manual review",
                "Compact auth-like gate with permissive-looking success path",
                "Short gate functions can hide inverted checks or permissive early returns.",
                "Exercise malformed, empty, and partially valid credentials."
            ));
        }

        if (containsAnyText(lower, "token", "auth", "password", "cmd", "/bin/sh", "powershell")) {
            findings.add(makeFinding(
                "suspicious_string", "MEDIUM", "Suspicious embedded string context",
                "Auth, command, or shell-related string tokens appear in pseudocode",
                "These tokens often sit near trust boundaries or execution pivots.",
                "Review associated parser, dispatcher, and authorization logic."
            ));
        }

        boolean integerMathHot = containsAnyText(lower, "+", "-", "*", "<<", ">>")
            && containsAnyText(lower, "length", "size", "count", "offset", "index");
        if (integerMathHot && !containsAnyText(lower, "size_t", "uint64", "check", "overflow")) {
            findings.add(makeFinding(
                "integer_risk", "MEDIUM", "Size or offset arithmetic merits overflow review",
                "Arithmetic appears near length, size, count, offset, or index handling",
                "Integer truncation or wraparound can destabilize allocation, bounds checks, and pointer math.",
                "Stress negative values, large counts, multiplication overflow, and signed-to-unsigned conversions."
            ));
        }

        if (containsAnyText(lower, "[", "]", "offset", "index") && !containsAnyText(lower, "if (", "min(", "max(", "bounds")) {
            findings.add(makeFinding(
                "bounds_pattern", "MEDIUM", "Index or offset usage without obvious nearby guard",
                "Array-style or offset-driven access appears without a visible local boundary check",
                "Out-of-bounds reads and writes often hide behind trusted index metadata.",
                "Probe oversized offsets, underflowed indexes, and contradictory declared lengths."
            ));
        }

        if (containsAnyText(lower, "->", "*", "offset", "base") && containsAnyText(lower, "+", "-")) {
            findings.add(makeFinding(
                "pointer_math", "LOW", "Pointer arithmetic and base-plus-offset flow",
                "Pointer-oriented arithmetic is present in pseudocode",
                "Pointer math is often correct, but it is a classic place for desync between validation and use.",
                "Cross-check base validity, offset normalization, and object lifetime assumptions."
            ));
        }

        if (containsAnyText(lower, "recv(", "read(", "fread(", "memcpy(", "malloc(", "realloc(")
                && !containsAnyText(lower, "== -1", "== 0", "!= 0", "null", "null)", "failed", "error")) {
            findings.add(makeFinding(
                "unchecked_return", "LOW", "Potential unchecked critical return value",
                "I/O, allocation, or copy-related calls appear without obvious nearby error handling text",
                "Unchecked failures can create state confusion, null dereferences, or incomplete validation paths.",
                "Review all failure returns and partial-success cases for the surrounding call sequence."
            ));
        }

        boolean trustBoundary = inputFacing && (containsAnyText(lower, "system(", "exec", "popen", "createremotethread", "virtualprotect")
            || containsAnyText(lower, "cmd", "command", "script", "powershell"));
        if (trustBoundary) {
            findings.add(makeFinding(
                "trust_boundary", "HIGH", "Input-to-capability trust boundary crossing",
                "Externally influenced parsing tokens appear near command, execution, or memory-control behaviors",
                "This shape deserves review for injection, unsafe dispatch, or policy bypass conditions.",
                "Track how user-controlled fields are normalized before capability-bearing operations."
            ));
        }

        if (parserShape && containsAnyText(lower, "goto", "continue", "break") && countOccurrences(lower, "return") > 2) {
            findings.add(makeFinding(
                "state_desync", "MEDIUM", "Complex parser exit paths may desynchronize state",
                "Parser-like logic includes multiple early exits or control-transfer paths",
                "Inconsistent cleanup or partially validated state can create weird-machine style bug surfaces.",
                "Exercise malformed records that abort at different parse stages and compare state cleanup."
            ));
        }

        // Incorporate advanced Phase 2 findings
        findings.addAll(collectAdvancedFindings(func, cCode));

        return findings;
    }

    private List<LocalHeuristicFinding> collectAdvancedFindings(Function func, String cCode) {
        List<LocalHeuristicFinding> findings = new ArrayList<>();
        if (func == null || cCode == null) return findings;

        String lower = cCode.toLowerCase(Locale.ROOT);
        Set<String> callees = new LinkedHashSet<>();
        try {
            for (Function called : func.getCalledFunctions(monitor)) {
                if (called != null && called.getName() != null) {
                    callees.add(called.getName().toLowerCase(Locale.ROOT));
                }
            }
        } catch (Exception e) {
            // best-effort
        }

        // 1. Use After Free (UAF)
        if (containsAnyText(lower, "free(", "delete(", "release(") && (containsAnyText(lower, "->", "*") || containsAny(callees, "memcpy", "strcpy"))) {
            findings.add(makeFinding(
                "use_after_free", "CRITICAL", "Potential Use After Free (UAF) hazard",
                "Presence of pointer deallocation patterns alongside subsequent dereference or copy logic",
                "Accessing objects or memory spaces after they have been released leads to undefined behavior, memory corruption, and arbitrary execution paths.",
                "Carefully inspect the lifetime of the freed object and ensure pointers are immediately set to null post-release."
            ));
        }

        // 2. Double Free
        if (countOccurrences(lower, "free(") > 1 || countOccurrences(lower, "delete ") > 1) {
            findings.add(makeFinding(
                "double_free", "CRITICAL", "Potential Double Free vulnerability",
                "Multiple pointer deallocation paths identified in this function",
                "Attempting to free an already deallocated chunk corrupts the memory allocator state, presenting a highly exploitable zero-day surface.",
                "Unify cleanup logic into a single fail-safe label or ensure pointers are nullified after being freed."
            ));
        }

        // 3. Type Confusion
        if (containsAnyText(lower, "reinterpret_cast", "(struct ", "union ") || lower.contains("void*")) {
            findings.add(makeFinding(
                "type_confusion", "HIGH", "Potential Type Confusion hazard",
                "Polymorphic or unsafe cast operations or union type structures detected",
                "Mismatch between allocated object type and the casted operational structure allows memory layouts to be misinterpreted.",
                "Enforce dynamic or safe casting boundaries and structure validation routines."
            ));
        }

        // 4. TOCTOU Race Condition
        if (containsAnyText(lower, "access(", "stat(", "open(") && countOccurrences(lower, "if (") > 1) {
            findings.add(makeFinding(
                "toctou_race", "HIGH", "Potential Time-of-Check to Time-of-Use (TOCTOU) pattern",
                "File state check immediately followed by access or operation without atomic synchronization",
                "File or resource attributes can be modified by an concurrent thread/process between checking and operation phases.",
                "Implement atomic locking mechanics or operate directly on file descriptors rather than file paths."
            ));
        }

        // 5. Integer Overflow Chain
        if (containsAnyText(lower, "+", "-", "*") && containsAny(callees, "malloc", "calloc", "realloc", "memcpy")) {
            findings.add(makeFinding(
                "integer_overflow_chain", "HIGH", "Integer arithmetic chain feeding memory allocation/copy",
                "Arithmetic operations directly precede allocation size or transfer length parameters",
                "Integer wrapping or truncation inside size calculations can result in under-allocated buffers that are then written to with larger payloads.",
                "Enforce explicit boundary checks on all factors and use safe overflow-checked math libraries."
            ));
        }

        // 6. Uninitialized Use
        if (containsAnyText(lower, "struct ", "char ", "int ") && !containsAnyText(lower, "= {", "= 0", "memset")) {
            findings.add(makeFinding(
                "uninitialized_use", "HIGH", "Uninitialized stack variable usage",
                "Stack-allocated local structures or arrays appear without visible local zeroing or default initialization",
                "Variables residing on the stack may contain residual memory contents, leaking sensitive context or causing non-deterministic crashes.",
                "Ensure all local buffers, arrays, and complex structs are explicitly zeroed out (e.g. via memset) at definition."
            ));
        }

        // 7. Kernel Object Abuse
        if (containsAnyText(lower, "openprocess", "duplicatetoken", "adjusttokenprivileges", "zwopenkey", "ntopenprocess")) {
            findings.add(makeFinding(
                "kernel_object_abuse", "CRITICAL", "High-severity kernel object or process token manipulation",
                "Use of powerful low-level system handle or process security token alteration APIs",
                "Insecure token derivation or over-privileged process handle replication could lead to local privilege escalations.",
                "Verify integrity validation and ensure the narrowest required access rights are requested."
            ));
        }

        // 8. IOCTL Attack Surface
        if (containsAnyText(lower, "deviceiocontrol", "ioctl", "irp", "iosp")) {
            findings.add(makeFinding(
                "ioctl_attack_surface", "HIGH", "Kernel driver IOCTL dispatch attack surface",
                "Direct exposure of DeviceIoControl or IOCTL dispatch processing",
                "Custom IOCTL handlers are historically a source of kernel overflows, arbitrary write primitives, or memory disclosure.",
                "Review parameter verification, buffer validation, and restrict access permissions to elevated users."
            ));
        }

        // 9. Hypervisor Escape
        if (containsAnyText(lower, "cpuid", "vmcall", "vmmcall", "in ", "out ", "hypervisor")) {
            findings.add(makeFinding(
                "hypervisor_escape", "CRITICAL", "Potential Hypervisor Escape or Backdoor Channel indicators",
                "Presence of instruction registers, CPUID virtualization checks, or VM communication channels",
                "Flaws in virtual machine hypervisor interfaces or device emulator components could allow guest-to-host execution.",
                "Strictly isolate guest-facing parsing logic and validate VM boundary interactions."
            ));
        }

        // 10. Pool Corruption
        if (containsAnyText(lower, "exallocatepool", "exfreepool", "pooltag", "nonpagedpool")) {
            findings.add(makeFinding(
                "pool_corruption", "CRITICAL", "Kernel Pool memory allocation and deletion",
                "Presence of Windows kernel-pool or system-level allocator APIs",
                "Buffer overflows or incorrect pool allocations directly corrupt the system kernel space, causing bugchecks or privilege escalation.",
                "Validate size math rigorously and ensure exact alignment when allocating/deallocating pool buffers."
            ));
        }

        // 11. Privilege Escalation
        if (containsAnyText(lower, "secreateprivilege", "sedebugprivilege", "raise", "token_elevate")) {
            findings.add(makeFinding(
                "privilege_escalation", "HIGH", "Security privilege escalation capability pattern",
                "Attempts to modify thread/process privileges or request elevated security tokens",
                "Elevation mechanics lacking robust signature checks or integrity-level gating allow low-privilege actors to hijack system capabilities.",
                "Ensure privilege elevation requires a cryptographically verified security boundary."
            ));
        }

        // 12. Race Condition Kernel
        if (containsAnyText(lower, "spinlock", "keacquirespinlock", "interlocked", "volatile", "sharedmemory")) {
            findings.add(makeFinding(
                "race_condition_kernel", "CRITICAL", "Kernel-level race condition or synchronization hazard",
                "Spinlock or atomic vocabulary detected alongside shared resources or pointers",
                "Inadequate synchronization when modifying global kernel pools or shared states can result in double-frees or UAFs.",
                "Ensure lock acquire and release labels enclose all multi-thread operational blocks completely."
            ));
        }

        return findings;
    }

    private LocalHeuristicFinding makeFinding(String id, String severity, String title, String evidence, String rationale, String analystNote) {
        LocalHeuristicFinding finding = new LocalHeuristicFinding();
        finding.id = id;
        finding.severity = severity;
        finding.title = title;
        finding.evidence = evidence;
        finding.rationale = rationale;
        finding.analystNote = analystNote;
        return finding;
    }

    private void addCallFinding(List<LocalHeuristicFinding> findings, Set<String> callees, String id, String severity,
            String title, String callee, String evidence, String rationale, String analystNote) {
        if (callees.contains(callee)) {
            findings.add(makeFinding(id, severity, title, evidence, rationale, analystNote));
        }
    }

    private boolean containsAny(Set<String> values, String... needles) {
        for (String needle : needles) {
            if (values.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAnyText(String lower, String... needles) {
        for (String needle : needles) {
            if (lower.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private int estimateInstructionCount(String cCode) {
        if (cCode == null || cCode.isEmpty()) {
            return 0;
        }
        return cCode.split("\n").length;
    }

    private int calculateCandidateScore(Function func, String cCode, List<LocalHeuristicFinding> findings) {
        int score = 0;
        for (LocalHeuristicFinding finding : findings) {
            if ("CRITICAL".equalsIgnoreCase(finding.severity)) {
                score += 28;
            } else if ("HIGH".equalsIgnoreCase(finding.severity)) {
                score += 18;
            } else if ("MEDIUM".equalsIgnoreCase(finding.severity)) {
                score += 10;
            } else {
                score += 5;
            }
        }

        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        int branchDensity = countOccurrences(lower, "if (") + countOccurrences(lower, "switch");
        int loopDensity = countOccurrences(lower, "for (") + countOccurrences(lower, "while");
        if (branchDensity > 10) score += 8;
        if (loopDensity > 3) score += 6;
        if (containsAnyText(lower, "recv(", "read(", "fread(", "accept(", "socket")) score += 8;
        if (containsAnyText(lower, "malloc(", "calloc(", "realloc(", "memcpy(", "memmove(", "strcpy(")) score += 10;
        if (containsAnyText(lower, "system(", "exec", "popen", "createprocess", "virtualprotect")) score += 12;
        if (containsAnyText(lower, "driver", "deviceiocontrol", "ioctl", "kernel", "hypervisor")) score += 14;
        if (containsAnyText(lower, "eac", "battleye", "vanguard", "anticheat")) score += 10;
        if (func != null && func.getParameterCount() >= 3) score += 4;

        if (score > 100) score = 100;
        return Math.max(score, 0);
    }

    private String candidateBand(int score) {
        if (score >= 92) return "CRITICAL_IMMEDIATE";
        if (score >= 80) return "CRITICAL_REVIEW";
        if (score >= 60) return "HIGH_PRIORITY";
        if (score >= 35) return "MEDIUM_PRIORITY";
        return "LOW_PRIORITY";
    }

    private void appendSection(StringBuilder sb, String title, List<String> lines) {
        if (lines == null || lines.isEmpty()) {
            return;
        }
        sb.append("--- ").append(title).append(" ---\n");
        for (String line : lines) {
            sb.append("- ").append(line).append("\n");
        }
    }

    private List<String> buildVariantAnalysis(Function func, String cCode) {
        List<String> lines = new ArrayList<>();
        if (func == null) {
            return lines;
        }

        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        int currentGuards = countOccurrences(lower, "if (") + countOccurrences(lower, "min(") + countOccurrences(lower, "sizeof(");
        int currentRiskCalls = countOccurrences(lower, "memcpy(") + countOccurrences(lower, "strcpy(") + countOccurrences(lower, "recv(");

        try {
            FunctionIterator it = currentProgram.getListing().getFunctions(true);
            int compared = 0;
            while (it.hasNext() && compared < 40) {
                Function other = it.next();
                if (other == null || other.equals(func) || other.isThunk()) {
                    continue;
                }
                if (Math.abs(other.getParameterCount() - func.getParameterCount()) > 1) {
                    continue;
                }
                String name = other.getName();
                if (name == null) {
                    continue;
                }
                if (!sharesVariantSignal(func.getName(), name)) {
                    continue;
                }

                String otherCode = decompileFunction(other);
                if (otherCode == null || otherCode.trim().isEmpty()) {
                    continue;
                }
                String otherLower = otherCode.toLowerCase(Locale.ROOT);
                int otherGuards = countOccurrences(otherLower, "if (") + countOccurrences(otherLower, "min(") + countOccurrences(otherLower, "sizeof(");
                int otherRiskCalls = countOccurrences(otherLower, "memcpy(") + countOccurrences(otherLower, "strcpy(") + countOccurrences(otherLower, "recv(");

                if (currentRiskCalls > 0 && currentGuards + 1 < otherGuards) {
                    lines.add("Function looks less guarded than nearby variant `" + name + "` despite similar shape.");
                }
                if (currentRiskCalls > otherRiskCalls && otherGuards >= currentGuards) {
                    lines.add("Current function performs riskier copy/input operations than sibling `" + name + "`.");
                }
                compared++;
                if (lines.size() >= 3) {
                    break;
                }
            }
        } catch (Exception e) {
            // Best-effort variant comparison only.
        }

        if (lines.isEmpty()) {
            lines.add("No strong sibling-variant mismatch identified in the sampled nearby functions.");
        }
        return lines;
    }

    private boolean sharesVariantSignal(String a, String b) {
        String na = a.toLowerCase(Locale.ROOT);
        String nb = b.toLowerCase(Locale.ROOT);
        if (na.equals(nb)) {
            return true;
        }
        int prefix = commonPrefixLength(na, nb);
        return prefix >= 5;
    }

    private int commonPrefixLength(String a, String b) {
        int len = Math.min(a.length(), b.length());
        int i = 0;
        while (i < len && a.charAt(i) == b.charAt(i)) {
            i++;
        }
        return i;
    }

    private List<String> buildInvariantChecks(Function func, String cCode) {
        List<String> lines = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";

        if (containsAnyText(lower, "malloc(", "calloc(", "realloc(") && containsAnyText(lower, "memcpy(", "memmove(", "strcpy(")) {
            lines.add("Invariant candidate: copied length must remain <= allocated capacity across all branches.");
        }
        if (containsAnyText(lower, "offset", "index", "length", "size")) {
            lines.add("Invariant candidate: all offsets and indexes must stay within the current buffer/object bounds.");
        }
        if (containsAnyText(lower, "auth", "token", "password", "session")) {
            lines.add("Invariant candidate: all malformed or ambiguous auth states must fail closed.");
        }
        if (containsAnyText(lower, "switch", "default:")) {
            lines.add("Invariant candidate: unsupported selectors should terminate safely, not continue parsing.");
        }
        if (lines.isEmpty()) {
            lines.add("No domain-specific invariant stood out beyond generic memory and state validation.");
        }
        return lines;
    }

    private List<String> buildSourceSinkCorrelation(Function func, String cCode) {
        List<String> lines = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";

        List<String> sources = new ArrayList<>();
        if (containsAnyText(lower, "recv(", "read(", "fread(", "accept(", "socket")) sources.add("external input");
        if (containsAnyText(lower, "http", "json", "xml", "packet", "request")) sources.add("parsed protocol/message data");

        List<String> sinks = new ArrayList<>();
        if (containsAnyText(lower, "malloc(", "calloc(", "realloc(")) sinks.add("allocation");
        if (containsAnyText(lower, "memcpy(", "memmove(", "strcpy(", "sprintf(")) sinks.add("copy/write primitive");
        if (containsAnyText(lower, "system(", "exec", "popen", "createprocess", "virtualprotect")) sinks.add("capability-bearing operation");

        if (!sources.isEmpty() && !sinks.isEmpty()) {
            lines.add("Potential flow: " + String.join(" + ", sources) + " -> " + String.join(" -> ", sinks));
            lines.add("Review whether normalization and length validation happen before the first sink is reached.");
        } else {
            lines.add("No strong local source-to-sink chain was inferred from the current pseudocode slice.");
        }
        return lines;
    }

    private List<String> buildStateMachineReview(String cCode) {
        List<String> lines = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        int returns = countOccurrences(lower, "return");
        int switches = countOccurrences(lower, "switch");

        if (switches > 0) {
            lines.add("Selector-driven control flow present; verify unknown states fail closed.");
        }
        if (returns > 2 && containsAnyText(lower, "goto", "continue", "break")) {
            lines.add("Multiple exits plus control-transfer paths may leave partially validated state behind.");
        }
        if (containsAnyText(lower, "default:", "return 0", "return false")) {
            lines.add("Default branch behavior should be checked for silent accept, partial cleanup, or inconsistent error signaling.");
        }
        if (lines.isEmpty()) {
            lines.add("No strong local state-machine warning beyond ordinary branch complexity.");
        }
        return lines;
    }

    private List<String> buildKnownSafePatternDiff(String cCode) {
        List<String> lines = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";

        if (containsAnyText(lower, "memcpy(", "memmove(") && !containsAnyText(lower, "sizeof(", "min(", "clamp", "bound")) {
            lines.add("Deviates from a safer copy pattern: raw copy appears without obvious clamping or size-derived bound.");
        }
        if (containsAnyText(lower, "strcmp(", "strncmp(") && containsAnyText(lower, "auth", "token", "password")) {
            lines.add("Deviates from a safer auth pattern: direct string comparison appears without visible normalization/constant-time handling.");
        }
        if (containsAnyText(lower, "malloc(", "realloc(") && !containsAnyText(lower, "null", "failed", "error")) {
            lines.add("Deviates from a safer allocation pattern: no obvious allocation failure handling nearby.");
        }
        if (lines.isEmpty()) {
            lines.add("No major deviation from a simple known-safe local pattern stood out in this slice.");
        }
        return lines;
    }

    private List<String> buildCrossPluginCorrelation(Function func) {
        List<String> lines = new ArrayList<>();
        if (func == null) {
            return lines;
        }

        try {
            BookmarkManager bmMgr = currentProgram.getBookmarkManager();
            Iterator<ghidra.program.model.listing.Bookmark> it = bmMgr.getBookmarksIterator();
            int nearby = 0;
            while (it.hasNext() && nearby < 6) {
                ghidra.program.model.listing.Bookmark bm = it.next();
                if (bm == null || bm.getAddress() == null) {
                    continue;
                }
                if (func.getBody().contains(bm.getAddress()) || func.getEntryPoint().equals(bm.getAddress())) {
                    lines.add("Bookmark correlation: [" + bm.getType() + "] " + bm.getCategory() + " -> " + bm.getComment());
                    nearby++;
                }
            }
        } catch (Exception e) {
            // Best-effort correlation only.
        }

        if (lines.isEmpty()) {
            lines.add("No direct bookmark correlation found for this function from other AIB workflows.");
        }
        return lines;
    }

    private List<String> buildTemporalSafetyAnalysis(String cCode) {
        List<String> lines = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        if (containsAnyText(lower, "free(", "delete", "release") && containsAnyText(lower, "return", "goto", "continue")) {
            lines.add("Temporal lifetime transitions are present; verify no freed object remains reachable across alternate exits.");
        }
        if (containsAnyText(lower, "free(", "delete") && containsAnyText(lower, "memcpy(", "strcpy(", "->")) {
            lines.add("Free/deallocation patterns appear near later dereference or copy-like behavior; review for use-after-free style hazards.");
        }
        if (containsAnyText(lower, "lock", "unlock", "acquire", "release")) {
            lines.add("Locking vocabulary detected; ensure resources and synchronization state unwind consistently on failure paths.");
        }
        if (lines.isEmpty()) {
            lines.add("No strong local temporal-safety warning beyond standard lifetime review.");
        }
        return lines;
    }

    private List<String> buildAnticheatAttackSurfaceAnalysis(String cCode) {
        List<String> lines = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        if (containsAnyText(lower, "driver", "deviceiocontrol", "ioctl", "\\\\.\\", "kernel")) {
            lines.add("Driver or device control surface indicators detected; review trust boundary and input validation closely.");
        }
        if (containsAnyText(lower, "eac", "battleye", "vanguard", "anticheat", "hypervisor")) {
            lines.add("Anticheat or hypervisor-adjacent terminology detected; prioritize integrity checks, IOCTL handling, and privilege boundaries.");
        }
        if (containsAnyText(lower, "handle", "pid", "process", "thread") && containsAnyText(lower, "openprocess", "duplicatetoken", "adjusttokenprivileges")) {
            lines.add("Process or token manipulation surface may intersect with anticheat/privilege-control logic.");
        }
        if (lines.isEmpty()) {
            lines.add("No strong anticheat-specific attack surface signal in the current pseudocode slice.");
        }
        return lines;
    }

    private List<String> buildCrossFunctionTaintAnalysis(Function func, String cCode) {
        List<String> lines = new ArrayList<>();
        String lower = cCode != null ? cCode.toLowerCase(Locale.ROOT) : "";
        boolean source = containsAnyText(lower, "recv(", "read(", "fread(", "accept(", "socket", "request", "packet");
        boolean transform = containsAnyText(lower, "parse", "decode", "deserialize", "copy", "memcpy(", "strcpy(");
        boolean sink = containsAnyText(lower, "malloc(", "realloc(", "memcpy(", "system(", "exec", "virtualprotect", "createprocess");

        if (source && transform && sink) {
            lines.add("Potential multi-stage taint chain: input source -> transform/parse -> memory/capability sink.");
        } else if (source && transform) {
            lines.add("Potential taint propagation from external input into parser/transform logic; downstream sinks should be reviewed in callers/callees.");
        }

        if (func != null) {
            try {
                int callees = func.getCalledFunctions(monitor).size();
                if (source && callees > 3) {
                    lines.add("Function fans out into multiple callees after input handling; trace which callee first enforces bounds or normalization.");
                }
            } catch (Exception e) {
                // Best-effort only.
            }
        }

        if (lines.isEmpty()) {
            lines.add("No strong local cross-function taint chain was inferred from the current slice.");
        }
        return lines;
    }

    private List<String> buildTrustedSourcePolicy() {
        List<String> lines = new ArrayList<>();
        lines.add("Use only globally recognized defensive sources if external enrichment is enabled.");
        lines.add("Approved families: NVD/CVE, CISA KEV, GitHub Security Advisories, OSV, CWE/CAPEC, MITRE ATT&CK.");
        lines.add("Treat external sources as context, not ground truth; prioritize local code evidence when sources disagree.");
        lines.add("Avoid sending full sensitive samples or secrets to third-party services unless explicitly intended.");
        lines.add("Online enrichment flag is currently " + (safeOnlineEnrichmentEnabled ? "ENABLED" : "DISABLED") + ".");
        return lines;
    }

    private List<String> buildSafeEnrichment(List<LocalHeuristicFinding> findings, int candidateScore) {
        List<String> lines = new ArrayList<>();
        lines.add("Candidate score band: " + candidateBand(candidateScore) + " (" + candidateScore + "/100).");

        Set<String> cwes = new LinkedHashSet<>();
        Set<String> capecs = new LinkedHashSet<>();
        Set<String> tactics = new LinkedHashSet<>();
        for (LocalHeuristicFinding finding : findings) {
            mapFindingToKnowledge(finding.id, cwes, capecs, tactics);
        }

        if (!cwes.isEmpty()) {
            lines.add("Mapped CWE candidates: " + String.join(", ", cwes));
        }
        if (!capecs.isEmpty()) {
            lines.add("Mapped CAPEC candidates: " + String.join(", ", capecs));
        }
        if (!tactics.isEmpty()) {
            lines.add("Relevant MITRE ATT&CK themes: " + String.join(", ", tactics));
        }

        if (!cwes.isEmpty()) {
            lines.add("Safe research query seeds: NVD/CVE + " + cwes.iterator().next() + ", OSV + " + cwes.iterator().next() + ", CWE/CAPEC taxonomies.");
        } else {
            lines.add("Safe research query seeds: NVD/CVE, CISA KEV, OSV, CWE, CAPEC, MITRE ATT&CK using the dominant local finding labels.");
        }

        if (safeOnlineEnrichmentEnabled) {
            lines.add("Online enrichment is enabled by config, but only approved defensive providers should be queried.");
        } else {
            lines.add("Online enrichment is disabled by config; this dossier is using local evidence plus safe taxonomy mapping only.");
        }
        return lines;
    }

    private void mapFindingToKnowledge(String findingId, Set<String> cwes, Set<String> capecs, Set<String> tactics) {
        if ("dangerous_call".equals(findingId) || "memory_pattern".equals(findingId) || "bounds_pattern".equals(findingId)) {
            cwes.add("CWE-119");
            cwes.add("CWE-120");
            cwes.add("CWE-125");
            capecs.add("CAPEC-100");
        }
        if ("integer_risk".equals(findingId)) {
            cwes.add("CWE-190");
            cwes.add("CWE-131");
        }
        if ("auth_logic".equals(findingId)) {
            cwes.add("CWE-287");
            cwes.add("CWE-863");
            capecs.add("CAPEC-115");
        }
        if ("trust_boundary".equals(findingId) || "suspicious_string".equals(findingId)) {
            cwes.add("CWE-20");
            cwes.add("CWE-74");
            capecs.add("CAPEC-152");
            tactics.add("Execution / Command and Scripting Abuse");
        }
        if ("parser_shape".equals(findingId) || "state_desync".equals(findingId) || "dispatch_pattern".equals(findingId)) {
            cwes.add("CWE-20");
            cwes.add("CWE-707");
            capecs.add("CAPEC-228");
        }
        if ("weak_crypto".equals(findingId)) {
            cwes.add("CWE-327");
            cwes.add("CWE-338");
        }
        if ("unchecked_return".equals(findingId)) {
            cwes.add("CWE-252");
        }
        if ("pointer_math".equals(findingId)) {
            cwes.add("CWE-823");
        }
        if ("fuzz_surface".equals(findingId)) {
            tactics.add("Initial Access / Input Handling Surface");
        }
        if ("temporal_safety".equals(findingId)) {
            cwes.add("CWE-416");
            cwes.add("CWE-415");
            capecs.add("CAPEC-25");
        }
        if ("anticheat_surface".equals(findingId)) {
            cwes.add("CWE-284");
            cwes.add("CWE-693");
            tactics.add("Defense Evasion / Privileged Component Abuse");
        }
        if ("taint_analysis".equals(findingId)) {
            cwes.add("CWE-20");
            cwes.add("CWE-74");
            capecs.add("CAPEC-153");
        }
        if ("kernel_object_abuse".equals(findingId) || "pool_corruption".equals(findingId) || "race_condition_kernel".equals(findingId)) {
            cwes.add("CWE-362");
            cwes.add("CWE-781");
            tactics.add("Privilege Escalation / Kernel Abuse");
        }
        if ("ioctl_attack_surface".equals(findingId) || "privilege_escalation".equals(findingId)) {
            cwes.add("CWE-782");
            cwes.add("CWE-269");
            capecs.add("CAPEC-233");
        }
        if ("hypervisor_escape".equals(findingId)) {
            cwes.add("CWE-250");
            cwes.add("CWE-693");
            tactics.add("Escape to Host / Hypervisor Boundary Abuse");
        }
    }

    private void scanFunctionVulnerabilitiesAdvanced() throws Exception {
        Function currentFunc = getFunctionContaining(currentAddress);
        if (currentFunc == null) {
            printerr("No function selected. Please place your cursor inside a function.");
            return;
        }

        println("  [ðŸ”“] [Advanced Mode] Scanning function with Chain-of-Thought (CoT) reasoning: " + currentFunc.getName() + "...");
        String cCode = decompileFunction(currentFunc);
        if (cCode == null || cCode.trim().isEmpty()) {
            printerr("Could not decompile function.");
            return;
        }

        List<LocalHeuristicFinding> localFindings = collectLocalHeuristicFindings(currentFunc, cCode);
        int candidateScore = calculateCandidateScore(currentFunc, cCode, localFindings);
        println("  [i] Candidate score: " + candidateScore + "/100 (" + candidateBand(candidateScore) + ")");

        String prompt = "You are an elite software security engineer performing defensive security triage and static code analysis on high-severity targets. "
            + "Analyze this decompiled C function for potential software vulnerabilities. "
            + "You MUST use a systematic Chain-of-Thought (CoT) reasoning process to evaluate the code before reaching a conclusion.\n\n"
            + "Follow this precise structure in your analysis:\n"
            + "1. Observe structural components and data flows.\n"
            + "2. Track variables and trace memory offsets/lengths.\n"
            + "3. Identify control flow validations and safety gates.\n"
            + "4. Synthesize vulnerability hypothesis if a path exists, otherwise confirm benign behavior.\n"
            + "5. Draft secure remediation code blocks.\n\n"
            + "Use the local heuristic dossier below to anchor your steps:\n"
            + buildDeepFunctionContext(currentFunc, cCode) + "\n"
            + "Ensure you only reference approved defensive knowledge sources (NVD/CVE, CISA KEV, GitHub Security Advisories, OSV, CWE/CAPEC, MITRE ATT&CK).\n\n"
            + "You MUST output your findings strictly as a valid, parsable JSON object with this exact structure and no other surrounding markdown or text:\n"
            + "{\n"
            + "  \"vulnerabilities_found\": true,\n"
            + "  \"severity\": \"CRITICAL\", // or HIGH, MEDIUM, LOW, NONE\n"
            + "  \"reasoning_steps\": [\n"
            + "    \"Step 1: Structural Observations - ...\",\n"
            + "    \"Step 2: Variable Lifetime & Math Tracing - ...\",\n"
            + "    \"Step 3: Control Boundary Assessment - ...\"\n"
            + "  ],\n"
            + "  \"details\": \"A concise description of the exact zero-day boundary or memory flaw identified...\",\n"
            + "  \"cvss_score\": 9.8,\n"
            + "  \"confidence\": \"HIGH\",\n"
            + "  \"suggested_remediation\": \"Complete secure-coding implementation to mitigate the issue...\"\n"
            + "}\n\n"
            + "Decompiled C Code:\n"
            + "```c\n" + cCode + "\n```";

        String jsonResponse = sendLLMRequest(prompt);
        if (jsonResponse == null) return;

        jsonResponse = cleanJSONResponse(jsonResponse);
        AIBUtils.printSection(this, "ADVANCED VULNERABILITY SCAN RESULTS");
        println(jsonResponse);

        // Bookmark findings if a vulnerability is detected
        String foundStr = AIBUtils.extractJSONValue(jsonResponse, "vulnerabilities_found");
        boolean found = "true".equalsIgnoreCase(foundStr);
        if (found) {
            String severity = AIBUtils.extractJSONValue(jsonResponse, "severity");
            String details = AIBUtils.extractJSONValue(jsonResponse, "details");
            
            Address entry = currentFunc.getEntryPoint();
            currentProgram.getBookmarkManager().setBookmark(entry, "Analysis", "VULNERABILITY",
                String.format("[VULN_%s] %s: %s", severity, currentFunc.getName(), details));

            // Prefix function name for quick identification
            if (!currentFunc.getName().startsWith("[VULN_")) {
                int transaction = currentProgram.startTransaction("AIB_SentinelAI_TagVuln");
                try {
                    currentFunc.setName("[VULN_" + severity + "]_" + currentFunc.getName(), SourceType.USER_DEFINED);
                    currentProgram.endTransaction(transaction, true);
                    AIBUtils.printResult(this, "Tagged function entry point with Bookmark & Renamed", currentFunc.getName());
                } catch (Exception e) {
                    currentProgram.endTransaction(transaction, false);
                }
            }
        } else {
            println("  [ðŸŸ¢] No vulnerabilities identified in this function under advanced CoT review.");
        }
    }

    private void generateDefensivePoc() throws Exception {
        Function currentFunc = getFunctionContaining(currentAddress);
        if (currentFunc == null) {
            printerr("No function selected. Please place your cursor inside a function.");
            return;
        }
        String cCode = decompileFunction(currentFunc);
        if (cCode == null || cCode.trim().isEmpty()) {
            printerr("Could not decompile function.");
            return;
        }

        String prompt = "Create a defensive validation skeleton for the selected function. "
            + "Do NOT produce weaponized exploit code, shellcode, bypass steps, or intrusive instructions. "
            + "Instead, produce a markdown checklist and optional pseudocode harness outline for safe lab validation, "
            + "including inputs to vary, telemetry to capture, expected benign failure conditions, and cleanup steps.\n\n"
            + buildDeepFunctionContext(currentFunc, cCode) + "\n"
            + "```c\n" + cCode + "\n```";

        String response = sendLLMRequest(prompt);
        if (response == null || response.trim().isEmpty()) {
            printerr("LLM API returned an empty or invalid response.");
            return;
        }

        AIBUtils.printSection(this, "DEFENSIVE POC SKELETON");
        println(response);

        File outputDir = getSentinelOutputDirectory();
        File reportFile = new File(outputDir, "defensive_poc_" + AIBUtils.sanitizeFilename(currentFunc.getName()) + "_" + AIBUtils.getFileTimestamp() + ".md");
        try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(reportFile), StandardCharsets.UTF_8))) {
            bw.write("# AIB SentinelAI Defensive PoC Skeleton\n");
            bw.write("Function: " + currentFunc.getName() + "\n");
            bw.write("Date: " + AIBUtils.getTimestamp() + "\n\n");
            bw.write(response);
        }
        AIBUtils.printResult(this, "Defensive PoC skeleton exported", reportFile.getAbsolutePath());
    }

    private void deep0DaySweep() throws Exception {
        AIBUtils.printSection(this, "DEEP 0-DAY SWEEP");
        println("  [i] Building ranked shortlist from local heuristics and candidate scoring...");

        FunctionIterator funcIter = currentProgram.getListing().getFunctions(true);
        List<Map<String, Object>> ranked = new ArrayList<>();
        int scanned = 0;
        while (funcIter.hasNext() && !monitor.isCancelled() && scanned < 120) {
            Function func = funcIter.next();
            if (func == null || func.isThunk()) {
                continue;
            }
            String cCode = decompileFunction(func);
            if (cCode == null || cCode.trim().isEmpty()) {
                continue;
            }
            List<LocalHeuristicFinding> findings = collectLocalHeuristicFindings(func, cCode);
            int score = calculateCandidateScore(func, cCode, findings);
            if (score < 35) {
                scanned++;
                continue;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", func.getName());
            item.put("address", AIBUtils.formatAddress(func.getEntryPoint()));
            item.put("score", score);
            item.put("band", candidateBand(score));
            item.put("findings", findings.size());
            item.put("findings_list", findings);
            item.put("code", cCode);
            ranked.add(item);
            scanned++;
        }

        ranked.sort((a, b) -> Integer.compare((Integer) b.get("score"), (Integer) a.get("score")));
        if (ranked.isEmpty()) {
            println("  [i] No high-signal candidates crossed the sweep threshold.");
            return;
        }

        int limit = Math.min(5, ranked.size());
        println("  [~] Top " + limit + " zero-day candidates selected for deep LLM-triage analysis...");
        for (int i = 0; i < limit; i++) {
            Map<String, Object> item = ranked.get(i);
            println(String.format("  Candidate %d. %s @ %s -> Score %s (%s, findings=%s)",
                i + 1, item.get("name"), item.get("address"), item.get("score"), item.get("band"), item.get("findings")));
        }

        String sweepPrompt = build0DaySweepPrompt(ranked.subList(0, limit), scanned);
        println("  [~] Sending deep 0-day sweep dispatch to the LLM...");
        String response = sendLLMRequest(sweepPrompt);
        if (response == null || response.trim().isEmpty()) {
            printerr("LLM API returned an empty or invalid response during the deep sweep.");
            return;
        }

        AIBUtils.printSection(this, "DEEP ZERO-DAY SWEEP EXECUTIVE TRIAGE REPORT");
        println(response);

        File outputDir = getSentinelOutputDirectory();
        File reportFile = new File(outputDir, "deep_0day_sweep_" + AIBUtils.getFileTimestamp() + ".md");
        try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(reportFile), StandardCharsets.UTF_8))) {
            bw.write("# SentinelAI Premium Zero-Day Sweep Triage & Mitigation Report\n\n");
            bw.write("Date: " + AIBUtils.getTimestamp() + "\n");
            bw.write("Total Scanned Functions: " + scanned + "\n\n");
            bw.write(response);
        }
        AIBUtils.printResult(this, "Premium Zero-Day Sweep report exported", reportFile.getAbsolutePath());
    }

    private String build0DaySweepPrompt(List<Map<String, Object>> candidates, int scannedCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are a principal security architect and world-class zero-day specialist.\n")
          .append("You have completed a static heuristic sweep of ").append(scannedCount).append(" functions inside the program: ")
          .append(currentProgram.getName()).append(".\n\n")
          .append("Here is the telemetry and decompiler context for the top zero-day vulnerability candidates identified by the static layer:\n\n");

        for (int i = 0; i < candidates.size(); i++) {
            Map<String, Object> item = candidates.get(i);
            sb.append("### Candidate #").append(i + 1).append(": ").append(item.get("name")).append(" @ ").append(item.get("address")).append("\n")
              .append("- Heuristic Score: ").append(item.get("score")).append("/100 (").append(item.get("band")).append(")\n")
              .append("- Heuristic Findings Count: ").append(item.get("findings")).append("\n")
              .append("- Local Heuristic Dossier Findings:\n");

            @SuppressWarnings("unchecked")
            List<LocalHeuristicFinding> findings = (List<LocalHeuristicFinding>) item.get("findings_list");
            for (LocalHeuristicFinding finding : findings) {
                sb.append("  - [").append(finding.severity).append("] ").append(finding.title).append(": ").append(finding.evidence).append("\n");
            }
            sb.append("- Decompiled C Code Snippet:\n")
              .append("```c\n").append(item.get("code")).append("\n```\n\n");
        }

        sb.append("--- INSTRUCTIONS ---\n")
          .append("Analyze these candidates systematically. Review memory copy logic, lifetime management, synchronization routines, and privilege gates.\n")
          .append("Produce an executive-level vulnerability ranking and secure mitigation report in Markdown. Include:\n")
          .append("1. **Executive Summary**: A summary of overall binary security posture.\n")
          .append("2. **Ranked Vulnerability Triage**: For each candidate, provide a detailed risk profile, root-cause analysis, and threat severity rating (using standardized defensive taxonomies like CWE/CAPEC).\n")
          .append("3. **Remediation & Secure Coding Guidance**: Concrete, premium-grade secure C/C++ coding examples to refactor the vulnerable blocks.\n")
          .append("4. **Safe Lab Validation Strategy**: Step-by-step methodologies to securely verify potential boundaries in a controlled test lab without causing operational disruption.\n\n")
          .append("Strictly follow the safe triage guidelines: do NOT produce weaponized exploit code, shellcode, or compromise steps.");

        return sb.toString();
    }

    private void addIfContains(String lower, List<String> observations, String needle, String message) {
        if (lower.contains(needle)) {
            observations.add(message);
        }
    }

    private int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}


