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

        // Show main menu
        String[] menuOptions = {
            "ðŸ§  Explain Selected Function",
            "âœï¸ Auto-Rename Selected Function & Variables",
            "ðŸ¦  Malware & Threat Classification (Global)",
            "ðŸ”“ Scan Selected Function for Vulnerabilities",
            "ðŸ§ª Research Disclosed Vulnerability (Safe)",
            "ðŸŒ Generate Full Binary Intelligence Briefing"
        };

        String selectedOption = askChoice("AIB SentinelAI â€” AI Analysis Suite",
            "Select an AI-assisted analysis operation:", Arrays.asList(menuOptions), menuOptions[0]);

        if (selectedOption.startsWith("ðŸ§ ")) {
            explainCurrentFunction();
        } else if (selectedOption.startsWith("âœï¸")) {
            autoRenameCurrentFunction();
        } else if (selectedOption.startsWith("ðŸ¦ ")) {
            classifyMalwareGlobal();
        } else if (selectedOption.startsWith("ðŸ”“")) {
            scanFunctionVulnerabilities();
        } else if (selectedOption.startsWith("ðŸ§ª")) {
            researchDisclosedVulnerability();
        } else if (selectedOption.startsWith("ðŸŒ")) {
            generateGlobalBriefing();
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
            AIBUtils.saveAPIConfig(config);
            AIBUtils.printResult(this, "API configuration saved to Desktop/AIB_Exports/.aib_config.json", preferredProvider);
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
            + "and its parameters/variables. Output your findings as a well-structured markdown document:\n\n"
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
        File outputDir = new File(AIBUtils.getOutputDirectory(this), "sentinel_ai");
        if (!outputDir.exists()) outputDir.mkdirs();
        
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
            + "Output a professional, exhaustive Threat intelligence report in Markdown format:";

        String response = sendLLMRequest(prompt);
        if (response == null) return;

        AIBUtils.printSection(this, "MALWARE THREAT ASSESSMENT REPORT");
        println(response);

        // Export report
        File outputDir = new File(AIBUtils.getOutputDirectory(this), "sentinel_ai");
        if (!outputDir.exists()) outputDir.mkdirs();
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

        String prompt = "Analyze this decompiled C function for potential software vulnerabilities. "
            + "Look for buffer overflows, integer overflows, format string vulnerabilities, logic bugs, race conditions, "
            + "unsafe string/memory copy usage (e.g. strcpy, memcpy without bounds checking), or weak custom encryption. "
            + "Output your findings as a parsable JSON object matching this exact structure:\n"
            + "{\n"
            + "  \"vulnerabilities_found\": true,\n"
            + "  \"severity\": \"HIGH\", // or MEDIUM, LOW, NONE\n"
            + "  \"details\": \"A concise description of what is vulnerable and why...\",\n"
            + "  \"cvss_score\": 7.5,\n"
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
            + "clearly in professional intelligence style:\n\n"
            + String.join("\n", functionSummaries);

        String response = sendLLMRequest(prompt);
        if (response == null) return;

        AIBUtils.printSection(this, "EXECUTIVE INTELLIGENCE BRIEFING");
        println(response);

        // Export brief
        File outputDir = new File(AIBUtils.getOutputDirectory(this), "sentinel_ai");
        if (!outputDir.exists()) outputDir.mkdirs();
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

        File outputDir = new File(AIBUtils.getOutputDirectory(this), "sentinel_ai");
        if (!outputDir.exists()) outputDir.mkdirs();

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
}


