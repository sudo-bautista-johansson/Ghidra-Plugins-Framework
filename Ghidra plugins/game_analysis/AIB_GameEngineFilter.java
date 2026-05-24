//AIB Game Engine Filter — Engine Runtime Function Classifier & Filter
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.GameAnalysis
//@keybinding
//@menupath Tools.AIB.Game Engine Filter
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB GAME ENGINE FILTER
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 *
 * Identifies game engine runtime functions by signature and allows
 * grouping, tagging, or renaming them to isolate custom developer game logic.
 *
 * Supported Game Engines:
 *   - Unity / IL2CPP
 *   - Unreal Engine (UE4 / UE5)
 *   - Godot Engine
 *
 * Actions:
 *   - Automatic detection of engine signature confidence
 *   - Classification of functions into ENGINE vs GAME_LOGIC
 *   - Tag mode: Prefixes functions with [ENGINE] or [GAME]
 *   - Namespace mode: Moves engine functions to "EngineRuntime" namespace
 *   - Bookmark mode: Creates bookmarks for quick filtering
 *   - Exports function classification report to JSON
 *
 * Language: Bilingual EN/ES
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_GameEngineFilter extends GhidraScript {

    private boolean useSpanish = false;
    private String t(String en, String es) { return useSpanish ? es : en; }

    // ========================================================================
    // ENGINE IDENTIFIERS
    // ========================================================================

    private static class EngineSignatures {
        String name;
        List<String> symbols;
        List<String> strings;

        EngineSignatures(String name, List<String> symbols, List<String> strings) {
            this.name = name;
            this.symbols = symbols;
            this.strings = strings;
        }
    }

    private Map<String, EngineSignatures> engineSpecs = new LinkedHashMap<>();

    private void initEngineSpecs() {
        engineSpecs.put("Unity/IL2CPP", new EngineSignatures("Unity/IL2CPP",
            Arrays.asList("il2cpp_", "mono_", "UnityEngine", "UnityPlayer", "il2cpp_init", "il2cpp_class_get_methods"),
            Arrays.asList("UnityEngine", "global-metadata.dat", "Mono", "UnityPlayer.dll", "UnityFS")
        ));
        
        engineSpecs.put("Unreal Engine", new EngineSignatures("Unreal Engine",
            Arrays.asList("UObject", "UFunction", "FName", "GEngine", "ProcessEvent", "StaticFindObject", "FPlatform", "UE4", "UE5"),
            Arrays.asList("UnrealEngine", "GEngine", "ProcessEvent", "StaticFindObject", "FFrame::Step", "/Script/CoreUObject")
        ));

        engineSpecs.put("Godot", new EngineSignatures("Godot",
            Arrays.asList("godot_", "GDScript", "_physics_process", "_ready", "gdnative", "godot_headers"),
            Arrays.asList("godot_", "GDScript", "GodotEngine", "scene/resources/packed_scene.h")
        ));
    }

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        // Language selection
        String langChoice = askChoice(
            "AIB Game Engine Filter — Language / Idioma",
            "Select language / Seleccione idioma:",
            Arrays.asList("English", "Español"), "English");
        useSpanish = "Español".equals(langChoice);

        String caseId = askString(
            t("AIB — Case ID", "AIB — ID de Caso"),
            t("Enter Case ID:", "Ingrese ID de Caso:"), "CASE_001");

        initEngineSpecs();
        printBanner();

        // 1. Engine Detection
        println("  [*] " + t("Analyzing binary for game engine signatures...",
            "Analizando el binario en busca de firmas de motores de juego..."));
        
        Map<String, Double> confidence = detectEngineConfidence();
        String detectedEngine = "Unknown";
        double maxConf = 0.0;
        
        for (Map.Entry<String, Double> entry : confidence.entrySet()) {
            println("    - " + entry.getKey() + ": " + String.format("%.1f%%", entry.getValue() * 100));
            if (entry.getValue() > maxConf) {
                maxConf = entry.getValue();
                detectedEngine = entry.getKey();
            }
        }

        if (maxConf < 0.15) {
            detectedEngine = "Unknown";
            println("  [!] " + t("No clear game engine signature detected.", 
                "No se detectó ninguna firma clara de motor de juego."));
        } else {
            println("  [✓] " + t("Detected Engine", "Motor Detectado") + ": " + 
                detectedEngine + " (" + String.format("%.1f%%", maxConf * 100) + " " + t("confidence", "de confianza") + ")");
        }

        // Prompt user to confirm engine selection
        List<String> engineOptions = new ArrayList<>(engineSpecs.keySet());
        engineOptions.add(t("None / Manual Filter", "Ninguno / Filtro Manual"));
        
        String confirmEngine = askChoice(
            t("AIB — Confirm Engine", "AIB — Confirmar Motor"),
            t("Select target engine filter:", "Seleccione el filtro de motor objetivo:"),
            engineOptions, 
            detectedEngine.equals("Unknown") ? engineOptions.get(engineOptions.size() - 1) : detectedEngine
        );

        if (confirmEngine.equals(t("None / Manual Filter", "Ninguno / Filtro Manual"))) {
            println("  [*] " + t("Manual selection: Exiting classification.", "Selección manual: Saliendo de la clasificación."));
            return;
        }

        // 2. Action selection
        String actionChoice = askChoice(
            t("AIB — Filter Action", "AIB — Acción de Filtro"),
            t("Choose action for engine functions:", "Seleccione acción para las funciones del motor:"),
            Arrays.asList(
                "Tag Mode (Prefix with [ENGINE] / [GAME])", 
                "Namespace Mode (Move to 'EngineRuntime' namespace)", 
                "Bookmark Mode (Create bookmarks only)"
            ),
            "Tag Mode (Prefix with [ENGINE] / [GAME])"
        );

        println("\n  [*] " + t("Classifying functions...", "Clasificando funciones..."));
        
        List<Function> engineFuncs = new ArrayList<>();
        List<Function> gameFuncs = new ArrayList<>();
        
        classifyFunctions(confirmEngine, engineFuncs, gameFuncs);

        println("  [✓] " + t("Classification complete", "Clasificación completada") + ":");
        println("    - " + t("Engine Functions", "Funciones del Motor") + ": " + engineFuncs.size());
        println("    - " + t("Game Logic Functions", "Funciones de Lógica de Juego") + ": " + gameFuncs.size());

        // 3. Apply action
        int modified = 0;
        int txId = currentProgram.startTransaction("AIB Engine Filter");
        try {
            if (actionChoice.contains("Tag Mode")) {
                modified = applyTagMode(engineFuncs, gameFuncs);
            } else if (actionChoice.contains("Namespace Mode")) {
                modified = applyNamespaceMode(engineFuncs);
            } else if (actionChoice.contains("Bookmark Mode")) {
                modified = applyBookmarkMode(engineFuncs, gameFuncs);
            }
        } finally {
            currentProgram.endTransaction(txId, true);
        }

        println("  [✓] " + t("Successfully applied actions to", "Acción aplicada exitosamente a") + " " + 
            modified + " " + t("functions", "funciones"));

        // 4. Export JSON
        exportResults(caseId, confirmEngine, engineFuncs, gameFuncs);

        printFooter();
    }

    // ========================================================================
    // ENGINE DETECTION & CLASSIFICATION
    // ========================================================================

    private Map<String, Double> detectEngineConfidence() {
        Map<String, Double> scores = new LinkedHashMap<>();
        for (String engine : engineSpecs.keySet()) {
            scores.put(engine, 0.0);
        }

        // Scan Symbols
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getAllSymbols(true);
        int symChecked = 0;
        
        Map<String, Integer> symHits = new HashMap<>();
        for (String engine : engineSpecs.keySet()) symHits.put(engine, 0);

        while (symbols.hasNext() && symChecked < 50000) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            symChecked++;

            for (Map.Entry<String, EngineSignatures> entry : engineSpecs.entrySet()) {
                String engine = entry.getKey();
                for (String sig : entry.getValue().symbols) {
                    if (name.contains(sig)) {
                        symHits.put(engine, symHits.get(engine) + 1);
                    }
                }
            }
        }

        // Scan Strings
        Map<String, Integer> stringHits = new HashMap<>();
        for (String engine : engineSpecs.keySet()) stringHits.put(engine, 0);
        
        DataIterator stringIt = currentProgram.getListing().getDefinedData(true);
        int stringsChecked = 0;
        while (stringIt.hasNext() && stringsChecked < 10000) {
            Data data = stringIt.next();
            if (data.getValue() instanceof String) {
                String value = (String) data.getValue();
                stringsChecked++;
                if (value == null) continue;

                for (Map.Entry<String, EngineSignatures> entry : engineSpecs.entrySet()) {
                    String engine = entry.getKey();
                    for (String sig : entry.getValue().strings) {
                        if (value.contains(sig)) {
                            stringHits.put(engine, stringHits.get(engine) + 1);
                        }
                    }
                }
            }
        }

        // Calculate scores
        for (String engine : engineSpecs.keySet()) {
            double symScore = Math.min(1.0, symHits.get(engine) / 10.0);
            double stringScore = Math.min(1.0, stringHits.get(engine) / 5.0);
            double total = (symScore * 0.6) + (stringScore * 0.4);
            scores.put(engine, total);
        }

        return scores;
    }

    private void classifyFunctions(String engineName, List<Function> engineFuncs, List<Function> gameFuncs) {
        EngineSignatures sigs = engineSpecs.get(engineName);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator iterator = funcMgr.getFunctions(true);

        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function func = iterator.next();
            String name = func.getName();
            Namespace ns = func.getParentNamespace();
            String nsName = ns != null ? ns.getName() : "";

            boolean isEngine = false;

            // 1. Classification by Name/Prefix
            for (String s : sigs.symbols) {
                if (name.contains(s) || nsName.contains(s)) {
                    isEngine = true;
                    break;
                }
            }

            // 2. Classification by Thunk or external linkage references
            if (!isEngine && func.isThunk()) {
                Function thunkTarget = func.getThunkedFunction(true);
                if (thunkTarget != null) {
                    String targetName = thunkTarget.getName();
                    for (String s : sigs.symbols) {
                        if (targetName.contains(s)) {
                            isEngine = true;
                            break;
                        }
                    }
                }
            }

            // 3. Classification by References to Engine Strings
            if (!isEngine) {
                try {
                    Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(func.getEntryPoint());
                    for (Reference ref : refs) {
                        Address toAddr = ref.getToAddress();
                        Data data = currentProgram.getListing().getDataAt(toAddr);
                        if (data != null && data.isDefined() && data.getValue() instanceof String) {
                            String strVal = (String) data.getValue();
                            for (String engineString : sigs.strings) {
                                if (strVal.contains(engineString)) {
                                    isEngine = true;
                                    break;
                                }
                            }
                        }
                        if (isEngine) break;
                    }
                } catch (Exception e) {
                    // Ignored
                }
            }

            if (isEngine) {
                engineFuncs.add(func);
            } else {
                gameFuncs.add(func);
            }
        }
    }

    // ========================================================================
    // ACTIONS
    // ========================================================================

    private int applyTagMode(List<Function> engineFuncs, List<Function> gameFuncs) throws Exception {
        int count = 0;
        
        // Tag engine functions with prefix [ENGINE]_ if not already tagged
        for (Function func : engineFuncs) {
            String name = func.getName();
            if (!name.startsWith("[ENGINE]_") && !name.startsWith("[GAME]_")) {
                func.setName("[ENGINE]_" + name, SourceType.ANALYSIS);
                count++;
            }
        }

        // Tag game functions with prefix [GAME]_ if not already tagged
        for (Function func : gameFuncs) {
            String name = func.getName();
            // Don't tag default FUN_ symbols to avoid cluttering unless already renamed
            if (!name.startsWith("FUN_") && !name.startsWith("SUB_") && 
                !name.startsWith("[ENGINE]_") && !name.startsWith("[GAME]_")) {
                func.setName("[GAME]_" + name, SourceType.ANALYSIS);
                count++;
            }
        }

        return count;
    }

    private int applyNamespaceMode(List<Function> engineFuncs) throws Exception {
        SymbolTable symTable = currentProgram.getSymbolTable();
        Namespace ns = symTable.getNamespace("EngineRuntime", currentProgram.getGlobalNamespace());
        if (ns == null) {
            ns = symTable.createNameSpace(currentProgram.getGlobalNamespace(), "EngineRuntime", SourceType.ANALYSIS);
        }

        int count = 0;
        for (Function func : engineFuncs) {
            if (func.getParentNamespace().equals(currentProgram.getGlobalNamespace())) {
                func.setParentNamespace(ns);
                count++;
            }
        }
        return count;
    }

    private int applyBookmarkMode(List<Function> engineFuncs, List<Function> gameFuncs) {
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        int count = 0;

        for (Function func : engineFuncs) {
            bmMgr.setBookmark(func.getEntryPoint(), "AIB_ENGINE", "EngineRuntime", 
                "[ENGINE] " + func.getName());
            count++;
        }

        for (Function func : gameFuncs) {
            String name = func.getName();
            if (!name.startsWith("FUN_") && !name.startsWith("SUB_")) {
                bmMgr.setBookmark(func.getEntryPoint(), "AIB_ENGINE", "GameLogic", 
                    "[GAME] " + func.getName());
                count++;
            }
        }

        return count;
    }

    // ========================================================================
    // EXPORT TO JSON
    // ========================================================================

    private void exportResults(String caseId, String engine, List<Function> engineFuncs, List<Function> gameFuncs) throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File outputDir = new File(desktop + File.separator + "AIB_Cases" + File.separator +
            caseId + File.separator + "exports");
        if (!outputDir.exists()) outputDir.mkdirs();

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "game_engine_filter_" + timestamp + ".json";

        Map<String, Object> data = new LinkedHashMap<>();
        
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("tool", "AIB Game Engine Filter");
        meta.put("version", "1.0.0");
        meta.put("organization", "Arcy Intelligence Bureau");
        meta.put("case_id", caseId);
        meta.put("binary", currentProgram.getName());
        meta.put("target_engine", engine);
        meta.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()));
        data.put("metadata", meta);

        Map<String, Object> stats = new LinkedHashMap<>();
        int total = engineFuncs.size() + gameFuncs.size();
        stats.put("total_functions", total);
        stats.put("engine_functions", engineFuncs.size());
        stats.put("game_functions", gameFuncs.size());
        stats.put("engine_ratio", total > 0 ? (double) engineFuncs.size() / total : 0.0);
        data.put("statistics", stats);

        List<Map<String, Object>> funList = new ArrayList<>();
        for (Function f : engineFuncs) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", f.getName());
            m.put("address", "0x" + f.getEntryPoint().toString());
            m.put("type", "ENGINE");
            funList.add(m);
        }
        for (Function f : gameFuncs) {
            String name = f.getName();
            if (!name.startsWith("FUN_") && !name.startsWith("SUB_")) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", name);
                m.put("address", "0x" + f.getEntryPoint().toString());
                m.put("type", "GAME_LOGIC");
                funList.add(m);
            }
        }
        data.put("classified_functions", funList);

        // Manual serialization
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

    private void printBanner() {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║         AIB GAME ENGINE FILTER — " +
            t("Runtime Isolation", "Aislamiento de Engine") + "    ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: " + currentProgram.getName());
        println("  Arch:   " + currentProgram.getLanguage());
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB Game Engine Filter — " + t("Complete", "Completado"));
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }
}
