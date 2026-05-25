# AIB Vulnerability Research Framework

This folder contains a plugin-oriented Java scaffold for Ghidra focused on defensive binary analysis.

Goals:
- Extract function, block, call, string, and decompiler context from a loaded program.
- Run local heuristic rules before sending context to an AI analyzer.
- Receive structured analysis containing findings, risk, technical explanation, safe theoretical hypotheses, fuzzing ideas, and mitigations.
- Render results inside a dedicated Ghidra provider panel.

Safety boundary:
- No exploit generation.
- No payload construction.
- No operational compromise instructions.
- The AI contract is limited to defensive analysis artifacts.

Suggested flow:
1. `BinaryContextExtractor` builds a normalized `AnalysisContext`.
2. `HeuristicEngine` produces local findings with reproducible rules.
3. `AiAnalyzer` consumes a reduced safe prompt built from the context.
4. `AnalysisOrchestrator` merges local and AI results.
5. `VulnerabilityWorkbenchProvider` displays the results in Ghidra.

Notes:
- This is a source scaffold for a real Ghidra extension project.
- It is intentionally modular so you can swap the AI transport or add rules without touching the UI.

How to load it in Ghidra:
- Today, the folders `advanced_ops`, `data_hunting`, `game_analysis`, and `report_automation` can be added to Ghidra Script Manager because they contain `GhidraScript` Java files.
- The `framework/` folder is not a drop-in script folder yet. It is source code for a future compiled Ghidra extension/plugin.
- If you want something you can "upload" right now, add the project root `c:\Users\User\Desktop\Ghidra plugins` as a Script Directory and run the existing scripts.
- If you want the new `framework/` panel inside Ghidra, the next step is to package it as a real extension with the standard Ghidra extension layout and build files.
