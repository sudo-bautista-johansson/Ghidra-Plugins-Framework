# AIB Ghidra Plugin Suite
### Arcy Intelligence Bureau (AIB) â€” DirecciÃ³n General

A complete suite of 12 professional intelligence-grade plugins for Ghidra, designed to accelerate data hunting, malware/OSINT analysis, ethical game analysis, advanced operations (including AI-powered binary analysis, entropy shielding, emulation-based decryption, and behavioral visualization), and technical reporting.

These tools are implemented as **GhidraScripts** (`.java` files) for maximum compatibility. They run directly from Ghidra's Script Manager on any operating system without requiring complex Gradle build environments or external dependency setups.

---

## ðŸ“‚ Project Structure

```
c:\Users\User\Desktop\Ghidra plugins\
â”œâ”€â”€ README.md                          â€” This installation & user guide
â”‚
â”œâ”€â”€ data_hunting\                      â€” Category 1: OSINT & Data Hunting (Phase 1)
â”‚   â”œâ”€â”€ AIB_NetworkArtifactExtractor.java â€” Advanced IoC regex scanner
â”‚   â”œâ”€â”€ AIB_CryptoDetector.java        â€” Math constants & S-box scanner
â”‚   â””â”€â”€ AIB_FileStructureParser.java   â€” Embedded file headers parser & struct applier
â”‚
â”œâ”€â”€ game_analysis\                     â€” Category 2: Reverse Engineering & Game Analysis (Phase 1)
â”‚   â”œâ”€â”€ AIB_RTTIVtableIdentifier.java  â€” C++ RTTI parser & class tree builder
â”‚   â”œâ”€â”€ AIB_PointerChainHelper.java    â€” Recursive data/code XREF pointer chain mapper
â”‚   â””â”€â”€ AIB_GameEngineFilter.java      â€” Unity/Unreal/Godot runtime noise classifier
â”‚
â”œâ”€â”€ report_automation\                 â€” Category 3: Documentation & Audit Logging (Phase 1)
â”‚   â”œâ”€â”€ AIB_TechnicalReportGenerator.java â€” Complete Markdown & JSON analysis reporter
â”‚   â””â”€â”€ AIB_AuditTrailLogger.java      â€” Snapshot-based session changes logger (diffs)
â”‚
â”œâ”€â”€ advanced_ops\                      â€” Category 4: Advanced Operations & "Mega OP" (Phase 2)
â”‚   â”œâ”€â”€ AIBUtils.java                  â€” Shared helper library (local copy)
â”‚   â”œâ”€â”€ AIB_SentinelAI.java            â€” LLM-powered code explanation, renaming & vulnerability scan
â”‚   â”œâ”€â”€ AIB_EntropyShield.java         â€” Shannon entropy heatmap & packer/anti-analysis detector
â”‚   â”œâ”€â”€ AIB_GhostDecrypter.java        â€” Pcode emulation-based/static string & API hash decrypter
â”‚   â””â”€â”€ AIB_CyberFlow.java             â€” Function behavior graph and MITRE ATT&CK chain mapper
â”‚
â””â”€â”€ lib\                               â€” Shared Utilities (Phase 1)
    â””â”€â”€ AIBUtils.java                  â€” Core shared helper class
```

---

## ðŸš€ Installation Guide

Installing the AIB Ghidra Plugin Suite is extremely straightforward:

1. **Open Ghidra** and load your project.
2. Open the **CodeBrowser** tool.
3. In the top menu, select **Window** âž” **Script Manager**.
4. In the Script Manager toolbar, click the **Script Directories** button (the list icon with green plus `+`).
5. Click the green plus sign `+` to add a new folder to the search path.
6. Select either the main folder where you cloned these plugins:  
   `c:\Users\User\Desktop\Ghidra plugins`  
   *(or add the individual subfolders if you prefer. Each category folder is now completely self-contained and compiles package-free!)*
7. Close the Script Directories window.
8. Look for the category **AIB** in the left-hand folder tree of the Script Manager. All 12 scripts will be visible and ready to execute.

---

## ðŸ› ï¸ Plugin Documentation & Usage

> [!TIP]
> All plugins support **bilingual interaction (English / EspaÃ±ol)**. You will be prompted to select your preferred language upon execution.

### Category 1: Data Hunting & OSINT

#### ðŸŒ AIB Network Artifact Extractor
* **Path:** `data_hunting/AIB_NetworkArtifactExtractor.java`
* **Purpose:** Performs advanced regex scans to isolate network indicators of compromise (IoCs) and exports them for OSINT processing.
* **Extraction Targets:** IPv4, IPv6, URLs, Domains (with TLD checks), User-Agents, Email Addresses, Windows/Unix file paths, and Registry keys.
* **Output:** Saves results as deduplicated JSON and CSV tables to your desktop directory.

#### ðŸ”‘ AIB Crypto Detector
* **Path:** `data_hunting/AIB_CryptoDetector.java`
* **Purpose:** Identifies cryptographic algorithms by locating known constants, search tables (S-Boxes), and hashing magic numbers.
* **Identified Algos:** AES (S-Boxes & Rcon), DES (S1-S8), MD5, SHA-1, SHA-256, Blowfish, RC4 instruction patterns, CRC32, and Base64.
* **Actions:** Automatically renames functions containing crypto constants with a `crypto_function_potential_<algo>` prefix and sets Ghidra bookmarks.

#### ðŸ“„ AIB File Structure Parser
* **Path:** `data_hunting/AIB_FileStructureParser.java`
* **Purpose:** Visual parser for identifying and mapping embedded file formats in the binary.
* **Supported Magic Signatures:** PE, ELF, Mach-O, ZIP, RAR, 7z, GZIP, PNG, JPEG, BMP, PDF, SQLite, UnityFS/AssetBundles, Unreal .pak, and certificates.
* **Actions:** Creates Ghidra structure definitions and overlays them at detected offsets. Displays a Hex/ASCII table for unrecognized files.

---

### Category 2: Game Analysis

#### ðŸ§¬ AIB RTTI & Vtable Identifier
* **Path:** `game_analysis/AIB_RTTIVtableIdentifier.java`
* **Purpose:** Scans and parses MSVC (`.?AV`) and GCC/Clang (`_ZTV`/`_ZTI`) RTTI metadata to reconstruct class structures.
* **Actions:** Enumerates virtual functions, renames them using the `ClassName::vfunc_N` standard, moves classes into nested namespaces, and prints a hierarchical inheritance tree in the Ghidra console.

#### ðŸ”— AIB Pointer Chain Helper
* **Path:** `game_analysis/AIB_PointerChainHelper.java`
* **Purpose:** Traces recursive data pointer chains and code cross-references (XREFs) to find static base addresses.
* **Cheat Engine Compatibility:** Computes and prints copy-pasteable pointer formulas (e.g. `[[base + 0x10] + 0x20]`) and outlines them as an ASCII tree.

#### âš™ï¸ AIB Game Engine Filter
* **Path:** `game_analysis/AIB_GameEngineFilter.java`
* **Purpose:** Identifies engine runtime code (Unity/IL2CPP, Unreal Engine, or Godot) to help you isolate developer-written game logic.
* **Actions:**
  - **Tag Mode:** Prefixes functions with `[ENGINE]_` or `[GAME]_`.
  - **Namespace Mode:** Organizes engine functions under an `EngineRuntime` namespace.
  - **Bookmark Mode:** Adds bookmarks at function entries.

---

### Category 3: Report Automation

#### ðŸ“ AIB Technical Report Generator
* **Path:** `report_automation/AIB_TechnicalReportGenerator.java`
* **Purpose:** Instantly creates a complete markdown report of your analysis state.
* **Content:** Gathers target metadata, renamed symbols of interest, all types of comments (Plate, Pre, Post, EOL, Repeatable), analysis bookmarks, and custom data structures.
* **Output:** Saves a `.md` report and a companion `.json` database file.

#### â±ï¸ AIB Audit Trail Logger
* **Path:** `report_automation/AIB_AuditTrailLogger.java`
* **Purpose:** Log and compare session progress in multi-analyst projects or long-term assessments.
* **Actions:** Captures a snapshot of comments, bookmarks, and symbols, automatically detects previous snapshots, and generates a structured Markdown diff (`audit_diff_*.md`) of added, modified, or deleted elements.

---

### Category 4: Advanced Operations & "Mega OP" (Phase 2)

#### ðŸ§  AIB SentinelAI â€” LLM-Powered Binary Analysis
* **Path:** `advanced_ops/AIB_SentinelAI.java`
* **Purpose:** Interfaces with Gemini 2.5 Pro or Claude 3.5 Sonnet to explain function logic, auto-rename variable names, run threat/malware classification, scan for software vulnerabilities, and turn disclosed advisories into safe defensive research plans.
* **Configuration:** Stores API keys locally and securely under `Desktop/AIB_Exports/.aib_config.json`.

#### ðŸ›¡ï¸ AIB Entropy Shield â€” Entropy & Anti-Analysis Detection
* **Path:** `advanced_ops/AIB_EntropyShield.java`
* **Purpose:** Computes section-level Shannon entropy and generates a sliding window heatmap. Identifies ~65 signatures of anti-debug, anti-VM, and anti-sandbox techniques.

#### ðŸ‘» AIB Ghost Decrypter â€” Emulation-Based String Decryption
* **Path:** `advanced_ops/AIB_GhostDecrypter.java`
* **Purpose:** Employs XOR loop detection, stack string recovery, and instant API hash resolution (supporting ROR13, CRC32, DJB2, FNV-1a) to extract decrypted strings statically and dynamically.

#### âš¡ AIB CyberFlow â€” Behavior Graph Visualization
* **Path:** `advanced_ops/AIB_CyberFlow.java`
* **Purpose:** Constructs an interactive behavioral flow call graph (exported as interactive HTML with vis.js or Graphviz DOT). Combines bookmarks from other AIB plugins to build a holistic threat map and MITRE ATT&CK chain mappings.

---

## âš™ï¸ Configuration & Output Paths

By default, all scripts export their results (JSON, CSV, MD) under a workspace-friendly structure on the current user's Desktop:

`C:\Users\<User>\Desktop\AIB_Cases\<Case_ID>\exports\`

Upon execution, the scripts will prompt for:
1. **Language:** English or EspaÃ±ol.
2. **Case ID:** Used as the subfolder name under `AIB_Cases` (e.g., `CASE_001`, `OPERATION_NEPTUNE`).

> [!WARNING]
> Ensure that Ghidra has write permissions to the user's Desktop folder to prevent file export errors during run.

---

## ðŸ›¡ï¸ License & Attributions
* **Developed by:** Arcy Intelligence Bureau (AIB) â€” DirecciÃ³n General.
* **Version:** 2.0.0 (Release-Ready, Phase 2 Complete)

