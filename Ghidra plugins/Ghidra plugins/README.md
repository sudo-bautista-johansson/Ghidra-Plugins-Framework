# AIB Ghidra Plugin Suite

Arcy Intelligence Bureau (AIB) maintains this repository as a collection of Ghidra automation scripts for reverse engineering, malware triage, game analysis, and technical reporting.

The main deliverable in this repo is a set of 12 Java-based `GhidraScript` tools that can be run directly from Ghidra's Script Manager without setting up a Gradle build. The repository also includes a separate `framework/` source scaffold for a future compiled Ghidra extension.

## What Is In This Repository

- `data_hunting/`: artifact extraction and binary content parsing
- `game_analysis/`: RTTI, pointer-chain, and engine-noise triage helpers
- `report_automation/`: reporting and audit logging scripts
- `advanced_ops/`: higher-level analysis, entropy heuristics, decryption, and graphing
- `lib/`: shared utility source used by the script suite
- `framework/`: source scaffold for a future plugin-style extension, not a drop-in Script Manager folder yet

## Project Structure

```text
c:\Users\User\Desktop\Ghidra plugins\
|-- README.md
|-- data_hunting\
|   |-- AIB_NetworkArtifactExtractor.java
|   |-- AIB_CryptoDetector.java
|   `-- AIB_FileStructureParser.java
|-- game_analysis\
|   |-- AIB_RTTIVtableIdentifier.java
|   |-- AIB_PointerChainHelper.java
|   `-- AIB_GameEngineFilter.java
|-- report_automation\
|   |-- AIB_TechnicalReportGenerator.java
|   `-- AIB_AuditTrailLogger.java
|-- advanced_ops\
|   |-- AIBUtils.java
|   |-- AIB_SentinelAI.java
|   |-- AIB_EntropyShield.java
|   |-- AIB_GhostDecrypter.java
|   `-- AIB_CyberFlow.java
|-- lib\
|   `-- AIBUtils.java
`-- framework\
    `-- src\main\java\...
```

## Script Suite Overview

### Data Hunting

#### AIB Network Artifact Extractor
- Path: `data_hunting/AIB_NetworkArtifactExtractor.java`
- Purpose: scans memory and listing content for network-related indicators such as IPv4, IPv6, URLs, domains, email addresses, user agents, file paths, and registry keys
- Output: bookmarks plus JSON and CSV exports

#### AIB Crypto Detector
- Path: `data_hunting/AIB_CryptoDetector.java`
- Purpose: looks for known constants, S-boxes, and hash-related patterns associated with common cryptographic or encoding routines
- Coverage: AES, DES, MD5, SHA-1, SHA-256, Blowfish, RC4, CRC32, Base64 heuristics
- Actions: bookmarks hits and can rename suspicious functions with a crypto-focused prefix

#### AIB File Structure Parser
- Path: `data_hunting/AIB_FileStructureParser.java`
- Purpose: identifies embedded file signatures and helps map file-like regions inside binaries
- Coverage: PE, ELF, Mach-O, ZIP, RAR, 7z, GZIP, PNG, JPEG, BMP, PDF, SQLite, UnityFS, Unreal `.pak`, and related formats
- Actions: applies structures or overlays where supported and prints parsing context for unknown regions

### Game Analysis

#### AIB RTTI & Vtable Identifier
- Path: `game_analysis/AIB_RTTIVtableIdentifier.java`
- Purpose: parses MSVC and GCC/Clang RTTI metadata to help reconstruct C++ class and vtable relationships
- Actions: enumerates virtual functions, renames vfuncs, builds inheritance context, and organizes namespaces

#### AIB Pointer Chain Helper
- Path: `game_analysis/AIB_PointerChainHelper.java`
- Purpose: traces recursive pointer chains and cross-references to help locate static bases and reusable offset paths
- Output: pointer formulas and ASCII-tree style path summaries

#### AIB Game Engine Filter
- Path: `game_analysis/AIB_GameEngineFilter.java`
- Purpose: separates likely engine runtime code from likely game-specific code in Unity, IL2CPP, Unreal, or Godot targets
- Modes: tag-based renaming, namespace organization, and bookmarking

### Report Automation

#### AIB Technical Report Generator
- Path: `report_automation/AIB_TechnicalReportGenerator.java`
- Purpose: compiles analysis metadata into a Markdown report plus companion JSON
- Includes: target metadata, renamed functions, comments, bookmarks, and custom structures

#### AIB Audit Trail Logger
- Path: `report_automation/AIB_AuditTrailLogger.java`
- Purpose: snapshots analysis state and generates structured diffs across sessions
- Output: `audit_diff_*.md` style change reports

### Advanced Operations

#### AIB SentinelAI
- Path: `advanced_ops/AIB_SentinelAI.java`
- Purpose: Combines Ghidra decompilation context with external LLM providers (Gemini 2.5 Flash & Claude 3.5 Sonnet) for explanation, renaming assistance, malware classification, and advanced zero-day static audits.
- Local Analysis Layer: Synthesizes a premium static analysis dossier covering variant analysis, invariant validation, source-to-sink data flow, state-machine reviews, safe-pattern diffs, and cross-plugin bookmark correlations.
- Dossier Enhancements: Features integrated sections for **Temporal Safety**, **Anticheat Surface**, and **Cross-Function Taint Analysis**.
- Advanced Heuristic Engine (12 Categories): Locally scans decompiled pseudocode to identify critical vulnerability surfaces including:
  * Memory Safety: *Use After Free (UAF)*, *Double Free*, *Pool Corruption*
  * Type & Race States: *Type Confusion*, *TOCTOU Race Condition*, *Kernel Race Condition*
  * Sizing & Stack: *Integer Overflow Chain*, *Uninitialized Stack Memory Use*
  * Privilege & Kernel: *Kernel Object/Token Abuse*, *IOCTL Dispatch Attack Surface*, *Hypervisor Escape*, *Privilege Escalation*
- CoT-Enhanced Vulnerability Scanner: Employs a multi-step Chain-of-Thought (CoT) reasoning model that outputs structured analysis JSONs complete with a `reasoning_steps` trail for analysts.
- Executive Deep Zero-Day Sweep: Iterates through up to 120 binary functions, scoring candidates heuristically (including bonuses for kernel/anticheat patterns and `CRITICAL_IMMEDIATE` prioritization), and dispatches the top candidates for a comprehensive, LLM-generated Zero-Day Triage & Mitigation Report.
- Safe Defensive PoC Generator: Produces safe, non-weaponized Markdown validation checklists and isolated telemetry harnesses for laboratory verification.
- Mappings: Enrichments mapped dynamically to CWE, CAPEC, and MITRE ATT&CK taxonomies.
- Note: Requires user-supplied API credentials.

#### AIB Entropy Shield
- Path: `advanced_ops/AIB_EntropyShield.java`
- Purpose: computes entropy and flags anti-analysis behavior
- Includes: section-level entropy, sliding-window analysis, packer signatures, anti-debug, anti-VM, and anti-sandbox heuristics

#### AIB Ghost Decrypter
- Path: `advanced_ops/AIB_GhostDecrypter.java`
- Purpose: assists with static and emulation-guided string decryption workflows
- Includes: XOR-loop detection, stack-string recovery, and API hash resolution
- Supported hash families in code: ROR13, CRC32, DJB2, FNV-1a

#### AIB CyberFlow
- Path: `advanced_ops/AIB_CyberFlow.java`
- Purpose: builds behavior-oriented call graphs and ATT&CK-style mappings from functions, APIs, and bookmarks
- Export formats: interactive HTML and Graphviz DOT

## Installation

### Load The Script Suite In Ghidra

1. Open Ghidra and load a project.
2. Open the CodeBrowser tool.
3. Go to `Window -> Script Manager`.
4. Click the Script Directories button.
5. Add this repository root as a script directory:

```text
c:\Users\User\Desktop\Ghidra plugins
```

6. Refresh the Script Manager if needed.
7. Run the scripts from the `AIB`, `AIB.DataHunting`, or related script categories shown by Ghidra.

### Important Note About `framework/`

The `framework/` directory is not part of the 12 drop-in scripts. It is source code for a future compiled extension or plugin panel. You do not need it to use the script suite from Script Manager.

## Runtime Behavior

Most scripts are interactive and prompt for:

- language selection: English or Espanol
- a case identifier such as `CASE_001` or `OPERATION_NEPTUNE`

Several scripts also create bookmarks, rename symbols, or generate files on the current user's Desktop.

## Output Paths

This repository now centers exports under `Desktop\AIB_Cases\<Case_ID>\...`.

- script and advanced-analysis results are organized under case-specific `exports` directories
- shared global configuration for AI-assisted workflows is stored under `Desktop\AIB_Cases\_global\config\`

Some comments and legacy helper names may still mention older layouts, but the active pathing has been moved toward the case-based structure.

## Dependencies And Compatibility

- Core script suite: plain Java `GhidraScript` files intended to run from Script Manager
- No Gradle build is required for the 12 scripts
- `AIB_SentinelAI` depends on external API access and user-provided credentials
- `AIB_CyberFlow` HTML export uses `vis.js`
- Desktop write permissions are required for export-heavy workflows

## Scope And Intended Use

This repository is geared toward defensive reverse engineering, malware triage, binary inspection, and workflow automation inside Ghidra. It can also support ethical game analysis tasks such as RTTI recovery, pointer path mapping, and engine/runtime separation.

The scripts are best understood as analyst accelerators: they surface likely signals, automate repetitive steps, and structure output, but they do not replace manual validation during reverse engineering.

## Version

- Maintainer: Arcy Intelligence Bureau (AIB)
- Repository status: script suite available, framework scaffold in progress
- README revision: aligned to current repository contents
