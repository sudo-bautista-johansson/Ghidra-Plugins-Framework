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
- Purpose: combines Ghidra decompilation context with external LLM providers for explanation, renaming assistance, threat classification, and defensive vulnerability review
- Current providers in code: Gemini 2.5 Flash and Claude 3.5 Sonnet
- Note: requires user-supplied API keys

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

This repository currently uses two export layouts depending on the script:

- newer or case-driven scripts commonly write under `Desktop\AIB_Cases\<Case_ID>\...`
- some scripts and shared utilities still write under `Desktop\AIB_Exports\...`

If you want a single uniform output layout, that should be treated as a follow-up cleanup task rather than assumed behavior today.

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
