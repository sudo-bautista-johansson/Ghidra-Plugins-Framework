AIB Ghidra Plugin Suite

Arcy Intelligence Bureau (AIB) — Dirección General

A complete suite of 12 professional intelligence-grade plugins for Ghidra, designed to accelerate:

Data hunting
Malware & OSINT analysis
Ethical game analysis
Advanced reverse engineering operations
AI-powered binary analysis
Entropy & anti-analysis detection
Emulation-based decryption
Behavioral visualization
Technical reporting

These tools are implemented as GhidraScripts (.java) for maximum compatibility.
They run directly from Ghidra's Script Manager on any operating system without requiring Gradle builds or complex dependency setups.

📁 Project Structure
C:\Users\User\Desktop\Ghidra plugins\
│
├── README.md
│
├── data_hunting\
│   ├── AIB_NetworkArtifactExtractor.java
│   ├── AIB_CryptoDetector.java
│   └── AIB_FileStructureParser.java
│
├── game_analysis\
│   ├── AIB_RTTIVtableIdentifier.java
│   ├── AIB_PointerChainHelper.java
│   └── AIB_GameEngineFilter.java
│
├── report_automation\
│   ├── AIB_TechnicalReportGenerator.java
│   └── AIB_AuditTrailLogger.java
│
├── advanced_ops\
│   ├── AIBUtils.java
│   ├── AIB_SentinelAI.java
│   ├── AIB_EntropyShield.java
│   ├── AIB_GhostDecrypter.java
│   └── AIB_CyberFlow.java
│
└── lib\
    └── AIBUtils.java
🚀 Installation Guide

Installing the AIB Ghidra Plugin Suite is straightforward:

Open Ghidra and load your project.
Open the CodeBrowser tool.
In the top menu, select:
Window → Script Manager
In the Script Manager toolbar, click the Script Directories button
(the list icon with the green +).
Click the green + button to add a new folder.
Select either:
C:\Users\User\Desktop\Ghidra plugins

Or add the individual category folders separately.

Close the Script Directories window.
In the Script Manager folder tree, look for the category:
AIB

All 12 scripts should now appear and be ready to execute.

🛠 Plugin Documentation & Usage

Tip:
All plugins support bilingual interaction (English / Español).
You will be prompted to select your preferred language when executing a script.

Category 1 — Data Hunting & OSINT
🌐 AIB Network Artifact Extractor

Path

data_hunting/AIB_NetworkArtifactExtractor.java
Purpose

Performs advanced regex scans to isolate network indicators of compromise (IoCs).

Extraction Targets
IPv4
IPv6
URLs
Domains (with TLD validation)
User-Agents
Email addresses
Windows & Unix file paths
Registry keys
Output

Exports deduplicated:

JSON
CSV

files to the desktop workspace.

🔑 AIB Crypto Detector

Path

data_hunting/AIB_CryptoDetector.java
Purpose

Detects cryptographic algorithms by locating:

Known constants
S-Boxes
Hashing magic numbers
Supported Algorithms
AES
DES
MD5
SHA-1
SHA-256
Blowfish
RC4
CRC32
Base64
Actions
Automatically renames suspicious functions
Adds bookmarks in Ghidra
Uses naming format:
crypto_function_potential_<algo>
📄 AIB File Structure Parser

Path

data_hunting/AIB_FileStructureParser.java
Purpose

Visual parser for identifying embedded file formats inside binaries.

Supported Signatures
PE
ELF
Mach-O
ZIP
RAR
7z
GZIP
PNG
JPEG
BMP
PDF
SQLite
UnityFS / AssetBundles
Unreal .pak
Certificates
Actions
Creates Ghidra structure definitions
Applies overlays at detected offsets
Displays Hex/ASCII tables for unknown files
Category 2 — Reverse Engineering & Game Analysis
🧬 AIB RTTI & Vtable Identifier

Path

game_analysis/AIB_RTTIVtableIdentifier.java
Purpose

Parses:

MSVC RTTI (.?AV)
GCC/Clang RTTI (_ZTV, _ZTI)

to reconstruct C++ class structures.

Actions
Enumerates virtual functions
Renames vfuncs using:
ClassName::vfunc_N
Builds inheritance trees
Organizes namespaces automatically
🔗 AIB Pointer Chain Helper

Path

game_analysis/AIB_PointerChainHelper.java
Purpose

Maps recursive pointer chains and code/data XREFs.

Features
Finds static base addresses
Generates Cheat Engine–style formulas
Example
[[base + 0x10] + 0x20]
Output
ASCII tree visualization
Pointer chain mapping
⚙️ AIB Game Engine Filter

Path

game_analysis/AIB_GameEngineFilter.java
Purpose

Identifies runtime code belonging to:

Unity / IL2CPP
Unreal Engine
Godot

Helps isolate actual game logic from engine internals.

Modes
Tag Mode

Prefixes functions:

[ENGINE]_
[GAME]_
Namespace Mode

Moves engine code into:

EngineRuntime
Bookmark Mode

Adds bookmarks to runtime functions.

Category 3 — Report Automation
📝 AIB Technical Report Generator

Path

report_automation/AIB_TechnicalReportGenerator.java
Purpose

Automatically generates a complete Markdown analysis report.

Includes
Target metadata
Renamed symbols
All comment types
Bookmarks
Custom structures
Output
.md
.json
⏱️ AIB Audit Trail Logger

Path

report_automation/AIB_AuditTrailLogger.java
Purpose

Tracks analysis progress across sessions.

Features
Snapshot system
Change detection
Structured diffs
Output
audit_diff_*.md
Category 4 — Advanced Operations ("Mega OP")
🧠 AIB SentinelAI — LLM-Powered Binary Analysis

Path

advanced_ops/AIB_SentinelAI.java
Purpose

Interfaces with:

Gemini 2.5 Pro
Claude 3.5 Sonnet
Features
Function explanation
Variable auto-renaming
Threat classification
Vulnerability scanning
Defensive research planning
Configuration

Stores API keys locally in:

Desktop/AIB_Exports/.aib_config.json
🛡️ AIB Entropy Shield

Path

advanced_ops/AIB_EntropyShield.java
Purpose

Performs entropy and anti-analysis detection.

Features
Shannon entropy heatmaps
Sliding window analysis
Detects ~65 anti-debug / anti-VM techniques
👻 AIB Ghost Decrypter

Path

advanced_ops/AIB_GhostDecrypter.java
Purpose

Static + emulation-based string decryption.

Features
XOR loop detection
Stack string recovery
API hash resolution
Supported Hashes
ROR13
CRC32
DJB2
FNV-1a
⚡ AIB CyberFlow

Path

advanced_ops/AIB_CyberFlow.java
Purpose

Builds interactive behavioral graphs and ATT&CK mappings.

Export Formats
Interactive HTML (vis.js)
Graphviz DOT
Features
Function behavior graphs
MITRE ATT&CK chain mapping
Threat visualization
⚙️ Configuration & Output Paths

By default, all scripts export results under:

C:\Users\<User>\Desktop\AIB_Cases\<Case_ID>\exports\
Runtime Prompts

Each script will prompt for:

Language
English / Español
Case ID

Examples:

CASE_001
OPERATION_NEPTUNE
⚠️ Warning

Ensure Ghidra has write permissions to the Desktop folder to avoid export errors.

🛡️ License & Attribution

Developed by:
Arcy Intelligence Bureau (AIB) — Dirección General

Version:

2.0.0

Status:

Release-Ready — Phase 2 Complete
