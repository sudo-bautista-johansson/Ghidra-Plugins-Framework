//AIB Entropy Shield — Entropy Analysis & Anti-Analysis Detection
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
import ghidra.program.model.lang.Register;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * AIB_EntropyShield — Phase 2 Mega OP Plugin #2
 *
 * Computes Shannon entropy at multiple granularities to detect packed/encrypted
 * sections, then identifies anti-analysis techniques (anti-debug, anti-VM,
 * anti-sandbox) by signature and heuristic.
 *
 * Features:
 * - Section-level Shannon entropy with classification
 * - Sliding window entropy for precise boundary detection
 * - Byte frequency distribution analysis
 * - Packer/protector signature detection (UPX, Themida, VMProtect, etc.)
 * - Anti-debug technique identification (~30 techniques)
 * - Anti-VM technique identification (~20 techniques)
 * - Anti-sandbox technique identification (~15 techniques)
 * - ASCII art entropy heatmap in console
 * - Full JSON export with confidence scores
 */
public class AIB_EntropyShield extends GhidraScript {

    // ========================================================================
    // DATA STRUCTURES
    // ========================================================================

    private static class EntropyResult {
        String sectionName;
        long startAddr;
        long endAddr;
        long size;
        double entropy;
        double asciiRatio;
        String classification;
    }

    private static class AntiAnalysisHit {
        String category;     // ANTI_DEBUG, ANTI_VM, ANTI_SANDBOX
        String technique;    // Technique name
        String description;  // Human-readable description
        String address;      // Address where detected
        String functionName; // Containing function
        double confidence;   // 0.0 - 1.0
        String mitreTactic;  // MITRE ATT&CK ID
    }

    private static class PackerSignature {
        String name;
        String[] sectionPatterns;    // Section name patterns
        String[] byteSignatures;     // Hex byte patterns to search
        String description;
    }

    // ========================================================================
    // CONSTANTS — Packer Signatures
    // ========================================================================

    private static final String[][] PACKER_SECTIONS = {
        {"UPX", "UPX0", "UPX1", "UPX2", "UPX!"},
        {"Themida", ".winlice", ".themida"},
        {"VMProtect", ".vmp0", ".vmp1", ".vmp2"},
        {"ASPack", ".aspack", ".adata"},
        {"PECompact", ".pec1", ".pec2", "PEC2"},
        {"MPRESS", ".MPRESS1", ".MPRESS2"},
        {"Enigma", ".enigma1", ".enigma2"},
        {"Armadillo", ".text1", ".adata", ".data1"},
        {"NSPack", ".nsp0", ".nsp1", ".nsp2"},
        {"PEtite", ".petite"},
        {"MEW", "MEW"},
        {"FSG", ".FSG"},
    };

    private static final String[][] PACKER_STRINGS = {
        {"UPX", "UPX!", "This file is packed with the UPX"},
        {"Themida", "THEMIDA", "WinLicense"},
        {"VMProtect", "VMProtect begin", "VMProtect end", ".vmp"},
        {"ASPack", "ASPack"},
        {"ConfuserEx", "ConfuserEx", "Confuser.Core"},
        {"Dotfuscator", "Dotfuscator", "DotfuscatorAttribute"},
        {"PyInstaller", "pyi-runtime", "MEIPASS", "pyiboot"},
        {"Py2Exe", "PYTHONSCRIPT", "py2exe"},
        {"Nuitka", "Nuitka", "nuitka"},
    };

    // ========================================================================
    // CONSTANTS — Anti-Debug API signatures
    // ========================================================================

    private static final String[][] ANTI_DEBUG_APIS = {
        {"IsDebuggerPresent", "Direct debugger presence check via PEB.BeingDebugged", "T1622"},
        {"CheckRemoteDebuggerPresent", "Remote debugger check via NtQueryInformationProcess", "T1622"},
        {"NtQueryInformationProcess", "Low-level process query — may check ProcessDebugPort (0x7)", "T1622"},
        {"NtQuerySystemInformation", "System-level query — can detect debug objects", "T1622"},
        {"OutputDebugStringA", "Anti-debug: checks if debugger consumes the string", "T1622"},
        {"OutputDebugStringW", "Anti-debug: checks if debugger consumes the string (wide)", "T1622"},
        {"DebugActiveProcess", "Self-debugging technique to prevent external attach", "T1622"},
        {"GetThreadContext", "Hardware breakpoint detection via DR0-DR7 registers", "T1622"},
        {"SetThreadContext", "Hardware breakpoint clearing / anti-debug evasion", "T1622"},
        {"NtSetInformationThread", "ThreadHideFromDebugger — hides thread from debugger", "T1622"},
        {"NtClose", "Anti-debug: invalid handle trick with debug exception", "T1622"},
        {"CloseHandle", "Anti-debug: invalid handle causes exception under debugger", "T1622"},
        {"UnhandledExceptionFilter", "SEH-based anti-debug: different behavior under debugger", "T1622"},
        {"SetUnhandledExceptionFilter", "SEH-based anti-debug setup", "T1622"},
        {"RaiseException", "Deliberate exception for anti-debug flow control", "T1622"},
        {"NtQueryObject", "Detect debug objects via ObjectAllTypesInformation", "T1622"},
        {"FindWindowA", "Detect debugger windows (OllyDbg, x64dbg, etc.)", "T1622"},
        {"FindWindowW", "Detect debugger windows (wide string variant)", "T1622"},
        {"GetForegroundWindow", "Check if debugger window is focused", "T1622"},
        {"EnumWindows", "Enumerate windows to find debugger UIs", "T1622"},
    };

    private static final String[][] ANTI_DEBUG_TIMING = {
        {"QueryPerformanceCounter", "Timing-based anti-debug: measures execution duration", "T1622"},
        {"QueryPerformanceFrequency", "Used with QPC for timing checks", "T1622"},
        {"GetTickCount", "Coarse timing check — detect single-stepping", "T1622"},
        {"GetTickCount64", "64-bit timing check", "T1622"},
        {"timeGetTime", "Multimedia timer — timing-based anti-debug", "T1622"},
        {"GetSystemTimeAsFileTime", "High-precision timing check", "T1622"},
    };

    // ========================================================================
    // CONSTANTS — Anti-VM signatures
    // ========================================================================

    private static final String[][] ANTI_VM_STRINGS = {
        {"VMware", "vmware", "VMwareVMware", "vmtoolsd", "vmwaretray", "vmhgfs.sys", "vmmouse.sys", "vmci.sys"},
        {"VirtualBox", "vbox", "VBoxGuest", "VBoxService", "VBoxMiniRdr", "VBoxSF.sys", "VirtualBox"},
        {"Hyper-V", "vmbus", "Hyper-V", "hvax64", "VMBusHID"},
        {"QEMU", "QEMU", "qemu-ga", "bochs", "BOCHS"},
        {"Xen", "XenProject", "xen", "xennet", "xenvbd"},
        {"Parallels", "prl_", "parallels", "prltoolsd"},
        {"KVM", "KVMKVMKVM", "virtio"},
    };

    private static final String[][] ANTI_VM_REGISTRY = {
        {"VMware", "SOFTWARE\\VMware, Inc.\\VMware Tools"},
        {"VirtualBox", "SOFTWARE\\Oracle\\VirtualBox Guest Additions"},
        {"Hyper-V", "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"},
        {"QEMU", "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"},
    };

    private static final String[][] ANTI_VM_MAC_PREFIXES = {
        {"VMware", "00:0C:29", "00:50:56", "00:05:69"},
        {"VirtualBox", "08:00:27"},
        {"Hyper-V", "00:15:5D"},
        {"Parallels", "00:1C:42"},
        {"Xen", "00:16:3E"},
    };

    // ========================================================================
    // CONSTANTS — Anti-Sandbox signatures
    // ========================================================================

    private static final String[][] ANTI_SANDBOX_STRINGS = {
        {"sandbox", "malware", "virus", "sample", "test", "cuckoo", "anubis", "joe sandbox",
         "hybrid-analysis", "any.run", "triage", "cape", "threatgrid"},
    };

    private static final String[][] ANTI_SANDBOX_APIS = {
        {"GetCursorPos", "Mouse movement detection — sandboxes often have static cursor", "T1497.001"},
        {"GetAsyncKeyState", "Keyboard activity check — sandboxes may have no input", "T1497.001"},
        {"GetSystemMetrics", "Screen resolution check — sandboxes use small screens", "T1497.001"},
        {"GlobalMemoryStatusEx", "RAM size check — sandboxes often have < 2GB", "T1497.001"},
        {"GetDiskFreeSpaceExA", "Disk size check — sandboxes often have < 60GB", "T1497.001"},
        {"GetDiskFreeSpaceExW", "Disk size check (wide variant)", "T1497.001"},
        {"GetSystemInfo", "CPU count check — sandboxes may have 1 CPU", "T1497.001"},
        {"GetModuleFileNameA", "Checks own filename for sandbox naming patterns", "T1497.001"},
        {"GetModuleFileNameW", "Checks own filename (wide variant)", "T1497.001"},
        {"GetComputerNameA", "Computer name check for known sandbox names", "T1497.001"},
        {"GetUserNameA", "Username check for sandbox-typical names", "T1497.001"},
        {"GetAdaptersInfo", "Network adapter enumeration — sandbox detection", "T1497.001"},
        {"GetTempPathA", "Temp path check for sandbox indicators", "T1497.001"},
        {"Sleep", "Sleep acceleration detection — sandboxes may fast-forward", "T1497.003"},
        {"SleepEx", "Extended sleep — same concept", "T1497.003"},
        {"WaitForSingleObject", "Timing-based sandbox detection via wait objects", "T1497.003"},
    };


    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        AIBUtils.printPluginHeader(this, "AIB EntropyShield — Entropy & Anti-Analysis Detection");

        // Choose analysis mode
        String[] modes = {
            "Full Analysis (Entropy + Anti-Debug + Anti-VM + Anti-Sandbox + Packers)",
            "Entropy Analysis Only",
            "Anti-Analysis Detection Only",
            "Packer Detection Only"
        };
        int mode = askChoice("AIB EntropyShield — Analysis Mode",
            "Select analysis scope:", Arrays.asList(modes), modes[0]).equals(modes[0]) ? 0 :
            askChoice("AIB EntropyShield — Analysis Mode",
                "Select analysis scope:", Arrays.asList(modes), modes[0]).equals(modes[1]) ? 1 :
            askChoice("AIB EntropyShield — Analysis Mode",
                "Select analysis scope:", Arrays.asList(modes), modes[0]).equals(modes[2]) ? 2 : 3;

        // Actually let the user pick properly
        String choice = askChoice("AIB EntropyShield — Analysis Mode",
            "Select analysis scope:", Arrays.asList(modes), modes[0]);
        if (choice.equals(modes[0])) mode = 0;
        else if (choice.equals(modes[1])) mode = 1;
        else if (choice.equals(modes[2])) mode = 2;
        else mode = 3;

        List<EntropyResult> entropyResults = new ArrayList<>();
        List<AntiAnalysisHit> antiHits = new ArrayList<>();
        List<String> packersFound = new ArrayList<>();

        // --- ENTROPY ANALYSIS ---
        if (mode == 0 || mode == 1) {
            AIBUtils.printSection(this, "ENTROPY ANALYSIS");
            entropyResults = analyzeEntropy();
            printEntropyHeatmap(entropyResults);
        }

        // --- PACKER DETECTION ---
        if (mode == 0 || mode == 3) {
            AIBUtils.printSection(this, "PACKER / PROTECTOR DETECTION");
            packersFound = detectPackers();
        }

        // --- ANTI-ANALYSIS DETECTION ---
        if (mode == 0 || mode == 2) {
            AIBUtils.printSection(this, "ANTI-DEBUG DETECTION");
            antiHits.addAll(detectAntiDebug());

            AIBUtils.printSection(this, "ANTI-VM DETECTION");
            antiHits.addAll(detectAntiVM());

            AIBUtils.printSection(this, "ANTI-SANDBOX DETECTION");
            antiHits.addAll(detectAntiSandbox());
        }

        // --- SUMMARY ---
        printSummary(entropyResults, antiHits, packersFound);

        // --- EXPORT ---
        exportResults(entropyResults, antiHits, packersFound);

        AIBUtils.printFooter(this, "AIB EntropyShield");
    }

    // ========================================================================
    // ENTROPY ANALYSIS
    // ========================================================================

    private List<EntropyResult> analyzeEntropy() throws Exception {
        List<EntropyResult> results = new ArrayList<>();
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;

            long size = block.getSize();
            if (size <= 0) continue;

            // Cap read size for very large blocks
            int readSize = (int) Math.min(size, 10 * 1024 * 1024); // 10MB max
            byte[] data = new byte[readSize];
            block.getBytes(block.getStart(), data);

            double entropy = AIBUtils.shannonEntropy(data);
            double ascii = AIBUtils.asciiRatio(data);
            String classification = AIBUtils.classifyEntropy(entropy);

            EntropyResult er = new EntropyResult();
            er.sectionName = block.getName();
            er.startAddr = block.getStart().getOffset();
            er.endAddr = block.getEnd().getOffset();
            er.size = size;
            er.entropy = entropy;
            er.asciiRatio = ascii;
            er.classification = classification;
            results.add(er);

            // Print result
            String status;
            if (entropy >= 7.0) {
                status = "⚠️  HIGH";
                // Add bookmark
                currentProgram.getBookmarkManager().setBookmark(
                    block.getStart(), "Analysis", "ENTROPY",
                    String.format("[PACKED] %s — Entropy: %.2f (%s)", block.getName(), entropy, classification));
            } else if (entropy >= 6.0) {
                status = "🔶 MEDIUM";
                currentProgram.getBookmarkManager().setBookmark(
                    block.getStart(), "Analysis", "ENTROPY",
                    String.format("[SUSPICIOUS] %s — Entropy: %.2f (%s)", block.getName(), entropy, classification));
            } else {
                status = "🟢 NORMAL";
            }

            println(String.format("  %s  %-12s  Size: %8d  Entropy: %.4f  ASCII: %.1f%%  [%s]",
                status, block.getName(), size, entropy, ascii * 100, classification));

            // Sliding window entropy for high-entropy sections
            if (entropy >= 6.0 && readSize >= 512) {
                double[] sliding = AIBUtils.slidingWindowEntropy(data, 256, 256);
                int highRegions = 0;
                for (double s : sliding) {
                    if (s >= 7.0) highRegions++;
                }
                println(String.format("         └─ Sliding window: %d/%d regions with entropy ≥ 7.0",
                    highRegions, sliding.length));
            }
        }

        return results;
    }

    // ========================================================================
    // PACKER DETECTION
    // ========================================================================

    private List<String> detectPackers() throws Exception {
        List<String> found = new ArrayList<>();
        Memory memory = currentProgram.getMemory();

        // Check section names
        for (MemoryBlock block : memory.getBlocks()) {
            String name = block.getName();
            for (String[] packer : PACKER_SECTIONS) {
                String packerName = packer[0];
                for (int i = 1; i < packer.length; i++) {
                    if (name.equalsIgnoreCase(packer[i]) || name.contains(packer[i])) {
                        String msg = String.format("[PACKER] %s detected via section name '%s'", packerName, name);
                        if (!found.contains(packerName)) {
                            found.add(packerName);
                        }
                        println("  🔴 " + msg);
                        currentProgram.getBookmarkManager().setBookmark(
                            block.getStart(), "Analysis", "PACKER", msg);
                    }
                }
            }
        }

        // Check strings for packer indicators
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String val = data.getDefaultValueRepresentation();
                if (val == null) continue;
                val = val.replace("\"", "");

                for (String[] packer : PACKER_STRINGS) {
                    String packerName = packer[0];
                    for (int i = 1; i < packer.length; i++) {
                        if (val.toLowerCase().contains(packer[i].toLowerCase())) {
                            String msg = String.format("[PACKER] %s indicator string: '%s'",
                                packerName, val.length() > 60 ? val.substring(0, 60) + "..." : val);
                            if (!found.contains(packerName)) {
                                found.add(packerName);
                            }
                            println("  🔴 " + msg);
                            currentProgram.getBookmarkManager().setBookmark(
                                data.getAddress(), "Analysis", "PACKER", msg);
                        }
                    }
                }
            }
        }

        // Check entry point anomaly
        Address entryPoint = currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext() ?
            null : null;
        // Use program's defined entry point
        AddressIterator entryPoints = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            Address ep = entryPoints.next();
            MemoryBlock epBlock = memory.getBlock(ep);
            if (epBlock != null) {
                String epSection = epBlock.getName();
                // Typical sections for entry points
                boolean unusual = !epSection.equals(".text") && !epSection.equals(".code") &&
                                  !epSection.equals("CODE") && !epSection.equals(".init");
                if (unusual) {
                    String msg = String.format("[PACKER] Entry point in unusual section '%s' at %s",
                        epSection, AIBUtils.formatAddress(ep));
                    println("  🟡 " + msg);
                    currentProgram.getBookmarkManager().setBookmark(
                        ep, "Analysis", "PACKER", msg);
                }
            }
        }

        if (found.isEmpty()) {
            println("  🟢 No known packer signatures detected.");
        } else {
            println(String.format("\n  Summary: %d packer(s) detected: %s", found.size(), String.join(", ", found)));
        }

        return found;
    }

    // ========================================================================
    // ANTI-DEBUG DETECTION
    // ========================================================================

    private List<AntiAnalysisHit> detectAntiDebug() throws Exception {
        List<AntiAnalysisHit> hits = new ArrayList<>();

        // Check imports for anti-debug APIs
        SymbolTable symTable = currentProgram.getSymbolTable();
        for (String[] apiInfo : ANTI_DEBUG_APIS) {
            hits.addAll(searchForAPIUsage(apiInfo[0], apiInfo[1], "ANTI_DEBUG", apiInfo[2], 0.85));
        }
        for (String[] apiInfo : ANTI_DEBUG_TIMING) {
            hits.addAll(searchForAPIUsage(apiInfo[0], apiInfo[1], "ANTI_DEBUG", apiInfo[2], 0.7));
        }

        // Check for RDTSC instruction (timing-based anti-debug)
        hits.addAll(searchForInstructionPattern("rdtsc",
            "RDTSC instruction — timing-based anti-debug via CPU cycle counter", "ANTI_DEBUG", "T1622", 0.6));

        // Check for INT 3 (breakpoint trap)
        hits.addAll(searchForBytePattern(new byte[]{(byte) 0xCC},
            "INT 3 (0xCC) — Software breakpoint / anti-debug trap", "ANTI_DEBUG", "T1622", 0.4));

        // Check for INT 2D (kernel debugger check)
        hits.addAll(searchForBytePattern(new byte[]{(byte) 0xCD, (byte) 0x2D},
            "INT 0x2D — Kernel debugger presence check", "ANTI_DEBUG", "T1622", 0.75));

        // Check for CPUID (used for both timing and VM detection)
        hits.addAll(searchForInstructionPattern("cpuid",
            "CPUID instruction — may be used for timing or VM detection", "ANTI_DEBUG", "T1622", 0.5));

        if (hits.isEmpty()) {
            println("  🟢 No anti-debug techniques detected.");
        }

        return hits;
    }

    // ========================================================================
    // ANTI-VM DETECTION
    // ========================================================================

    private List<AntiAnalysisHit> detectAntiVM() throws Exception {
        List<AntiAnalysisHit> hits = new ArrayList<>();

        // Search strings for VM indicators
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String val = data.getDefaultValueRepresentation();
                if (val == null) continue;
                val = val.replace("\"", "");

                for (String[] vmInfo : ANTI_VM_STRINGS) {
                    String vmName = vmInfo[0];
                    for (int i = 1; i < vmInfo.length; i++) {
                        if (val.toLowerCase().contains(vmInfo[i].toLowerCase()) && val.length() < 200) {
                            AntiAnalysisHit hit = new AntiAnalysisHit();
                            hit.category = "ANTI_VM";
                            hit.technique = vmName + " string detection";
                            hit.description = String.format("VM indicator string '%s' found (target: %s)",
                                val.length() > 50 ? val.substring(0, 50) + "..." : val, vmName);
                            hit.address = AIBUtils.formatAddress(data.getAddress());
                            hit.confidence = 0.8;
                            hit.mitreTactic = "T1497.001";

                            // Find containing function
                            Function func = getFunctionContaining(data.getAddress());
                            hit.functionName = func != null ? func.getName() : "N/A";

                            hits.add(hit);
                            println(String.format("  🔴 [ANTI-VM] %s at %s — %s",
                                hit.technique, hit.address, hit.description));

                            currentProgram.getBookmarkManager().setBookmark(
                                data.getAddress(), "Analysis", "ANTI-VM",
                                String.format("[ANTI-VM] %s: %s", vmName, val));
                            break;
                        }
                    }
                }

                // Check for MAC address prefixes
                for (String[] macInfo : ANTI_VM_MAC_PREFIXES) {
                    String vmName = macInfo[0];
                    for (int i = 1; i < macInfo.length; i++) {
                        String macClean = macInfo[i].replace(":", "").toLowerCase();
                        String valClean = val.replace(":", "").replace("-", "").toLowerCase();
                        if (valClean.contains(macClean)) {
                            AntiAnalysisHit hit = new AntiAnalysisHit();
                            hit.category = "ANTI_VM";
                            hit.technique = vmName + " MAC prefix detection";
                            hit.description = String.format("VM MAC prefix %s found (target: %s)", macInfo[i], vmName);
                            hit.address = AIBUtils.formatAddress(data.getAddress());
                            hit.confidence = 0.85;
                            hit.mitreTactic = "T1497.001";
                            Function func = getFunctionContaining(data.getAddress());
                            hit.functionName = func != null ? func.getName() : "N/A";
                            hits.add(hit);
                            println(String.format("  🔴 [ANTI-VM] %s at %s", hit.technique, hit.address));
                            break;
                        }
                    }
                }

                // Check for registry paths
                for (String[] regInfo : ANTI_VM_REGISTRY) {
                    String vmName = regInfo[0];
                    if (val.toLowerCase().contains(regInfo[1].toLowerCase())) {
                        AntiAnalysisHit hit = new AntiAnalysisHit();
                        hit.category = "ANTI_VM";
                        hit.technique = vmName + " registry check";
                        hit.description = String.format("VM registry path '%s' found", regInfo[1]);
                        hit.address = AIBUtils.formatAddress(data.getAddress());
                        hit.confidence = 0.9;
                        hit.mitreTactic = "T1497.001";
                        Function func = getFunctionContaining(data.getAddress());
                        hit.functionName = func != null ? func.getName() : "N/A";
                        hits.add(hit);
                        println(String.format("  🔴 [ANTI-VM] %s at %s", hit.technique, hit.address));
                        currentProgram.getBookmarkManager().setBookmark(
                            data.getAddress(), "Analysis", "ANTI-VM",
                            String.format("[ANTI-VM] %s registry: %s", vmName, regInfo[1]));
                    }
                }
            }
        }

        // Check for VMware backdoor I/O port 0x5658
        hits.addAll(searchForInstructionPattern("in",
            "IN instruction — may check VMware backdoor I/O port 0x5658", "ANTI_VM", "T1497.001", 0.4));

        if (hits.isEmpty()) {
            println("  🟢 No anti-VM techniques detected.");
        }

        return hits;
    }

    // ========================================================================
    // ANTI-SANDBOX DETECTION
    // ========================================================================

    private List<AntiAnalysisHit> detectAntiSandbox() throws Exception {
        List<AntiAnalysisHit> hits = new ArrayList<>();

        // Check for sandbox-detection APIs
        for (String[] apiInfo : ANTI_SANDBOX_APIS) {
            hits.addAll(searchForAPIUsage(apiInfo[0], apiInfo[1], "ANTI_SANDBOX", apiInfo[2], 0.6));
        }

        // Check strings for known sandbox names
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String val = data.getDefaultValueRepresentation();
                if (val == null) continue;
                val = val.replace("\"", "").toLowerCase();

                for (String[] sandboxNames : ANTI_SANDBOX_STRINGS) {
                    for (String name : sandboxNames) {
                        if (val.contains(name.toLowerCase()) && val.length() < 200 && val.length() > name.length()) {
                            AntiAnalysisHit hit = new AntiAnalysisHit();
                            hit.category = "ANTI_SANDBOX";
                            hit.technique = "Sandbox name detection";
                            hit.description = String.format("Sandbox indicator '%s' in string", name);
                            hit.address = AIBUtils.formatAddress(data.getAddress());
                            hit.confidence = 0.65;
                            hit.mitreTactic = "T1497.001";
                            Function func = getFunctionContaining(data.getAddress());
                            hit.functionName = func != null ? func.getName() : "N/A";
                            hits.add(hit);
                            println(String.format("  🟡 [ANTI-SANDBOX] Sandbox name '%s' at %s", name, hit.address));
                            break;
                        }
                    }
                }
            }
        }

        if (hits.isEmpty()) {
            println("  🟢 No anti-sandbox techniques detected.");
        }

        return hits;
    }

    // ========================================================================
    // HELPER — Search for API usage
    // ========================================================================

    private List<AntiAnalysisHit> searchForAPIUsage(String apiName, String description,
            String category, String mitre, double confidence) throws Exception {
        List<AntiAnalysisHit> hits = new ArrayList<>();
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getSymbolIterator(apiName, true);

        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            // Check references to this symbol
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            ReferenceIterator refs = refMgr.getReferencesTo(sym.getAddress());
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);

                AntiAnalysisHit hit = new AntiAnalysisHit();
                hit.category = category;
                hit.technique = apiName;
                hit.description = description;
                hit.address = AIBUtils.formatAddress(fromAddr);
                hit.functionName = func != null ? func.getName() : "N/A";
                hit.confidence = confidence;
                hit.mitreTactic = mitre;
                hits.add(hit);

                String tag = "[" + category.replace("_", "-") + "]";
                println(String.format("  🔴 %s %s at %s in %s — %s",
                    tag, apiName, hit.address, hit.functionName, description));

                currentProgram.getBookmarkManager().setBookmark(
                    fromAddr, "Analysis", category.replace("_", "-"),
                    String.format("%s %s: %s", tag, apiName, description));

                // Rename function if it's a default name
                if (func != null && (func.getName().startsWith("FUN_") || func.getName().startsWith("SUB_"))) {
                    String newName = category.toLowerCase() + "_" + apiName + "_check";
                    try {
                        func.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        println("         └─ Renamed: " + func.getName() + " → " + newName);
                    } catch (Exception e) {
                        // Name collision — add address suffix
                        try {
                            func.setName(newName + "_" + fromAddr.toString(),
                                ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        } catch (Exception e2) { /* ignore */ }
                    }
                }
            }
        }

        return hits;
    }

    // ========================================================================
    // HELPER — Search for instruction patterns
    // ========================================================================

    private List<AntiAnalysisHit> searchForInstructionPattern(String mnemonic, String description,
            String category, String mitre, double confidence) throws Exception {
        List<AntiAnalysisHit> hits = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(true);
        int count = 0;
        int maxHits = 20; // Limit to avoid noise

        while (instructions.hasNext() && !monitor.isCancelled() && count < maxHits) {
            Instruction insn = instructions.next();
            if (insn.getMnemonicString().equalsIgnoreCase(mnemonic)) {
                Function func = getFunctionContaining(insn.getAddress());

                AntiAnalysisHit hit = new AntiAnalysisHit();
                hit.category = category;
                hit.technique = mnemonic.toUpperCase() + " instruction";
                hit.description = description;
                hit.address = AIBUtils.formatAddress(insn.getAddress());
                hit.functionName = func != null ? func.getName() : "N/A";
                hit.confidence = confidence;
                hit.mitreTactic = mitre;
                hits.add(hit);

                if (count < 5) { // Only print first 5
                    println(String.format("  🟡 [%s] %s at %s in %s",
                        category.replace("_", "-"), mnemonic.toUpperCase(), hit.address, hit.functionName));
                }
                count++;
            }
        }

        if (count > 5) {
            println(String.format("         └─ ... and %d more %s instructions", count - 5, mnemonic.toUpperCase()));
        }

        return hits;
    }

    // ========================================================================
    // HELPER — Search for byte patterns
    // ========================================================================

    private List<AntiAnalysisHit> searchForBytePattern(byte[] pattern, String description,
            String category, String mitre, double confidence) throws Exception {
        List<AntiAnalysisHit> hits = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        Address addr = memory.getMinAddress();
        int count = 0;
        int maxHits = 10;

        while (addr != null && count < maxHits && !monitor.isCancelled()) {
            addr = memory.findBytes(addr, pattern, null, true, monitor);
            if (addr == null) break;

            // Only count if inside code
            MemoryBlock block = memory.getBlock(addr);
            if (block != null && block.isExecute()) {
                Function func = getFunctionContaining(addr);

                AntiAnalysisHit hit = new AntiAnalysisHit();
                hit.category = category;
                hit.technique = "Byte pattern";
                hit.description = description;
                hit.address = AIBUtils.formatAddress(addr);
                hit.functionName = func != null ? func.getName() : "N/A";
                hit.confidence = confidence;
                hit.mitreTactic = mitre;
                hits.add(hit);

                if (count < 3) {
                    println(String.format("  🟡 [%s] %s at %s",
                        category.replace("_", "-"), description, hit.address));
                }
                count++;
            }

            try {
                addr = addr.add(pattern.length);
            } catch (Exception e) {
                break;
            }
        }

        if (count > 3) {
            println(String.format("         └─ ... and %d more occurrences", count - 3));
        }

        return hits;
    }

    // ========================================================================
    // VISUALIZATION — Entropy Heatmap
    // ========================================================================

    private void printEntropyHeatmap(List<EntropyResult> results) {
        if (results.isEmpty()) return;

        AIBUtils.printSection(this, "ENTROPY HEATMAP");

        // ASCII art gradient: ░▒▓█
        String[] gradient = {"░", "░", "▒", "▒", "▓", "▓", "█", "█", "█"};

        println("  Section          Entropy  [0.0 ════════════════════ 8.0]  Classification");
        println("  ─────────────────────────────────────────────────────────────────────────");

        for (EntropyResult er : results) {
            int barLen = 30;
            int filled = (int) (er.entropy / 8.0 * barLen);
            StringBuilder bar = new StringBuilder();
            for (int i = 0; i < barLen; i++) {
                if (i < filled) {
                    int gradIdx = (int) (er.entropy);
                    if (gradIdx >= gradient.length) gradIdx = gradient.length - 1;
                    bar.append(gradient[gradIdx]);
                } else {
                    bar.append("·");
                }
            }

            String color;
            if (er.entropy >= 7.0) color = "🔴";
            else if (er.entropy >= 6.0) color = "🟡";
            else color = "🟢";

            println(String.format("  %s %-14s  %.4f  [%s]  %s",
                color, er.sectionName, er.entropy, bar.toString(), er.classification));
        }
    }

    // ========================================================================
    // SUMMARY
    // ========================================================================

    private void printSummary(List<EntropyResult> entropy, List<AntiAnalysisHit> anti, List<String> packers) {
        AIBUtils.printSection(this, "SHIELD ASSESSMENT SUMMARY");

        int highEntropy = 0;
        for (EntropyResult er : entropy) {
            if (er.entropy >= 7.0) highEntropy++;
        }

        int antiDebug = 0, antiVM = 0, antiSandbox = 0;
        for (AntiAnalysisHit h : anti) {
            switch (h.category) {
                case "ANTI_DEBUG": antiDebug++; break;
                case "ANTI_VM": antiVM++; break;
                case "ANTI_SANDBOX": antiSandbox++; break;
            }
        }

        // Threat level calculation
        int threatScore = 0;
        threatScore += highEntropy * 20;
        threatScore += packers.size() * 25;
        threatScore += antiDebug * 10;
        threatScore += antiVM * 10;
        threatScore += antiSandbox * 8;

        String threatLevel;
        if (threatScore >= 100) threatLevel = "🔴 CRITICAL — Heavily protected/obfuscated binary";
        else if (threatScore >= 60) threatLevel = "🟠 HIGH — Significant anti-analysis measures detected";
        else if (threatScore >= 30) threatLevel = "🟡 MODERATE — Some protection mechanisms present";
        else if (threatScore >= 10) threatLevel = "🔵 LOW — Minimal protection detected";
        else threatLevel = "🟢 CLEAN — No significant protections detected";

        println(String.format("  Threat Assessment Score: %d/100+", Math.min(threatScore, 100)));
        println(String.format("  Threat Level: %s", threatLevel));
        println("");
        println(String.format("  High-Entropy Sections:  %d", highEntropy));
        println(String.format("  Packers Detected:       %d  %s", packers.size(),
            packers.isEmpty() ? "" : "(" + String.join(", ", packers) + ")"));
        println(String.format("  Anti-Debug Techniques:  %d", antiDebug));
        println(String.format("  Anti-VM Techniques:     %d", antiVM));
        println(String.format("  Anti-Sandbox Techniques: %d", antiSandbox));
        println(String.format("  Total Indicators:       %d", anti.size() + packers.size() + highEntropy));
    }

    // ========================================================================
    // EXPORT
    // ========================================================================

    private void exportResults(List<EntropyResult> entropy, List<AntiAnalysisHit> anti,
            List<String> packers) throws Exception {
        File outputDir = AIBUtils.getOutputDirectory(this);
        String timestamp = AIBUtils.getFileTimestamp();

        // Build JSON data
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("plugin", "AIB_EntropyShield");
        report.put("version", AIBUtils.AIB_VERSION);
        report.put("timestamp", AIBUtils.getTimestamp());
        report.put("program", currentProgram.getName());
        report.put("program_hash", AIBUtils.computeProgramHash(currentProgram));

        // Entropy results
        List<Map<String, Object>> entropyList = new ArrayList<>();
        for (EntropyResult er : entropy) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("section", er.sectionName);
            m.put("start_address", String.format("0x%X", er.startAddr));
            m.put("end_address", String.format("0x%X", er.endAddr));
            m.put("size", er.size);
            m.put("entropy", Math.round(er.entropy * 10000.0) / 10000.0);
            m.put("ascii_ratio", Math.round(er.asciiRatio * 1000.0) / 1000.0);
            m.put("classification", er.classification);
            entropyList.add(m);
        }
        report.put("entropy_analysis", entropyList);
        report.put("packers_detected", packers);

        // Anti-analysis results
        List<Map<String, Object>> antiList = new ArrayList<>();
        for (AntiAnalysisHit h : anti) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("category", h.category);
            m.put("technique", h.technique);
            m.put("description", h.description);
            m.put("address", h.address);
            m.put("function", h.functionName);
            m.put("confidence", h.confidence);
            m.put("mitre_attack", h.mitreTactic);
            antiList.add(m);
        }
        report.put("anti_analysis_indicators", antiList);

        // Summary stats
        Map<String, Object> summary = new LinkedHashMap<>();
        int antiDebug = 0, antiVM = 0, antiSandbox = 0;
        for (AntiAnalysisHit h : anti) {
            switch (h.category) {
                case "ANTI_DEBUG": antiDebug++; break;
                case "ANTI_VM": antiVM++; break;
                case "ANTI_SANDBOX": antiSandbox++; break;
            }
        }
        summary.put("total_sections_analyzed", entropy.size());
        summary.put("high_entropy_sections", (int) entropy.stream().filter(e -> e.entropy >= 7.0).count());
        summary.put("packers_count", packers.size());
        summary.put("anti_debug_count", antiDebug);
        summary.put("anti_vm_count", antiVM);
        summary.put("anti_sandbox_count", antiSandbox);
        summary.put("total_indicators", anti.size());
        report.put("summary", summary);

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "entropy_shield_" + timestamp + ".json";
        AIBUtils.exportToJSON(report, jsonPath);
        AIBUtils.printResult(this, "JSON report exported", jsonPath);

        // Export entropy heatmap CSV
        String csvPath = outputDir.getAbsolutePath() + File.separator +
            "entropy_heatmap_" + timestamp + ".csv";
        String[] headers = {"Section", "Start", "End", "Size", "Entropy", "ASCII%", "Classification"};
        List<String[]> rows = new ArrayList<>();
        for (EntropyResult er : entropy) {
            rows.add(new String[]{
                er.sectionName,
                String.format("0x%X", er.startAddr),
                String.format("0x%X", er.endAddr),
                String.valueOf(er.size),
                String.format("%.4f", er.entropy),
                String.format("%.1f", er.asciiRatio * 100),
                er.classification
            });
        }
        AIBUtils.exportToCSV(headers, rows, csvPath);
        AIBUtils.printResult(this, "Entropy heatmap CSV exported", csvPath);
    }
}
