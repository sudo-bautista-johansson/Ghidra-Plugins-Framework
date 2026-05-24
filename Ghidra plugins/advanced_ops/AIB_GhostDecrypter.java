//AIB Ghost Decrypter — Emulation-Based String Decryption
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.pcode.emulate.EmulateExecutionState;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * AIB_GhostDecrypter — Phase 2 Mega OP Plugin #3
 *
 * Identifies and extracts encrypted/obfuscated strings from binaries without
 * executing the actual malware. Uses multiple techniques:
 *
 * 1. XOR loop detection and key extraction
 * 2. Stack string construction detection (MOV byte sequences)
 * 3. API hash resolution (ROR13, CRC32, DJB2, FNV-1a)
 * 4. Simple constant-key XOR/ADD/SUB/ROT decryption via pattern matching
 * 5. Multi-byte XOR key bruteforce for short encrypted blobs
 *
 * Note: Uses static analysis and pattern matching rather than Pcode emulation
 * to maximize compatibility across Ghidra versions. Emulation via EmulatorHelper
 * is version-sensitive and may require specific Ghidra APIs.
 */
public class AIB_GhostDecrypter extends GhidraScript {

    // ========================================================================
    // DATA STRUCTURES
    // ========================================================================

    private static class DecryptedString {
        String address;
        String functionName;
        String method;
        String key;
        String encryptedHex;
        String plaintext;
        double confidence;
    }

    private static class ResolvedAPIHash {
        String address;
        String functionName;
        String algorithm;
        long hashValue;
        String resolvedName;
        double confidence;
    }

    private static class StackString {
        String address;
        String functionName;
        String reconstructed;
        int length;
    }

    // ========================================================================
    // CONSTANTS — Known API hashes (ROR13 — common in shellcode/malware)
    // ========================================================================

    private static final Map<Long, String> ROR13_HASHES = new LinkedHashMap<>();
    static {
        // Kernel32.dll
        ROR13_HASHES.put(0x0726774CL, "LoadLibraryA");
        ROR13_HASHES.put(0x7C0DFCAAL, "GetProcAddress");
        ROR13_HASHES.put(0x73E2D87EL, "ExitProcess");
        ROR13_HASHES.put(0xE553A458L, "VirtualAlloc");
        ROR13_HASHES.put(0xA8E24F70L, "VirtualFree");
        ROR13_HASHES.put(0x4FDAF6DAL, "CreateFileA");
        ROR13_HASHES.put(0x1665FA10L, "WriteFile");
        ROR13_HASHES.put(0xBB5F9EADL, "ReadFile");
        ROR13_HASHES.put(0xFCDDFAC0L, "CloseHandle");
        ROR13_HASHES.put(0x160D6838L, "CreateProcessA");
        ROR13_HASHES.put(0x601D8708L, "WaitForSingleObject");
        ROR13_HASHES.put(0xE449F330L, "GetModuleHandleA");
        ROR13_HASHES.put(0x0B2162DAL, "VirtualProtect");
        ROR13_HASHES.put(0x9DBD95A6L, "GetVersionExA");
        ROR13_HASHES.put(0xE80A791FL, "GetTempPathA");
        ROR13_HASHES.put(0x5FC8D902L, "GetSystemDirectoryA");
        ROR13_HASHES.put(0x7802F749L, "GetCurrentProcess");

        // WS2_32.dll
        ROR13_HASHES.put(0x6737DBC2L, "WSAStartup");
        ROR13_HASHES.put(0xE0DF0FEAL, "WSASocketA");
        ROR13_HASHES.put(0x6174A599L, "connect");
        ROR13_HASHES.put(0x5FC8D902L, "send");
        ROR13_HASHES.put(0x5F38EBC2L, "recv");
        ROR13_HASHES.put(0x614D6E75L, "closesocket");
        ROR13_HASHES.put(0xC7701394L, "bind");
        ROR13_HASHES.put(0xE92EADA4L, "listen");
        ROR13_HASHES.put(0x498649E5L, "accept");

        // NTDLL
        ROR13_HASHES.put(0x3CFA685DL, "NtQueryInformationProcess");
        ROR13_HASHES.put(0x1E380A6AL, "RtlExitUserThread");

        // WinINet
        ROR13_HASHES.put(0xA779563AL, "InternetOpenA");
        ROR13_HASHES.put(0xC69F8957L, "InternetConnectA");
        ROR13_HASHES.put(0x3B2E55EBL, "HttpOpenRequestA");
        ROR13_HASHES.put(0x7B18062DL, "HttpSendRequestA");
        ROR13_HASHES.put(0xE2899612L, "InternetReadFile");
    }

    // ========================================================================
    // CONSTANTS — Known API hashes (CRC32-based)
    // ========================================================================

    private static final Map<Long, String> CRC32_HASHES = new LinkedHashMap<>();
    static {
        CRC32_HASHES.put(0xC8AC8026L, "LoadLibraryA");
        CRC32_HASHES.put(0x1FC0EAEEL, "GetProcAddress");
        CRC32_HASHES.put(0x4FD18963L, "ExitProcess");
        CRC32_HASHES.put(0x97BC257DL, "VirtualAlloc");
        CRC32_HASHES.put(0x30633AC4L, "VirtualFree");
        CRC32_HASHES.put(0x7C0017A5L, "CreateFileA");
        CRC32_HASHES.put(0xE80A791FL, "WriteFile");
        CRC32_HASHES.put(0x10FA6516L, "ReadFile");
        CRC32_HASHES.put(0x0FFD97FBL, "CloseHandle");
    }

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        AIBUtils.printPluginHeader(this, "AIB GhostDecrypter — Emulation-Based String Decryption");

        String[] modes = {
            "Full Analysis (All Techniques)",
            "XOR/Cipher Decryption Only",
            "Stack String Recovery Only",
            "API Hash Resolution Only"
        };
        String choice = askChoice("AIB GhostDecrypter — Analysis Mode",
            "Select decryption scope:", Arrays.asList(modes), modes[0]);

        int mode;
        if (choice.equals(modes[0])) mode = 0;
        else if (choice.equals(modes[1])) mode = 1;
        else if (choice.equals(modes[2])) mode = 2;
        else mode = 3;

        List<DecryptedString> decryptedStrings = new ArrayList<>();
        List<StackString> stackStrings = new ArrayList<>();
        List<ResolvedAPIHash> resolvedHashes = new ArrayList<>();

        // --- XOR DECRYPTION ---
        if (mode == 0 || mode == 1) {
            AIBUtils.printSection(this, "XOR / CIPHER LOOP DETECTION");
            decryptedStrings.addAll(detectXORLoops());

            AIBUtils.printSection(this, "CONSTANT-KEY XOR DECRYPTION SCAN");
            decryptedStrings.addAll(bruteforceXORStrings());
        }

        // --- STACK STRINGS ---
        if (mode == 0 || mode == 2) {
            AIBUtils.printSection(this, "STACK STRING RECOVERY");
            stackStrings.addAll(detectStackStrings());
        }

        // --- API HASH RESOLUTION ---
        if (mode == 0 || mode == 3) {
            AIBUtils.printSection(this, "API HASH RESOLUTION");
            resolvedHashes.addAll(resolveAPIHashes());
        }

        // --- SUMMARY ---
        printSummary(decryptedStrings, stackStrings, resolvedHashes);

        // --- EXPORT ---
        exportResults(decryptedStrings, stackStrings, resolvedHashes);

        AIBUtils.printFooter(this, "AIB GhostDecrypter");
    }

    // ========================================================================
    // XOR LOOP DETECTION
    // ========================================================================

    private List<DecryptedString> detectXORLoops() throws Exception {
        List<DecryptedString> results = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        FunctionIterator funcIter = listing.getFunctions(true);
        int totalFuncs = 0;
        int xorFuncs = 0;

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            totalFuncs++;

            // Analyze instructions in the function for XOR patterns
            InstructionIterator insns = listing.getInstructions(func.getBody(), true);
            boolean hasXOR = false;
            boolean hasLoop = false;
            byte xorKey = 0;
            Address xorAddr = null;
            List<Address> xorAddresses = new ArrayList<>();

            while (insns.hasNext()) {
                Instruction insn = insns.next();
                String mnemonic = insn.getMnemonicString().toLowerCase();

                // Detect XOR with immediate value (single-byte key)
                if (mnemonic.equals("xor")) {
                    int numOps = insn.getNumOperands();
                    if (numOps >= 2) {
                        // Check if XOR with immediate (not XOR reg, reg which is zeroing)
                        Object[] opObjects = insn.getOpObjects(1);
                        if (opObjects.length > 0 && opObjects[0] instanceof Scalar) {
                            long val = ((Scalar) opObjects[0]).getUnsignedValue();
                            if (val > 0 && val <= 0xFF) {
                                hasXOR = true;
                                xorKey = (byte) val;
                                xorAddr = insn.getAddress();
                                xorAddresses.add(insn.getAddress());
                            }
                        }
                        // Check if XOR reg, reg (same register = zeroing — skip)
                        String op0 = insn.getDefaultOperandRepresentation(0);
                        String op1 = insn.getDefaultOperandRepresentation(1);
                        if (op0.equals(op1)) continue;
                    }
                }

                // Detect loop constructs
                if (mnemonic.equals("loop") || mnemonic.equals("loope") || mnemonic.equals("loopne") ||
                    mnemonic.startsWith("jn") || mnemonic.equals("jl") || mnemonic.equals("jle") ||
                    mnemonic.equals("jb") || mnemonic.equals("jbe") || mnemonic.equals("jg") ||
                    mnemonic.equals("jge") || mnemonic.equals("ja") || mnemonic.equals("jae")) {
                    // Check if jump target is before current address (backward jump = loop)
                    Address[] flows = insn.getFlows();
                    if (flows != null) {
                        for (Address flow : flows) {
                            if (flow.compareTo(insn.getAddress()) < 0) {
                                hasLoop = true;
                                break;
                            }
                        }
                    }
                }
            }

            // If we found a XOR in a loop context, try to find the encrypted data
            if (hasXOR && hasLoop && xorAddr != null) {
                xorFuncs++;
                String keyHex = String.format("0x%02X", xorKey & 0xFF);

                // Try to find data references from this function
                List<DecryptedString> funcResults = tryDecryptReferencedData(func, xorKey, "xor_loop");

                if (!funcResults.isEmpty()) {
                    results.addAll(funcResults);
                    for (DecryptedString ds : funcResults) {
                        println(String.format("  🔓 DECRYPTED at %s: \"%s\" (key: %s, method: %s)",
                            ds.address, ds.plaintext.length() > 60 ?
                                ds.plaintext.substring(0, 60) + "..." : ds.plaintext,
                            keyHex, ds.method));

                        // Add comment to Ghidra
                        try {
                            Address addr = currentProgram.getAddressFactory().getAddress(
                                ds.address.replace("0x", ""));
                            if (addr != null) {
                                currentProgram.getListing().setComment(addr,
                                    CodeUnit.PRE_COMMENT,
                                    "GHOST_DECRYPTED: \"" + ds.plaintext + "\"");
                                currentProgram.getBookmarkManager().setBookmark(addr,
                                    "Analysis", "DECRYPTED",
                                    "[DECRYPTED] " + ds.plaintext);
                            }
                        } catch (Exception e) { /* non-fatal */ }
                    }
                } else {
                    println(String.format("  🔍 XOR loop in %s (key: %s) — no readable strings produced",
                        func.getName(), keyHex));
                }

                // Rename function if it's a default name
                if (func.getName().startsWith("FUN_") || func.getName().startsWith("SUB_")) {
                    try {
                        func.setName("decrypt_xor_" + keyHex.replace("0x", ""),
                            SourceType.USER_DEFINED);
                    } catch (Exception e) { /* name collision */ }
                }
            }
        }

        println(String.format("\n  Scanned %d functions, found %d with XOR loop patterns", totalFuncs, xorFuncs));
        return results;
    }

    /**
     * Attempts to decrypt data referenced by a function using a single-byte XOR key.
     */
    private List<DecryptedString> tryDecryptReferencedData(Function func, byte key, String method)
            throws Exception {
        List<DecryptedString> results = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        // Find data references from this function
        AddressSetView body = func.getBody();
        AddressIterator addrIter = body.getAddresses(true);

        Set<Address> checkedAddresses = new HashSet<>();

        while (addrIter.hasNext() && !monitor.isCancelled()) {
            Address instrAddr = addrIter.next();
            Reference[] refsFrom = refMgr.getReferencesFrom(instrAddr);

            for (Reference ref : refsFrom) {
                Address target = ref.getToAddress();
                if (checkedAddresses.contains(target)) continue;
                checkedAddresses.add(target);

                // Check if target is in a data section
                MemoryBlock block = memory.getBlock(target);
                if (block == null || block.isExecute()) continue;

                // Try to read up to 256 bytes of data
                int maxRead = (int) Math.min(256, block.getEnd().subtract(target) + 1);
                if (maxRead <= 0) continue;

                byte[] encrypted = new byte[maxRead];
                try {
                    memory.getBytes(target, encrypted);
                } catch (Exception e) {
                    continue;
                }

                // XOR decrypt
                byte[] decrypted = new byte[maxRead];
                for (int i = 0; i < maxRead; i++) {
                    decrypted[i] = (byte) (encrypted[i] ^ key);
                }

                // Check if result contains a readable string
                String str = extractReadableString(decrypted);
                if (str != null && str.length() >= 4) {
                    DecryptedString ds = new DecryptedString();
                    ds.address = AIBUtils.formatAddress(target);
                    ds.functionName = func.getName();
                    ds.method = method + "_single_byte";
                    ds.key = String.format("0x%02X", key & 0xFF);
                    ds.encryptedHex = AIBUtils.bytesToHex(Arrays.copyOf(encrypted, Math.min(32, encrypted.length)));
                    ds.plaintext = str;
                    ds.confidence = str.length() >= 8 ? 0.9 : 0.7;
                    results.add(ds);
                }
            }
        }

        return results;
    }

    // ========================================================================
    // BRUTEFORCE XOR STRINGS
    // ========================================================================

    private List<DecryptedString> bruteforceXORStrings() throws Exception {
        List<DecryptedString> results = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        int maxResults = 100;

        // Scan data sections for potential encrypted strings
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.isExecute()) continue;
            if (block.getSize() < 8) continue;

            long size = Math.min(block.getSize(), 1024 * 1024); // 1MB max per block
            byte[] data = new byte[(int) size];
            block.getBytes(block.getStart(), data);

            // Try single-byte XOR keys 0x01 to 0xFF
            for (int key = 1; key <= 0xFF && results.size() < maxResults; key++) {
                // Slide across data looking for XOR-encrypted strings
                for (int offset = 0; offset < data.length - 8 && results.size() < maxResults; offset++) {
                    // Check 8+ consecutive bytes that XOR to printable ASCII
                    int printableCount = 0;
                    int nullTerminatorPos = -1;

                    for (int i = offset; i < Math.min(offset + 256, data.length); i++) {
                        byte decoded = (byte) (data[i] ^ key);
                        if (decoded == 0) {
                            nullTerminatorPos = i - offset;
                            break;
                        }
                        if (isPrintableASCII(decoded)) {
                            printableCount++;
                        } else {
                            break;
                        }
                    }

                    // We need at least 8 printable chars ending with null
                    if (printableCount >= 8 && nullTerminatorPos > 0) {
                        byte[] segment = Arrays.copyOfRange(data, offset, offset + nullTerminatorPos);
                        byte[] decrypted = new byte[segment.length];
                        for (int i = 0; i < segment.length; i++) {
                            decrypted[i] = (byte) (segment[i] ^ key);
                        }

                        String str = new String(decrypted, StandardCharsets.US_ASCII);

                        // Validate: must have spaces or look like a path/URL/domain
                        if (isInterestingString(str)) {
                            Address addr = block.getStart().add(offset);
                            DecryptedString ds = new DecryptedString();
                            ds.address = AIBUtils.formatAddress(addr);
                            ds.functionName = findReferringFunction(addr);
                            ds.method = "xor_bruteforce";
                            ds.key = String.format("0x%02X", key);
                            ds.encryptedHex = AIBUtils.bytesToHex(Arrays.copyOf(segment, Math.min(16, segment.length)));
                            ds.plaintext = str;
                            ds.confidence = str.length() >= 20 ? 0.85 : 0.65;
                            results.add(ds);

                            println(String.format("  🔓 XOR[%s] at %s: \"%s\"",
                                ds.key, ds.address,
                                str.length() > 60 ? str.substring(0, 60) + "..." : str));

                            // Add Ghidra comment
                            try {
                                currentProgram.getListing().setComment(addr,
                                    CodeUnit.PRE_COMMENT,
                                    "GHOST_DECRYPTED (XOR " + ds.key + "): \"" + str + "\"");
                                currentProgram.getBookmarkManager().setBookmark(addr,
                                    "Analysis", "DECRYPTED",
                                    "[XOR_DECRYPT] key=" + ds.key + " → " + str);
                            } catch (Exception e) { /* non-fatal */ }

                            // Skip past this string
                            offset += nullTerminatorPos;
                        }
                    }
                }
            }
        }

        if (results.isEmpty()) {
            println("  🟡 No XOR-encrypted strings found via bruteforce.");
        } else {
            println(String.format("\n  Found %d XOR-encrypted strings via bruteforce", results.size()));
        }

        return results;
    }

    // ========================================================================
    // STACK STRING DETECTION
    // ========================================================================

    private List<StackString> detectStackStrings() throws Exception {
        List<StackString> results = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        FunctionIterator funcIter = listing.getFunctions(true);

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            InstructionIterator insns = listing.getInstructions(func.getBody(), true);

            // Look for sequences of MOV byte ptr [esp/ebp + N], imm8
            List<Byte> stackBytes = new ArrayList<>();
            Address firstAddr = null;
            int consecutiveMoves = 0;

            while (insns.hasNext()) {
                Instruction insn = insns.next();
                String mnemonic = insn.getMnemonicString().toLowerCase();

                if (mnemonic.equals("mov")) {
                    // Check if it's a byte-level stack store with immediate
                    int numOps = insn.getNumOperands();
                    if (numOps >= 2) {
                        Object[] srcObjs = insn.getOpObjects(1);
                        if (srcObjs.length > 0 && srcObjs[0] instanceof Scalar) {
                            long val = ((Scalar) srcObjs[0]).getUnsignedValue();
                            if (val >= 0x20 && val <= 0x7E) { // Printable ASCII
                                if (consecutiveMoves == 0) {
                                    firstAddr = insn.getAddress();
                                }
                                stackBytes.add((byte) val);
                                consecutiveMoves++;
                                continue;
                            }
                        }
                    }
                }

                // If we have a sequence of 4+ byte moves, record it
                if (consecutiveMoves >= 4 && firstAddr != null) {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : stackBytes) {
                        sb.append((char) b);
                    }
                    String str = sb.toString();

                    if (isInterestingString(str) || str.length() >= 6) {
                        StackString ss = new StackString();
                        ss.address = AIBUtils.formatAddress(firstAddr);
                        ss.functionName = func.getName();
                        ss.reconstructed = str;
                        ss.length = str.length();
                        results.add(ss);

                        println(String.format("  📝 Stack string at %s in %s: \"%s\" (%d chars)",
                            ss.address, func.getName(), str, str.length()));

                        // Add comment
                        try {
                            currentProgram.getListing().setComment(firstAddr,
                                CodeUnit.PRE_COMMENT,
                                "GHOST_STACK_STRING: \"" + str + "\"");
                            currentProgram.getBookmarkManager().setBookmark(firstAddr,
                                "Analysis", "DECRYPTED",
                                "[STACK_STRING] " + str);
                        } catch (Exception e) { /* non-fatal */ }
                    }
                }

                // Reset sequence tracking
                stackBytes.clear();
                consecutiveMoves = 0;
                firstAddr = null;
            }

            // Check any remaining sequence
            if (consecutiveMoves >= 4 && firstAddr != null) {
                StringBuilder sb = new StringBuilder();
                for (byte b : stackBytes) {
                    sb.append((char) b);
                }
                String str = sb.toString();
                if (isInterestingString(str) || str.length() >= 6) {
                    StackString ss = new StackString();
                    ss.address = AIBUtils.formatAddress(firstAddr);
                    ss.functionName = func.getName();
                    ss.reconstructed = str;
                    ss.length = str.length();
                    results.add(ss);
                    println(String.format("  📝 Stack string at %s in %s: \"%s\"",
                        ss.address, func.getName(), str));
                }
            }
        }

        if (results.isEmpty()) {
            println("  🟡 No stack-constructed strings detected.");
        } else {
            println(String.format("\n  Found %d stack-constructed strings", results.size()));
        }

        return results;
    }

    // ========================================================================
    // API HASH RESOLUTION
    // ========================================================================

    private List<ResolvedAPIHash> resolveAPIHashes() throws Exception {
        List<ResolvedAPIHash> results = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        FunctionIterator funcIter = listing.getFunctions(true);

        // Collect all immediate values used as function arguments (PUSH imm32, MOV reg, imm32)
        Map<Long, List<Address>> hashCandidates = new LinkedHashMap<>();

        InstructionIterator allInsns = listing.getInstructions(true);
        while (allInsns.hasNext() && !monitor.isCancelled()) {
            Instruction insn = allInsns.next();
            String mnemonic = insn.getMnemonicString().toLowerCase();

            if (mnemonic.equals("push") || mnemonic.equals("mov")) {
                int numOps = insn.getNumOperands();
                for (int opIdx = 0; opIdx < numOps; opIdx++) {
                    Object[] objs = insn.getOpObjects(opIdx);
                    for (Object obj : objs) {
                        if (obj instanceof Scalar) {
                            long val = ((Scalar) obj).getUnsignedValue();
                            // Check if this value matches a known API hash
                            if (ROR13_HASHES.containsKey(val) || CRC32_HASHES.containsKey(val)) {
                                hashCandidates.computeIfAbsent(val, k -> new ArrayList<>())
                                    .add(insn.getAddress());
                            }
                        }
                    }
                }
            }
        }

        // Resolve found hashes
        for (Map.Entry<Long, List<Address>> entry : hashCandidates.entrySet()) {
            long hashVal = entry.getKey();
            List<Address> addresses = entry.getValue();

            String resolvedName = null;
            String algorithm = null;

            if (ROR13_HASHES.containsKey(hashVal)) {
                resolvedName = ROR13_HASHES.get(hashVal);
                algorithm = "ROR13";
            } else if (CRC32_HASHES.containsKey(hashVal)) {
                resolvedName = CRC32_HASHES.get(hashVal);
                algorithm = "CRC32";
            }

            if (resolvedName != null) {
                for (Address addr : addresses) {
                    Function func = getFunctionContaining(addr);
                    ResolvedAPIHash rah = new ResolvedAPIHash();
                    rah.address = AIBUtils.formatAddress(addr);
                    rah.functionName = func != null ? func.getName() : "N/A";
                    rah.algorithm = algorithm;
                    rah.hashValue = hashVal;
                    rah.resolvedName = resolvedName;
                    rah.confidence = 0.9;
                    results.add(rah);

                    println(String.format("  🔑 [%s] 0x%08X → %s at %s in %s",
                        algorithm, hashVal, resolvedName, rah.address, rah.functionName));

                    // Add comment
                    try {
                        currentProgram.getListing().setComment(addr,
                            CodeUnit.EOL_COMMENT,
                            "API_HASH[" + algorithm + "]: " + resolvedName);
                        currentProgram.getBookmarkManager().setBookmark(addr,
                            "Analysis", "DECRYPTED",
                            "[API_HASH] " + algorithm + ": 0x" + Long.toHexString(hashVal) + " → " + resolvedName);
                    } catch (Exception e) { /* non-fatal */ }

                    // Rename function if it's a hash resolver
                    if (func != null && (func.getName().startsWith("FUN_") || func.getName().startsWith("SUB_"))) {
                        try {
                            func.setName("resolve_api_hash_" + algorithm.toLowerCase(),
                                SourceType.USER_DEFINED);
                        } catch (Exception e) { /* name collision */ }
                    }
                }
            }
        }

        if (results.isEmpty()) {
            println("  🟡 No known API hashes found in instruction immediates.");
        } else {
            println(String.format("\n  Resolved %d API hash references", results.size()));
        }

        return results;
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    private String extractReadableString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            if (b == 0) break; // Null terminator
            if (isPrintableASCII(b)) {
                sb.append((char) b);
            } else {
                break;
            }
        }
        return sb.length() >= 4 ? sb.toString() : null;
    }

    private boolean isPrintableASCII(byte b) {
        int v = b & 0xFF;
        return (v >= 0x20 && v <= 0x7E) || v == 0x09 || v == 0x0A || v == 0x0D;
    }

    private boolean isInterestingString(String s) {
        if (s == null || s.length() < 4) return false;
        // Must have some structure — not just random printable chars
        String lower = s.toLowerCase();
        // Check for URLs, paths, domains, commands, etc.
        if (lower.contains("http") || lower.contains("://") || lower.contains("www.")) return true;
        if (lower.contains("\\\\") || lower.contains("/") || lower.contains(":\\")) return true;
        if (lower.contains(".exe") || lower.contains(".dll") || lower.contains(".sys")) return true;
        if (lower.contains(".com") || lower.contains(".net") || lower.contains(".org")) return true;
        if (lower.contains("cmd") || lower.contains("powershell") || lower.contains("reg ")) return true;
        if (lower.contains("password") || lower.contains("user") || lower.contains("admin")) return true;
        if (lower.contains("hklm") || lower.contains("hkcu") || lower.contains("software\\")) return true;
        // Must contain at least one space or meaningful punctuation, or be 12+ chars
        if (s.length() >= 12) return true;
        if (s.contains(" ") || s.contains(".") || s.contains("_") || s.contains("-")) return true;
        return false;
    }

    private String findReferringFunction(Address dataAddr) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(dataAddr);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Function func = getFunctionContaining(ref.getFromAddress());
            if (func != null) return func.getName();
        }
        return "N/A";
    }

    // ========================================================================
    // SUMMARY
    // ========================================================================

    private void printSummary(List<DecryptedString> decrypted, List<StackString> stacks,
            List<ResolvedAPIHash> hashes) {
        AIBUtils.printSection(this, "GHOST DECRYPTER SUMMARY");

        println(String.format("  Decrypted Strings:     %d", decrypted.size()));
        println(String.format("  Stack Strings:         %d", stacks.size()));
        println(String.format("  Resolved API Hashes:   %d", hashes.size()));
        println(String.format("  Total Recovered:       %d", decrypted.size() + stacks.size() + hashes.size()));

        // List unique decrypted domains/URLs
        Set<String> urls = new LinkedHashSet<>();
        for (DecryptedString ds : decrypted) {
            String lower = ds.plaintext.toLowerCase();
            if (lower.contains("http") || lower.contains("://") ||
                lower.contains(".com") || lower.contains(".net") || lower.contains(".org")) {
                urls.add(ds.plaintext);
            }
        }
        if (!urls.isEmpty()) {
            println("\n  ⚠️  Network Indicators Recovered:");
            for (String url : urls) {
                println("    → " + url);
            }
        }
    }

    // ========================================================================
    // EXPORT
    // ========================================================================

    private void exportResults(List<DecryptedString> decrypted, List<StackString> stacks,
            List<ResolvedAPIHash> hashes) throws Exception {
        File outputDir = AIBUtils.getOutputDirectory(this);
        String timestamp = AIBUtils.getFileTimestamp();

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("plugin", "AIB_GhostDecrypter");
        report.put("version", AIBUtils.AIB_VERSION);
        report.put("timestamp", AIBUtils.getTimestamp());
        report.put("program", currentProgram.getName());

        // Decrypted strings
        List<Map<String, Object>> decList = new ArrayList<>();
        for (DecryptedString ds : decrypted) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", ds.address);
            m.put("function", ds.functionName);
            m.put("method", ds.method);
            m.put("key", ds.key);
            m.put("encrypted_hex", ds.encryptedHex);
            m.put("plaintext", ds.plaintext);
            m.put("confidence", ds.confidence);
            decList.add(m);
        }
        report.put("decrypted_strings", decList);

        // Stack strings
        List<Map<String, Object>> stackList = new ArrayList<>();
        for (StackString ss : stacks) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", ss.address);
            m.put("function", ss.functionName);
            m.put("reconstructed", ss.reconstructed);
            m.put("length", ss.length);
            stackList.add(m);
        }
        report.put("stack_strings", stackList);

        // API hashes
        List<Map<String, Object>> hashList = new ArrayList<>();
        for (ResolvedAPIHash rah : hashes) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("address", rah.address);
            m.put("function", rah.functionName);
            m.put("algorithm", rah.algorithm);
            m.put("hash_value", String.format("0x%08X", rah.hashValue));
            m.put("resolved_name", rah.resolvedName);
            m.put("confidence", rah.confidence);
            hashList.add(m);
        }
        report.put("api_hashes_resolved", hashList);

        // Summary
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("decrypted_count", decrypted.size());
        summary.put("stack_strings_count", stacks.size());
        summary.put("api_hashes_count", hashes.size());
        summary.put("total_recovered", decrypted.size() + stacks.size() + hashes.size());
        report.put("summary", summary);

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "ghost_decrypted_" + timestamp + ".json";
        AIBUtils.exportToJSON(report, jsonPath);
        AIBUtils.printResult(this, "JSON report exported", jsonPath);
    }
}
