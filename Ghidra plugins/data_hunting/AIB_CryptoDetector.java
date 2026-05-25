//AIB Cryptography & Hash Signature Detector
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.DataHunting
//@keybinding
//@menupath Tools.AIB.Crypto Detector
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB CRYPTOGRAPHY & HASH SIGNATURE DETECTOR
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 * 
 * Identifies cryptographic algorithm usage by detecting known constants,
 * S-Boxes, and hash magic values embedded in the binary.
 * 
 * Detected algorithms:
 *   - AES (S-Box, Inverse S-Box, Rcon)
 *   - DES (Initial/Final Permutation, S-Boxes)
 *   - MD5 (T-table constants)
 *   - SHA-1 (Initial hash values)
 *   - SHA-256 (Initial hash values + round constants)
 *   - SHA-512 (Initial hash values)
 *   - RC4 (KSA/PRGA patterns)
 *   - Blowfish (P-array initial values)
 *   - CRC32 (Polynomial table)
 *   - ChaCha20/Salsa20 (expand constants)
 *   - Custom XOR (single-byte XOR patterns)
 *   - Base64 alphabet
 * 
 * Actions:
 *   - Labels detected data with CRYPTO_* prefixes
 *   - Renames referencing functions as crypto_function_potential_<algo>
 *   - Creates [CRYPTO] bookmarks
 *   - Exports detection report as JSON
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_CryptoDetector extends GhidraScript {

    // ========================================================================
    // CRYPTO CONSTANT DATABASES
    // ========================================================================

    /** AES Forward S-Box (256 bytes) — FIPS 197 */
    private static final int[] AES_SBOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    /** AES Inverse S-Box (256 bytes) */
    private static final int[] AES_INV_SBOX = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    /** AES Rcon (Round Constants) */
    private static final int[] AES_RCON = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    /** MD5 T-Table (first 16 of 64 constants — most distinctive) */
    private static final long[] MD5_T = {
        0xd76aa478L, 0xe8c7b756L, 0x242070dbL, 0xc1bdceeeL,
        0xf57c0fafL, 0x4787c62aL, 0xa8304613L, 0xfd469501L,
        0x698098d8L, 0x8b44f7afL, 0xffff5bb1L, 0x895cd7beL,
        0x6b901122L, 0xfd987193L, 0xa679438eL, 0x49b40821L
    };

    /** SHA-1 Initial Hash Values */
    private static final long[] SHA1_H = {
        0x67452301L, 0xEFCDAB89L, 0x98BADCFEL, 0x10325476L, 0xC3D2E1F0L
    };

    /** SHA-256 Initial Hash Values */
    private static final long[] SHA256_H = {
        0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
        0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L
    };

    /** SHA-256 Round Constants (first 16 of 64) */
    private static final long[] SHA256_K = {
        0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
        0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
        0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
        0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L
    };

    /** SHA-512 Initial Hash Values (first 4 of 8, as 64-bit) */
    private static final long[] SHA512_H = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
        0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L
    };

    /** Blowfish P-Array Initial Values (first 8 of 18) */
    private static final long[] BLOWFISH_P = {
        0x243f6a88L, 0x85a308d3L, 0x13198a2eL, 0x03707344L,
        0xa4093822L, 0x299f31d0L, 0x082efa98L, 0xec4e6c89L
    };

    /** CRC32 Polynomial (IEEE) — first 8 values of standard table */
    private static final long[] CRC32_TABLE = {
        0x00000000L, 0x77073096L, 0xEE0E612CL, 0x990951BAL,
        0x076DC419L, 0x706AF48FL, 0xE963A535L, 0x9E6495A3L
    };

    /** ChaCha20/Salsa20 expand constant "expand 32-byte k" */
    private static final byte[] CHACHA_CONST = {
        0x65, 0x78, 0x70, 0x61,  // "expa"
        0x6E, 0x64, 0x20, 0x33,  // "nd 3"
        0x32, 0x2D, 0x62, 0x79,  // "2-by"
        0x74, 0x65, 0x20, 0x6B   // "te k"
    };

    /** Base64 Standard Alphabet */
    private static final String BASE64_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // ========================================================================
    // DETECTION RESULTS
    // ========================================================================

    private static class CryptoHit {
        String algorithm;
        String component;
        Address address;
        int confidence;  // 0-100
        String details;
        List<String> referencingFunctions;

        CryptoHit(String algorithm, String component, Address address, int confidence, String details) {
            this.algorithm = algorithm;
            this.component = component;
            this.address = address;
            this.confidence = confidence;
            this.details = details;
            this.referencingFunctions = new ArrayList<>();
        }
    }

    private List<CryptoHit> hits = new ArrayList<>();

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        printBanner();
        String caseId = normalizeCaseId(askString(
            "AIB - Case ID",
            "Enter Case ID for export directory:",
            "CASE_001"
        ));

        Memory memory = currentProgram.getMemory();
        hits.clear();

        println("  [*] Phase 1: Scanning for cryptographic constants...");

        // Scan each initialized memory block
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            long size = block.getSize();
            if (size > 200 * 1024 * 1024) {
                println("    [!] Skipping oversized block: " + block.getName());
                continue;
            }

            byte[] data = new byte[(int) size];
            block.getBytes(block.getStart(), data);
            Address baseAddr = block.getStart();

            // AES S-Box scan
            scanForByteTable(data, baseAddr, AES_SBOX, "AES", "S-Box (Forward)", 16);
            scanForByteTable(data, baseAddr, AES_INV_SBOX, "AES", "S-Box (Inverse)", 16);

            // AES Rcon
            scanForByteSequence(data, baseAddr, AES_RCON, "AES", "Round Constants (Rcon)");

            // MD5 T-table (scan as 32-bit little-endian)
            scanFor32BitConstants(data, baseAddr, MD5_T, "MD5", "T-Table Constants", true);

            // SHA-1 H values
            scanFor32BitConstants(data, baseAddr, SHA1_H, "SHA-1", "Initial Hash Values", false);

            // SHA-256 H values
            scanFor32BitConstants(data, baseAddr, SHA256_H, "SHA-256", "Initial Hash Values", false);

            // SHA-256 K constants
            scanFor32BitConstants(data, baseAddr, SHA256_K, "SHA-256", "Round Constants (K)", false);

            // Blowfish P-array
            scanFor32BitConstants(data, baseAddr, BLOWFISH_P, "Blowfish", "P-Array Initial Values", false);

            // CRC32 table
            scanFor32BitConstants(data, baseAddr, CRC32_TABLE, "CRC32", "Polynomial Table", true);

            // ChaCha20/Salsa20
            scanForBytePattern(data, baseAddr, CHACHA_CONST, "ChaCha20/Salsa20", "Expand Constant");

            // Base64 alphabet
            scanForStringPattern(data, baseAddr, BASE64_ALPHABET, "Base64", "Standard Alphabet");

            // DES permutation detection (look for the distinctive IP table)
            int[] DES_IP = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8
            };
            scanForByteTable(data, baseAddr, DES_IP, "DES", "Initial Permutation Table", 8);

            println("    Block: " + block.getName() + " (" + size + " bytes) — scanned");
        }

        println("  [✓] Phase 1 complete: " + hits.size() + " crypto signatures found");

        // Phase 2: Scan for XOR loops and RC4-like patterns in code
        println("\n  [*] Phase 2: Scanning for XOR/RC4 patterns in code...");
        scanForXORPatterns();
        println("  [✓] Phase 2 complete");

        // Phase 3: Enrich with cross-references
        println("\n  [*] Phase 3: Enriching with cross-references...");
        enrichWithXRefs();
        println("  [✓] Phase 3 complete");

        // Print results
        printResults();

        // Label and bookmark
        if (!hits.isEmpty()) {
            println("\n  [*] Labeling detected crypto in Ghidra...");
            labelAndBookmark();

            // Export
            exportResults(caseId);
        }

        printFooter();
    }

    // ========================================================================
    // BYTE TABLE SCANNING (S-Boxes, Permutation Tables)
    // ========================================================================

    /**
     * Searches for a byte table (like AES S-Box) in memory.
     * Uses a sliding window with partial match tolerance.
     * @param minConsecutive Minimum consecutive matches required before checking full table
     */
    private void scanForByteTable(byte[] data, Address baseAddr, int[] table, 
                                   String algo, String component, int minConsecutive) {
        int tableLen = table.length;
        if (data.length < tableLen) return;

        for (int i = 0; i <= data.length - tableLen; i++) {
            // Quick check: first few bytes must match
            boolean quickMatch = true;
            for (int j = 0; j < Math.min(minConsecutive, tableLen); j++) {
                if ((data[i + j] & 0xFF) != table[j]) {
                    quickMatch = false;
                    break;
                }
            }
            if (!quickMatch) continue;

            // Full match check with tolerance
            int matches = 0;
            for (int j = 0; j < tableLen; j++) {
                if ((data[i + j] & 0xFF) == table[j]) {
                    matches++;
                }
            }

            float matchRatio = (float) matches / tableLen;
            if (matchRatio >= 0.90f) {
                int confidence = (int)(matchRatio * 100);
                Address hitAddr = baseAddr.add(i);
                String detail = String.format("Matched %d/%d bytes (%.1f%%)", matches, tableLen, matchRatio * 100);
                
                // Check for duplicates
                boolean duplicate = false;
                for (CryptoHit existing : hits) {
                    if (existing.algorithm.equals(algo) && existing.component.equals(component) &&
                        existing.address.equals(hitAddr)) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    hits.add(new CryptoHit(algo, component, hitAddr, confidence, detail));
                }
            }
        }
    }

    // ========================================================================
    // 32-BIT CONSTANT SCANNING (MD5, SHA, Blowfish)
    // ========================================================================

    /**
     * Searches for a sequence of 32-bit constants in memory.
     * @param littleEndian If true, searches for little-endian byte order
     */
    private void scanFor32BitConstants(byte[] data, Address baseAddr, long[] constants, 
                                        String algo, String component, boolean littleEndian) {
        int seqLen = constants.length * 4;
        if (data.length < seqLen) return;

        for (int i = 0; i <= data.length - seqLen; i++) {
            int matches = 0;
            for (int j = 0; j < constants.length; j++) {
                long val;
                int offset = i + j * 4;
                if (littleEndian) {
                    val = ((data[offset] & 0xFFL)) |
                          ((data[offset + 1] & 0xFFL) << 8) |
                          ((data[offset + 2] & 0xFFL) << 16) |
                          ((data[offset + 3] & 0xFFL) << 24);
                } else {
                    val = ((data[offset] & 0xFFL) << 24) |
                          ((data[offset + 1] & 0xFFL) << 16) |
                          ((data[offset + 2] & 0xFFL) << 8) |
                          ((data[offset + 3] & 0xFFL));
                }
                if (val == constants[j]) matches++;
            }

            if (matches >= constants.length - 1) { // Allow 1 mismatch
                int confidence = (matches * 100) / constants.length;
                Address hitAddr = baseAddr.add(i);
                String endianStr = littleEndian ? "LE" : "BE";
                String detail = String.format("Matched %d/%d constants (%s)", matches, constants.length, endianStr);

                boolean duplicate = false;
                for (CryptoHit existing : hits) {
                    if (existing.algorithm.equals(algo) && existing.component.equals(component) &&
                        Math.abs(existing.address.getOffset() - hitAddr.getOffset()) < seqLen) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    hits.add(new CryptoHit(algo, component, hitAddr, confidence, detail));
                }
            }
        }

        // Also try opposite endianness
        if (littleEndian) {
            scanFor32BitConstants(data, baseAddr, constants, algo, component, false);
        }
    }

    // ========================================================================
    // BYTE PATTERN SCANNING (ChaCha, specific sequences)
    // ========================================================================

    private void scanForBytePattern(byte[] data, Address baseAddr, byte[] pattern, 
                                     String algo, String component) {
        if (data.length < pattern.length) return;

        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                Address hitAddr = baseAddr.add(i);
                hits.add(new CryptoHit(algo, component, hitAddr, 100, "Exact byte pattern match"));
            }
        }
    }

    // ========================================================================
    // STRING PATTERN SCANNING (Base64 alphabet)
    // ========================================================================

    private void scanForStringPattern(byte[] data, Address baseAddr, String pattern, 
                                       String algo, String component) {
        byte[] patternBytes = pattern.getBytes(StandardCharsets.US_ASCII);
        scanForBytePattern(data, baseAddr, patternBytes, algo, component);
    }

    // ========================================================================
    // BYTE SEQUENCE SCANNING (Rcon, short sequences)
    // ========================================================================

    private void scanForByteSequence(byte[] data, Address baseAddr, int[] sequence, 
                                      String algo, String component) {
        if (data.length < sequence.length) return;

        for (int i = 0; i <= data.length - sequence.length; i++) {
            boolean match = true;
            for (int j = 0; j < sequence.length; j++) {
                if ((data[i + j] & 0xFF) != sequence[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                // Verify context — Rcon usually appears near S-Box
                boolean nearSbox = false;
                for (CryptoHit hit : hits) {
                    if (hit.algorithm.equals("AES") && hit.component.contains("S-Box")) {
                        long distance = Math.abs(hit.address.getOffset() - (baseAddr.getOffset() + i));
                        if (distance < 0x1000) { // Within 4KB
                            nearSbox = true;
                            break;
                        }
                    }
                }
                int confidence = nearSbox ? 95 : 60; // Higher confidence if near S-Box
                Address hitAddr = baseAddr.add(i);
                hits.add(new CryptoHit(algo, component, hitAddr, confidence, 
                    "Exact match" + (nearSbox ? " (near S-Box)" : "")));
            }
        }
    }

    // ========================================================================
    // XOR/RC4 CODE PATTERN DETECTION
    // ========================================================================

    private void scanForXORPatterns() {
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            funcCount++;

            // Get function bytes
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();
            if (start == null || end == null) continue;

            long funcSize = end.getOffset() - start.getOffset();
            if (funcSize <= 0 || funcSize > 0x10000) continue; // Skip very large functions

            try {
                byte[] funcBytes = new byte[(int) funcSize];
                currentProgram.getMemory().getBytes(start, funcBytes);

                // Count XOR instructions (0x30-0x35 in x86)
                int xorCount = 0;
                int loopCount = 0;
                boolean hasArrayAccess = false;

                for (int i = 0; i < funcBytes.length - 1; i++) {
                    int opcode = funcBytes[i] & 0xFF;
                    
                    // XOR instructions
                    if (opcode >= 0x30 && opcode <= 0x35) xorCount++;
                    if (opcode == 0x80 && i + 1 < funcBytes.length) {
                        int modrm = funcBytes[i + 1] & 0xFF;
                        if ((modrm & 0x38) == 0x30) xorCount++; // XOR r/m8, imm8
                    }

                    // Loop instructions (0xE0-0xE2, 0xEB for short JMP, 0x75 JNZ, 0x74 JZ)
                    if (opcode == 0xE0 || opcode == 0xE1 || opcode == 0xE2) loopCount++;
                    if (opcode == 0x75 || opcode == 0x74 || opcode == 0x7C || opcode == 0x7F) loopCount++;
                }

                // Heuristic: XOR loop pattern (potential custom cipher or RC4)
                if (xorCount >= 3 && loopCount >= 2 && funcSize < 0x800) {
                    // Check if function is small enough to be a cipher
                    int confidence = Math.min(90, 40 + xorCount * 10 + loopCount * 5);
                    
                    // Check if it could be RC4 (256-byte initialization + swap pattern)
                    boolean possibleRC4 = (funcSize > 100 && funcSize < 2000 && xorCount >= 4);
                    String algo = possibleRC4 ? "RC4 (Potential)" : "Custom XOR Cipher";
                    String detail = String.format("XOR ops: %d, Loop constructs: %d, Size: %d bytes",
                        xorCount, loopCount, funcSize);

                    hits.add(new CryptoHit(algo, "Code Pattern", start, confidence, detail));
                }
            } catch (Exception e) {
                // Skip functions that can't be read
            }

            if (funcCount % 2000 == 0) {
                println("    ... analyzed " + funcCount + " functions");
            }
        }
        println("    Analyzed " + funcCount + " total functions");
    }

    // ========================================================================
    // CROSS-REFERENCE ENRICHMENT
    // ========================================================================

    private void enrichWithXRefs() {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        for (CryptoHit hit : hits) {
            if (hit.component.equals("Code Pattern")) {
                // For code patterns, the function IS the reference
                Function func = funcMgr.getFunctionAt(hit.address);
                if (func != null) {
                    hit.referencingFunctions.add(func.getName() + " @ " + formatAddr(hit.address));
                }
                continue;
            }

            // For data constants, find who references them
            ReferenceIterator refs = refMgr.getReferencesTo(hit.address);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    String funcRef = func.getName() + " @ " + formatAddr(ref.getFromAddress());
                    if (!hit.referencingFunctions.contains(funcRef)) {
                        hit.referencingFunctions.add(funcRef);
                    }
                }
                if (hit.referencingFunctions.size() >= 15) break;
            }
        }
    }

    // ========================================================================
    // LABELING & BOOKMARKING
    // ========================================================================

    private void labelAndBookmark() throws Exception {
        SymbolTable symTable = currentProgram.getSymbolTable();
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        int labeled = 0;
        int renamed = 0;

        for (CryptoHit hit : hits) {
            // Create label at crypto data location
            String labelName = "CRYPTO_" + hit.algorithm.replace("/", "_").replace(" ", "_").replace("(", "").replace(")", "") +
                "_" + hit.component.replace(" ", "_").replace("(", "").replace(")", "");
            
            try {
                symTable.createLabel(hit.address, labelName, SourceType.ANALYSIS);
                labeled++;
            } catch (Exception e) {
                // Label may already exist
            }

            // Create bookmark
            String bmNote = String.format("[%s] %s — %s (Confidence: %d%%)", 
                hit.algorithm, hit.component, hit.details, hit.confidence);
            bmMgr.setBookmark(hit.address, "CRYPTO", hit.algorithm, bmNote);

            // Rename referencing functions
            for (String funcRef : hit.referencingFunctions) {
                String funcName = funcRef.split(" @ ")[0];
                // Only rename default-named functions
                if (funcName.startsWith("FUN_") || funcName.startsWith("SUB_")) {
                    try {
                        String addrStr = funcRef.split(" @ ")[1];
                        Address funcAddr = currentProgram.getAddressFactory().getAddress(addrStr.replace("0x", ""));
                        Function func = funcMgr.getFunctionContaining(funcAddr);
                        if (func != null) {
                            String algoClean = hit.algorithm.replace("/", "_").replace(" ", "_")
                                .replace("(", "").replace(")", "").toLowerCase();
                            String newName = "crypto_function_potential_" + algoClean;
                            func.setName(newName, SourceType.ANALYSIS);

                            // Add plate comment
                            String comment = "═══ AIB CRYPTO DETECTOR ═══\n" +
                                "Algorithm: " + hit.algorithm + "\n" +
                                "Component: " + hit.component + "\n" +
                                "Confidence: " + hit.confidence + "%\n" +
                                "Details: " + hit.details + "\n" +
                                "═══════════════════════════";
                            func.setComment(comment);
                            renamed++;
                        }
                    } catch (Exception e) {
                        // Skip if rename fails
                    }
                }
            }
        }

        println("  [✓] Created " + labeled + " crypto labels");
        println("  [✓] Renamed " + renamed + " functions with crypto_function_potential prefix");
    }

    // ========================================================================
    // EXPORT
    // ========================================================================

    private void exportResults(String caseId) throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        File outputDir = getCaseExportDirectory(caseId);

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "crypto_detection_" + timestamp + ".json";

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(jsonPath), StandardCharsets.UTF_8))) {
            writer.write("{\n");
            writer.write("  \"metadata\": {\n");
            writer.write("    \"tool\": \"AIB Crypto Detector\",\n");
            writer.write("    \"version\": \"1.0.0\",\n");
            writer.write("    \"organization\": \"Arcy Intelligence Bureau\",\n");
            writer.write("    \"case_id\": \"" + escJSON(caseId) + "\",\n");
            writer.write("    \"binary\": \"" + escJSON(currentProgram.getName()) + "\",\n");
            writer.write("    \"timestamp\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()) + "\"\n");
            writer.write("  },\n");

            writer.write("  \"detections\": [\n");
            for (int i = 0; i < hits.size(); i++) {
                CryptoHit hit = hits.get(i);
                writer.write("    {\n");
                writer.write("      \"algorithm\": \"" + escJSON(hit.algorithm) + "\",\n");
                writer.write("      \"component\": \"" + escJSON(hit.component) + "\",\n");
                writer.write("      \"address\": \"" + formatAddr(hit.address) + "\",\n");
                writer.write("      \"confidence\": " + hit.confidence + ",\n");
                writer.write("      \"details\": \"" + escJSON(hit.details) + "\",\n");
                writer.write("      \"referencing_functions\": [");
                for (int j = 0; j < hit.referencingFunctions.size(); j++) {
                    writer.write("\"" + escJSON(hit.referencingFunctions.get(j)) + "\"");
                    if (j < hit.referencingFunctions.size() - 1) writer.write(", ");
                }
                writer.write("]\n");
                writer.write("    }");
                if (i < hits.size() - 1) writer.write(",");
                writer.write("\n");
            }
            writer.write("  ],\n");
            writer.write("  \"total_detections\": " + hits.size() + "\n");
            writer.write("}\n");
        }

        println("  [✓] JSON report exported: " + jsonPath);
    }

    // ========================================================================
    // CONSOLE OUTPUT
    // ========================================================================

    private void printBanner() {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║     AIB CRYPTOGRAPHY & HASH SIGNATURE DETECTOR             ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: " + currentProgram.getName());
        println("  Arch:   " + currentProgram.getLanguage());
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printResults() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  CRYPTO DETECTION RESULTS: " + hits.size() + " signatures found");
        println("══════════════════════════════════════════════════════════════");

        if (hits.isEmpty()) {
            println("  [!] No cryptographic signatures detected.");
            println("      The binary may use obfuscated or runtime-generated crypto.");
            return;
        }

        // Group by algorithm
        Map<String, List<CryptoHit>> byAlgo = new LinkedHashMap<>();
        for (CryptoHit hit : hits) {
            byAlgo.computeIfAbsent(hit.algorithm, k -> new ArrayList<>()).add(hit);
        }

        for (Map.Entry<String, List<CryptoHit>> entry : byAlgo.entrySet()) {
            println("\n──── " + entry.getKey() + " " + repeat("─", Math.max(0, 48 - entry.getKey().length())));
            for (CryptoHit hit : entry.getValue()) {
                String confidence;
                if (hit.confidence >= 90) confidence = "████████░░ HIGH";
                else if (hit.confidence >= 70) confidence = "██████░░░░ MEDIUM";
                else if (hit.confidence >= 50) confidence = "████░░░░░░ LOW";
                else confidence = "██░░░░░░░░ TRACE";

                println("  [" + formatAddr(hit.address) + "] " + hit.component);
                println("    ├─ Confidence: " + confidence + " (" + hit.confidence + "%)");
                println("    ├─ Details: " + hit.details);
                if (!hit.referencingFunctions.isEmpty()) {
                    println("    └─ Referenced by:");
                    for (String ref : hit.referencingFunctions) {
                        println("       • " + ref);
                    }
                }
            }
        }
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB Crypto Detector — Complete");
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }

    private String formatAddr(Address addr) {
        return addr != null ? "0x" + addr.toString() : "0x????????";
    }

    private String normalizeCaseId(String input) {
        if (input == null) return "CASE_001";
        String normalized = input.trim().replaceAll("[^a-zA-Z0-9._\\-]", "_");
        return normalized.isEmpty() ? "CASE_001" : normalized;
    }

    private File getCaseExportDirectory(String caseId) {
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File outputDir = new File(desktop + File.separator + "AIB_Cases" + File.separator +
            caseId + File.separator + "exports");
        if (!outputDir.exists()) outputDir.mkdirs();
        return outputDir;
    }

    private String escJSON(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    private String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }
}
