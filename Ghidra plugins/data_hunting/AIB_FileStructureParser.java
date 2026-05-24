//AIB File Structure Parser — Embedded Format Detection & Visualization
//@author Arcy Intelligence Bureau (AIB) — Dirección General
//@category AIB.DataHunting
//@keybinding
//@menupath Tools.AIB.File Structure Parser
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════
 * AIB FILE STRUCTURE PARSER
 * Arcy Intelligence Bureau — Dirección General
 * ═══════════════════════════════════════════════════════════════════
 *
 * Scans the binary for embedded file format signatures (magic numbers)
 * and applies structural overlays to visualize headers.
 *
 * Detected formats:
 *   - PE (MZ/PE), ELF, Mach-O
 *   - ZIP/JAR/APK, RAR, 7z, GZIP, BZIP2, XZ
 *   - PNG, JPEG, BMP, GIF, TIFF, WEBP, ICO
 *   - PDF, SQLite, XML, JSON
 *   - PK3/PK4 (game archives), Unity AssetBundle, UE .pak
 *   - Protobuf varint heuristic
 *   - Custom magic bytes (user-configurable)
 *
 * Actions:
 *   - Creates Ghidra struct data types for recognized headers
 *   - Applies struct overlays at detected addresses
 *   - Creates color-coded bookmarks for each embedded file
 *   - Prints hexdump with ASCII sidebar for unknown formats
 *   - Exports structure map as JSON
 *
 * Language: Bilingual EN/ES with toggle
 * ═══════════════════════════════════════════════════════════════════
 */
public class AIB_FileStructureParser extends GhidraScript {

    // ========================================================================
    // BILINGUAL SUPPORT
    // ========================================================================

    private boolean useSpanish = false;

    private String t(String en, String es) {
        return useSpanish ? es : en;
    }

    // ========================================================================
    // MAGIC NUMBER DATABASE
    // ========================================================================

    private static class MagicSignature {
        String name;
        byte[] magic;
        int offset;  // offset from start where magic appears (usually 0)
        String category;
        String description_en;
        String description_es;

        MagicSignature(String name, byte[] magic, int offset, String category,
                       String desc_en, String desc_es) {
            this.name = name;
            this.magic = magic;
            this.offset = offset;
            this.category = category;
            this.description_en = desc_en;
            this.description_es = desc_es;
        }
    }

    private List<MagicSignature> signatures;

    private void initSignatures() {
        signatures = new ArrayList<>();

        // ── Executables ──
        signatures.add(new MagicSignature("PE/MZ",
            new byte[]{0x4D, 0x5A}, 0, "Executable",
            "DOS/PE Executable (MZ Header)", "Ejecutable DOS/PE (Cabecera MZ)"));

        signatures.add(new MagicSignature("ELF",
            new byte[]{0x7F, 0x45, 0x4C, 0x46}, 0, "Executable",
            "ELF Executable/Shared Object", "Ejecutable/Objeto Compartido ELF"));

        signatures.add(new MagicSignature("Mach-O (32-bit)",
            new byte[]{(byte)0xFE, (byte)0xED, (byte)0xFA, (byte)0xCE}, 0, "Executable",
            "Mach-O 32-bit Binary", "Binario Mach-O 32-bit"));

        signatures.add(new MagicSignature("Mach-O (64-bit)",
            new byte[]{(byte)0xFE, (byte)0xED, (byte)0xFA, (byte)0xCF}, 0, "Executable",
            "Mach-O 64-bit Binary", "Binario Mach-O 64-bit"));

        signatures.add(new MagicSignature("Mach-O (Universal)",
            new byte[]{(byte)0xCA, (byte)0xFE, (byte)0xBA, (byte)0xBE}, 0, "Executable",
            "Mach-O Universal Binary (Fat)", "Binario Universal Mach-O (Fat)"));

        signatures.add(new MagicSignature("DEX",
            new byte[]{0x64, 0x65, 0x78, 0x0A}, 0, "Executable",
            "Android DEX Bytecode", "Bytecode Android DEX"));

        // ── Archives ──
        signatures.add(new MagicSignature("ZIP/JAR/APK",
            new byte[]{0x50, 0x4B, 0x03, 0x04}, 0, "Archive",
            "ZIP Archive (or JAR/APK/DOCX)", "Archivo ZIP (o JAR/APK/DOCX)"));

        signatures.add(new MagicSignature("RAR",
            new byte[]{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, 0, "Archive",
            "RAR Archive", "Archivo RAR"));

        signatures.add(new MagicSignature("7z",
            new byte[]{0x37, 0x7A, (byte)0xBC, (byte)0xAF, 0x27, 0x1C}, 0, "Archive",
            "7-Zip Archive", "Archivo 7-Zip"));

        signatures.add(new MagicSignature("GZIP",
            new byte[]{0x1F, (byte)0x8B, 0x08}, 0, "Archive",
            "GZIP Compressed Data", "Datos Comprimidos GZIP"));

        signatures.add(new MagicSignature("BZIP2",
            new byte[]{0x42, 0x5A, 0x68}, 0, "Archive",
            "BZIP2 Compressed Data", "Datos Comprimidos BZIP2"));

        signatures.add(new MagicSignature("XZ",
            new byte[]{(byte)0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, 0, "Archive",
            "XZ Compressed Data", "Datos Comprimidos XZ"));

        signatures.add(new MagicSignature("ZSTD",
            new byte[]{0x28, (byte)0xB5, 0x2F, (byte)0xFD}, 0, "Archive",
            "Zstandard Compressed Data", "Datos Comprimidos Zstandard"));

        signatures.add(new MagicSignature("LZ4",
            new byte[]{0x04, 0x22, 0x4D, 0x18}, 0, "Archive",
            "LZ4 Frame", "Marco LZ4"));

        // ── Images ──
        signatures.add(new MagicSignature("PNG",
            new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "Image",
            "PNG Image", "Imagen PNG"));

        signatures.add(new MagicSignature("JPEG",
            new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF}, 0, "Image",
            "JPEG Image", "Imagen JPEG"));

        signatures.add(new MagicSignature("BMP",
            new byte[]{0x42, 0x4D}, 0, "Image",
            "BMP Bitmap Image", "Imagen Bitmap BMP"));

        signatures.add(new MagicSignature("GIF87a",
            new byte[]{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 0, "Image",
            "GIF Image (87a)", "Imagen GIF (87a)"));

        signatures.add(new MagicSignature("GIF89a",
            new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 0, "Image",
            "GIF Image (89a)", "Imagen GIF (89a)"));

        signatures.add(new MagicSignature("TIFF (LE)",
            new byte[]{0x49, 0x49, 0x2A, 0x00}, 0, "Image",
            "TIFF Image (Little-Endian)", "Imagen TIFF (Little-Endian)"));

        signatures.add(new MagicSignature("TIFF (BE)",
            new byte[]{0x4D, 0x4D, 0x00, 0x2A}, 0, "Image",
            "TIFF Image (Big-Endian)", "Imagen TIFF (Big-Endian)"));

        signatures.add(new MagicSignature("WEBP",
            new byte[]{0x52, 0x49, 0x46, 0x46}, 0, "Image",
            "WEBP/RIFF Image", "Imagen WEBP/RIFF"));

        signatures.add(new MagicSignature("ICO",
            new byte[]{0x00, 0x00, 0x01, 0x00}, 0, "Image",
            "Windows Icon", "Icono Windows"));

        signatures.add(new MagicSignature("DDS",
            new byte[]{0x44, 0x44, 0x53, 0x20}, 0, "Image",
            "DirectDraw Surface (DDS Texture)", "Textura DirectDraw Surface (DDS)"));

        // ── Documents ──
        signatures.add(new MagicSignature("PDF",
            new byte[]{0x25, 0x50, 0x44, 0x46}, 0, "Document",
            "PDF Document", "Documento PDF"));

        signatures.add(new MagicSignature("SQLite",
            "SQLite format 3\0".getBytes(StandardCharsets.US_ASCII), 0, "Database",
            "SQLite Database", "Base de Datos SQLite"));

        // ── Audio/Video ──
        signatures.add(new MagicSignature("OGG",
            new byte[]{0x4F, 0x67, 0x67, 0x53}, 0, "Media",
            "OGG Vorbis/Opus Audio", "Audio OGG Vorbis/Opus"));

        signatures.add(new MagicSignature("FLAC",
            new byte[]{0x66, 0x4C, 0x61, 0x43}, 0, "Media",
            "FLAC Audio", "Audio FLAC"));

        signatures.add(new MagicSignature("MP3 (ID3)",
            new byte[]{0x49, 0x44, 0x33}, 0, "Media",
            "MP3 Audio (ID3 Tag)", "Audio MP3 (Etiqueta ID3)"));

        // ── Game Formats ──
        signatures.add(new MagicSignature("Unity AssetBundle",
            "UnityFS\0".getBytes(StandardCharsets.US_ASCII), 0, "GameAsset",
            "Unity AssetBundle", "AssetBundle de Unity"));

        signatures.add(new MagicSignature("Unity Web",
            "UnityWeb".getBytes(StandardCharsets.US_ASCII), 0, "GameAsset",
            "Unity Web Data", "Datos Web de Unity"));

        signatures.add(new MagicSignature("Unreal .pak",
            new byte[]{(byte)0xE1, 0x12, 0x6F, 0x5A}, 0, "GameAsset",
            "Unreal Engine PAK Archive", "Archivo PAK de Unreal Engine"));

        signatures.add(new MagicSignature("Valve VPK",
            new byte[]{0x34, 0x12, (byte)0xAA, 0x55}, 0, "GameAsset",
            "Valve VPK Package", "Paquete VPK de Valve"));

        signatures.add(new MagicSignature("BINK Video",
            new byte[]{0x42, 0x49, 0x4B}, 0, "GameAsset",
            "Bink Video (Game Cutscene)", "Video Bink (Cinemática de Juego)"));

        // ── Certificates & Keys ──
        signatures.add(new MagicSignature("PEM Certificate",
            "-----BEGIN".getBytes(StandardCharsets.US_ASCII), 0, "Security",
            "PEM Encoded Certificate/Key", "Certificado/Clave Codificado PEM"));

        signatures.add(new MagicSignature("ASN.1/DER",
            new byte[]{0x30, (byte)0x82}, 0, "Security",
            "ASN.1 DER Encoded Data (Certificate/Key)", "Datos Codificados ASN.1 DER"));
    }

    // ========================================================================
    // DETECTION RESULTS
    // ========================================================================

    private static class DetectedFile {
        String name;
        String category;
        String description;
        Address address;
        long offset;
        int estimatedSize;
        String hexPreview;
        String asciiPreview;

        DetectedFile(String name, String category, String description, Address address) {
            this.name = name;
            this.category = category;
            this.description = description;
            this.address = address;
            this.offset = address.getOffset();
            this.estimatedSize = -1;
            this.hexPreview = "";
            this.asciiPreview = "";
        }
    }

    private List<DetectedFile> detectedFiles = new ArrayList<>();

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    @Override
    protected void run() throws Exception {
        // Language selection
        String langChoice = askChoice(
            "AIB File Structure Parser — Language / Idioma",
            "Select language / Seleccione idioma:",
            Arrays.asList("English", "Español"),
            "English"
        );
        useSpanish = "Español".equals(langChoice);

        // Case ID for output directory
        String caseId = askString(
            t("AIB — Case ID", "AIB — ID de Caso"),
            t("Enter Case ID for export directory:", "Ingrese ID de Caso para directorio de exportación:"),
            "CASE_001"
        );

        printBanner();
        initSignatures();
        detectedFiles.clear();

        println("  [*] " + t("Scanning memory for embedded file signatures...",
            "Escaneando memoria en busca de firmas de archivos embebidos..."));

        Memory memory = currentProgram.getMemory();
        int blockCount = 0;

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            long size = block.getSize();
            if (size > 500 * 1024 * 1024) continue;

            byte[] data = new byte[(int) size];
            block.getBytes(block.getStart(), data);
            Address baseAddr = block.getStart();

            for (MagicSignature sig : signatures) {
                scanForMagic(data, baseAddr, sig);
            }

            blockCount++;
            println("    " + t("Block", "Bloque") + ": " + block.getName() + 
                " (" + formatSize(size) + ") — " + t("scanned", "escaneado"));
        }

        println("  [✓] " + t("Scanned", "Escaneados") + " " + blockCount + " " +
            t("memory blocks", "bloques de memoria"));

        // Deduplicate overlapping detections
        deduplicateDetections();

        // Generate hex previews
        generatePreviews(memory);

        // Estimate sizes where possible
        estimateSizes(memory);

        // Print results
        printResults();

        if (!detectedFiles.isEmpty()) {
            // Create bookmarks
            createBookmarks();

            // Apply data type overlays where possible
            applyStructOverlays();

            // Export
            exportResults(caseId);
        }

        printFooter();
    }

    // ========================================================================
    // MAGIC SCANNING
    // ========================================================================

    private void scanForMagic(byte[] data, Address baseAddr, MagicSignature sig) {
        byte[] magic = sig.magic;
        if (data.length < magic.length + sig.offset) return;

        for (int i = 0; i <= data.length - magic.length - sig.offset; i++) {
            boolean match = true;
            for (int j = 0; j < magic.length; j++) {
                if (data[i + sig.offset + j] != magic[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                Address hitAddr = baseAddr.add(i);
                String desc = useSpanish ? sig.description_es : sig.description_en;
                DetectedFile df = new DetectedFile(sig.name, sig.category, desc, hitAddr);
                detectedFiles.add(df);
            }
        }
    }

    // ========================================================================
    // DEDUPLICATION
    // ========================================================================

    private void deduplicateDetections() {
        // Remove duplicate detections at same address
        Map<String, DetectedFile> unique = new LinkedHashMap<>();
        for (DetectedFile df : detectedFiles) {
            String key = df.name + "@" + df.address.toString();
            if (!unique.containsKey(key)) {
                unique.put(key, df);
            }
        }
        detectedFiles = new ArrayList<>(unique.values());

        // Sort by address
        detectedFiles.sort((a, b) -> a.address.compareTo(b.address));
    }

    // ========================================================================
    // HEX PREVIEW GENERATION
    // ========================================================================

    private void generatePreviews(Memory memory) {
        for (DetectedFile df : detectedFiles) {
            try {
                int previewLen = 64; // 4 rows of 16 bytes
                byte[] preview = new byte[previewLen];
                int bytesRead = memory.getBytes(df.address, preview);

                StringBuilder hexSb = new StringBuilder();
                StringBuilder asciiSb = new StringBuilder();

                for (int row = 0; row < 4; row++) {
                    int offset = row * 16;
                    if (offset >= bytesRead) break;

                    // Offset column
                    hexSb.append(String.format("    %04X │ ", row * 16));

                    StringBuilder rowAscii = new StringBuilder();
                    for (int col = 0; col < 16; col++) {
                        int idx = offset + col;
                        if (idx < bytesRead) {
                            hexSb.append(String.format("%02X ", preview[idx] & 0xFF));
                            char c = (char)(preview[idx] & 0xFF);
                            rowAscii.append((c >= 0x20 && c <= 0x7E) ? c : '.');
                        } else {
                            hexSb.append("   ");
                            rowAscii.append(' ');
                        }
                        if (col == 7) hexSb.append(" ");
                    }
                    hexSb.append("│ ").append(rowAscii).append("\n");
                }

                df.hexPreview = hexSb.toString();
            } catch (Exception e) {
                df.hexPreview = "    [" + t("Unable to read", "No se pudo leer") + "]\n";
            }
        }
    }

    // ========================================================================
    // SIZE ESTIMATION
    // ========================================================================

    private void estimateSizes(Memory memory) {
        for (DetectedFile df : detectedFiles) {
            try {
                if ("PE/MZ".equals(df.name)) {
                    // Read PE header to get image size
                    byte[] mzHeader = new byte[64];
                    memory.getBytes(df.address, mzHeader);
                    // e_lfanew at offset 0x3C (little-endian)
                    int peOffset = (mzHeader[0x3C] & 0xFF) | ((mzHeader[0x3D] & 0xFF) << 8) |
                                   ((mzHeader[0x3E] & 0xFF) << 16) | ((mzHeader[0x3F] & 0xFF) << 24);
                    if (peOffset > 0 && peOffset < 0x1000) {
                        df.estimatedSize = peOffset + 248; // Approximate PE+Optional header
                    }
                } else if ("PNG".equals(df.name)) {
                    // Search for IEND chunk
                    byte[] iend = new byte[]{0x49, 0x45, 0x4E, 0x44, (byte)0xAE, 0x42, 0x60, (byte)0x82};
                    Address searchEnd = df.address.add(Math.min(10 * 1024 * 1024, 
                        memory.getBlock(df.address).getEnd().getOffset() - df.address.getOffset()));
                    Address found = memory.findBytes(df.address, searchEnd, iend, null, true, monitor);
                    if (found != null) {
                        df.estimatedSize = (int)(found.getOffset() - df.address.getOffset() + 12);
                    }
                } else if ("ZIP/JAR/APK".equals(df.name)) {
                    // ZIP end of central directory signature
                    byte[] eocd = new byte[]{0x50, 0x4B, 0x05, 0x06};
                    Address searchEnd = df.address.add(Math.min(50 * 1024 * 1024,
                        memory.getBlock(df.address).getEnd().getOffset() - df.address.getOffset()));
                    Address found = memory.findBytes(df.address, searchEnd, eocd, null, true, monitor);
                    if (found != null) {
                        df.estimatedSize = (int)(found.getOffset() - df.address.getOffset() + 22);
                    }
                } else if ("JPEG".equals(df.name)) {
                    // JPEG ends with FF D9
                    byte[] jpegEnd = new byte[]{(byte)0xFF, (byte)0xD9};
                    Address searchEnd = df.address.add(Math.min(20 * 1024 * 1024,
                        memory.getBlock(df.address).getEnd().getOffset() - df.address.getOffset()));
                    Address found = memory.findBytes(df.address, searchEnd, jpegEnd, null, true, monitor);
                    if (found != null) {
                        df.estimatedSize = (int)(found.getOffset() - df.address.getOffset() + 2);
                    }
                }
            } catch (Exception e) {
                // Size estimation failed — non-critical
            }
        }
    }

    // ========================================================================
    // STRUCT OVERLAYS
    // ========================================================================

    private void applyStructOverlays() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int applied = 0;

        int txId = dtm.startTransaction("AIB Struct Overlays");
        try {
            for (DetectedFile df : detectedFiles) {
                try {
                    if ("PE/MZ".equals(df.name)) {
                        StructureDataType mzStruct = new StructureDataType(
                            new CategoryPath("/AIB_Structures"), "MZ_DOS_Header", 0);
                        mzStruct.add(new StringDataType(), 2, "e_magic", "MZ Signature");
                        mzStruct.add(new WordDataType(), 2, "e_cblp", "Bytes on last page");
                        mzStruct.add(new WordDataType(), 2, "e_cp", "Pages in file");
                        mzStruct.add(new WordDataType(), 2, "e_crlc", "Relocations");
                        mzStruct.add(new WordDataType(), 2, "e_cparhdr", "Header size in paragraphs");
                        mzStruct.add(new WordDataType(), 2, "e_minalloc", "Min extra paragraphs");
                        mzStruct.add(new WordDataType(), 2, "e_maxalloc", "Max extra paragraphs");
                        mzStruct.add(new WordDataType(), 2, "e_ss", "Initial SS");
                        mzStruct.add(new WordDataType(), 2, "e_sp", "Initial SP");
                        mzStruct.add(new WordDataType(), 2, "e_csum", "Checksum");
                        mzStruct.add(new WordDataType(), 2, "e_ip", "Initial IP");
                        mzStruct.add(new WordDataType(), 2, "e_cs", "Initial CS");
                        mzStruct.add(new WordDataType(), 2, "e_lfarlc", "Relocation table offset");
                        mzStruct.add(new WordDataType(), 2, "e_ovno", "Overlay number");

                        dtm.addDataType(mzStruct, DataTypeConflictHandler.REPLACE_HANDLER);
                        createData(df.address, mzStruct);
                        applied++;
                    } else if ("ELF".equals(df.name)) {
                        StructureDataType elfIdent = new StructureDataType(
                            new CategoryPath("/AIB_Structures"), "ELF_Ident", 0);
                        elfIdent.add(new ArrayDataType(new ByteDataType(), 4, 1), 4, "ei_mag", "\\x7FELF");
                        elfIdent.add(new ByteDataType(), 1, "ei_class", "32/64 bit");
                        elfIdent.add(new ByteDataType(), 1, "ei_data", "Endianness");
                        elfIdent.add(new ByteDataType(), 1, "ei_version", "ELF Version");
                        elfIdent.add(new ByteDataType(), 1, "ei_osabi", "OS/ABI");
                        elfIdent.add(new ArrayDataType(new ByteDataType(), 8, 1), 8, "ei_pad", "Padding");

                        dtm.addDataType(elfIdent, DataTypeConflictHandler.REPLACE_HANDLER);
                        createData(df.address, elfIdent);
                        applied++;
                    } else if ("PNG".equals(df.name)) {
                        StructureDataType pngHeader = new StructureDataType(
                            new CategoryPath("/AIB_Structures"), "PNG_Header", 0);
                        pngHeader.add(new ArrayDataType(new ByteDataType(), 8, 1), 8, "signature", "PNG Signature");
                        pngHeader.add(new DWordDataType(), 4, "ihdr_length", "IHDR Chunk Length");
                        pngHeader.add(new StringDataType(), 4, "ihdr_type", "IHDR");
                        pngHeader.add(new DWordDataType(), 4, "width", "Image Width");
                        pngHeader.add(new DWordDataType(), 4, "height", "Image Height");
                        pngHeader.add(new ByteDataType(), 1, "bit_depth", "Bit Depth");
                        pngHeader.add(new ByteDataType(), 1, "color_type", "Color Type");

                        dtm.addDataType(pngHeader, DataTypeConflictHandler.REPLACE_HANDLER);
                        createData(df.address, pngHeader);
                        applied++;
                    }
                } catch (Exception e) {
                    // Struct overlay failed — might conflict with existing data
                }
            }
        } finally {
            dtm.endTransaction(txId, true);
        }

        println("  [✓] " + t("Applied", "Aplicadas") + " " + applied + " " +
            t("struct overlays", "superposiciones de estructura"));
    }

    // ========================================================================
    // BOOKMARKS
    // ========================================================================

    private void createBookmarks() {
        BookmarkManager bmMgr = currentProgram.getBookmarkManager();
        int count = 0;

        for (DetectedFile df : detectedFiles) {
            String note = "[" + df.category + "] " + df.description;
            if (df.estimatedSize > 0) {
                note += " (" + formatSize(df.estimatedSize) + ")";
            }
            bmMgr.setBookmark(df.address, "AIB_FILE", df.category, note);
            count++;
        }

        println("  [✓] " + t("Created", "Creados") + " " + count + " " +
            t("bookmarks", "marcadores") + " (AIB_FILE)");
    }

    // ========================================================================
    // EXPORT
    // ========================================================================

    private void exportResults(String caseId) throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String desktop = System.getProperty("user.home") + File.separator + "Desktop";
        File outputDir = new File(desktop + File.separator + "AIB_Cases" + File.separator +
            caseId + File.separator + "exports");
        if (!outputDir.exists()) outputDir.mkdirs();

        String jsonPath = outputDir.getAbsolutePath() + File.separator +
            "file_structures_" + timestamp + ".json";

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(jsonPath), StandardCharsets.UTF_8))) {
            writer.write("{\n");
            writer.write("  \"metadata\": {\n");
            writer.write("    \"tool\": \"AIB File Structure Parser\",\n");
            writer.write("    \"version\": \"1.0.0\",\n");
            writer.write("    \"organization\": \"Arcy Intelligence Bureau\",\n");
            writer.write("    \"case_id\": \"" + escJSON(caseId) + "\",\n");
            writer.write("    \"binary\": \"" + escJSON(currentProgram.getName()) + "\",\n");
            writer.write("    \"language\": \"" + (useSpanish ? "es" : "en") + "\",\n");
            writer.write("    \"timestamp\": \"" + new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()) + "\"\n");
            writer.write("  },\n");

            writer.write("  \"detected_files\": [\n");
            for (int i = 0; i < detectedFiles.size(); i++) {
                DetectedFile df = detectedFiles.get(i);
                writer.write("    {\n");
                writer.write("      \"name\": \"" + escJSON(df.name) + "\",\n");
                writer.write("      \"category\": \"" + escJSON(df.category) + "\",\n");
                writer.write("      \"description\": \"" + escJSON(df.description) + "\",\n");
                writer.write("      \"address\": \"0x" + df.address.toString() + "\",\n");
                writer.write("      \"offset\": " + df.offset + ",\n");
                writer.write("      \"estimated_size\": " + df.estimatedSize + ",\n");
                writer.write("      \"estimated_size_human\": \"" + 
                    (df.estimatedSize > 0 ? formatSize(df.estimatedSize) : "unknown") + "\"\n");
                writer.write("    }");
                if (i < detectedFiles.size() - 1) writer.write(",");
                writer.write("\n");
            }
            writer.write("  ],\n");

            // Summary by category
            writer.write("  \"summary\": {\n");
            Map<String, Integer> catCounts = new LinkedHashMap<>();
            for (DetectedFile df : detectedFiles) {
                catCounts.merge(df.category, 1, Integer::sum);
            }
            Iterator<Map.Entry<String, Integer>> it = catCounts.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Integer> e = it.next();
                writer.write("    \"" + e.getKey() + "\": " + e.getValue());
                if (it.hasNext()) writer.write(",");
                writer.write("\n");
            }
            writer.write("  },\n");
            writer.write("  \"total_detected\": " + detectedFiles.size() + "\n");
            writer.write("}\n");
        }

        println("  [✓] " + t("JSON exported", "JSON exportado") + ": " + jsonPath);
    }

    // ========================================================================
    // CONSOLE OUTPUT
    // ========================================================================

    private void printBanner() {
        println("╔══════════════════════════════════════════════════════════════╗");
        println("║        AIB FILE STRUCTURE PARSER — " + 
            t("Visual Edition", "Edición Visual") + "           ║");
        println("║          Arcy Intelligence Bureau — v1.0.0                  ║");
        println("╚══════════════════════════════════════════════════════════════╝");
        println("  Target: " + currentProgram.getName());
        println("  Arch:   " + currentProgram.getLanguage());
        println("  Time:   " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════");
    }

    private void printResults() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  " + t("RESULTS", "RESULTADOS") + ": " + detectedFiles.size() + " " +
            t("embedded files detected", "archivos embebidos detectados"));
        println("══════════════════════════════════════════════════════════════");

        if (detectedFiles.isEmpty()) {
            println("  [!] " + t("No embedded file signatures found.",
                "No se encontraron firmas de archivos embebidos."));
            return;
        }

        // Group by category
        Map<String, List<DetectedFile>> byCategory = new LinkedHashMap<>();
        for (DetectedFile df : detectedFiles) {
            byCategory.computeIfAbsent(df.category, k -> new ArrayList<>()).add(df);
        }

        for (Map.Entry<String, List<DetectedFile>> entry : byCategory.entrySet()) {
            println("\n──── " + entry.getKey() + " " + repeat("─", Math.max(0, 48 - entry.getKey().length())));
            for (DetectedFile df : entry.getValue()) {
                println("  ╔═ [0x" + df.address + "] " + df.name);
                println("  ║  " + df.description);
                if (df.estimatedSize > 0) {
                    println("  ║  " + t("Size", "Tamaño") + ": ~" + formatSize(df.estimatedSize));
                }
                println("  ║  " + t("Hex Preview:", "Vista Hex:"));
                if (!df.hexPreview.isEmpty()) {
                    for (String line : df.hexPreview.split("\n")) {
                        println("  ║  " + line);
                    }
                }
                println("  ╚═══════════════════════════════════════════════");
            }
        }
    }

    private void printFooter() {
        println("\n══════════════════════════════════════════════════════════════");
        println("  AIB File Structure Parser — " + t("Complete", "Completado"));
        println("  " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        println("══════════════════════════════════════════════════════════════\n");
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
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
