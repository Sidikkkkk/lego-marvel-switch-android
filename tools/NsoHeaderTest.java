package org.sidikkkkk.switchport;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

public final class NsoHeaderTest {
    private static final int MODULE_SIZE = 0x14c;

    public static void main(String[] arguments) throws Exception {
        if (arguments.length == 1) {
            Path path = Path.of(arguments[0]);
            try (var input = Files.newInputStream(path)) {
                System.out.println(NsoHeader.inspect(input, Files.size(path)));
            }
            return;
        }

        byte[] valid = fixture().array();
        String report = NsoHeader.inspect(new ByteArrayInputStream(valid), valid.length);
        require(report.contains("1234" + "0".repeat(60)), "Build ID");
        require(report.contains("12 byte tersimpan, 32 byte di memori (terkompresi)"), "Compression");
        require(report.contains("(terkompresi)\nSHA-256 sesuai header"), "Decoded data hash");
        require(report.contains("SHA-256 tidak tersedia di header"), "Optional hash");
        require(NsoHeader.inspect(new ByteArrayInputStream(valid), -1)
                .contains("Semua segmen berhasil dibaca"), "Unknown file length");
        expectError(new byte[255], 255, "Header NSO0 terpotong");
        expectError(new byte[MODULE_SIZE], MODULE_SIZE, "Magic NSO0");
        expectError(valid, MODULE_SIZE - 1, "File NSO0 terpotong");
        expectError(Arrays.copyOf(valid, MODULE_SIZE - 1), -1, "Segmen .data terpotong");
        expectError(fixture().putInt(0x20, 0x110).array(), MODULE_SIZE, "bertumpang tindih");
        expectError(fixture().putInt(0x34, 0xfffffff0).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().putInt(0x68, 0).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().putInt(0x10, 0xff).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().put(0x100, (byte) 0).array(), MODULE_SIZE, "Segmen .text: SHA-256 berbeda");
        expectError(fixture().put(0x14b, (byte) 0).array(), MODULE_SIZE, "Segmen .data: SHA-256 berbeda");
        expectError(fixture().put(0x143, (byte) 0).array(), MODULE_SIZE, "Offset salinan LZ4 tidak valid");
        expectError(fixture().put(0x143, (byte) 3).array(), MODULE_SIZE, "Offset salinan LZ4 tidak valid");
        expectError(fixture().putInt(0x38, 33).array(), MODULE_SIZE, "ukuran hasil LZ4 tidak valid");
        expectError(fixture().put(0x145, (byte) 0xff).array(), MODULE_SIZE, "Panjang LZ4 melampaui");

        byte[] reordered = fixture().putInt(0x10, 0x120).putInt(0x20, 0x100).array();
        System.arraycopy(valid, 0x100, reordered, 0x120, 0x20);
        System.arraycopy(valid, 0x120, reordered, 0x100, 0x20);
        require(NsoHeader.inspect(new ByteArrayInputStream(reordered), reordered.length)
                .contains("Segmen NSO0 berhasil diperiksa"), "File offsets out of segment order");
        byte[] empty = module(new byte[]{0}, new byte[0]).array();
        require(NsoHeader.inspect(new ByteArrayInputStream(empty), empty.length)
                .contains("1 byte tersimpan, 0 byte di memori"), "Empty LZ4 block");
        byte[] wrapsHistory = largeMatchFixture();
        require(NsoHeader.inspect(new ByteArrayInputStream(wrapsHistory), wrapsHistory.length)
                .contains("(terkompresi)\nSHA-256 sesuai header"), "Match crosses history buffer boundary");
        require(report.contains(".bss [0x2020, 0x2020)  0 byte"), "Zero-sized BSS");
        byte[] withBss = fixture().putInt(0x3c, 0x123).array();
        String memoryReport = NsoHeader.inspect(new ByteArrayInputStream(withBss), withBss.length);
        require(memoryReport.contains(".bss [0x2020, 0x2143)  291 byte"), "BSS starts after decoded data");
        require(memoryReport.contains("Rentang dari base [0x0, 0x2143)  8515 byte"), "Unrounded image span");
        require(memoryReport.contains("Segmen dan .bss  387 byte\nCelah dalam rentang  8128 byte"),
                "Occupied bytes and gaps");
        expectError(fixture().putInt(0x24, 0x2040).putInt(0x3c, 0x40).array(), MODULE_SIZE,
                ".bss bertumpang tindih dengan .rodata");
        expectError(fixture().putInt(0x34, 0xffffffd0).putInt(0x3c, 0x11).array(), MODULE_SIZE,
                ".bss melampaui batas offset");
        byte[] endAtLimit = fixture().putInt(0x34, 0xffffffd0).putInt(0x3c, 0x10).array();
        require(NsoHeader.inspect(new ByteArrayInputStream(endAtLimit), endAtLimit.length)
                .contains(".bss [0xfffffff0, 0x100000000)  16 byte"), "Exclusive end at offset limit");
        byte[] emptyAtEnd = module(new byte[]{0}, new byte[0]).putInt(0x34, 0xfffffff0).array();
        require(NsoHeader.inspect(new ByteArrayInputStream(emptyAtEnd), emptyAtEnd.length)
                .contains("Rentang dari base [0x0, 0x1020)"), "Empty segment does not enlarge image span");

        byte[] forLoad = withBss.clone();
        Arrays.fill(forLoad, 0x120, 0x140, (byte) 'R');
        NsoHeader.Inspection loaded = NsoHeader.inspect(new ByteArrayInputStream(forLoad), forLoad.length, 0x2143);
        ByteBuffer image = loaded.memoryImage();
        require(image != null && image.remaining() == 0x2143, "Image span fits exact budget");
        require(loaded.report().contains("Muat segmen ke buffer RAM berhasil (8515 byte)"), "Image load report");
        require(image.isReadOnly(), "Verified image is read-only");
        byte[] expectedImage = new byte[0x2143];
        Arrays.fill(expectedImage, 0, 0x20, (byte) 'T');
        Arrays.fill(expectedImage, 0x1000, 0x1020, (byte) 'R');
        byte[] expectedData = "AB".repeat(13).concat("ACDEFG").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(expectedData, 0, expectedImage, 0x2000, expectedData.length);
        require(image.equals(ByteBuffer.wrap(expectedImage)), "Raw and LZ4 data placement, zero BSS and gaps");

        NsoHeader.Inspection skipped = NsoHeader.inspect(new ByteArrayInputStream(forLoad), forLoad.length, 0x2142);
        require(skipped.memoryImage() == null && skipped.report().contains("Muat ke RAM dilewati")
                && skipped.report().contains("SHA-256 sesuai header"), "Low budget keeps streaming validation");
        require(NsoHeader.inspect(new ByteArrayInputStream(endAtLimit), endAtLimit.length, Long.MAX_VALUE)
                .memoryImage() == null, "Image greater than an int-sized byte buffer is skipped");
        require(NsoHeader.inspect(new ByteArrayInputStream(emptyAtEnd), emptyAtEnd.length, 0x1020)
                .memoryImage().remaining() == 0x1020, "Empty segment outside image requires no write view");

        ByteBuffer largeImage = NsoHeader.inspect(new ByteArrayInputStream(wrapsHistory),
                wrapsHistory.length, 100_000).memoryImage();
        byte[] expectedLargeData = new byte[70_007];
        Arrays.fill(expectedLargeData, (byte) 'A');
        largeImage.position(0x2000);
        require(largeImage.equals(ByteBuffer.wrap(expectedLargeData)), "Staged decoded bytes across the LZ4 history wrap");
        expectError(fixture().put(0x14b, (byte) 0).array(), MODULE_SIZE, 0x2020, "Segmen .data: SHA-256 berbeda");
        require(loaded.report().contains("MOD0 tidak terdeteksi"), "Staged module without a MOD0 header");
        String metadata = inspectMetadata(dynamicFixture());
        require(metadata.contains("MOD0 0x2180, .dynamic 0x2000 (13 entri)"), "Signed MOD0 dynamic offset");
        require(metadata.contains("Dependensi DT_NEEDED  2\n  sdk.nso\n  rtld.nso"), "Dependency string offsets");
        require(metadata.contains("Relokasi RELA  2 entri"), "RELA table count");
        require(metadata.contains("Relokasi RELR  2 entri"), "RELR table word count");
        require(metadata.contains("Relokasi PLT RELA  1 entri"), "PLT format and table count");
        expectMetadataError(dynamicFixture().putInt(0x384, 0x80), "Rentang .dynamic di luar data segmen");
        ByteBuffer unterminatedDynamic = dynamicFixture();
        for (int position = 0x2d0; position < 0x400; position += 16) {
            if (position != 0x380) {
                unterminatedDynamic.putLong(position, 0x70000000L);
            }
        }
        expectMetadataError(unterminatedDynamic, "DT_NULL tidak ditemukan");
        expectMetadataError(dynamicFixture().putInt(0x104, 0x3c).putInt(0x13c, 0x30444f4d),
                "Header MOD0 terpotong");
        expectMetadataError(dynamicFixture().putLong(0x228, 0x10bf), "Rentang DT_STRTAB di luar data segmen");
        expectMetadataError(dynamicFixture().putLong(0x238, 17), "Nama DT_NEEDED tidak diakhiri NUL");
        expectMetadataError(dynamicFixture().putLong(0x258, 49), "Ukuran tabel relokasi RELA tidak valid");
        String relocations = inspectMetadata(relocationFixture());
        require(relocations.contains("R_AARCH64_RELATIVE  1 entri"), "RELA relative type");
        require(relocations.contains("R_AARCH64_GLOB_DAT  1 entri"), "RELA symbol type");
        require(relocations.contains("R_AARCH64_JUMP_SLOT  1 entri"), "PLT type");
        require(relocations.contains("Referensi simbol impor  2 entri")
                && relocations.contains("#1 imp_func\n")
                && relocations.indexOf("#1 imp_func") == relocations.lastIndexOf("#1 imp_func"),
                "Two references to one sampled import");
        String defined = inspectMetadata(relocationFixture().putLong(0x318, (2L << 32) | 257));
        require(defined.contains("R_AARCH64_ABS64  1 entri")
                && defined.contains("Referensi simbol  3 entri\nReferensi simbol impor  2 entri"),
                "A defined symbol is excluded from imports");
        require(inspectMetadata(relocationFixture().putInt(0x9c, 0))
                .contains("#1 imp_func"), "SysV DT_HASH bounds the symbol table without an NSO extent");
        require(inspectMetadata(relocationFixture().putInt(0x9c, 0).putLong(0x2f8, 0x5000))
                .contains("batas .dynsym atau .dynstr belum terverifikasi"), "Unbounded names are not inspected");
        require(inspectMetadata(relocationFixture().putLong(0x348, (3L << 32) | 1026))
                .contains("Indeks simbol di luar tabel  1 entri"), "Out-of-range symbol index is reported");
        require(inspectMetadata(relocationFixture().putLong(0x318, 0xffff_ffffL))
                .contains("Tipe 4294967295  1 entri"), "Unknown relocation type remains unsigned");
        require(inspectMetadata(relocationFixture().putInt(0x180, -1))
                .contains("#1 (nama tidak tersedia)"), "Invalid name index cannot escape the string table");
        testRelativeRelocations();
        testImportAudit();
        testRelocationBoundaryEvidence();
        testWeakGotSimulation();
        testImportBindingSimulation();
        testStartupTrace();
        testStartupRegisterSimulation();
        testStartupMemoryRead();
        System.out.println("NSO checks passed.");
    }

    private static void testImportBindingSimulation() throws IOException {
        ByteBuffer main = relocationFixture().putLong(0x310, 0x21c0);
        main.put(0x184, (byte) 0x12).putLong(0x328, 0x21c8).putLong(0x338, -8).putLong(0x340, 0x21d0);
        main.putLong(0x3c8, 0xabcdef).putLong(0x3d0, 0x123456);
        ByteBuffer provider = relocationFixture().put(0x184, (byte) 0x12).putShort(0x186, (short) 1);
        provider.putLong(0x188, 0x20);
        String report = bindingReport(main, provider);
        require(report.contains("2 dari 2 referensi kandidat tunggal diuji.")
                && report.contains("ABS64 0 | GLOB_DAT 1 | JUMP_SLOT 1")
                && report.contains("imp_func → sdk @0x21c8 = 0x200000018")
                && report.contains("imp_func → sdk @0x21d0 = 0x200000020")
                && main.getLong(0x3c8) == 0xabcdef && main.getLong(0x3d0) == 0x123456,
                "Unique function definition, signed addend, and preserved source bytes");

        provider.put(0x184, (byte) 0x10);
        require(bindingReport(main, provider).contains("JUMP_SLOT ke ekspor STT_NOTYPE sejajar di .text  1"),
                "An aligned executable NOTYPE address is eligible for the numeric slot simulation");
        require(bindingReport(main, provider.putLong(0x188, 0x2000))
                .contains("ekspor tipe 0 di st_value 0x2000 tidak menunjukkan instruksi sejajar di .text"),
                "NOTYPE data never becomes a jump target");
        require(bindingReport(main, provider.putLong(0x188, 0x21))
                .contains("ekspor tipe 0 di st_value 0x21 tidak menunjukkan instruksi sejajar di .text"),
                "A misaligned NOTYPE address never becomes a jump target");
        provider.put(0x184, (byte) 0x12).putLong(0x188, 0x20);

        main.putLong(0x330, (1L << 32) | 257).putLong(0x350, 1);
        report = bindingReport(main, provider);
        require(report.contains("1 dari 2 referensi kandidat tunggal diuji.")
                && report.contains("ABS64 1 | GLOB_DAT 0 | JUMP_SLOT 0")
                && report.contains("R_AARCH64_JUMP_SLOT entri 0x2140 target 0x21d0 — addend JUMP_SLOT bukan nol (1)"),
                "ABS64 is simulated while JUMP_SLOT with a nonzero addend is skipped");

        main.putLong(0x350, 0).putLong(0x340, 0x21c8);
        require(bindingReport(main, provider).contains("0 dari 2 referensi kandidat tunggal diuji."),
                "Conflicting offsets are not used");
        main.putLong(0x340, 0x21d0);
        require(bindingReport(main, provider.putLong(0x188, 0x9000))
                .contains("0 dari 2 referensi kandidat tunggal diuji."), "Export address must be mapped");
        provider.putLong(0x188, 0x20).putInt(0x198, 18).put(0x19c, (byte) 0x12).putLong(0x1a0, 0x24);
        require(bindingReport(main, provider).contains("0 dari 2 referensi kandidat tunggal diuji."),
                "A single module with conflicting exports is not used");
    }

    private static void testStartupTrace() throws IOException {
        ByteBuffer main = relocationFixture().putLong(0x310, 0x21c0);
        ByteBuffer rtld = relocationFixture().putInt(0x100, 0x14000002).putInt(0x108, 0x94000003)
                .putInt(0x114, 0x17ffffff).putInt(0x110, 0xd503201f);
        NsoImportAudit audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(rtld, audit, "rtld");
        String report = audit.report();
        require(report.contains("0x200000000 B → 0x200000008\n  0x200000008 BL → 0x200000014 (X30 = 0x20000000c)")
                && report.contains("0x200000014 B → 0x200000010\n  0x200000010 kata 0xd503201f — jejak berhenti")
                && report.contains("main basis 0x100000000\n    .text [0x100000000, 0x100000040)")
                && report.contains("rtld basis 0x200000000\n    .text [0x200000000, 0x200000040)"),
                "Branch sign extension, link register, unsupported instruction, and shared simulated bases");

        audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(rtld.putInt(0x100, 0x14000010), audit, "rtld");
        require(audit.report().contains("0x200000000 B → 0x200000040\nJejak berhenti. Target di luar .text rtld."),
                "Branches cannot read past the end of .text");
    }

    private static void testStartupRegisterSimulation() throws IOException {
        ByteBuffer main = relocationFixture().putLong(0x310, 0x21c0);
        ByteBuffer rtld = relocationFixture().putInt(0x100, 0x14000002).putInt(0x108, 0xf100001f)
                .putInt(0x10c, 0x540000c1).putInt(0x110, 0x54000040).putInt(0x118, 0x10000042)
                .putInt(0x11c, 0x91002043).putInt(0x120, 0xb0000004).putInt(0x124, 0xd4000001);
        NsoImportAudit audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(rtld, audit, "rtld");
        String report = audit.report();
        require(report.contains("0x200000008 CMP X0, #0x0 (NZCV = 0x6)")
                && report.contains("0x20000000c B.NE → 0x200000024 (tidak diambil)")
                && report.contains("0x200000010 B.EQ → 0x200000018 (diambil)")
                && report.contains("0x200000018 ADR X2 = 0x200000020")
                && report.contains("0x20000001c ADD X3, X2 = 0x200000028")
                && report.contains("0x200000020 ADRP X4 = 0x200001000")
                && report.contains("0x200000024 kata 0xd4000001 — jejak berhenti")
                && report.contains("Kata .text mulai 0x200000024"),
                "Flags, taken and untaken branches, register arithmetic, and stop before a system call");
        audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(rtld.putInt(0x108, 0xf100003f), audit, "rtld");
        require(audit.report().contains("CMP X1, #0x0 — jejak berhenti, nilai register belum diketahui.")
                && !audit.report().contains("0x20000000c B.NE"), "Unknown thread handle never picks a branch");
    }

    private static String bindingReport(ByteBuffer main, ByteBuffer provider) throws IOException {
        NsoImportAudit audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(provider, audit, "sdk");
        return audit.report();
    }

    private static void testStartupMemoryRead() throws IOException {
        ByteBuffer main = relocationFixture().putLong(0x310, 0x21c0);
        ByteBuffer rtld = relocationFixture().putInt(0x100, 0x14000002).putInt(0x108, 0xf100001f)
                .putInt(0x10c, 0x540000c1).putInt(0x110, 0x2a0103f3).putInt(0x114, 0x94000002)
                .putInt(0x118, 0x21e8).putInt(0x11c, 0xb94003c0).putInt(0x120, 0x93407c00)
                .putInt(0x124, 0x8b1e0000).putInt(0x128, 0xf9400005).putInt(0x12c, 0xf100027f);
        NsoImportAudit audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(rtld, audit, "rtld");
        String report = audit.report();
        require(report.contains("MOV W19, W1 = belum diketahui")
                && report.contains("0x200000014 BL → 0x20000001c (X30 = 0x200000018)")
                && report.contains("LDR W0, [X30, #0x0] @0x200000018 = 0x21e8")
                && report.contains("SXTW X0, W0 = 0x21e8")
                && report.contains("ADD X0, X0, X30 = 0x200002200 (awal .bss rtld)")
                && report.contains("LDR X5, [X0, #0x0] @0x200002200 = 0x0")
                && report.contains("CMP X19, #0x0 — jejak berhenti, nilai register belum diketahui"),
                "Inline data, tracked unknown handle, and a read within the zeroed BSS buffer");

        audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(rtld.putInt(0x118, 0xffff_fffc), audit, "rtld");
        report = audit.report();
        require(report.contains("LDR W0, [X30, #0x0] @0x200000018 = 0xfffffffc")
                && report.contains("SXTW X0, W0 = 0xfffffffffffffffc")
                && report.contains("ADD X0, X0, X30 = 0x200000014")
                && report.contains("@0x200000014 — jejak berhenti, alamat di luar rentang baca rtld yang sejajar"),
                "Word zero extension, signed extension, and rejection of a misaligned doubleword");

        audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(rtld.putInt(0x118, 0x0fe0), audit, "rtld");
        require(audit.report().contains("@0x200000ff8 — jejak berhenti, alamat di luar rentang baca rtld yang sejajar"),
                "A read in a gap between mapped segments must stop even if it fits in the backing array");
    }

    private static void testWeakGotSimulation() throws IOException {
        ByteBuffer main = relocationFixture().putLong(0x310, 0x21c0);
        main.position(0x152).put("__rel_dyn_start\0".getBytes(StandardCharsets.US_ASCII));
        main.put(0x184, (byte) 0x20).putLong(0x328, 0x21e0).putLong(0x348, (2L << 32) | 1026);
        main.putLong(0x3e0, 0x123456789abcdefL);
        ByteBuffer provider = relocationFixture();
        provider.position(0x152).put("__rel_dyn_start\0".getBytes(StandardCharsets.US_ASCII));

        NsoImportAudit audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        require(audit.report().contains("Pemindaian ekspor modul belum lengkap"), "No module means no test");
        compareExportModule(provider, audit, "sdk");
        require(audit.report().contains("__rel_dyn_start @0x21e0  0x123456789abcdef → 0x0\n1 slot diuji.")
                && main.getLong(0x3e0) == 0x123456789abcdefL, "Weak fallback changes only the slot copy");

        provider.put(0x184, (byte) 0x11).putShort(0x186, (short) 1);
        compareExportModule(provider, audit, "subsdk0");
        require(audit.report().contains("0 slot diuji.") && !audit.report().contains("@0x21e0  0x"),
                "Do not simulate zero when there is a provider");
        audit.noteExportScanFailure();
        require(audit.report().contains("Pemindaian ekspor modul belum lengkap"), "Do not use a partial scan");

        provider.putShort(0x186, (short) 0);
        main.putLong(0x328, 0x21e1);
        audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        compareExportModule(provider, audit, "sdk");
        require(!audit.report().contains("slot diuji.") && audit.report().contains("Uji dilewati."),
                "An unaligned slot is never read or simulated");
    }

    private static void testRelocationBoundaryEvidence() throws IOException {
        ByteBuffer main = relocationFixture().putLong(0x310, 0x21c0);
        main.position(0x152).put("__rel_dyn_start\0".getBytes(StandardCharsets.US_ASCII));
        main.put(0x184, (byte) 0x20).putLong(0x188, 0x11223344);
        main.putLong(0x328, 0x21e0).putLong(0x338, -8);
        NsoImportAudit audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        String report = audit.report();
        require(report.contains("Belum ada kandidat  1")
                && report.contains("__rel_dyn_start #1 STB_WEAK (SHN_UNDEF, tipe 0, vis 0, st_value 0x11223344)")
                && report.contains("2 referensi. Pertama RELA @0x2128 R_AARCH64_GLOB_DAT → 0x21e0, addend -8\n")
                && report.contains("DT_REL tidak tercatat\n  DT_RELA [0x2110, 0x2140)\n  DT_JMPREL [0x2140, 0x2158)"),
                "Report exposes the stored symbol and relocation facts without supplying a candidate");

        main.position(0x152).put("__rel_plt_end\0".getBytes(StandardCharsets.US_ASCII));
        main.put(0x184, (byte) 0x10).putLong(0x330, (2L << 32) | 1025);
        main.putLong(0x278, 16).putLong(0x288, 17).putLong(0x340, 0x21e8);
        audit = new NsoImportAudit();
        NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(), 0x2220, audit);
        require(audit.report().contains("__rel_plt_end #1 STB_GLOBAL")
                && audit.report().contains("1 referensi. Pertama PLT REL @0x2140 R_AARCH64_JUMP_SLOT → 0x21e8\n")
                && audit.report().contains("DT_JMPREL [0x2140, 0x2150)"),
                "REL data does not contain an explicit addend");
    }

    private static void testImportAudit() throws IOException {
        NsoImportAudit audit = new NsoImportAudit();
        ByteBuffer main = relocationFixture().putLong(0x310, 0x21c0);
        String mainReport = NsoHeader.inspectFolderMain(new ByteArrayInputStream(main.array()), main.capacity(),
                0x2220, audit);
        require(mainReport.contains("1 entri diterapkan ke buffer RAM.") && audit.hasImports(),
                "Folder scan keeps the relative simulation and collects imports");
        require(audit.report().contains("Referensi impor main  2\nNama impor unik diperiksa  1"),
                "Repeated references count separately from unique names");
        require(audit.report().contains("Belum ada kandidat  1") && audit.report().contains("  imp_func\n"),
                "Missing name is visible before any matches");

        ByteBuffer provider = relocationFixture();
        provider.put(0x184, (byte) 0x12).putShort(0x186, (short) 1); // Global function.
        provider.putInt(0x198, 18).put(0x19c, (byte) 0x12); // Duplicate export in the same file.
        require(compareExportModule(provider, audit, "subsdk0").equals("1 nama impor cocok.")
                && audit.report().contains("Satu kandidat  1\nBeberapa kandidat  0"),
                "One module is counted once per name");

        provider.put(0x184, (byte) 0x22).put(0x185, (byte) 3); // Weak and protected.
        require(compareExportModule(provider, audit, "sdk").equals("1 nama impor cocok.")
                && audit.report().contains("Satu kandidat  0\nBeberapa kandidat  1")
                && audit.report().contains("imp_func → subsdk0, sdk"), "Multiple candidates are reported");

        provider.put(0x185, (byte) 2).put(0x19c, (byte) 0x02); // Hidden and local.
        require(compareExportModule(provider, audit, "hidden").equals("0 nama impor cocok."),
                "Hidden and local definitions are excluded");
        provider.put(0x185, (byte) 0).putShort(0x186, (short) 0);
        require(compareExportModule(provider, audit, "undefined").equals("0 nama impor cocok."),
                "A visible undefined symbol is not an export");
        provider.putShort(0x186, (short) 1).put(0x158, (byte) 1);
        require(compareExportModule(provider, audit, "bad-name").equals("0 nama impor cocok."),
                "A longer or malformed name cannot match an import prefix");
        require(compareExportModule(provider.putLong(0x2f8, 0x5000).putInt(0x9c, 0), audit, "bad-table")
                .contains("belum terverifikasi"), "An unverified table is distinguished from zero matches");
        require(compareExportModule(ByteBuffer.allocate(4), audit, "main.npdm") == null,
                "Non-NSO siblings are skipped");
    }

    private static void testRelativeRelocations() throws IOException {
        ByteBuffer module = relocationFixture();
        module.putLong(0x310, 0x21c0).putLong(0x320, 0x2180);
        module.putLong(0x328, 0x21c8).putLong(0x3c8, 0x1234);
        module.putLong(0x340, 0x21d0).putLong(0x3d0, 0x5678);
        require(!inspectMetadata(module).contains("basis simulasi"), "Application is opt-in");

        NsoHeader.Inspection result = inspectRelative(module);
        ByteBuffer image = result.memoryImage().order(ByteOrder.LITTLE_ENDIAN);
        require(result.report().contains("basis simulasi 0x100000000")
                && result.report().contains("1 entri diterapkan ke buffer RAM.")
                && image.getLong(0x21c0) == 0x1_0000_2180L, "Report and computed relocation");
        require(image.isReadOnly() && image.getLong(0x21c8) == 0x1234 && image.getLong(0x21d0) == 0x5678
                && module.getLong(0x3c0) == 0, "Other relocation types and source bytes are preserved");

        module.putLong(0x328, 0x2200).putLong(0x330, 1027).putLong(0x338, -16);
        result = inspectRelative(module);
        require(result.report().contains("2 entri diterapkan ke buffer RAM.")
                && result.memoryImage().order(ByteOrder.LITTLE_ENDIAN).getLong(0x2200) == 0xffff_fff0L,
                "Negative explicit addend in .bss");

        for (long invalidTarget : new long[]{0x21c9, 0x1800, 0x2118, 0x2220, -8}) {
            result = inspectRelative(module.putLong(0x328, invalidTarget));
            require(result.report().contains("R_AARCH64_RELATIVE  2 entri")
                    && result.report().contains("Uji dibatalkan sebelum penulisan.")
                    && result.memoryImage().getLong(0x21c0) == 0,
                    "Invalid later target must leave the first target intact: " + invalidTarget);
        }
        result = inspectRelative(module.putLong(0x328, 0x21d8).putLong(0x330, (1L << 32) | 1027));
        require(result.report().contains("Uji dibatalkan sebelum penulisan.")
                && result.memoryImage().getLong(0x21c0) == 0, "Unsupported symbol index prevents all writes");
    }

    private static ByteBuffer fixture() throws Exception {
        byte[] compressed = {0x2f, 'A', 'B', 2, 0, 6, 0x50, 'C', 'D', 'E', 'F', 'G'};
        byte[] decompressed = new byte[32];
        for (int i = 0; i < 27; i++) {
            decompressed[i] = (byte) ('A' + i % 2);
        }
        System.arraycopy(compressed, 7, decompressed, 27, 5);
        return module(compressed, decompressed);
    }

    private static ByteBuffer module(byte[] compressed, byte[] decompressed) throws Exception {
        ByteBuffer header = ByteBuffer.allocate(0x140 + compressed.length).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0, 0x304f534e).putInt(0x0c, 4 | (1 << 3) | (1 << 5));
        header.putInt(0x10, 0x100).putInt(0x14, 0).putInt(0x18, 0x20);
        header.putInt(0x20, 0x120).putInt(0x24, 0x1000).putInt(0x28, 0x20);
        header.putInt(0x30, 0x140).putInt(0x34, 0x2000).putInt(0x38, decompressed.length);
        header.put(0x40, (byte) 0x12).put(0x41, (byte) 0x34);
        header.putInt(0x68, compressed.length);
        byte[] text = new byte[0x20];
        Arrays.fill(text, (byte) 'T');
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        header.position(0xa0).put(digest.digest(text));
        header.position(0xe0).put(digest.digest(decompressed));
        header.position(0x100).put(text);
        header.position(0x140).put(compressed);
        return header;
    }

    private static byte[] largeMatchFixture() throws Exception {
        int matchLength = 70_001;
        byte[] decompressed = new byte[1 + matchLength + 5];
        Arrays.fill(decompressed, (byte) 'A');
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        compressed.write(new byte[]{0x1f, 'A', 1, 0});
        for (int extension = matchLength - 19; ; extension -= 255) {
            compressed.write(Math.min(extension, 255));
            if (extension < 255) {
                break;
            }
        }
        compressed.write(new byte[]{0x50, 'A', 'A', 'A', 'A', 'A'});
        return module(compressed.toByteArray(), decompressed).array();
    }

    private static ByteBuffer dynamicFixture() {
        ByteBuffer module = ByteBuffer.allocate(0x400).order(ByteOrder.LITTLE_ENDIAN);
        module.putInt(0, 0x304f534e);
        module.putInt(0x10, 0x100).putInt(0x14, 0).putInt(0x18, 0x40);
        module.putInt(0x20, 0x140).putInt(0x24, 0x1000).putInt(0x28, 0xc0);
        module.putInt(0x30, 0x200).putInt(0x34, 0x2000).putInt(0x38, 0x200);
        module.putInt(0x3c, 0x20);
        module.putInt(0x104, 0x2180);
        module.putInt(0x380, 0x30444f4d).putInt(0x384, -0x180);
        byte[] strings = "\0sdk.nso\0rtld.nso\0".getBytes(StandardCharsets.US_ASCII);
        module.position(0x140).put(strings);
        module.position(0x200);
        module.putLong(1).putLong(1).putLong(1).putLong(9); // DT_NEEDED
        module.putLong(5).putLong(0x1000).putLong(10).putLong(strings.length);
        module.putLong(7).putLong(0x1040).putLong(8).putLong(48).putLong(9).putLong(24);
        module.putLong(2).putLong(24).putLong(20).putLong(7).putLong(23).putLong(0x1070);
        module.putLong(36).putLong(0x1088).putLong(35).putLong(16).putLong(37).putLong(8);
        module.putLong(0).putLong(0); // DT_NULL
        return module;
    }

    private static ByteBuffer relocationFixture() {
        ByteBuffer module = dynamicFixture();
        byte[] strings = "\0sdk.nso\0rtld.nso\0imp_func\0defined\0".getBytes(StandardCharsets.US_ASCII);
        module.position(0x140).put(strings);
        module.putInt(0x98, 0x28).putInt(0x9c, 3 * 24);
        module.putInt(0x180, 18); // Undefined symbol #1, named imp_func.
        module.putInt(0x198, 27).putShort(0x19e, (short) 1); // Defined symbol #2.
        module.putInt(0x1c0, 1).putInt(0x1c4, 3); // SysV hash nbucket and nchain.
        module.putLong(0x238, strings.length);
        module.putLong(0x248, 0x2110).putLong(0x298, 0x2140).putLong(0x2a8, 0x2158);
        module.position(0x2d0);
        module.putLong(6).putLong(0x1028).putLong(11).putLong(24).putLong(4).putLong(0x1080);
        module.putLong(0).putLong(0);
        module.putLong(0x318, 1027).putLong(0x330, (1L << 32) | 1025).putLong(0x348, (1L << 32) | 1026);
        return module;
    }

    private static String inspectMetadata(ByteBuffer module) throws IOException {
        return NsoHeader.inspect(new ByteArrayInputStream(module.array()), module.capacity(), 0x2220).report();
    }

    private static NsoHeader.Inspection inspectRelative(ByteBuffer module) throws IOException {
        return NsoHeader.inspectWithRelativeTest(new ByteArrayInputStream(module.array()), module.capacity(), 0x2220);
    }

    private static String compareExportModule(ByteBuffer module, NsoImportAudit audit, String name)
            throws IOException {
        return NsoHeader.inspectExportModule(new BufferedInputStream(new ByteArrayInputStream(module.array())),
                module.capacity(), 0x2220, audit, name);
    }

    private static void expectMetadataError(ByteBuffer module, String detail) throws IOException {
        String report = inspectMetadata(module);
        require(report.contains("Segmen NSO0 berhasil diperiksa")
                && report.contains("Metadata MOD0 belum bisa dibaca: " + detail), report);
    }

    private static void expectError(byte[] bytes, long fileLength, String detail) throws IOException {
        expectError(bytes, fileLength, -1, detail);
    }

    private static void expectError(byte[] bytes, long fileLength, long memoryBudget, String detail)
            throws IOException {
        try {
            NsoHeader.inspect(new ByteArrayInputStream(bytes), fileLength, memoryBudget);
        } catch (IOException error) {
            require(error.getMessage().contains(detail), error.getMessage());
            return;
        }
        throw new AssertionError("Expected error containing: " + detail);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
