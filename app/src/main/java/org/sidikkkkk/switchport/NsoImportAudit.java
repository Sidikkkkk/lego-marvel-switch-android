package org.sidikkkkk.switchport;

import static org.sidikkkkk.switchport.NsoRelocations.AARCH64_ABS64;
import static org.sidikkkkk.switchport.NsoRelocations.AARCH64_GLOB_DAT;
import static org.sidikkkkk.switchport.NsoRelocations.AARCH64_JUMP_SLOT;

import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class NsoImportAudit {
    private static final int STB_GLOBAL = 1;
    private static final int STB_WEAK = 2;
    private static final int STV_DEFAULT = 0;
    private static final int STV_PROTECTED = 3;
    private static final int SHN_UNDEF = 0;
    private static final int SHN_XINDEX = 0xffff;
    private static final int SHN_LORESERVE = 0xff00;
    private static final int STT_NOTYPE = 0;
    private static final int STT_FUNC = 2;
    private static final int MAX_NAME_BYTES = 1024;
    private static final int MAX_MISSING_NAMES = 20;
    private static final int MAX_AMBIGUOUS_NAMES = 10;
    private static final int MAX_BINDING_SAMPLES = 4;
    private static final int MAX_SKIPPED_SAMPLES = 6;

    private record WeakSlot(long offset, long original) {}
    record BindingSlot(String name, int entry, long offset, int type, long addend, long original, String reason) {}
    private record Export(String module, long address, int type, long value, boolean inText) {}

    private final Map<String, WeakSlot> weakSlots = new LinkedHashMap<>();
    private final List<BindingSlot> bindingSlots = new ArrayList<>();
    private boolean exportScanFailed;
    private int scannedModules;

    private final Map<String, Long> imports = new LinkedHashMap<>();
    private final Map<String, List<Export>> candidates = new LinkedHashMap<>();
    private final StringBuilder boundaryEvidence = new StringBuilder();
    private final StringBuilder tableRanges = new StringBuilder();
    private final StringBuilder moduleRanges = new StringBuilder();
    private final StringBuilder startupTrace = new StringBuilder();
    private long references = -1;
    private long invalidReferences;

    void addImport(String name, long count) {
        imports.merge(name, count, Long::sum);
    }

    void finishImports(long count, long invalid) {
        references = count;
        invalidReferences = invalid;
    }

    boolean hasImports() {
        return references >= 0 && !imports.isEmpty();
    }

    void addBoundaryEvidence(String row) {
        boundaryEvidence.append(row);
    }

    void addWeakSlot(String name, long offset, long original) {
        weakSlots.put(name, new WeakSlot(offset, original));
    }

    void addBindingSlot(BindingSlot slot) {
        bindingSlots.add(slot);
    }

    void addModuleLayout(String name, long base, NsoHeader.Segment[] segments, long bssStart, long bssEnd) {
        moduleRanges.append("  ").append(name).append(" basis 0x").append(Long.toHexString(base)).append('\n');
        for (NsoHeader.Segment segment : segments) {
            if (segment.unpackedSize() > 0) {
                appendRange(segment.name(), base + segment.memoryOffset(), base + segment.memoryEnd());
            }
        }
        if (bssEnd > bssStart) {
            appendRange(".bss", base + bssStart, base + bssEnd);
        }
    }

    private void appendRange(String name, long start, long end) {
        moduleRanges.append("    ").append(name).append(" [0x").append(Long.toHexString(start))
                .append(", 0x").append(Long.toHexString(end)).append(")\n");
    }

    void noteExportScanFailure() {
        exportScanFailed = true;
    }

    boolean hasBoundaryEvidence() {
        return boundaryEvidence.length() != 0;
    }

    void addTableRange(String tag, long start, long size) {
        tableRanges.append("  ").append(tag);
        if (size > 0) {
            tableRanges.append(" [0x").append(Long.toHexString(start))
                    .append(", 0x").append(Long.toHexString(start + size)).append(')');
        } else {
            tableRanges.append(size == 0 ? "  0 byte" : " tidak tercatat");
        }
        tableRanges.append('\n');
    }

    int compareExports(String module, ByteBuffer data, NsoRelocations.SymbolTable symbols,
                       NsoHeader.Segment[] segments, long bssStart, long bssEnd) throws InterruptedIOException {
        // Use disjoint 4 GiB ranges. The temporary main image uses range 1.
        long base = (2L + scannedModules) << 32;
        Map<String, Export> matches = new LinkedHashMap<>();
        for (long index = 1; index < symbols.count(); ++index) {
            if ((index & 0x3ff) == 1) {
                checkInterrupted();
            }
            int entry = (int) (symbols.address() + index * NsoRelocations.SYMBOL_ENTRY_SIZE);
            int binding = (data.get(entry + 4) & 0xff) >>> 4;
            int visibility = data.get(entry + 5) & 3;
            int section = data.getShort(entry + 6) & 0xffff;
            if ((binding != STB_GLOBAL && binding != STB_WEAK)
                    || (visibility != STV_DEFAULT && visibility != STV_PROTECTED)
                    || section == SHN_UNDEF || section == SHN_XINDEX) {
                continue;
            }
            String name = exactName(data, symbols, entry);
            if (name != null && imports.containsKey(name)) {
                int type = data.get(entry + 4) & 0xf;
                long value = data.getLong(entry + 8);
                NsoHeader.Segment text = segments[0];
                boolean inText = value >= text.memoryOffset() && value <= text.memoryEnd() - Integer.BYTES
                        && (value & 3) == 0;
                boolean mapped = NsoDynamic.regionEnd(segments, value, 1) >= 0
                        || (value >= bssStart && value < bssEnd);
                if (type == STT_FUNC) {
                    mapped = inText;
                }
                boolean supported = mapped && text.memoryOffset() == 0 && type <= STT_FUNC
                        && section < SHN_LORESERVE && (data.get(entry + 5) & 0xfc) == 0;
                Export definition = new Export(module, supported ? base + value : -1, type, value, inText);
                matches.merge(name, definition, (first, second) -> first.equals(second)
                        ? first : new Export(module, -1, -1, 0, false));
            }
        }
        for (var entry : matches.entrySet()) {
            candidates.computeIfAbsent(entry.getKey(), key -> new ArrayList<>()).add(entry.getValue());
        }
        addModuleLayout(module, base, segments, bssStart, bssEnd);
        if (module.equals("rtld")) {
            NsoStartupProbe.append(startupTrace, data, segments[0], base);
        }
        ++scannedModules;
        return matches.size();
    }

    String report() {
        StringBuilder output = new StringBuilder("Pemeriksaan impor ExeFS\n");
        if (references < 0) {
            return output.append("Daftar impor main belum tersedia. Lihat rincian main di bawah.\n").toString();
        }
        int single = 0;
        int ambiguous = 0;
        int missing = 0;
        long named = 0;
        long singleReferences = 0;
        StringBuilder missingExamples = new StringBuilder();
        StringBuilder ambiguousExamples = new StringBuilder();
        for (var entry : imports.entrySet()) {
            named += entry.getValue();
            List<Export> modules = candidates.get(entry.getKey());
            if (modules == null) {
                if (++missing <= MAX_MISSING_NAMES) {
                    missingExamples.append("  ").append(entry.getKey()).append('\n');
                }
            } else if (modules.size() == 1) {
                ++single;
                singleReferences += entry.getValue();
            } else if (++ambiguous <= MAX_AMBIGUOUS_NAMES) {
                ambiguousExamples.append("  ").append(entry.getKey()).append(" → ")
                        .append(modules.get(0).module());
                for (int index = 1; index < modules.size(); ++index) {
                    ambiguousExamples.append(", ").append(modules.get(index).module());
                }
                ambiguousExamples.append('\n');
            }
        }
        output.append("Referensi impor main  ").append(references).append('\n')
                .append("Nama impor unik diperiksa  ").append(imports.size()).append('\n')
                .append("Satu kandidat  ").append(single).append('\n')
                .append("Beberapa kandidat  ").append(ambiguous).append('\n')
                .append("Belum ada kandidat  ").append(missing).append('\n');
        if (references != named || invalidReferences > 0) {
            output.append("Referensi tanpa nama yang diperiksa  ").append(references - named).append('\n')
                    .append("Referensi dengan indeks di luar tabel  ").append(invalidReferences).append('\n');
        }
        if (missing > 0) {
            output.append("Contoh nama tanpa kandidat (maks. ").append(MAX_MISSING_NAMES).append(")\n")
                    .append(missingExamples);
        }
        if (ambiguous > 0) {
            output.append("Contoh nama dengan beberapa kandidat (maks. ").append(MAX_AMBIGUOUS_NAMES).append(")\n")
                    .append(ambiguousExamples);
        }
        if (singleReferences > 0 || !bindingSlots.isEmpty()) {
            appendBindingTest(output, singleReferences);
        }
        output.append("\nAwal startup rtld (simulasi instruksi)\n");
        if (startupTrace.length() == 0) {
            output.append("Modul rtld belum terverifikasi dalam pemindaian ini.\n");
        } else {
            output.append(startupTrace);
        }
        if (moduleRanges.length() > 0) {
            output.append("\nPeta modul (alamat simulasi)\n").append(moduleRanges);
        }
        if (hasBoundaryEvidence()) {
            appendWeakTest(output, single, named);
            output.append("\nDetail simbol __rel_ di main\n").append(boundaryEvidence)
                    .append("Rentang tabel relokasi main (offset)\n").append(tableRanges);
        }
        return output.toString();
    }

    private void appendBindingTest(StringBuilder output, long singleReferences) {
        output.append("\nSimulasi pengikatan impor main (salinan slot .data)\n");
        if (exportScanFailed || scannedModules == 0) {
            output.append("Uji dilewati. Pemindaian ekspor modul belum lengkap.\n");
            return;
        }

        Map<Long, Integer> targetCounts = new LinkedHashMap<>();
        for (BindingSlot slot : bindingSlots) {
            targetCounts.merge(slot.offset(), 1, Integer::sum);
        }
        ByteBuffer copies = ByteBuffer.allocate(bindingSlots.size() * Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
        int abs = 0;
        int glob = 0;
        int jump = 0;
        int jumpNoType = 0;
        StringBuilder examples = new StringBuilder();
        StringBuilder skipped = new StringBuilder();
        int skippedCount = 0;
        for (BindingSlot slot : bindingSlots) {
            List<Export> definitions = candidates.get(slot.name());
            if (definitions == null || definitions.size() != 1) {
                continue;
            }
            Export definition = definitions.get(0);
            String reason = slot.reason();
            if (reason == null && targetCounts.get(slot.offset()) != 1) {
                reason = "beberapa relokasi impor menunjuk slot yang sama";
            }
            if (reason == null && definition.address() < 0) {
                reason = definition.type() < 0 ? "definisi dalam modul bertentangan"
                        : "ekspor di luar cakupan uji (tipe " + definition.type() + ", st_value 0x"
                                + Long.toHexString(definition.value()) + ')';
            }
            if (reason == null && slot.type() == AARCH64_JUMP_SLOT && definition.type() != STT_FUNC
                    && (definition.type() != STT_NOTYPE || !definition.inText())) {
                reason = "ekspor tipe " + definition.type() + " di st_value 0x"
                        + Long.toHexString(definition.value()) + " tidak menunjukkan instruksi sejajar di .text";
            }
            long address = 0;
            if (reason == null) {
                try {
                    address = Math.addExact(definition.address(), slot.addend());
                    if (address < 0) {
                        reason = "hasil alamat negatif";
                    }
                } catch (ArithmeticException error) {
                    reason = "penjumlahan alamat melampaui batas";
                }
            }
            if (reason != null) {
                if (++skippedCount <= MAX_SKIPPED_SAMPLES) {
                    skipped.append("  ").append(slot.name()).append(" → ").append(definition.module())
                            .append(' ').append(NsoRelocations.typeName(slot.type()))
                            .append(" entri 0x").append(Integer.toHexString(slot.entry()))
                            .append(" target 0x").append(Long.toHexString(slot.offset()))
                            .append(" — ").append(reason).append('\n');
                }
                continue;
            }
            int position = copies.position();
            copies.putLong(slot.original());
            copies.putLong(position, address);
            if (abs + glob + jump < MAX_BINDING_SAMPLES) {
                examples.append("  ").append(slot.name()).append(" → ").append(definition.module())
                        .append(" @0x").append(Long.toHexString(slot.offset())).append(" = 0x")
                        .append(Long.toHexString(copies.getLong(position))).append('\n');
            }
            switch (slot.type()) {
                case AARCH64_ABS64 -> ++abs;
                case AARCH64_GLOB_DAT -> ++glob;
                case AARCH64_JUMP_SLOT -> {
                    ++jump;
                    if (definition.type() == STT_NOTYPE) {
                        ++jumpNoType;
                    }
                }
            }
        }
        int applied = abs + glob + jump;
        output.append(applied).append(" dari ").append(singleReferences).append(" referensi kandidat tunggal diuji.\n")
                .append("ABS64 ").append(abs).append(" | GLOB_DAT ").append(glob)
                .append(" | JUMP_SLOT ").append(jump).append('\n')
                .append("Referensi kandidat tunggal belum diuji  ").append(singleReferences - applied).append('\n');
        if (jumpNoType != 0) {
            output.append("JUMP_SLOT ke ekspor STT_NOTYPE sejajar di .text  ").append(jumpNoType).append('\n');
        }
        if (skipped.length() != 0) {
            output.append("Alasan entri dilewati (maks. ").append(MAX_SKIPPED_SAMPLES).append(")\n").append(skipped);
        }
        long uncaptured = singleReferences - applied - skippedCount;
        if (uncaptured > 0) {
            output.append("Referensi di luar batas pencatatan  ").append(uncaptured).append('\n');
        }
        output.append(examples);
    }

    private void appendWeakTest(StringBuilder output, int single, long named) {
        output.append("\nSimulasi GOT weak (ELF, salinan slot .data)\n");
        if (exportScanFailed || scannedModules == 0) {
            output.append("Uji dilewati. Pemindaian ekspor modul belum lengkap.\n");
            return;
        }

        Map<String, WeakSlot> eligible = new LinkedHashMap<>();
        Set<Long> offsets = new LinkedHashSet<>();
        for (var entry : weakSlots.entrySet()) {
            String name = entry.getKey();
            WeakSlot slot = entry.getValue();
            if (imports.get(name) != 1 || candidates.containsKey(name)) {
                continue;
            }
            if (!offsets.add(slot.offset())) {
                output.append("Uji dilewati. Beberapa simbol menunjuk slot yang sama.\n");
                return;
            }
            eligible.put(name, slot);
        }
        if (single + eligible.size() != imports.size() || named != references || invalidReferences != 0) {
            output.append("Uji dilewati. Masih ada impor lain yang belum punya satu kandidat.\n");
            return;
        }

        ByteBuffer copies = ByteBuffer.allocate(eligible.size() * Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
        for (var entry : eligible.entrySet()) {
            WeakSlot slot = entry.getValue();
            int position = copies.position();
            copies.putLong(slot.original());
            long before = copies.getLong(position);
            copies.putLong(position, 0L); // S = 0 for an unresolved weak reference. A was verified as zero.
            output.append("  ").append(entry.getKey()).append(" @0x").append(Long.toHexString(slot.offset()))
                    .append("  0x").append(Long.toHexString(before)).append(" → 0x")
                    .append(Long.toHexString(copies.getLong(position))).append('\n');
        }
        output.append(eligible.size()).append(" slot diuji.\n");
    }

    static String exactName(ByteBuffer data, NsoRelocations.SymbolTable symbols, int entry)
            throws InterruptedIOException {
        checkInterrupted();
        long offset = Integer.toUnsignedLong(data.getInt(entry));
        if (offset == 0 || offset >= symbols.stringSize()) {
            return null;
        }
        long start = symbols.strings() + offset;
        long end = Math.min(symbols.strings() + symbols.stringSize(), start + MAX_NAME_BYTES + 1);
        StringBuilder name = new StringBuilder();
        for (long position = start; position < end; ++position) {
            int value = data.get((int) position) & 0xff;
            if (value == 0) {
                return name.length() == 0 ? null : name.toString();
            }
            if (value < 0x20 || value > 0x7e) {
                return null;
            }
            name.append((char) value);
        }
        return null;
    }

    private static void checkInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("Pemeriksaan impor dibatalkan.");
        }
    }
}
