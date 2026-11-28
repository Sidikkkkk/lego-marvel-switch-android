package org.sidikkkkk.switchport;

import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
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
    private static final int MAX_NAME_BYTES = 1024;
    private static final int MAX_MISSING_NAMES = 20;
    private static final int MAX_AMBIGUOUS_NAMES = 10;

    private final Map<String, Long> imports = new LinkedHashMap<>();
    private final Map<String, List<String>> candidates = new LinkedHashMap<>();
    private final StringBuilder boundaryEvidence = new StringBuilder();
    private final StringBuilder tableRanges = new StringBuilder();
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

    int compareExports(String module, ByteBuffer data, NsoRelocations.SymbolTable symbols)
            throws InterruptedIOException {
        Set<String> matches = new LinkedHashSet<>();
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
                matches.add(name);
            }
        }
        for (String name : matches) {
            candidates.computeIfAbsent(name, key -> new ArrayList<>()).add(module);
        }
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
        StringBuilder missingExamples = new StringBuilder();
        StringBuilder ambiguousExamples = new StringBuilder();
        for (var entry : imports.entrySet()) {
            named += entry.getValue();
            List<String> modules = candidates.get(entry.getKey());
            if (modules == null) {
                if (++missing <= MAX_MISSING_NAMES) {
                    missingExamples.append("  ").append(entry.getKey()).append('\n');
                }
            } else if (modules.size() == 1) {
                ++single;
            } else if (++ambiguous <= MAX_AMBIGUOUS_NAMES) {
                ambiguousExamples.append("  ").append(entry.getKey()).append(" → ")
                        .append(modules.get(0));
                for (int index = 1; index < modules.size(); ++index) {
                    ambiguousExamples.append(", ").append(modules.get(index));
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
        if (hasBoundaryEvidence()) {
            output.append("\nDetail simbol __rel_ di main\n").append(boundaryEvidence)
                    .append("Rentang tabel relokasi main (offset)\n").append(tableRanges);
        }
        return output.toString();
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
