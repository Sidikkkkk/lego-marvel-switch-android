package org.sidikkkkk.switchport;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

final class NsoDynamic {
    private static final int MOD0_MAGIC = 0x30444f4d;
    private static final int MOD0_HEADER_SIZE = 0x1c;
    private static final int DYNAMIC_ENTRY_SIZE = 16;
    private static final int RELA_ENTRY_SIZE = 24;
    private static final int REL_ENTRY_SIZE = 16;
    private static final int RELR_ENTRY_SIZE = 8;
    private static final long SIMULATED_BASE = 0x1_0000_0000L;
    private static final int DT_NEEDED = 1;
    private static final int DT_PLTRELSZ = 2;
    private static final int DT_HASH = 4;
    private static final int DT_STRTAB = 5;
    private static final int DT_SYMTAB = 6;
    private static final int DT_RELA = 7;
    private static final int DT_RELASZ = 8;
    private static final int DT_RELAENT = 9;
    private static final int DT_STRSZ = 10;
    private static final int DT_SYMENT = 11;
    private static final int DT_REL = 17;
    private static final int DT_RELSZ = 18;
    private static final int DT_RELENT = 19;
    private static final int DT_PLTREL = 20;
    private static final int DT_JMPREL = 23;
    private static final int DT_RELRSZ = 35;
    private static final int DT_RELR = 36;
    private static final int DT_RELRENT = 37;
    private static final int MAX_DISPLAYED_DEPENDENCIES = 16;
    private static final int MAX_DISPLAYED_NAME = 120;

    private NsoDynamic() {}

    static String describe(ByteBuffer image, NsoHeader.Segment[] segments, long symbolOffset, long symbolSize,
                           long bssStart, long bssEnd, NsoImportAudit audit, String exportModule) throws IOException {
        NsoHeader.Segment text = segments[0];
        if (text.unpackedSize() < 8) {
            if (exportModule != null) {
                audit.noteExportScanFailure();
            }
            return "MOD0 tidak terdeteksi pada awalan .text." + (exportModule == null ? "\n" : "");
        }
        ByteBuffer data = image.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        long mod0 = text.memoryOffset()
                + Integer.toUnsignedLong(data.getInt((int) text.memoryOffset() + 4));
        if (regionEnd(segments, mod0, Integer.BYTES) < 0 || data.getInt((int) mod0) != MOD0_MAGIC) {
            if (exportModule != null) {
                audit.noteExportScanFailure();
            }
            return "MOD0 tidak terdeteksi pada offset dari awalan .text." + (exportModule == null ? "\n" : "");
        }
        if (regionEnd(segments, mod0, MOD0_HEADER_SIZE) < 0) {
            throw new IOException("Header MOD0 terpotong.");
        }
        long dynamic = mod0 + data.getInt((int) mod0 + 4);
        long dynamicEnd = requireRange(segments, dynamic, DYNAMIC_ENTRY_SIZE, ".dynamic");
        long[] tags = new long[DT_RELRENT + 1];
        Arrays.fill(tags, -1);
        long[] needed = new long[MAX_DISPLAYED_DEPENDENCIES];
        int neededCount = 0;
        int dynamicCount = 0;
        for (long entry = dynamic; entry <= dynamicEnd - DYNAMIC_ENTRY_SIZE; entry += DYNAMIC_ENTRY_SIZE) {
            checkInterrupted();
            long tag = data.getLong((int) entry);
            if (tag == 0) {
                NsoRelocations.SymbolTable symbols = symbolTable(data, segments, tags, symbolOffset, symbolSize);
                if (exportModule != null) {
                    if (symbols == null) {
                        audit.noteExportScanFailure();
                        return "Batas .dynsym atau .dynstr belum terverifikasi.";
                    }
                    return audit.compareExports(exportModule, data, symbols) + " nama impor cocok.";
                }
                StringBuilder report = new StringBuilder("Metadata pemuatan MOD0\n")
                        .append("MOD0 0x").append(Long.toHexString(mod0))
                        .append(", .dynamic 0x").append(Long.toHexString(dynamic))
                        .append(" (").append(dynamicCount).append(" entri)\n");
                appendDependencies(report, data, segments, tags, needed, neededCount);
                NsoRelocations relocations = new NsoRelocations(data, symbols, audit != null);
                appendRelocations(report, segments, tags, relocations);
                relocations.appendReport(report);
                if (audit != null && symbols != null) {
                    relocations.captureImports(audit, segments[2]);
                    if (audit.hasBoundaryEvidence()) {
                        // appendRelocations validated these byte ranges before collecting the evidence.
                        audit.addTableRange("DT_REL", tags[DT_REL], tags[DT_RELSZ]);
                        audit.addTableRange("DT_RELA", tags[DT_RELA], tags[DT_RELASZ]);
                        audit.addTableRange("DT_JMPREL", tags[DT_JMPREL], tags[DT_PLTRELSZ]);
                    }
                }
                if (!data.isReadOnly()) {
                    appendRelativeTest(report, data, segments, tags, bssStart, bssEnd);
                }
                return report.toString();
            }
            long value = data.getLong((int) entry + Long.BYTES);
            if (tag == DT_NEEDED) {
                if (neededCount < needed.length) {
                    needed[neededCount] = value;
                }
                ++neededCount;
            } else if (tag > DT_NEEDED && tag < tags.length && isTrackedTag((int) tag)) {
                if (value < 0) {
                    throw new IOException("Nilai tabel dinamis di luar rentang yang didukung.");
                }
                tags[(int) tag] = value;
            }
            ++dynamicCount;
        }
        throw new IOException("DT_NULL tidak ditemukan di dalam segmen .dynamic.");
    }

    private static void appendRelativeTest(StringBuilder report, ByteBuffer data, NsoHeader.Segment[] segments,
                                           long[] tags, long bssStart, long bssEnd) throws InterruptedIOException {
        report.append("\nUji R_AARCH64_RELATIVE (DT_RELA, basis simulasi 0x")
                .append(Long.toHexString(SIMULATED_BASE)).append(")\n");
        if (segments[0].memoryOffset() != 0) {
            report.append("Uji dilewati karena offset .text bukan nol.\n");
            return;
        }
        long size = tags[DT_RELASZ];
        if (size <= 0) {
            report.append("Tabel DT_RELA kosong atau tidak tersedia.\n");
            return;
        }
        try {
            long applied = applyRelativeEntries(data, segments, tags[DT_RELA], size, bssStart, bssEnd);
            report.append(applied).append(" entri diterapkan ke buffer RAM.\n");
        } catch (InterruptedIOException error) {
            throw error;
        } catch (IOException error) {
            report.append("Uji dibatalkan sebelum penulisan. ").append(error.getMessage()).append('\n');
        }
    }

    private static long applyRelativeEntries(ByteBuffer data, NsoHeader.Segment[] segments,
                                             long start, long size, long bssStart, long bssEnd) throws IOException {
        long end = start + size;
        // The caller has validated the table extent and entry size. Validate all destinations before writing.
        for (long entry = start; entry < end; entry += RELA_ENTRY_SIZE) {
            checkInterrupted();
            long info = data.getLong((int) entry + Long.BYTES);
            if ((int) info != NsoRelocations.AARCH64_RELATIVE) {
                continue;
            }
            long target = data.getLong((int) entry);
            boolean inBss = target >= bssStart && target <= bssEnd - Long.BYTES;
            if ((info >>> 32) != 0 || (target & (Long.BYTES - 1)) != 0
                    || (!inBss && regionEnd(segments, target, Long.BYTES) < 0)
                    || (target < end && target + Long.BYTES > start)) {
                throw new IOException("Entri RELATIVE #" + (entry - start) / RELA_ENTRY_SIZE
                        + " memiliki indeks simbol atau target yang tidak valid (0x"
                        + Long.toHexString(target) + ").");
            }
        }
        checkInterrupted();

        long applied = 0;
        for (long entry = start; entry < end; entry += RELA_ENTRY_SIZE) {
            int offset = (int) entry;
            if (data.getInt(offset + Long.BYTES) == NsoRelocations.AARCH64_RELATIVE) {
                int target = (int) data.getLong(offset);
                long addend = data.getLong(offset + 2 * Long.BYTES);
                data.putLong(target, SIMULATED_BASE + addend);
                ++applied;
            }
        }
        return applied;
    }

    private static boolean isTrackedTag(int tag) {
        return switch (tag) {
            case DT_HASH, DT_STRTAB, DT_STRSZ, DT_SYMTAB, DT_SYMENT, DT_RELA, DT_RELASZ, DT_RELAENT, DT_REL, DT_RELSZ,
                    DT_RELENT, DT_RELR, DT_RELRSZ, DT_RELRENT, DT_JMPREL, DT_PLTRELSZ, DT_PLTREL -> true;
            default -> false;
        };
    }

    private static void appendDependencies(StringBuilder report, ByteBuffer data, NsoHeader.Segment[] segments,
                                           long[] tags, long[] needed, int count) throws IOException {
        report.append("Dependensi DT_NEEDED  ").append(count).append('\n');
        if (count == 0) {
            return;
        }
        long strings = tags[DT_STRTAB];
        long size = tags[DT_STRSZ];
        requireRange(segments, strings, size, "DT_STRTAB");
        int displayed = Math.min(count, needed.length);
        for (int index = 0; index < displayed; ++index) {
            long offset = needed[index];
            if (offset < 0 || offset >= size) {
                throw new IOException("Offset nama DT_NEEDED di luar tabel string.");
            }
            report.append("  ").append(readName(data, strings + offset, strings + size)).append('\n');
        }
        if (displayed < count) {
            report.append("  … ").append(count - displayed).append(" dependensi lain\n");
        }
    }

    static String readName(ByteBuffer data, long offset, long end) throws IOException {
        StringBuilder name = new StringBuilder();
        for (long index = offset; index < end; ++index) {
            if (((index - offset) & 0x3fff) == 0) {
                checkInterrupted();
            }
            int character = Byte.toUnsignedInt(data.get((int) index));
            if (character == 0) {
                if (index - offset > MAX_DISPLAYED_NAME) {
                    name.append('…');
                }
                return name.toString();
            }
            if (name.length() < MAX_DISPLAYED_NAME) {
                name.append(character >= 0x20 && character < 0x7f ? (char) character : '\ufffd');
            }
        }
        throw new IOException("Nama DT_NEEDED tidak diakhiri NUL dalam tabel string.");
    }

    private static NsoRelocations.SymbolTable symbolTable(ByteBuffer data, NsoHeader.Segment[] segments,
                                                           long[] tags, long symbolOffset, long symbolSize) {
        long address = tags[DT_SYMTAB];
        long strings = tags[DT_STRTAB];
        long stringSize = tags[DT_STRSZ];
        int entrySize = NsoRelocations.SYMBOL_ENTRY_SIZE;
        if (address < 0 || (tags[DT_SYMENT] >= 0 && tags[DT_SYMENT] != entrySize)
                || regionEnd(segments, strings, stringSize) < 0) {
            return null;
        }
        if (symbolSize > 0) {
            NsoHeader.Segment rodata = segments[1];
            if (address != rodata.memoryOffset() + symbolOffset || symbolSize > rodata.unpackedSize() - symbolOffset) {
                return null;
            }
        } else {
            long hash = tags[DT_HASH];
            if (regionEnd(segments, hash, 2 * Integer.BYTES) < 0) {
                return null;
            }
            long buckets = Integer.toUnsignedLong(data.getInt((int) hash));
            long chains = Integer.toUnsignedLong(data.getInt((int) hash + Integer.BYTES));
            if (regionEnd(segments, hash, (2 + buckets + chains) * Integer.BYTES) < 0) {
                return null;
            }
            symbolSize = chains * entrySize;
        }
        if (symbolSize % entrySize != 0 || regionEnd(segments, address, symbolSize) < 0) {
            return null;
        }
        return new NsoRelocations.SymbolTable(address, symbolSize / entrySize, strings, stringSize);
    }

    private static void appendRelocations(StringBuilder report, NsoHeader.Segment[] segments, long[] tags,
                                          NsoRelocations relocations) throws IOException {
        appendTable(report, segments, "RELA", tags[DT_RELA], tags[DT_RELASZ], tags[DT_RELAENT],
                RELA_ENTRY_SIZE, relocations);
        appendTable(report, segments, "REL", tags[DT_REL], tags[DT_RELSZ], tags[DT_RELENT],
                REL_ENTRY_SIZE, relocations);
        appendTable(report, segments, "RELR", tags[DT_RELR], tags[DT_RELRSZ], tags[DT_RELRENT],
                RELR_ENTRY_SIZE, null);
        if (tags[DT_PLTRELSZ] > 0 || tags[DT_JMPREL] >= 0) {
            long type = tags[DT_PLTREL];
            if (type != DT_REL && type != DT_RELA) {
                throw new IOException("Format relokasi PLT tidak dikenali.");
            }
            appendTable(report, segments, type == DT_RELA ? "PLT RELA" : "PLT REL", tags[DT_JMPREL],
                    tags[DT_PLTRELSZ], -1, type == DT_RELA ? RELA_ENTRY_SIZE : REL_ENTRY_SIZE, relocations);
        }
    }

    private static void appendTable(StringBuilder report, NsoHeader.Segment[] segments, String name,
                                    long address, long size, long declaredEntrySize, int entrySize,
                                    NsoRelocations relocations)
            throws IOException {
        if (address < 0 && size <= 0) {
            return;
        }
        if (size < 0 || size % entrySize != 0 || (declaredEntrySize >= 0 && declaredEntrySize != entrySize)) {
            throw new IOException("Ukuran tabel relokasi " + name + " tidak valid.");
        }
        if (size > 0) {
            requireRange(segments, address, size, name);
            if (relocations != null) {
                relocations.scan(address, size, entrySize, name);
            }
        }
        report.append("Relokasi ").append(name).append("  ").append(size / entrySize).append(" entri\n");
    }

    private static long requireRange(NsoHeader.Segment[] segments, long offset, long length, String name)
            throws IOException {
        long end = regionEnd(segments, offset, length);
        if (end < 0) {
            throw new IOException("Rentang " + name + " di luar data segmen.");
        }
        return end;
    }

    private static long regionEnd(NsoHeader.Segment[] segments, long offset, long length) {
        if (offset < 0 || length <= 0) {
            return -1;
        }
        for (NsoHeader.Segment segment : segments) {
            if (offset >= segment.memoryOffset() && offset < segment.memoryEnd()
                    && length <= segment.memoryEnd() - offset) {
                return segment.memoryEnd();
            }
        }
        return -1;
    }

    private static void checkInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("Pemeriksaan MOD0 dibatalkan.");
        }
    }
}
