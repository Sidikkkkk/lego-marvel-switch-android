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
    private static final int DT_NEEDED = 1;
    private static final int DT_PLTRELSZ = 2;
    private static final int DT_STRTAB = 5;
    private static final int DT_RELA = 7;
    private static final int DT_RELASZ = 8;
    private static final int DT_RELAENT = 9;
    private static final int DT_STRSZ = 10;
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

    static String describe(ByteBuffer image, NsoHeader.Segment[] segments) throws IOException {
        NsoHeader.Segment text = segments[0];
        if (text.unpackedSize() < 8) {
            return "MOD0 tidak terdeteksi pada awalan .text.\n";
        }
        ByteBuffer data = image.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        long mod0 = text.memoryOffset()
                + Integer.toUnsignedLong(data.getInt((int) text.memoryOffset() + 4));
        if (regionEnd(segments, mod0, Integer.BYTES) < 0 || data.getInt((int) mod0) != MOD0_MAGIC) {
            return "MOD0 tidak terdeteksi pada offset dari awalan .text.\n";
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
                StringBuilder report = new StringBuilder("Metadata pemuatan MOD0\n")
                        .append("MOD0 0x").append(Long.toHexString(mod0))
                        .append(", .dynamic 0x").append(Long.toHexString(dynamic))
                        .append(" (").append(dynamicCount).append(" entri)\n");
                appendDependencies(report, data, segments, tags, needed, neededCount);
                appendRelocations(report, segments, tags);
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

    private static boolean isTrackedTag(int tag) {
        return switch (tag) {
            case DT_STRTAB, DT_STRSZ, DT_RELA, DT_RELASZ, DT_RELAENT, DT_REL, DT_RELSZ,
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

    private static String readName(ByteBuffer data, long offset, long end) throws IOException {
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

    private static void appendRelocations(StringBuilder report, NsoHeader.Segment[] segments, long[] tags)
            throws IOException {
        appendTable(report, segments, "RELA", tags[DT_RELA], tags[DT_RELASZ], tags[DT_RELAENT], RELA_ENTRY_SIZE);
        appendTable(report, segments, "REL", tags[DT_REL], tags[DT_RELSZ], tags[DT_RELENT], REL_ENTRY_SIZE);
        appendTable(report, segments, "RELR", tags[DT_RELR], tags[DT_RELRSZ], tags[DT_RELRENT], RELR_ENTRY_SIZE);
        if (tags[DT_PLTRELSZ] > 0 || tags[DT_JMPREL] >= 0) {
            long type = tags[DT_PLTREL];
            if (type != DT_REL && type != DT_RELA) {
                throw new IOException("Format relokasi PLT tidak dikenali.");
            }
            appendTable(report, segments, type == DT_RELA ? "PLT RELA" : "PLT REL", tags[DT_JMPREL],
                    tags[DT_PLTRELSZ], -1, type == DT_RELA ? RELA_ENTRY_SIZE : REL_ENTRY_SIZE);
        }
    }

    private static void appendTable(StringBuilder report, NsoHeader.Segment[] segments, String name,
                                    long address, long size, long declaredEntrySize, int entrySize)
            throws IOException {
        if (address < 0 && size <= 0) {
            return;
        }
        if (size < 0 || size % entrySize != 0 || (declaredEntrySize >= 0 && declaredEntrySize != entrySize)) {
            throw new IOException("Ukuran tabel relokasi " + name + " tidak valid.");
        }
        if (size > 0) {
            requireRange(segments, address, size, name);
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
