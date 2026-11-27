package org.sidikkkkk.switchport;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

final class NsoRelocations {
    static final int SYMBOL_ENTRY_SIZE = 24;
    private static final int MAX_TYPE_ROWS = 24;
    private static final int MAX_IMPORT_SAMPLES = 16;

    record SymbolTable(long address, long count, long strings, long stringSize) {}

    private final ByteBuffer data;
    private final SymbolTable symbols;
    private final Map<Integer, Long> types = new LinkedHashMap<>();
    private final Set<Long> imports = new LinkedHashSet<>();
    private long otherTypes;
    private long symbolReferences;
    private long importReferences;
    private long invalidSymbolReferences;

    NsoRelocations(ByteBuffer data, SymbolTable symbols) {
        this.data = data;
        this.symbols = symbols;
    }

    void scan(long address, long size, int entrySize) throws InterruptedIOException {
        for (long offset = 0; offset < size; offset += entrySize) {
            if ((offset & 0xfff) == 0 && Thread.currentThread().isInterrupted()) {
                throw new InterruptedIOException("Pemeriksaan relokasi dibatalkan.");
            }
            long info = data.getLong((int) (address + offset) + Long.BYTES);
            int type = (int) info;
            Long count = types.get(type);
            if (count != null) {
                types.put(type, count + 1);
            } else if (types.size() < MAX_TYPE_ROWS) {
                types.put(type, 1L);
            } else {
                ++otherTypes;
            }
            long symbolIndex = info >>> 32;
            if (symbolIndex > 0) {
                recordSymbol(symbolIndex);
            }
        }
    }

    private void recordSymbol(long index) {
        ++symbolReferences;
        if (symbols == null) {
            return;
        }
        if (index >= symbols.count) {
            ++invalidSymbolReferences;
            return;
        }
        int entry = (int) (symbols.address + index * SYMBOL_ENTRY_SIZE);
        // Elf64_Sym.st_shndx is at byte 6. SHN_UNDEF is zero.
        if (data.getShort(entry + 6) == 0) {
            ++importReferences;
            if (imports.size() < MAX_IMPORT_SAMPLES) {
                imports.add(index);
            }
        }
    }

    void appendReport(StringBuilder report) throws InterruptedIOException {
        if (types.isEmpty()) {
            return;
        }
        report.append("\nJenis relokasi AArch64 (REL, RELA, PLT)\n");
        for (var entry : types.entrySet()) {
            report.append("  ").append(typeName(entry.getKey())).append("  ").append(entry.getValue())
                    .append(" entri\n");
        }
        if (otherTypes > 0) {
            report.append("  Jenis lain  ").append(otherTypes).append(" entri\n");
        }
        report.append("Referensi simbol  ").append(symbolReferences).append(" entri\n");
        if (symbolReferences == 0) {
            return;
        }
        if (symbols == null) {
            report.append("Nama impor tidak diperiksa karena batas .dynsym atau .dynstr belum terverifikasi.\n");
            return;
        }
        report.append("Referensi simbol impor  ").append(importReferences).append(" entri\n");
        if (invalidSymbolReferences > 0) {
            report.append("Indeks simbol di luar tabel  ").append(invalidSymbolReferences).append(" entri\n");
        }
        if (!imports.isEmpty()) {
            report.append("Contoh simbol impor (maks. ").append(MAX_IMPORT_SAMPLES).append(")\n");
            for (long index : imports) {
                report.append("  #").append(index).append(' ').append(symbolName(index)).append('\n');
            }
        }
    }

    private String symbolName(long index) throws InterruptedIOException {
        long nameOffset = Integer.toUnsignedLong(data.getInt((int) (symbols.address + index * SYMBOL_ENTRY_SIZE)));
        if (nameOffset == 0 || nameOffset >= symbols.stringSize) {
            return "(nama tidak tersedia)";
        }
        try {
            return NsoDynamic.readName(data, symbols.strings + nameOffset, symbols.strings + symbols.stringSize);
        } catch (InterruptedIOException error) {
            throw error;
        } catch (IOException error) {
            return "(nama tidak diakhiri NUL)";
        }
    }

    private static String typeName(int type) {
        return switch (type) {
            case 0 -> "R_AARCH64_NONE";
            case 257 -> "R_AARCH64_ABS64";
            case 580 -> "R_AARCH64_AUTH_ABS64";
            case 1024 -> "R_AARCH64_COPY";
            case 1025 -> "R_AARCH64_GLOB_DAT";
            case 1026 -> "R_AARCH64_JUMP_SLOT";
            case 1027 -> "R_AARCH64_RELATIVE";
            case 1028 -> "R_AARCH64_TLS_IMPDEF1";
            case 1029 -> "R_AARCH64_TLS_IMPDEF2";
            case 1030 -> "R_AARCH64_TLS_TPREL";
            case 1031 -> "R_AARCH64_TLSDESC";
            case 1032 -> "R_AARCH64_IRELATIVE";
            default -> "Tipe " + Integer.toUnsignedString(type);
        };
    }
}
