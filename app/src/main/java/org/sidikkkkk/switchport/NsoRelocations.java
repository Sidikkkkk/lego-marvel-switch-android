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
    static final int AARCH64_RELATIVE = 1027;
    private static final int AARCH64_GLOB_DAT = 1025;
    private static final int STB_WEAK = 2;
    private static final int MAX_TYPE_ROWS = 24;
    private static final int MAX_IMPORT_SAMPLES = 16;
    private static final int MAX_TRACKED_IMPORT_INDICES = 4096;

    record SymbolTable(long address, long count, long strings, long stringSize) {}

    private static final class ImportUse {
        final int firstEntry;
        final int entrySize;
        final String table;
        long count = 1;

        ImportUse(int firstEntry, int entrySize, String table) {
            this.firstEntry = firstEntry;
            this.entrySize = entrySize;
            this.table = table;
        }
    }

    private final ByteBuffer data;
    private final SymbolTable symbols;
    private final Map<Long, ImportUse> importUses;
    private final Map<Integer, Long> types = new LinkedHashMap<>();
    private final Set<Long> imports = new LinkedHashSet<>();
    private long otherTypes;
    private long symbolReferences;
    private long importReferences;
    private long invalidSymbolReferences;

    NsoRelocations(ByteBuffer data, SymbolTable symbols, boolean captureImports) {
        this.data = data;
        this.symbols = symbols;
        importUses = captureImports ? new LinkedHashMap<>() : null;
    }

    void scan(long address, long size, int entrySize, String table) throws InterruptedIOException {
        for (long offset = 0; offset < size; offset += entrySize) {
            if ((offset & 0xfff) == 0 && Thread.currentThread().isInterrupted()) {
                throw new InterruptedIOException("Pemeriksaan relokasi dibatalkan.");
            }
            int entry = (int) (address + offset);
            long info = data.getLong(entry + Long.BYTES);
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
                recordSymbol(symbolIndex, entry, entrySize, table);
            }
        }
    }

    private void recordSymbol(long index, int relocationEntry, int entrySize, String table) {
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
            if (importUses != null) {
                ImportUse use = importUses.get(index);
                if (use != null) {
                    ++use.count;
                } else if (importUses.size() < MAX_TRACKED_IMPORT_INDICES) {
                    importUses.put(index, new ImportUse(relocationEntry, entrySize, table));
                }
            }
        }
    }

    void captureImports(NsoImportAudit audit, NsoHeader.Segment writableData) throws InterruptedIOException {
        for (var entry : importUses.entrySet()) {
            int offset = (int) (symbols.address + entry.getKey() * SYMBOL_ENTRY_SIZE);
            String name = NsoImportAudit.exactName(data, symbols, offset);
            if (name != null) {
                ImportUse use = entry.getValue();
                audit.addImport(name, use.count);
                if (isRelocationBoundaryName(name)) {
                    audit.addBoundaryEvidence(describeBoundary(name, entry.getKey(), offset, use));
                    captureWeakSlot(audit, name, offset, use, writableData);
                }
            }
        }
        audit.finishImports(importReferences, invalidSymbolReferences);
    }

    private void captureWeakSlot(NsoImportAudit audit, String name, int symbol, ImportUse use,
                                 NsoHeader.Segment writableData) {
        int entry = use.firstEntry;
        if (use.count != 1 || !use.table.equals("RELA") || data.get(symbol + 4) != (STB_WEAK << 4)
                || data.get(symbol + 5) != 0 || data.getLong(symbol + 8) != 0
                || data.getInt(entry + Long.BYTES) != AARCH64_GLOB_DAT || data.getLong(entry + 2 * Long.BYTES) != 0) {
            return;
        }
        long target = data.getLong(entry);
        if ((target & (Long.BYTES - 1)) == 0 && target >= writableData.memoryOffset()
                && target <= writableData.memoryEnd() - Long.BYTES) {
            audit.addWeakSlot(name, target, data.getLong((int) target));
        }
    }

    private static boolean isRelocationBoundaryName(String name) {
        return switch (name) {
            case "__rel_dyn_start", "__rel_dyn_end", "__rel_plt_start", "__rel_plt_end" -> true;
            default -> false;
        };
    }

    private String describeBoundary(String name, long index, int symbol, ImportUse use) {
        int info = data.get(symbol + 4) & 0xff;
        String binding = switch (info >>> 4) {
            case 0 -> "STB_LOCAL";
            case 1 -> "STB_GLOBAL";
            case STB_WEAK -> "STB_WEAK";
            default -> "binding " + (info >>> 4);
        };
        int entry = use.firstEntry;
        StringBuilder row = new StringBuilder("  ").append(name).append(" #").append(index)
                .append(' ').append(binding).append(" (SHN_UNDEF, tipe ").append(info & 0xf)
                .append(", vis ").append(data.get(symbol + 5) & 3).append(", st_value 0x")
                .append(Long.toHexString(data.getLong(symbol + 8))).append(")\n")
                .append("    ").append(use.count).append(" referensi. Pertama ").append(use.table)
                .append(" @0x").append(Integer.toHexString(entry)).append(' ')
                .append(typeName(data.getInt(entry + Long.BYTES)))
                .append(" → 0x").append(Long.toHexString(data.getLong(entry)));
        if (use.entrySize == 3 * Long.BYTES) {
            row.append(", addend ").append(data.getLong(entry + 2 * Long.BYTES));
        }
        return row.append('\n').toString();
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
            case AARCH64_GLOB_DAT -> "R_AARCH64_GLOB_DAT";
            case 1026 -> "R_AARCH64_JUMP_SLOT";
            case AARCH64_RELATIVE -> "R_AARCH64_RELATIVE";
            case 1028 -> "R_AARCH64_TLS_IMPDEF1";
            case 1029 -> "R_AARCH64_TLS_IMPDEF2";
            case 1030 -> "R_AARCH64_TLS_TPREL";
            case 1031 -> "R_AARCH64_TLSDESC";
            case 1032 -> "R_AARCH64_IRELATIVE";
            default -> "Tipe " + Integer.toUnsignedString(type);
        };
    }
}
