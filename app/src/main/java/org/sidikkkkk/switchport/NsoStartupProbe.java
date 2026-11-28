package org.sidikkkkk.switchport;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

final class NsoStartupProbe {
    private static final int BRANCH_MASK = 0xfc00_0000;
    private static final int B = 0x1400_0000;
    private static final int BL = 0x9400_0000;
    private static final int MAX_STEPS = 1024;
    private static final int NEARBY_WORDS = 12;
    private static final String[] CONDITIONS = {"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
            "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"};

    private record Flags(boolean n, boolean z, boolean c, boolean v) {
        static Flags subtract(int left, int right) {
            int result = left - right;
            return new Flags(result < 0, result == 0, Integer.compareUnsigned(left, right) >= 0,
                    ((left ^ right) & (left ^ result)) < 0);
        }

        static Flags subtract(long left, long right) {
            long result = left - right;
            return new Flags(result < 0, result == 0, Long.compareUnsigned(left, right) >= 0,
                    ((left ^ right) & (left ^ result)) < 0);
        }

        boolean holds(int condition) {
            boolean positive = switch (condition >>> 1) {
                case 0 -> z;
                case 1 -> c;
                case 2 -> n;
                case 3 -> v;
                case 4 -> c && !z;
                case 5 -> n == v;
                case 6 -> n == v && !z;
                default -> true;
            };
            return (condition & 1) != 0 && condition != 15 ? !positive : positive;
        }

        int nzcv() {
            return (n ? 8 : 0) | (z ? 4 : 0) | (c ? 2 : 0) | (v ? 1 : 0);
        }
    }

    private NsoStartupProbe() {}

    static void append(StringBuilder report, ByteBuffer image, NsoHeader.Segment[] segments, long base,
                       long bssStart, long bssEnd) {
        ByteBuffer data = image.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        NsoHeader.Segment text = segments[0];
        NsoHeader.Segment writableData = segments[2];
        long pc = text.memoryOffset();
        long lastInstruction = text.memoryEnd() - Integer.BYTES;
        if ((pc & 3) != 0 || pc > lastInstruction) {
            report.append("Titik masuk .text tidak berisi instruksi AArch64 4 byte yang sejajar.\n");
            return;
        }
        // On the normal process entry path, X0 is zero. X1 (thread handle) and SP remain unknown.
        long[] registers = new long[32];
        boolean[] known = new boolean[32];
        known[0] = true;
        known[31] = true; // XZR/WZR. The SP encodings check index 31 explicitly.
        Flags flags = null;
        Map<Long, Byte> memoryWrites = new HashMap<>();
        report.append("  Kondisi awal simulasi X0 = 0x0\n");
        for (int step = 0; step < MAX_STEPS; ++step) {
            int instruction = data.getInt((int) pc);
            int opcode = instruction & BRANCH_MASK;
            int opcodeWithoutSf = instruction & 0x7f80_0000;
            boolean registerCompare = (instruction & 0xffe0_fc1f) == 0xeb00_001f;
            boolean unscaledLoad = (instruction & 0xbfe0_0c00) == 0xb840_0000;
            boolean postIndexedLoad = (instruction & 0xbfe0_0c00) == 0xb840_0400;
            boolean unsignedStore = (instruction & 0x7fc0_0000) == 0x3900_0000;
            boolean unscaledStore = (instruction & 0x7fe0_0c00) == 0x3800_0000;
            boolean pairStore = (instruction & 0x7fc0_0000) == 0x2900_0000;
            boolean registerOffsetStore = (instruction & 0xffe0_fc00) == 0xf820_6800;
            long address = base + pc;
            long target = pc + Integer.BYTES;
            report.append("  0x").append(Long.toHexString(address)).append(' ');
            if (opcode == B || opcode == BL) {
                // Discard the opcode, then sign-extend imm26 with two zero bits appended.
                target = pc + ((instruction << 6) >> 4);
                report.append(opcode == BL ? "BL" : "B").append(" → 0x").append(Long.toHexString(base + target));
                if (opcode == BL) {
                    registers[30] = address + Integer.BYTES;
                    known[30] = true;
                    report.append(" (X30 = 0x").append(Long.toHexString(registers[30])).append(')');
                }
            } else if (registerCompare || (instruction & 0x7f80_001f) == 0x7100_001f) {
                int source = (instruction >>> 5) & 31;
                boolean wide = instruction < 0;
                long right;
                boolean operandsKnown;
                if (registerCompare) {
                    int secondSource = (instruction >>> 16) & 31;
                    report.append("CMP ").append(zeroReg(source, true)).append(", ").append(zeroReg(secondSource, true));
                    right = registers[secondSource];
                    operandsKnown = known[source] && known[secondSource];
                } else {
                    int immediate = immediate12(instruction);
                    String sourceName = wide ? reg(source) : source == 31 ? "WSP" : "W" + source;
                    report.append("CMP ").append(sourceName).append(", #0x").append(Integer.toHexString(immediate));
                    right = immediate;
                    operandsKnown = source != 31 && known[source];
                }
                if (!operandsKnown) {
                    report.append(" — jejak berhenti, nilai register belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                flags = wide ? Flags.subtract(registers[source], right)
                        : Flags.subtract((int) registers[source], (int) right);
                report.append(" (NZCV = 0x").append(Integer.toHexString(flags.nzcv())).append(')');
            } else if ((instruction & 0xff00_0010) == 0x5400_0000) {
                int condition = instruction & 15;
                int imm19 = (instruction >>> 5) & 0x7ffff;
                long branch = pc + ((imm19 << 13) >> 11);
                report.append("B.").append(CONDITIONS[condition]).append(" → 0x").append(Long.toHexString(base + branch));
                if (flags == null && condition < 14) {
                    report.append(" — jejak berhenti, NZCV belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                boolean taken = condition >= 14 || flags.holds(condition);
                if (taken) {
                    target = branch;
                }
                report.append(taken ? " (diambil)" : " (tidak diambil)");
            } else if ((instruction & 0x7e00_0000) == 0x3400_0000) {
                boolean wide = instruction < 0;
                boolean nonzero = (instruction & 0x0100_0000) != 0;
                int source = instruction & 31;
                int imm19 = (instruction >>> 5) & 0x7ffff;
                long branch = pc + ((imm19 << 13) >> 11);
                report.append(nonzero ? "CBNZ " : "CBZ ").append(zeroReg(source, wide))
                        .append(" → 0x").append(Long.toHexString(base + branch));
                if (!known[source]) {
                    report.append(" — jejak berhenti, nilai register belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                long value = wide ? registers[source] : registers[source] & 0xffff_ffffL;
                boolean taken = (value != 0) == nonzero;
                if (taken) {
                    target = branch;
                }
                report.append(taken ? " (diambil)" : " (tidak diambil)");
            } else if ((instruction & 0x1f00_0000) == 0x1000_0000) {
                int destination = instruction & 31;
                int imm21 = (((instruction >>> 5) & 0x7ffff) << 2) | ((instruction >>> 29) & 3);
                long displacement = (imm21 << 11) >> 11;
                boolean page = instruction < 0;
                long value = page ? (address & ~0xfffL) + (displacement << 12) : address + displacement;
                report.append(page ? "ADRP " : "ADR ").append(destination == 31 ? "XZR" : reg(destination))
                        .append(" = 0x").append(Long.toHexString(value));
                if (destination != 31) {
                    registers[destination] = value;
                    known[destination] = true;
                }
            } else if ((instruction & 0xbf80_0000) == 0x9100_0000) {
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                boolean subtract = (instruction & 0x4000_0000) != 0;
                report.append(subtract ? "SUB " : "ADD ").append(reg(destination)).append(", ").append(reg(source));
                if (source == 31 || destination == 31 || !known[source]) {
                    report.append(" — jejak berhenti, register atau SP belum dapat dimodelkan.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                int immediate = immediate12(instruction);
                registers[destination] = registers[source] + (subtract ? -immediate : immediate);
                known[destination] = true;
                report.append(" = 0x").append(Long.toHexString(registers[destination]));
            } else if ((instruction & 0x7fe0_ffe0) == 0x2a00_03e0) {
                int source = (instruction >>> 16) & 31;
                int destination = instruction & 31;
                boolean wide = instruction < 0;
                long value = wide ? registers[source] : registers[source] & 0xffff_ffffL;
                report.append("MOV ").append(zeroReg(destination, wide)).append(", ").append(zeroReg(source, wide));
                writeRegister(report, registers, known, destination, value, known[source]);
            } else if (unscaledLoad || postIndexedLoad || (instruction & 0xbfc0_0000) == 0xb940_0000) {
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                boolean wide = (instruction & 0x4000_0000) != 0;
                int size = wide ? Long.BYTES : Integer.BYTES;
                boolean signedOffset = unscaledLoad || postIndexedLoad;
                int byteOffset = signedOffset ? (instruction << 11) >> 23 : ((instruction >>> 10) & 0xfff) * size;
                report.append(unscaledLoad ? "LDUR " : "LDR ").append(zeroReg(destination, wide)).append(", [")
                        .append(reg(source)).append(postIndexedLoad ? "], #" : ", #")
                        .append(signedOffset ? Integer.toString(byteOffset) : "0x" + Integer.toHexString(byteOffset));
                if (!postIndexedLoad) {
                    report.append(']');
                }
                if (source == 31 || !known[source]) {
                    report.append(" — jejak berhenti, register alamat belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                if (postIndexedLoad && source == destination) {
                    report.append(" — jejak berhenti, register alamat dan tujuan post-index sama.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                long loadAddress = registers[source] + (postIndexedLoad ? 0 : byteOffset);
                long offset = loadAddress - base;
                boolean inBss = offset >= bssStart && offset <= bssEnd - size;
                if (loadAddress < base || (offset & (size - 1)) != 0
                        || (!inBss && NsoDynamic.regionEnd(segments, offset, size) < 0)) {
                    report.append(" @0x").append(Long.toHexString(loadAddress))
                            .append(" — jejak berhenti, alamat di luar rentang baca rtld yang sejajar.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                long value = wide ? data.getLong((int) offset) : data.getInt((int) offset) & 0xffff_ffffL;
                for (int index = 0; index < size; ++index) {
                    Byte stored = memoryWrites.get(offset + index);
                    if (stored != null) {
                        int shift = Byte.SIZE * index;
                        value = (value & ~(0xffL << shift)) | ((stored & 0xffL) << shift);
                    }
                }
                report.append(" @0x").append(Long.toHexString(loadAddress));
                writeRegister(report, registers, known, destination, value, true);
                if (postIndexedLoad) {
                    registers[source] = loadAddress + byteOffset;
                    report.append(" (").append(reg(source)).append(" = 0x")
                            .append(Long.toHexString(registers[source])).append(')');
                }
            } else if (unsignedStore || unscaledStore || pairStore || registerOffsetStore) {
                int source = instruction & 31;
                int secondSource = (instruction >>> 10) & 31;
                int addressRegister = (instruction >>> 5) & 31;
                int offsetRegister = (instruction >>> 16) & 31;
                int size;
                long byteOffset;
                if (pairStore) {
                    boolean wide = instruction < 0;
                    size = wide ? Long.BYTES : Integer.BYTES;
                    int scaledOffset = (instruction << 10) >> 25; // Signed imm7 in bits 21:15.
                    byteOffset = scaledOffset * size;
                    report.append("STP ").append(zeroReg(source, wide)).append(", ")
                            .append(zeroReg(secondSource, wide));
                } else if (registerOffsetStore) {
                    size = Long.BYTES;
                    byteOffset = registers[offsetRegister];
                    report.append("STR ").append(zeroReg(source, true));
                } else {
                    size = instruction < 0 ? Integer.BYTES : 1;
                    int encodedOffset = (instruction >>> 12) & 0x1ff;
                    byteOffset = unscaledStore ? (encodedOffset << 23) >> 23 : ((instruction >>> 10) & 0xfff) * size;
                    report.append(unscaledStore ? "STUR" : "STR").append(size == 1 ? "B " : " ")
                            .append(zeroReg(source, false));
                }
                report.append(", [").append(reg(addressRegister)).append(", ");
                if (registerOffsetStore) {
                    report.append(zeroReg(offsetRegister, true));
                } else {
                    report.append('#').append(byteOffset);
                }
                report.append(']');
                if (addressRegister == 31 || !known[addressRegister] || !known[source]
                        || (pairStore && !known[secondSource]) || (registerOffsetStore && !known[offsetRegister])) {
                    report.append(" — jejak berhenti, nilai atau alamat simpan belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                long storeAddress = registers[addressRegister] + byteOffset;
                long offset = storeAddress - base;
                int totalSize = pairStore ? 2 * size : size;
                report.append(" @0x").append(Long.toHexString(storeAddress));
                boolean inBss = offset >= bssStart && offset <= bssEnd - totalSize;
                boolean inData = registerOffsetStore && offset >= writableData.memoryOffset()
                        && offset <= writableData.memoryEnd() - totalSize;
                if (storeAddress < base || (!inBss && !inData)) {
                    report.append(registerOffsetStore
                            ? " — jejak berhenti, alamat simpan di luar .data atau .bss rtld.\n"
                            : " — jejak berhenti, alamat simpan di luar .bss rtld.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                if ((storeAddress & (size - 1)) != 0) {
                    report.append(" — jejak berhenti, alamat simpan tidak sejajar.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                report.append(" = 0x");
                appendStoreValue(report, memoryWrites, offset, registers[source], size);
                if (pairStore) {
                    report.append(", 0x");
                    appendStoreValue(report, memoryWrites, offset + size, registers[secondSource], size);
                }
                report.append(inData ? " (.data simulasi)" : " (.bss simulasi)");
            } else if ((instruction & 0xffc0_0000) == 0xb340_0000) {
                int immr = (instruction >>> 16) & 63;
                int imms = (instruction >>> 10) & 63;
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                if (immr <= imms || source == 31) {
                    report.append("BFM — jejak berhenti, hanya bentuk BFI 64-bit yang didukung.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                int lsb = Long.SIZE - immr;
                int width = imms + 1;
                long fieldMask = (1L << width) - 1;
                long value = (registers[destination] & ~(fieldMask << lsb))
                        | ((registers[source] & fieldMask) << lsb);
                report.append("BFI ").append(zeroReg(destination, true)).append(", ").append(zeroReg(source, true))
                        .append(", #").append(lsb).append(", #").append(width);
                writeRegister(report, registers, known, destination, value, known[source] && known[destination]);
            } else if ((instruction & 0xffff_fc00) == 0x9340_7c00) {
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                report.append("SXTW ").append(zeroReg(destination, true)).append(", ").append(zeroReg(source, false));
                writeRegister(report, registers, known, destination, (int) registers[source], known[source]);
            } else if ((instruction & 0x3fe0_fc00) == 0x0b00_0000) {
                int left = (instruction >>> 5) & 31;
                int right = (instruction >>> 16) & 31;
                int destination = instruction & 31;
                boolean wide = instruction < 0;
                boolean subtract = (instruction & 0x4000_0000) != 0;
                long value = subtract ? registers[left] - registers[right] : registers[left] + registers[right];
                if (!wide) {
                    value &= 0xffff_ffffL;
                }
                boolean valueKnown = known[left] && known[right];
                report.append(subtract ? "SUB " : "ADD ")
                        .append(zeroReg(destination, wide)).append(", ").append(zeroReg(left, wide))
                        .append(", ").append(zeroReg(right, wide));
                writeRegister(report, registers, known, destination, value, valueKnown);
                if (wide && destination != 31 && valueKnown && bssEnd > bssStart && value == base + bssStart) {
                    report.append(" (awal .bss rtld)");
                }
            } else if (opcodeWithoutSf == 0x1200_0000 || opcodeWithoutSf == 0x3200_0000) {
                boolean wide = instruction < 0;
                boolean and = opcodeWithoutSf == 0x1200_0000;
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                report.append(and ? "AND " : "ORR ");
                Long mask = logicalImmediateMask(instruction, wide ? Long.SIZE : Integer.SIZE);
                if (mask == null || destination == 31) {
                    report.append(mask == null ? "— jejak berhenti, encoding mask tidak valid.\n"
                            : "— jejak berhenti, SP belum dapat dimodelkan.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                report.append(zeroReg(destination, wide)).append(", ").append(zeroReg(source, wide))
                        .append(", #0x").append(Long.toHexString(mask));
                long value = and ? registers[source] & mask : registers[source] | mask;
                writeRegister(report, registers, known, destination, wide ? value : value & 0xffff_ffffL, known[source]);
            } else if ((instruction & 0x7fe0_fc00) == 0x1b00_7c00) {
                boolean wide = instruction < 0;
                int left = (instruction >>> 5) & 31;
                int right = (instruction >>> 16) & 31;
                int destination = instruction & 31;
                report.append("MUL ").append(zeroReg(destination, wide)).append(", ").append(zeroReg(left, wide))
                        .append(", ").append(zeroReg(right, wide));
                long value = registers[left] * registers[right];
                writeRegister(report, registers, known, destination, wide ? value : value & 0xffff_ffffL,
                        known[left] && known[right]);
            } else if (opcodeWithoutSf == 0x5280_0000 || opcodeWithoutSf == 0x7280_0000) {
                boolean wide = instruction < 0;
                boolean keep = opcodeWithoutSf == 0x7280_0000;
                String mnemonic = keep ? "MOVK" : "MOVZ";
                int destination = instruction & 31;
                int shift = ((instruction >>> 21) & 3) * 16;
                report.append(mnemonic).append(' ').append(zeroReg(destination, wide));
                if (!wide && shift >= 32) {
                    report.append(" — jejak berhenti, encoding ").append(mnemonic).append(" W tidak valid.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                long value = ((instruction >>> 5) & 0xffffL) << shift;
                if (keep) {
                    value |= registers[destination] & ~(0xffffL << shift);
                }
                writeRegister(report, registers, known, destination, wide ? value : value & 0xffff_ffffL,
                        !keep || known[destination]);
            } else if ((instruction & 0xffff_fc1f) == 0xd65f_0000) {
                int source = (instruction >>> 5) & 31;
                report.append("RET ").append(zeroReg(source, true));
                if (!known[source]) {
                    report.append(" — jejak berhenti, alamat balik belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                target = registers[source] - base;
                report.append(" → 0x").append(Long.toHexString(registers[source]));
            } else {
                report.append("kata 0x").append(Integer.toHexString(instruction))
                        .append(" — jejak berhenti, instruksi di luar cakupan.\n");
                appendWords(report, data, pc, lastInstruction, base);
                return;
            }
            report.append('\n');
            if ((target & 3) != 0) {
                report.append("Jejak berhenti. Target tidak sejajar 4 byte.\n");
                return;
            }
            if (target < text.memoryOffset() || target > lastInstruction) {
                report.append("Jejak berhenti. Target di luar .text rtld.\n");
                return;
            }
            pc = target;
        }
        report.append("Jejak berhenti setelah ").append(MAX_STEPS).append(" instruksi.\n");
        appendWords(report, data, pc, lastInstruction, base);
    }

    private static void appendStoreValue(StringBuilder report, Map<Long, Byte> memoryWrites,
                                         long offset, long value, int size) {
        long stored = switch (size) {
            case 1 -> value & 0xffL;
            case Integer.BYTES -> value & 0xffff_ffffL;
            case Long.BYTES -> value;
            default -> throw new IllegalArgumentException("Unsupported store size: " + size);
        };
        for (int index = 0; index < size; ++index) {
            memoryWrites.put(offset + index, (byte) (stored >>> (Byte.SIZE * index)));
        }
        report.append(Long.toHexString(stored));
    }

    private static int immediate12(int instruction) {
        int value = (instruction >>> 10) & 0xfff;
        return (instruction & 0x0040_0000) == 0 ? value : value << 12;
    }

    private static Long logicalImmediateMask(int instruction, int width) {
        int n = (instruction >>> 22) & 1;
        int imms = (instruction >>> 10) & 63;
        int immr = (instruction >>> 16) & 63;
        int length = 31 - Integer.numberOfLeadingZeros((n << 6) | (~imms & 63));
        if (length < 1 || (1 << length) > width) {
            return null;
        }
        int elementSize = 1 << length;
        int levels = elementSize - 1;
        int lastSetBit = imms & levels;
        if (lastSetBit == levels) {
            return null;
        }
        int rotation = immr & levels;
        long element = (1L << (lastSetBit + 1)) - 1;
        if (rotation != 0) {
            long elementMask = elementSize == Long.SIZE ? -1L : (1L << elementSize) - 1;
            element = ((element >>> rotation) | (element << (elementSize - rotation))) & elementMask;
        }
        long mask = 0;
        for (int shift = 0; shift < width; shift += elementSize) {
            mask |= element << shift;
        }
        return mask;
    }

    private static String reg(int index) {
        return index == 31 ? "SP" : "X" + index;
    }

    private static String zeroReg(int index, boolean wide) {
        return (wide ? "X" : "W") + (index == 31 ? "ZR" : Integer.toString(index));
    }

    private static void writeRegister(StringBuilder report, long[] registers, boolean[] known, int index,
                                      long value, boolean valueKnown) {
        if (index == 31) {
            report.append(" (hasil dibuang)");
            return;
        }
        registers[index] = value;
        known[index] = valueKnown;
        if (valueKnown) {
            report.append(" = 0x").append(Long.toHexString(value));
        } else {
            report.append(" = belum diketahui");
        }
    }

    private static void appendWords(StringBuilder report, ByteBuffer data, long pc, long lastInstruction, long base) {
        report.append("  Kata .text mulai 0x").append(Long.toHexString(base + pc)).append('\n').append("    ");
        for (int index = 0; index < NEARBY_WORDS && pc <= lastInstruction; ++index, pc += Integer.BYTES) {
            report.append(" 0x").append(Integer.toHexString(data.getInt((int) pc)));
        }
        report.append('\n');
    }
}
