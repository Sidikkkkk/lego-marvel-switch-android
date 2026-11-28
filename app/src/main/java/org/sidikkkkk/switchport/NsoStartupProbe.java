package org.sidikkkkk.switchport;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

final class NsoStartupProbe {
    private static final int BRANCH_MASK = 0xfc00_0000;
    private static final int B = 0x1400_0000;
    private static final int BL = 0x9400_0000;
    private static final int MAX_STEPS = 32;
    private static final int NEARBY_WORDS = 12;
    private static final String[] CONDITIONS = {"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
            "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"};

    private record Flags(boolean n, boolean z, boolean c, boolean v) {
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
        report.append("  Kondisi awal simulasi X0 = 0x0\n");
        for (int step = 0; step < MAX_STEPS; ++step) {
            int instruction = data.getInt((int) pc);
            int opcode = instruction & BRANCH_MASK;
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
            } else if ((instruction & 0xff80_001f) == 0xf100_001f) {
                int source = (instruction >>> 5) & 31;
                int immediate = immediate12(instruction);
                report.append("CMP ").append(reg(source)).append(", #0x").append(Integer.toHexString(immediate));
                if (source == 31 || !known[source]) {
                    report.append(" — jejak berhenti, nilai register belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                flags = Flags.subtract(registers[source], immediate);
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
            } else if ((instruction & 0xff80_0000) == 0x9100_0000) {
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                report.append("ADD ").append(reg(destination)).append(", ").append(reg(source));
                if (source == 31 || destination == 31 || !known[source]) {
                    report.append(" — jejak berhenti, register atau SP belum dapat dimodelkan.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                registers[destination] = registers[source] + immediate12(instruction);
                known[destination] = true;
                report.append(" = 0x").append(Long.toHexString(registers[destination]));
            } else if ((instruction & 0x7fe0_ffe0) == 0x2a00_03e0) {
                int source = (instruction >>> 16) & 31;
                int destination = instruction & 31;
                boolean wide = instruction < 0;
                long value = wide ? registers[source] : registers[source] & 0xffff_ffffL;
                report.append("MOV ").append(zeroReg(destination, wide)).append(", ").append(zeroReg(source, wide));
                writeRegister(report, registers, known, destination, value, known[source]);
            } else if ((instruction & 0xbfc0_0000) == 0xb940_0000) {
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                boolean wide = (instruction & 0x4000_0000) != 0;
                int size = wide ? Long.BYTES : Integer.BYTES;
                long byteOffset = ((instruction >>> 10) & 0xfff) * size;
                report.append("LDR ").append(zeroReg(destination, wide)).append(", [").append(reg(source))
                        .append(", #0x").append(Long.toHexString(byteOffset)).append(']');
                if (source == 31 || !known[source]) {
                    report.append(" — jejak berhenti, register alamat belum diketahui.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                long loadAddress = registers[source] + byteOffset;
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
                report.append(" @0x").append(Long.toHexString(loadAddress));
                writeRegister(report, registers, known, destination, value, true);
            } else if ((instruction & 0xffff_fc00) == 0x9340_7c00) {
                int source = (instruction >>> 5) & 31;
                int destination = instruction & 31;
                report.append("SXTW ").append(zeroReg(destination, true)).append(", ").append(zeroReg(source, false));
                writeRegister(report, registers, known, destination, (int) registers[source], known[source]);
            } else if ((instruction & 0xbfe0_fc00) == 0x8b00_0000) {
                int left = (instruction >>> 5) & 31;
                int right = (instruction >>> 16) & 31;
                int destination = instruction & 31;
                boolean subtract = (instruction & 0x4000_0000) != 0;
                long value = subtract ? registers[left] - registers[right] : registers[left] + registers[right];
                boolean valueKnown = known[left] && known[right];
                report.append(subtract ? "SUB " : "ADD ")
                        .append(zeroReg(destination, true)).append(", ").append(zeroReg(left, true))
                        .append(", ").append(zeroReg(right, true));
                writeRegister(report, registers, known, destination, value, valueKnown);
                if (destination != 31 && valueKnown && bssEnd > bssStart && value == base + bssStart) {
                    report.append(" (awal .bss rtld)");
                }
            } else if ((instruction & 0x7f80_0000) == 0x5280_0000) {
                boolean wide = instruction < 0;
                int destination = instruction & 31;
                int shift = ((instruction >>> 21) & 3) * 16;
                report.append("MOVZ ").append(zeroReg(destination, wide));
                if (!wide && shift >= 32) {
                    report.append(" — jejak berhenti, encoding MOVZ W tidak valid.\n");
                    appendWords(report, data, pc, lastInstruction, base);
                    return;
                }
                long value = ((instruction >>> 5) & 0xffffL) << shift;
                writeRegister(report, registers, known, destination, value, true);
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

    private static int immediate12(int instruction) {
        int value = (instruction >>> 10) & 0xfff;
        return (instruction & 0x0040_0000) == 0 ? value : value << 12;
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
