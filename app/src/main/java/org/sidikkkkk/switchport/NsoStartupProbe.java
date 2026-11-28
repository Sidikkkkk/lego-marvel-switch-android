package org.sidikkkkk.switchport;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

final class NsoStartupProbe {
    private static final int BRANCH_MASK = 0xfc00_0000;
    private static final int B = 0x1400_0000;
    private static final int BL = 0x9400_0000;
    private static final int MAX_STEPS = 8;

    private NsoStartupProbe() {}

    static void append(StringBuilder report, ByteBuffer image, NsoHeader.Segment text, long base) {
        ByteBuffer data = image.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        long pc = text.memoryOffset();
        long lastInstruction = text.memoryEnd() - Integer.BYTES;
        if ((pc & 3) != 0 || pc > lastInstruction) {
            report.append("Titik masuk .text tidak berisi instruksi AArch64 4 byte yang sejajar.\n");
            return;
        }
        for (int step = 0; step < MAX_STEPS; ++step) {
            int instruction = data.getInt((int) pc);
            int opcode = instruction & BRANCH_MASK;
            report.append("  0x").append(Long.toHexString(base + pc)).append(' ');
            if (opcode != B && opcode != BL) {
                report.append("kata 0x").append(Integer.toHexString(instruction))
                        .append(" — jejak berhenti, instruksi di luar cakupan.\n");
                return;
            }
            // Discard the opcode, then sign-extend imm26 with two zero bits appended.
            int displacement = (instruction << 6) >> 4;
            long target = pc + displacement;
            report.append(opcode == BL ? "BL" : "B").append(" → 0x").append(Long.toHexString(base + target));
            if (opcode == BL) {
                report.append(" (X30 = 0x").append(Long.toHexString(base + pc + Integer.BYTES)).append(')');
            }
            report.append('\n');
            if (target < text.memoryOffset() || target > lastInstruction) {
                report.append("Jejak berhenti. Target di luar .text rtld.\n");
                return;
            }
            pc = target;
        }
        report.append("Jejak berhenti setelah ").append(MAX_STEPS).append(" cabang.\n");
    }
}
