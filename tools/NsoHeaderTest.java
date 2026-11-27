package org.sidikkkkk.switchport;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

public final class NsoHeaderTest {
    private static final int MODULE_SIZE = 0x14c;

    public static void main(String[] arguments) throws IOException {
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
        require(NsoHeader.inspect(new ByteArrayInputStream(valid), -1)
                .contains("Batas akhir segmen belum diperiksa"), "Unknown file length");
        expectError(new byte[255], 255, "Header NSO0 terpotong");
        expectError(new byte[MODULE_SIZE], MODULE_SIZE, "Magic NSO0");
        expectError(valid, MODULE_SIZE - 1, "File NSO0 terpotong");
        expectError(fixture().putInt(0x20, 0x110).array(), MODULE_SIZE, "bertumpang tindih");
        expectError(fixture().putInt(0x34, 0xfffffff0).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().putInt(0x68, 0).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().putInt(0x10, 0xff).array(), MODULE_SIZE, "tidak valid");
        System.out.println("10 NSO header checks passed.");
    }

    private static ByteBuffer fixture() {
        ByteBuffer header = ByteBuffer.allocate(MODULE_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0, 0x304f534e).putInt(0x0c, 4);
        header.putInt(0x10, 0x100).putInt(0x14, 0).putInt(0x18, 0x20);
        header.putInt(0x20, 0x120).putInt(0x24, 0x1000).putInt(0x28, 0x20);
        header.putInt(0x30, 0x140).putInt(0x34, 0x2000).putInt(0x38, 0x20);
        header.put(0x40, (byte) 0x12).put(0x41, (byte) 0x34);
        header.putInt(0x68, 0x0c);
        return header;
    }

    private static void expectError(byte[] bytes, long fileLength, String detail) throws IOException {
        try {
            NsoHeader.inspect(new ByteArrayInputStream(bytes), fileLength);
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
