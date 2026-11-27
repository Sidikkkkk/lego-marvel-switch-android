package org.sidikkkkk.switchport;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

public final class NsoHeaderTest {
    private static final int MODULE_SIZE = 0x14c;

    public static void main(String[] arguments) throws Exception {
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
        require(report.contains("(terkompresi)\nSHA-256 sesuai header"), "Decoded data hash");
        require(report.contains("SHA-256 tidak tersedia di header"), "Optional hash");
        require(NsoHeader.inspect(new ByteArrayInputStream(valid), -1)
                .contains("Semua segmen berhasil dibaca"), "Unknown file length");
        expectError(new byte[255], 255, "Header NSO0 terpotong");
        expectError(new byte[MODULE_SIZE], MODULE_SIZE, "Magic NSO0");
        expectError(valid, MODULE_SIZE - 1, "File NSO0 terpotong");
        expectError(Arrays.copyOf(valid, MODULE_SIZE - 1), -1, "Segmen .data terpotong");
        expectError(fixture().putInt(0x20, 0x110).array(), MODULE_SIZE, "bertumpang tindih");
        expectError(fixture().putInt(0x34, 0xfffffff0).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().putInt(0x68, 0).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().putInt(0x10, 0xff).array(), MODULE_SIZE, "tidak valid");
        expectError(fixture().put(0x100, (byte) 0).array(), MODULE_SIZE, "Segmen .text: SHA-256 berbeda");
        expectError(fixture().put(0x14b, (byte) 0).array(), MODULE_SIZE, "Segmen .data: SHA-256 berbeda");
        expectError(fixture().put(0x143, (byte) 0).array(), MODULE_SIZE, "Offset salinan LZ4 tidak valid");
        expectError(fixture().put(0x143, (byte) 3).array(), MODULE_SIZE, "Offset salinan LZ4 tidak valid");
        expectError(fixture().putInt(0x38, 33).array(), MODULE_SIZE, "ukuran hasil LZ4 tidak valid");
        expectError(fixture().put(0x145, (byte) 0xff).array(), MODULE_SIZE, "Panjang LZ4 melampaui");

        byte[] reordered = fixture().putInt(0x10, 0x120).putInt(0x20, 0x100).array();
        System.arraycopy(valid, 0x100, reordered, 0x120, 0x20);
        System.arraycopy(valid, 0x120, reordered, 0x100, 0x20);
        require(NsoHeader.inspect(new ByteArrayInputStream(reordered), reordered.length)
                .contains("Segmen NSO0 berhasil diperiksa"), "File offsets out of segment order");
        byte[] empty = module(new byte[]{0}, new byte[0]).array();
        require(NsoHeader.inspect(new ByteArrayInputStream(empty), empty.length)
                .contains("1 byte tersimpan, 0 byte di memori"), "Empty LZ4 block");
        byte[] wrapsHistory = largeMatchFixture();
        require(NsoHeader.inspect(new ByteArrayInputStream(wrapsHistory), wrapsHistory.length)
                .contains("(terkompresi)\nSHA-256 sesuai header"), "Match crosses history buffer boundary");
        System.out.println("22 NSO checks passed.");
    }

    private static ByteBuffer fixture() throws Exception {
        byte[] compressed = {0x2f, 'A', 'B', 2, 0, 6, 0x50, 'C', 'D', 'E', 'F', 'G'};
        byte[] decompressed = new byte[32];
        for (int i = 0; i < 27; i++) {
            decompressed[i] = (byte) ('A' + i % 2);
        }
        System.arraycopy(compressed, 7, decompressed, 27, 5);
        return module(compressed, decompressed);
    }

    private static ByteBuffer module(byte[] compressed, byte[] decompressed) throws Exception {
        ByteBuffer header = ByteBuffer.allocate(0x140 + compressed.length).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0, 0x304f534e).putInt(0x0c, 4 | (1 << 3) | (1 << 5));
        header.putInt(0x10, 0x100).putInt(0x14, 0).putInt(0x18, 0x20);
        header.putInt(0x20, 0x120).putInt(0x24, 0x1000).putInt(0x28, 0x20);
        header.putInt(0x30, 0x140).putInt(0x34, 0x2000).putInt(0x38, decompressed.length);
        header.put(0x40, (byte) 0x12).put(0x41, (byte) 0x34);
        header.putInt(0x68, compressed.length);
        byte[] text = new byte[0x20];
        Arrays.fill(text, (byte) 'T');
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        header.position(0xa0).put(digest.digest(text));
        header.position(0xe0).put(digest.digest(decompressed));
        header.position(0x100).put(text);
        header.position(0x140).put(compressed);
        return header;
    }

    private static byte[] largeMatchFixture() throws Exception {
        int matchLength = 70_001;
        byte[] decompressed = new byte[1 + matchLength + 5];
        Arrays.fill(decompressed, (byte) 'A');
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        compressed.write(new byte[]{0x1f, 'A', 1, 0});
        for (int extension = matchLength - 19; ; extension -= 255) {
            compressed.write(Math.min(extension, 255));
            if (extension < 255) {
                break;
            }
        }
        compressed.write(new byte[]{0x50, 'A', 'A', 'A', 'A', 'A'});
        return module(compressed.toByteArray(), decompressed).array();
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
