package org.sidikkkkk.switchport;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

final class NsoHeader {
    private static final int HEADER_SIZE = 0x100;
    private static final int MAGIC = 0x304f534e;
    private static final long ADDRESS_LIMIT = 1L << 32;
    private static final String[] SEGMENT_NAMES = {".text", ".rodata", ".data"};
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private record Segment(long fileOffset, long storedSize, long memoryOffset,
                           long unpackedSize, boolean compressed) {}

    private NsoHeader() {}

    static String inspect(InputStream input, long fileLength) throws IOException {
        byte[] bytes = new byte[HEADER_SIZE];
        try {
            new DataInputStream(input).readFully(bytes);
        } catch (EOFException error) {
            throw new IOException("Header NSO0 terpotong.", error);
        }

        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        if (header.getInt(0) != MAGIC) {
            throw new IOException("Magic NSO0 tidak ditemukan. Pilih file main asli dari ExeFS.");
        }

        int flags = header.getInt(0x0c);
        Segment[] segments = new Segment[SEGMENT_NAMES.length];
        long minimumSize = HEADER_SIZE;
        for (int index = 0; index < segments.length; ++index) {
            int offset = 0x10 + index * 0x10;
            long fileOffset = unsignedInt(header, offset);
            long memoryOffset = unsignedInt(header, offset + 4);
            long unpackedSize = unsignedInt(header, offset + 8);
            boolean compressed = (flags & (1 << index)) != 0;
            long storedSize = compressed ? unsignedInt(header, 0x60 + index * 4) : unpackedSize;
            if (memoryOffset + unpackedSize > ADDRESS_LIMIT
                    || (compressed && (storedSize == 0) != (unpackedSize == 0))
                    || (storedSize > 0 && fileOffset < HEADER_SIZE)) {
                throw new IOException("Rentang atau ukuran segmen " + SEGMENT_NAMES[index] + " tidak valid.");
            }

            Segment segment = new Segment(fileOffset, storedSize, memoryOffset, unpackedSize, compressed);
            for (int previous = 0; previous < index; ++previous) {
                Segment other = segments[previous];
                if (overlaps(segment.fileOffset, segment.storedSize, other.fileOffset, other.storedSize)
                        || overlaps(segment.memoryOffset, segment.unpackedSize,
                                    other.memoryOffset, other.unpackedSize)) {
                    throw new IOException("Segmen " + SEGMENT_NAMES[index] + " bertumpang tindih.");
                }
            }
            segments[index] = segment;
            if (storedSize > 0) {
                minimumSize = Math.max(minimumSize, fileOffset + storedSize);
            }
        }

        if (fileLength >= 0 && fileLength < minimumSize) {
            throw new IOException("File NSO0 terpotong. Header memerlukan sedikitnya " + minimumSize + " byte.");
        }

        StringBuilder report = new StringBuilder("Header NSO0 terbaca\nBuild ID  ");
        for (int index = 0x40; index < 0x60; ++index) {
            int value = Byte.toUnsignedInt(bytes[index]);
            report.append(HEX[value >>> 4]).append(HEX[value & 0x0f]);
        }
        report.append("\n\n");
        for (int index = 0; index < segments.length; ++index) {
            Segment segment = segments[index];
            report.append(SEGMENT_NAMES[index])
                    .append("  file 0x").append(Long.toHexString(segment.fileOffset))
                    .append("  memori 0x").append(Long.toHexString(segment.memoryOffset))
                    .append("\n").append(segment.storedSize).append(" byte tersimpan, ")
                    .append(segment.unpackedSize).append(" byte di memori")
                    .append(segment.compressed ? " (terkompresi)\n" : "\n");
        }
        if (fileLength < 0) {
            report.append("\nPenyedia file tidak memberi ukuran. Batas akhir segmen belum diperiksa.");
        } else {
            report.append("\nUkuran file  ").append(fileLength).append(" byte");
        }
        return report.toString();
    }

    private static long unsignedInt(ByteBuffer source, int offset) {
        return Integer.toUnsignedLong(source.getInt(offset));
    }

    private static boolean overlaps(long start, long size, long otherStart, long otherSize) {
        return size > 0 && otherSize > 0 && start < otherStart + otherSize && otherStart < start + size;
    }
}
