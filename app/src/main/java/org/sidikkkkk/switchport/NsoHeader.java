package org.sidikkkkk.switchport;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Comparator;

final class NsoHeader {
    private static final int HEADER_SIZE = 0x100;
    private static final int MAGIC = 0x304f534e;
    private static final long ADDRESS_LIMIT = 1L << 32;
    private static final int DATA_SEGMENT = 2;
    private static final int BSS_SIZE_OFFSET = 0x3c;
    private static final long REPORT_ONLY = -1;
    private static final String[] SEGMENT_NAMES = {".text", ".rodata", ".data"};
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private record Segment(String name, long fileOffset, long storedSize, long memoryOffset,
                           long unpackedSize, boolean compressed, byte[] expectedHash) {
        long memoryEnd() {
            return memoryOffset + unpackedSize;
        }
    }

    private record MemoryLayout(long bssStart, long bssSize, long rangeEnd, long usedSize) {}

    record Inspection(String report, ByteBuffer memoryImage) {}

    private NsoHeader() {}

    static String inspect(InputStream input, long fileLength) throws IOException {
        return inspect(input, fileLength, REPORT_ONLY).report();
    }

    static Inspection inspect(InputStream input, long fileLength, long memoryBudget) throws IOException {
        byte[] bytes = new byte[HEADER_SIZE];
        DataInputStream data = new DataInputStream(new BufferedInputStream(input));
        try {
            data.readFully(bytes);
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
                    || (compressed && storedSize == 0 && unpackedSize > 0)
                    || (storedSize > 0 && fileOffset < HEADER_SIZE)) {
                throw new IOException("Rentang atau ukuran segmen " + SEGMENT_NAMES[index] + " tidak valid.");
            }

            int hashOffset = 0xa0 + index * 0x20;
            byte[] expectedHash = (flags & (1 << (index + 3))) != 0
                    ? Arrays.copyOfRange(bytes, hashOffset, hashOffset + 0x20) : null;
            Segment segment = new Segment(SEGMENT_NAMES[index], fileOffset, storedSize,
                    memoryOffset, unpackedSize, compressed, expectedHash);
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
        MemoryLayout memory = memoryLayout(segments, unsignedInt(header, BSS_SIZE_OFFSET));
        byte[] image = allocateImage(memory.rangeEnd, memoryBudget);
        verifySegments(data, segments, image);

        StringBuilder report = new StringBuilder("Segmen NSO0 berhasil diperiksa\nBuild ID  ");
        for (int index = 0x40; index < 0x60; ++index) {
            int value = Byte.toUnsignedInt(bytes[index]);
            report.append(HEX[value >>> 4]).append(HEX[value & 0x0f]);
        }
        report.append("\n\n");
        for (Segment segment : segments) {
            report.append(segment.name)
                    .append("  file 0x").append(Long.toHexString(segment.fileOffset))
                    .append("  memori [0x").append(Long.toHexString(segment.memoryOffset))
                    .append(", 0x").append(Long.toHexString(segment.memoryEnd())).append(")")
                    .append("\n").append(segment.storedSize).append(" byte tersimpan, ")
                    .append(segment.unpackedSize).append(" byte di memori")
                    .append(segment.compressed ? " (terkompresi)\n" : "\n")
                    .append(segment.expectedHash != null
                            ? "SHA-256 sesuai header\n" : "SHA-256 tidak tersedia di header\n");
        }
        report.append("\nTata letak memori (offset relatif)\n")
                .append(".bss [0x").append(Long.toHexString(memory.bssStart))
                .append(", 0x").append(Long.toHexString(memory.bssStart + memory.bssSize))
                .append(")  ").append(memory.bssSize).append(" byte\n")
                .append("Rentang dari base [0x0, 0x").append(Long.toHexString(memory.rangeEnd))
                .append(")  ").append(memory.rangeEnd).append(" byte\n")
                .append("Segmen dan .bss  ").append(memory.usedSize).append(" byte\n")
                .append("Celah dalam rentang  ").append(memory.rangeEnd - memory.usedSize).append(" byte\n");
        if (image != null) {
            report.append("\nMuat segmen ke buffer RAM berhasil (").append(image.length).append(" byte).\n");
        } else if (memoryBudget >= 0) {
            report.append("\nMuat ke RAM dilewati. Buffer tidak tersedia dalam batas heap untuk uji ini.\n");
        }
        if (fileLength < 0) {
            report.append("\nUkuran file tidak tersedia. Semua segmen berhasil dibaca.");
        } else {
            report.append("\nUkuran file  ").append(fileLength).append(" byte");
        }
        ByteBuffer memoryImage = image == null ? null : ByteBuffer.wrap(image).asReadOnlyBuffer();
        return new Inspection(report.toString(), memoryImage);
    }

    private static byte[] allocateImage(long size, long memoryBudget) {
        if (size > memoryBudget || size > Integer.MAX_VALUE) {
            return null;
        }
        try {
            return new byte[(int) size];
        } catch (OutOfMemoryError error) {
            return null;
        }
    }

    private static MemoryLayout memoryLayout(Segment[] segments, long bssSize) throws IOException {
        long bssStart = segments[DATA_SEGMENT].memoryEnd();
        long bssEnd = bssStart + bssSize;
        if (bssEnd > ADDRESS_LIMIT) {
            throw new IOException("Rentang memori .bss melampaui batas offset NSO0.");
        }

        long rangeEnd = bssSize > 0 ? bssEnd : 0;
        long usedSize = bssSize;
        for (Segment segment : segments) {
            if (overlaps(bssStart, bssSize, segment.memoryOffset, segment.unpackedSize)) {
                throw new IOException("Rentang memori .bss bertumpang tindih dengan " + segment.name + ".");
            }
            if (segment.unpackedSize > 0) {
                rangeEnd = Math.max(rangeEnd, segment.memoryEnd());
                usedSize += segment.unpackedSize;
            }
        }
        return new MemoryLayout(bssStart, bssSize, rangeEnd, usedSize);
    }

    private static void verifySegments(DataInputStream input, Segment[] segments, byte[] image) throws IOException {
        Segment[] fileOrder = segments.clone();
        Arrays.sort(fileOrder, Comparator.comparingLong(Segment::fileOffset));
        byte[] buffer = new byte[16 * 1024];
        long position = HEADER_SIZE;
        for (Segment segment : fileOrder) {
            MessageDigest digest = segment.expectedHash != null ? newSha256() : null;
            try {
                if (segment.storedSize > 0) {
                    skipFully(input, segment.fileOffset - position);
                    ByteBuffer destination = image == null || segment.unpackedSize == 0 ? null
                            : ByteBuffer.wrap(image, (int) segment.memoryOffset, (int) segment.unpackedSize);
                    if (segment.compressed) {
                        Lz4Block.verify(input, segment.storedSize, segment.unpackedSize, digest, destination);
                    } else {
                        readRaw(input, segment.storedSize, buffer, digest, destination);
                    }
                    position = segment.fileOffset + segment.storedSize;
                }
                if (digest != null && !MessageDigest.isEqual(digest.digest(), segment.expectedHash)) {
                    throw new IOException("SHA-256 berbeda dari header.");
                }
            } catch (EOFException error) {
                String detail = error.getMessage();
                throw new IOException("Segmen " + segment.name + " terpotong."
                        + (detail == null ? "" : " " + detail), error);
            } catch (IOException error) {
                throw new IOException("Segmen " + segment.name + ": " + error.getMessage(), error);
            }
        }
    }

    private static void skipFully(DataInputStream input, long length) throws IOException {
        while (length > 0) {
            checkInterrupted();
            long skipped = input.skip(length);
            if (skipped == 0) {
                input.readUnsignedByte();
                skipped = 1;
            }
            length -= skipped;
        }
    }

    private static void readRaw(DataInputStream input, long length, byte[] buffer,
                                MessageDigest digest, ByteBuffer destination) throws IOException {
        while (length > 0) {
            checkInterrupted();
            int count = (int) Math.min(length, buffer.length);
            input.readFully(buffer, 0, count);
            if (digest != null) {
                digest.update(buffer, 0, count);
            }
            if (destination != null) {
                destination.put(buffer, 0, count);
            }
            length -= count;
        }
    }

    private static void checkInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("Pemeriksaan NSO0 dibatalkan.");
        }
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 tidak tersedia.", error);
        }
    }

    private static long unsignedInt(ByteBuffer source, int offset) {
        return Integer.toUnsignedLong(source.getInt(offset));
    }

    private static boolean overlaps(long start, long size, long otherStart, long otherSize) {
        return size > 0 && otherSize > 0 && start < otherStart + otherSize && otherStart < start + size;
    }
}
