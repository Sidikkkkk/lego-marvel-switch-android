package org.sidikkkkk.switchport;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.MessageDigest;

final class Lz4Block {
    private static final int HISTORY_SIZE = 1 << 16;
    private static final int HISTORY_MASK = HISTORY_SIZE - 1;
    private static final int CHUNK_SIZE = 1 << 14;

    private final byte[] history = new byte[HISTORY_SIZE];
    private final DataInputStream input;
    private final long unpackedSize;
    private final MessageDigest digest;
    private long remaining;
    private long written;

    private Lz4Block(DataInputStream input, long storedSize, long unpackedSize, MessageDigest digest) {
        this.input = input;
        this.remaining = storedSize;
        this.unpackedSize = unpackedSize;
        this.digest = digest;
    }

    static void verify(DataInputStream input, long storedSize, long unpackedSize, MessageDigest digest)
            throws IOException {
        new Lz4Block(input, storedSize, unpackedSize, digest).verify();
    }

    private void verify() throws IOException {
        boolean matched = false;
        while (remaining > 0) {
            int token = readByte();
            long literalLength = readLength(token >>> 4, unpackedSize - written);
            if (literalLength > remaining) {
                throw new EOFException("Literal LZ4 melampaui ukuran blok.");
            }
            copyLiterals(literalLength);

            if (remaining == 0) {
                if (written != unpackedSize || (matched && literalLength < 5)) {
                    throw new IOException("Akhir atau ukuran hasil LZ4 tidak valid.");
                }
                return;
            }

            int offset = readByte() | (readByte() << 8);
            if (offset == 0 || offset > written) {
                throw new IOException("Offset salinan LZ4 tidak valid.");
            }
            if (unpackedSize - written < 12) {
                throw new IOException("Posisi salinan terakhir LZ4 tidak valid.");
            }
            long matchLength = readLength(token & 0x0f, unpackedSize - written - 4) + 4;
            copyMatch(matchLength, offset);
            matched = true;
        }
        throw new EOFException("Urutan literal terakhir LZ4 tidak ditemukan.");
    }

    private int readByte() throws IOException {
        if (remaining == 0) {
            throw new EOFException("Blok LZ4 terpotong.");
        }
        int value = input.readUnsignedByte();
        --remaining;
        return value;
    }

    private long readLength(int tokenLength, long outputRemaining) throws IOException {
        long length = tokenLength;
        int extension = tokenLength == 15 ? 255 : 0;
        while (extension == 255 && length <= outputRemaining) {
            extension = readByte();
            length += extension;
        }
        if (length > outputRemaining) {
            throw new IOException("Panjang LZ4 melampaui ukuran hasil yang tercantum di header.");
        }
        return length;
    }

    private void copyLiterals(long length) throws IOException {
        while (length > 0) {
            int start = (int) written & HISTORY_MASK;
            int count = chunkLength(start, length);
            input.readFully(history, start, count);
            remaining -= count;
            length -= count;
            commitChunk(start, count);
        }
    }

    private void copyMatch(long length, int offset) throws IOException {
        while (length > 0) {
            int start = (int) written & HISTORY_MASK;
            int count = chunkLength(start, length);
            // Byte order matters when the match is longer than its offset.
            for (int position = start; position < start + count; ++position) {
                history[position] = history[(position - offset) & HISTORY_MASK];
            }
            length -= count;
            commitChunk(start, count);
        }
    }

    private static int chunkLength(int start, long remaining) throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("Pemeriksaan NSO0 dibatalkan.");
        }
        return (int) Math.min(remaining, Math.min(CHUNK_SIZE, HISTORY_SIZE - start));
    }

    private void commitChunk(int start, int count) {
        if (digest != null) {
            digest.update(history, start, count);
        }
        written += count;
    }
}
