package org.dencliv.crypto.symmetric.padding;

import java.security.SecureRandom;
import java.util.Arrays;

public final class ISO10126Padding implements Padding {
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public byte[] add(byte[] input, int blockSize) {
        var count = blockSize - input.length % blockSize;
        var padding = new byte[count];
        RANDOM.nextBytes(padding);
        padding[count - 1] = (byte) count;

        var output = Arrays.copyOf(input, input.length + count);
        System.arraycopy(padding, 0, output, input.length, count);
        return output;
    }

    @Override
    public byte[] remove(byte[] input, int blockSize) {
        var count = input[input.length - 1] & 0xff;
        if (count < 1 || count > blockSize) {
            throw new IllegalArgumentException("Invalid padding");
        }
        return Arrays.copyOf(input, input.length - count);
    }
}
