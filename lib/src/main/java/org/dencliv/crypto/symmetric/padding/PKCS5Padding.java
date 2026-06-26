package org.dencliv.crypto.symmetric.padding;

import java.util.Arrays;

public final class PKCS5Padding implements Padding {
    @Override
    public byte[] add(byte[] input, int blockSize) {
        var count = blockSize - input.length % blockSize;
        var output = Arrays.copyOf(input, input.length + count);
        Arrays.fill(output, input.length, output.length, (byte) count);
        return output;
    }

    @Override
    public byte[] remove(byte[] input, int blockSize) {
        var count = input[input.length - 1] & 0xff;
        if (count < 1 || count > blockSize) {
            throw new IllegalArgumentException("Invalid padding");
        }
        for (var index = input.length - count; index < input.length; index++) {
            if ((input[index] & 0xff) != count) {
                throw new IllegalArgumentException("Invalid padding");
            }
        }
        return Arrays.copyOf(input, input.length - count);
    }
}
