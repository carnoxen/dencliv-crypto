package org.dencliv.crypto.block.operation;

import org.dencliv.crypto.block.algorithm.Algorithm;

public final class CTR implements Operation {
    @Override
    public byte[] encrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        validateIv(iv, algorithm.blockSize());
        var output = new byte[input.length];
        var counter = iv.clone();
        var keyStream = new byte[algorithm.blockSize()];

        for (var offset = 0; offset < input.length; offset += algorithm.blockSize()) {
            algorithm.encryptBlock(counter, 0, keyStream, 0);
            var length = Math.min(algorithm.blockSize(), input.length - offset);
            for (var index = 0; index < length; index++) {
                output[offset + index] = (byte) (input[offset + index] ^ keyStream[index]);
            }
            increment(counter);
        }
        return output;
    }

    @Override
    public byte[] decrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        return encrypt(algorithm, iv, input);
    }

    private static void validateIv(byte[] iv, int blockSize) {
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV must match the block size");
        }
    }

    private static void increment(byte[] counter) {
        for (var index = counter.length - 1; index >= 0; index--) {
            if (++counter[index] != 0) {
                return;
            }
        }
    }
}
