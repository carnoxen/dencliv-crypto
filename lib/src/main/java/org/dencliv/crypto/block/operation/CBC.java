package org.dencliv.crypto.block.operation;

import java.util.Arrays;

import org.dencliv.crypto.block.algorithm.Algorithm;

public final class CBC implements Operation {
    @Override
    public byte[] encrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        var blockSize = algorithm.blockSize();
        validate(iv, input, blockSize);
        var output = new byte[input.length];
        var previous = iv.clone();

        for (var offset = 0; offset < input.length; offset += blockSize) {
            var block = Arrays.copyOfRange(input, offset, offset + blockSize);
            xor(block, 0, previous);
            algorithm.encryptBlock(block, 0, output, offset);
            previous = Arrays.copyOfRange(output, offset, offset + blockSize);
        }
        return output;
    }

    @Override
    public byte[] decrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        var blockSize = algorithm.blockSize();
        validate(iv, input, blockSize);
        var output = new byte[input.length];
        var previous = iv.clone();
        for (var offset = 0; offset < input.length; offset += blockSize) {
            algorithm.decryptBlock(input, offset, output, offset);
            xor(output, offset, previous);
            previous = Arrays.copyOfRange(input, offset, offset + blockSize);
        }
        return output;
    }

    private static void validate(byte[] iv, byte[] input, int blockSize) {
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV must match the block size");
        }
        if (input.length == 0 || input.length % blockSize != 0) {
            throw new IllegalArgumentException("Input must contain complete blocks");
        }
    }

    private static void xor(byte[] block, int offset, byte[] other) {
        for (var index = 0; index < other.length; index++) {
            block[offset + index] ^= other[index];
        }
    }
}
