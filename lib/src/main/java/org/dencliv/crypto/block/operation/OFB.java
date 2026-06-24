package org.dencliv.crypto.block.operation;

import org.dencliv.crypto.block.algorithm.Algorithm;

public final class OFB implements Operation {
    @Override
    public byte[] encrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        var blockSize = algorithm.blockSize();
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV must match the block size");
        }

        var output = new byte[input.length];
        var feedback = iv.clone();
        for (var offset = 0; offset < input.length; offset += blockSize) {
            algorithm.encryptBlock(feedback, 0, feedback, 0);
            var length = Math.min(blockSize, input.length - offset);
            for (var index = 0; index < length; index++) {
                output[offset + index] = (byte) (input[offset + index] ^ feedback[index]);
            }
        }
        return output;
    }

    @Override
    public byte[] decrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        return encrypt(algorithm, iv, input);
    }
}
