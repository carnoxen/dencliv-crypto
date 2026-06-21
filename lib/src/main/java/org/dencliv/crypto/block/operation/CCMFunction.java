package org.dencliv.crypto.block.operation;

import java.security.MessageDigest;
import java.util.Arrays;

import org.dencliv.crypto.block.algorithm.AlgorithmFunction;

final class CCMFunction implements OperationFunction {
    private static final int BLOCK_SIZE = 16;
    private static final int TAG_SIZE = 16;

    @Override
    public byte[] encrypt(AlgorithmFunction algorithm, byte[] nonce, byte[] input) {
        var lengthSize = validate(algorithm, nonce, input.length);
        var tag = authenticationTag(algorithm, nonce, input, lengthSize);
        var ciphertext = crypt(algorithm, nonce, input, lengthSize);
        xor(tag, counterBlock(algorithm, nonce, lengthSize, 0));
        var output = Arrays.copyOf(ciphertext, ciphertext.length + TAG_SIZE);
        System.arraycopy(tag, 0, output, ciphertext.length, TAG_SIZE);
        return output;
    }

    @Override
    public byte[] decrypt(AlgorithmFunction algorithm, byte[] nonce, byte[] input) {
        if (input.length < TAG_SIZE) {
            throw new IllegalArgumentException("Input must contain an authentication tag");
        }

        var ciphertext = Arrays.copyOf(input, input.length - TAG_SIZE);
        var receivedTag = Arrays.copyOfRange(input, ciphertext.length, input.length);
        var lengthSize = validate(algorithm, nonce, ciphertext.length);
        var plaintext = crypt(algorithm, nonce, ciphertext, lengthSize);
        var expectedTag = authenticationTag(algorithm, nonce, plaintext, lengthSize);
        xor(expectedTag, counterBlock(algorithm, nonce, lengthSize, 0));
        if (!MessageDigest.isEqual(receivedTag, expectedTag)) {
            throw new IllegalArgumentException("Invalid authentication tag");
        }
        return plaintext;
    }

    private static int validate(AlgorithmFunction algorithm, byte[] nonce, int inputLength) {
        if (algorithm.blockSize() != BLOCK_SIZE) {
            throw new IllegalArgumentException("CCM requires a 16-byte block cipher");
        }
        if (nonce.length < 7 || nonce.length > 13) {
            throw new IllegalArgumentException("CCM nonce must be 7 to 13 bytes");
        }

        var lengthSize = 15 - nonce.length;
        if (lengthSize < 8 && inputLength >= 1L << lengthSize * 8) {
            throw new IllegalArgumentException("Input is too long for the CCM nonce");
        }
        return lengthSize;
    }

    private static byte[] authenticationTag(
            AlgorithmFunction algorithm,
            byte[] nonce,
            byte[] input,
            int lengthSize) {
        var state = new byte[BLOCK_SIZE];
        state[0] = (byte) (((TAG_SIZE - 2) / 2 << 3) | lengthSize - 1);
        System.arraycopy(nonce, 0, state, 1, nonce.length);
        putLength(state, BLOCK_SIZE - lengthSize, lengthSize, input.length);
        algorithm.encryptBlock(state, 0, state, 0);

        var block = new byte[BLOCK_SIZE];
        for (var offset = 0; offset < input.length; offset += BLOCK_SIZE) {
            var length = Math.min(BLOCK_SIZE, input.length - offset);
            System.arraycopy(input, offset, block, 0, length);
            for (var index = 0; index < BLOCK_SIZE; index++) {
                block[index] ^= state[index];
            }
            algorithm.encryptBlock(block, 0, state, 0);
            Arrays.fill(block, (byte) 0);
        }
        return state;
    }

    private static byte[] crypt(
            AlgorithmFunction algorithm,
            byte[] nonce,
            byte[] input,
            int lengthSize) {
        var output = new byte[input.length];
        for (var offset = 0; offset < input.length; offset += BLOCK_SIZE) {
            var counter = offset / BLOCK_SIZE + 1;
            var keyStream = counterBlock(algorithm, nonce, lengthSize, counter);
            var length = Math.min(BLOCK_SIZE, input.length - offset);
            for (var index = 0; index < length; index++) {
                output[offset + index] = (byte) (input[offset + index] ^ keyStream[index]);
            }
        }
        return output;
    }

    private static byte[] counterBlock(
            AlgorithmFunction algorithm,
            byte[] nonce,
            int lengthSize,
            int counter) {
        var block = new byte[BLOCK_SIZE];
        block[0] = (byte) (lengthSize - 1);
        System.arraycopy(nonce, 0, block, 1, nonce.length);
        putLength(block, BLOCK_SIZE - lengthSize, lengthSize, counter);
        algorithm.encryptBlock(block, 0, block, 0);
        return block;
    }

    private static void putLength(byte[] output, int offset, int size, long value) {
        for (var index = size - 1; index >= 0; index--) {
            output[offset + index] = (byte) value;
            value >>>= 8;
        }
    }

    private static void xor(byte[] target, byte[] other) {
        for (var index = 0; index < target.length; index++) {
            target[index] ^= other[index];
        }
    }
}
