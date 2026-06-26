package org.dencliv.crypto.symmetric.operation;

import java.security.MessageDigest;
import java.util.Arrays;

import org.dencliv.crypto.symmetric.algorithm.Algorithm;

public final class GCM implements Operation {
    private static final int BLOCK_SIZE = 16;
    private static final int TAG_SIZE = 16;

    @Override
    public byte[] encrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        validate(algorithm, iv);
        var hashKey = encrypt(algorithm, new byte[BLOCK_SIZE]);
        var initialCounter = initialCounter(hashKey, iv);
        var ciphertext = crypt(algorithm, initialCounter, input);
        var tag = tag(algorithm, hashKey, initialCounter, ciphertext);
        var output = Arrays.copyOf(ciphertext, ciphertext.length + TAG_SIZE);
        System.arraycopy(tag, 0, output, ciphertext.length, TAG_SIZE);
        return output;
    }

    @Override
    public byte[] decrypt(Algorithm algorithm, byte[] iv, byte[] input) {
        validate(algorithm, iv);
        if (input.length < TAG_SIZE) {
            throw new IllegalArgumentException("Input must contain an authentication tag");
        }

        var ciphertext = Arrays.copyOf(input, input.length - TAG_SIZE);
        var receivedTag = Arrays.copyOfRange(input, ciphertext.length, input.length);
        var hashKey = encrypt(algorithm, new byte[BLOCK_SIZE]);
        var initialCounter = initialCounter(hashKey, iv);
        if (!MessageDigest.isEqual(receivedTag, tag(algorithm, hashKey, initialCounter, ciphertext))) {
            throw new IllegalArgumentException("Invalid authentication tag");
        }
        return crypt(algorithm, initialCounter, ciphertext);
    }

    private static void validate(Algorithm algorithm, byte[] iv) {
        if (algorithm.blockSize() != BLOCK_SIZE) {
            throw new IllegalArgumentException("GCM requires a 16-byte block cipher");
        }
        if (iv.length == 0) {
            throw new IllegalArgumentException("IV must not be empty");
        }
    }

    private static byte[] initialCounter(byte[] hashKey, byte[] iv) {
        if (iv.length == 12) {
            var counter = Arrays.copyOf(iv, BLOCK_SIZE);
            counter[BLOCK_SIZE - 1] = 1;
            return counter;
        }

        var length = ((iv.length + BLOCK_SIZE - 1) / BLOCK_SIZE + 1) * BLOCK_SIZE;
        var blocks = Arrays.copyOf(iv, length);
        putLong(blocks, length - 8, (long) iv.length * 8);
        return ghash(hashKey, blocks);
    }

    private static byte[] crypt(Algorithm algorithm, byte[] initialCounter, byte[] input) {
        var output = new byte[input.length];
        var counter = initialCounter.clone();
        var keyStream = new byte[BLOCK_SIZE];
        for (var offset = 0; offset < input.length; offset += BLOCK_SIZE) {
            increment(counter);
            algorithm.encryptBlock(counter, 0, keyStream, 0);
            var length = Math.min(BLOCK_SIZE, input.length - offset);
            for (var index = 0; index < length; index++) {
                output[offset + index] = (byte) (input[offset + index] ^ keyStream[index]);
            }
        }
        return output;
    }

    private static byte[] tag(
            Algorithm algorithm,
            byte[] hashKey,
            byte[] initialCounter,
            byte[] ciphertext) {
        var length = ((ciphertext.length + BLOCK_SIZE - 1) / BLOCK_SIZE + 1) * BLOCK_SIZE;
        var blocks = Arrays.copyOf(ciphertext, length);
        putLong(blocks, length - 8, (long) ciphertext.length * 8);
        var tag = ghash(hashKey, blocks);
        var encryptedCounter = encrypt(algorithm, initialCounter);
        xor(tag, encryptedCounter);
        return tag;
    }

    private static byte[] ghash(byte[] hashKey, byte[] blocks) {
        var hash = new byte[BLOCK_SIZE];
        for (var offset = 0; offset < blocks.length; offset += BLOCK_SIZE) {
            for (var index = 0; index < BLOCK_SIZE; index++) {
                hash[index] ^= blocks[offset + index];
            }
            hash = multiply(hash, hashKey);
        }
        return hash;
    }

    private static byte[] multiply(byte[] left, byte[] right) {
        var product = new byte[BLOCK_SIZE];
        var factor = right.clone();
        for (var bit = 0; bit < 128; bit++) {
            if ((left[bit / 8] & (1 << (7 - bit % 8))) != 0) {
                xor(product, factor);
            }
            var lowBit = (factor[BLOCK_SIZE - 1] & 1) != 0;
            shiftRight(factor);
            if (lowBit) {
                factor[0] ^= (byte) 0xe1;
            }
        }
        return product;
    }

    private static void increment(byte[] counter) {
        for (var index = BLOCK_SIZE - 1; index >= BLOCK_SIZE - 4; index--) {
            if (++counter[index] != 0) {
                return;
            }
        }
    }

    private static void shiftRight(byte[] value) {
        var carry = 0;
        for (var index = 0; index < value.length; index++) {
            var nextCarry = value[index] & 1;
            value[index] = (byte) ((value[index] & 0xff) >>> 1 | carry << 7);
            carry = nextCarry;
        }
    }

    private static byte[] encrypt(Algorithm algorithm, byte[] block) {
        var output = new byte[BLOCK_SIZE];
        algorithm.encryptBlock(block, 0, output, 0);
        return output;
    }

    private static void xor(byte[] target, byte[] other) {
        for (var index = 0; index < target.length; index++) {
            target[index] ^= other[index];
        }
    }

    private static void putLong(byte[] output, int offset, long value) {
        for (var index = 7; index >= 0; index--) {
            output[offset + index] = (byte) value;
            value >>>= 8;
        }
    }
}
