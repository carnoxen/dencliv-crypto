package org.dencliv.crypto.block.algorithm;

final class AESFunction implements AlgorithmFunction {
    private static final int BLOCK_SIZE = 16;
    private static final int[] SBOX = new int[256];
    private static final int[] INVERSE_SBOX = new int[256];

    static {
        for (var value = 0; value < 256; value++) {
            var inverse = value == 0 ? 0 : power(value, 254);
            var substituted = inverse
                    ^ rotateByte(inverse, 1)
                    ^ rotateByte(inverse, 2)
                    ^ rotateByte(inverse, 3)
                    ^ rotateByte(inverse, 4)
                    ^ 0x63;
            SBOX[value] = substituted;
            INVERSE_SBOX[substituted] = value;
        }
    }

    private final byte[] roundKeys;
    private final int rounds;

    AESFunction(byte[] key) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24, or 32 bytes");
        }
        rounds = key.length / 4 + 6;
        roundKeys = expandKey(key);
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public void encryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset) {
        var state = new byte[BLOCK_SIZE];
        System.arraycopy(input, inputOffset, state, 0, BLOCK_SIZE);
        addRoundKey(state, 0);
        for (var round = 1; round < rounds; round++) {
            substitute(state, SBOX);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }
        substitute(state, SBOX);
        shiftRows(state);
        addRoundKey(state, rounds);
        System.arraycopy(state, 0, output, outputOffset, BLOCK_SIZE);
    }

    @Override
    public void decryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset) {
        var state = new byte[BLOCK_SIZE];
        System.arraycopy(input, inputOffset, state, 0, BLOCK_SIZE);
        addRoundKey(state, rounds);
        for (var round = rounds - 1; round > 0; round--) {
            inverseShiftRows(state);
            substitute(state, INVERSE_SBOX);
            addRoundKey(state, round);
            inverseMixColumns(state);
        }
        inverseShiftRows(state);
        substitute(state, INVERSE_SBOX);
        addRoundKey(state, 0);
        System.arraycopy(state, 0, output, outputOffset, BLOCK_SIZE);
    }

    private byte[] expandKey(byte[] key) {
        var expanded = new byte[BLOCK_SIZE * (rounds + 1)];
        System.arraycopy(key, 0, expanded, 0, key.length);
        var generated = key.length;
        var rcon = 1;
        var temporary = new byte[4];

        while (generated < expanded.length) {
            System.arraycopy(expanded, generated - 4, temporary, 0, 4);
            if (generated % key.length == 0) {
                rotateWord(temporary);
                substitute(temporary, SBOX);
                temporary[0] ^= (byte) rcon;
                rcon = multiply(rcon, 2);
            } else if (key.length == 32 && generated % key.length == 16) {
                substitute(temporary, SBOX);
            }
            for (var index = 0; index < 4; index++) {
                expanded[generated] = (byte) (expanded[generated - key.length] ^ temporary[index]);
                generated++;
            }
        }
        return expanded;
    }

    private void addRoundKey(byte[] state, int round) {
        var offset = round * BLOCK_SIZE;
        for (var index = 0; index < BLOCK_SIZE; index++) {
            state[index] ^= roundKeys[offset + index];
        }
    }

    private static void substitute(byte[] state, int[] box) {
        for (var index = 0; index < state.length; index++) {
            state[index] = (byte) box[state[index] & 0xff];
        }
    }

    private static void shiftRows(byte[] state) {
        var copy = state.clone();
        for (var row = 0; row < 4; row++) {
            for (var column = 0; column < 4; column++) {
                state[row + 4 * column] = copy[row + 4 * ((column + row) % 4)];
            }
        }
    }

    private static void inverseShiftRows(byte[] state) {
        var copy = state.clone();
        for (var row = 0; row < 4; row++) {
            for (var column = 0; column < 4; column++) {
                state[row + 4 * column] = copy[row + 4 * ((column - row + 4) % 4)];
            }
        }
    }

    private static void mixColumns(byte[] state) {
        transformColumns(state, new int[]{2, 3, 1, 1});
    }

    private static void inverseMixColumns(byte[] state) {
        transformColumns(state, new int[]{14, 11, 13, 9});
    }

    private static void transformColumns(byte[] state, int[] factors) {
        var copy = state.clone();
        for (var column = 0; column < 4; column++) {
            var offset = column * 4;
            for (var row = 0; row < 4; row++) {
                var value = 0;
                for (var index = 0; index < 4; index++) {
                    value ^= multiply(copy[offset + index] & 0xff, factors[(index - row + 4) % 4]);
                }
                state[offset + row] = (byte) value;
            }
        }
    }

    private static void rotateWord(byte[] word) {
        var first = word[0];
        System.arraycopy(word, 1, word, 0, 3);
        word[3] = first;
    }

    private static int multiply(int left, int right) {
        var result = 0;
        while (right != 0) {
            if ((right & 1) != 0) {
                result ^= left;
            }
            left = (left << 1) ^ ((left & 0x80) == 0 ? 0 : 0x11b);
            right >>>= 1;
        }
        return result & 0xff;
    }

    private static int power(int value, int exponent) {
        var result = 1;
        while (exponent != 0) {
            if ((exponent & 1) != 0) {
                result = multiply(result, value);
            }
            value = multiply(value, value);
            exponent >>>= 1;
        }
        return result;
    }

    private static int rotateByte(int value, int distance) {
        return ((value << distance) | (value >>> (8 - distance))) & 0xff;
    }
}
