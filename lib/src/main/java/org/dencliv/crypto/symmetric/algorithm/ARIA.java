package org.dencliv.crypto.symmetric.algorithm;

import java.util.HexFormat;

public final class ARIA implements Algorithm {
    private static final int BLOCK_SIZE = 16;
    private static final byte[][] CONSTANTS = {
            hex("517cc1b727220a94fe13abe8fa9a6ee0"),
            hex("6db14acc9e21c820ff28b1d5ef5de2b0"),
            hex("db92371d2126e9700324977504e8c90e")
    };
    private static final byte[] S1 = new byte[256];
    private static final byte[] S2 = hex("""
            e2 4e 54 fc 94 c2 4a cc 62 0d 6a 46 3c 4d 8b d1
            5e fa 64 cb b4 97 be 2b bc 77 2e 03 d3 19 59 c1
            1d 06 41 6b 55 f0 99 69 ea 9c 18 ae 63 df e7 bb
            00 73 66 fb 96 4c 85 e4 3a 09 45 aa 0f ee 10 eb
            2d 7f f4 29 ac cf ad 91 8d 78 c8 95 f9 2f ce cd
            08 7a 88 38 5c 83 2a 28 47 db b8 c7 93 a4 12 53
            ff 87 0e 31 36 21 58 48 01 8e 37 74 32 ca e9 b1
            b7 ab 0c d7 c4 56 42 26 07 98 60 d9 b6 b9 11 40
            ec 20 8c bd a0 c9 84 04 49 23 f1 4f 50 1f 13 dc
            d8 c0 9e 57 e3 c3 7b 65 3b 02 8f 3e e8 25 92 e5
            15 dd fd 17 a9 bf d4 9a 7e c5 39 67 fe 76 9d 43
            a7 e1 d0 f5 68 f2 1b 34 70 05 a3 8a d5 79 86 a8
            30 c6 51 4b 1e a6 27 f6 35 d2 6e 24 16 82 5f da
            e6 75 a2 ef 2c b2 1c 9f 5d 6f 80 0a 72 44 9b 6c
            90 0b 5b 33 7d 5a 52 f3 61 a1 f7 b0 d6 3f 7c 6d
            ed 14 e0 a5 3d 22 b3 f8 89 de 71 1a af ba b5 81
            """);
    private static final byte[] S3 = new byte[256];
    private static final byte[] S4 = new byte[256];

    static {
        for (var value = 0; value < 256; value++) {
            var inverse = value == 0 ? 0 : power(value, 254);
            S1[value] = (byte) (inverse
                    ^ rotateByte(inverse, 1)
                    ^ rotateByte(inverse, 2)
                    ^ rotateByte(inverse, 3)
                    ^ rotateByte(inverse, 4)
                    ^ 0x63);
        }
        for (var value = 0; value < 256; value++) {
            S3[S1[value] & 0xff] = (byte) value;
            S4[S2[value] & 0xff] = (byte) value;
        }
    }

    private final int rounds;
    private final byte[][] encryptionKeys;
    private final byte[][] decryptionKeys;

    public ARIA(byte[] key) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("ARIA key must be 16, 24, or 32 bytes");
        }
        rounds = key.length / 4 + 8;
        encryptionKeys = expandKey(key);
        decryptionKeys = invertKeys(encryptionKeys);
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public void encryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset) {
        transform(input, inputOffset, output, outputOffset, encryptionKeys);
    }

    @Override
    public void decryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset) {
        transform(input, inputOffset, output, outputOffset, decryptionKeys);
    }

    private void transform(byte[] input, int inputOffset, byte[] output, int outputOffset, byte[][] roundKeys) {
        var state = new byte[BLOCK_SIZE];
        System.arraycopy(input, inputOffset, state, 0, BLOCK_SIZE);
        for (var round = 0; round < rounds - 1; round++) {
            applyRound(state, roundKeys[round], (round & 1) == 0);
        }
        xorInto(state, roundKeys[rounds - 1]);
        substitute(state, false);
        xorInto(state, roundKeys[rounds]);
        System.arraycopy(state, 0, output, outputOffset, BLOCK_SIZE);
    }

    private byte[][] expandKey(byte[] key) {
        var keySize = key.length / 8 - 2;
        var w0 = new byte[BLOCK_SIZE];
        var kr = new byte[BLOCK_SIZE];
        System.arraycopy(key, 0, w0, 0, BLOCK_SIZE);
        System.arraycopy(key, BLOCK_SIZE, kr, 0, key.length - BLOCK_SIZE);

        var w1 = xor(roundResult(w0, CONSTANTS[keySize], true), kr);
        var w2 = xor(roundResult(w1, CONSTANTS[(keySize + 1) % 3], false), w0);
        var w3 = xor(roundResult(w2, CONSTANTS[(keySize + 2) % 3], true), w1);
        var words = new byte[][]{w0, w1, w2, w3};
        var keys = new byte[rounds + 1][BLOCK_SIZE];
        var distances = new int[]{19, 31, 67, 97, 109};
        var keyIndex = 0;

        for (var distance : distances) {
            for (var word = 0; word < words.length && keyIndex < keys.length; word++) {
                keys[keyIndex++] = xor(words[word], rotateRight(words[(word + 1) % 4], distance));
            }
        }
        return keys;
    }

    private byte[][] invertKeys(byte[][] keys) {
        var inverted = new byte[keys.length][BLOCK_SIZE];
        inverted[0] = keys[rounds].clone();
        inverted[rounds] = keys[0].clone();
        for (var index = 1; index < rounds; index++) {
            inverted[index] = keys[rounds - index].clone();
            diffuse(inverted[index]);
        }
        return inverted;
    }

    private static byte[] roundResult(byte[] state, byte[] roundKey, boolean odd) {
        var result = state.clone();
        applyRound(result, roundKey, odd);
        return result;
    }

    private static void applyRound(byte[] state, byte[] roundKey, boolean odd) {
        xorInto(state, roundKey);
        substitute(state, odd);
        diffuse(state);
    }

    private static void substitute(byte[] state, boolean typeOne) {
        var boxes = typeOne
                ? new byte[][]{S1, S2, S3, S4}
                : new byte[][]{S3, S4, S1, S2};
        for (var index = 0; index < state.length; index++) {
            state[index] = boxes[index & 3][state[index] & 0xff];
        }
    }

    private static void diffuse(byte[] state) {
        var x = state.clone();
        state[0] = xor(x, 3, 4, 6, 8, 9, 13, 14);
        state[1] = xor(x, 2, 5, 7, 8, 9, 12, 15);
        state[2] = xor(x, 1, 4, 6, 10, 11, 12, 15);
        state[3] = xor(x, 0, 5, 7, 10, 11, 13, 14);
        state[4] = xor(x, 0, 2, 5, 8, 11, 14, 15);
        state[5] = xor(x, 1, 3, 4, 9, 10, 14, 15);
        state[6] = xor(x, 0, 2, 7, 9, 10, 12, 13);
        state[7] = xor(x, 1, 3, 6, 8, 11, 12, 13);
        state[8] = xor(x, 0, 1, 4, 7, 10, 13, 15);
        state[9] = xor(x, 0, 1, 5, 6, 11, 12, 14);
        state[10] = xor(x, 2, 3, 5, 6, 8, 13, 15);
        state[11] = xor(x, 2, 3, 4, 7, 9, 12, 14);
        state[12] = xor(x, 1, 2, 6, 7, 9, 11, 12);
        state[13] = xor(x, 0, 3, 6, 7, 8, 10, 13);
        state[14] = xor(x, 0, 3, 4, 5, 9, 11, 14);
        state[15] = xor(x, 1, 2, 4, 5, 8, 10, 15);
    }

    private static byte[] rotateRight(byte[] value, int distance) {
        var result = new byte[BLOCK_SIZE];
        var byteDistance = distance / 8;
        var bitDistance = distance % 8;
        for (var index = 0; index < BLOCK_SIZE; index++) {
            var high = value[(index - byteDistance + BLOCK_SIZE) % BLOCK_SIZE] & 0xff;
            var low = value[(index - byteDistance - 1 + BLOCK_SIZE) % BLOCK_SIZE] & 0xff;
            result[index] = (byte) (high >>> bitDistance | low << (8 - bitDistance));
        }
        return result;
    }

    private static byte[] xor(byte[] left, byte[] right) {
        var result = left.clone();
        xorInto(result, right);
        return result;
    }

    private static void xorInto(byte[] left, byte[] right) {
        for (var index = 0; index < BLOCK_SIZE; index++) {
            left[index] ^= right[index];
        }
    }

    private static byte xor(byte[] value, int... indices) {
        var result = 0;
        for (var index : indices) {
            result ^= value[index] & 0xff;
        }
        return (byte) result;
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
        return (value << distance | value >>> (8 - distance)) & 0xff;
    }

    private static byte[] hex(String value) {
        return HexFormat.of().parseHex(value.replaceAll("\\s", ""));
    }
}
