package org.dencliv.crypto.block.algorithm;

import java.util.HexFormat;

public final class SEED implements Algorithm {
    private static final int BLOCK_SIZE = 16;
    private static final int[] KC = {
            0x9e3779b9, 0x3c6ef373, 0x78dde6e6, 0xf1bbcdcc,
            0xe3779b99, 0xc6ef3733, 0x8dde6e67, 0x1bbcdccf,
            0x3779b99e, 0x6ef3733c, 0xdde6e678, 0xbbcdccf1,
            0x779b99e3, 0xef3733c6, 0xde6e678d, 0xbcdccf1b
    };
    private static final byte[] S0 = sBox("""
            A9 85 D6 D3 54 1D AC 25 5D 43 18 1E 51 FC CA 63
            28 44 20 9D E0 E2 C8 17 A5 8F 03 7B BB 13 D2 EE
            70 8C 3F A8 32 DD F6 74 EC 95 0B 57 5C 5B BD 01
            24 1C 73 98 10 CC F2 D9 2C E7 72 83 9B D1 86 C9
            60 50 A3 EB 0D B6 9E 4F B7 5A C6 78 A6 12 AF D5
            61 C3 B4 41 52 7D 8D 08 1F 99 00 19 04 53 F7 E1
            FD 76 2F 27 B0 8B 0E AB A2 6E 93 4D 69 7C 09 0A
            BF EF F3 C5 87 14 FE 64 DE 2E 4B 1A 06 21 6B 66
            02 F5 92 8A 0C B3 7E D0 7A 47 96 E5 26 80 AD DF
            A1 30 37 AE 36 15 22 38 F4 A7 45 4C 81 E9 84 97
            35 CB CE 3C 71 11 C7 89 75 FB DA F8 94 59 82 C4
            FF 49 39 67 C0 CF D7 B8 0F 8E 42 23 91 6C DB A4
            34 F1 48 C2 6F 3D 2D 40 BE 3E BC C1 AA BA 4E 55
            3B DC 68 7F 9C D8 4A 56 77 A0 ED 46 B5 2B 65 FA
            E3 B9 B1 9F 5E F9 E6 B2 31 EA 6D 5F E4 F0 CD 88
            16 3A 58 D4 62 29 07 33 E8 1B 05 79 90 6A 2A 9A
            """);
    private static final byte[] S1 = sBox("""
            38 E8 2D A6 CF DE B3 B8 AF 60 55 C7 44 6F 6B 5B
            C3 62 33 B5 29 A0 E2 A7 D3 91 11 06 1C BC 36 4B
            EF 88 6C A8 17 C4 16 F4 C2 45 E1 D6 3F 3D 8E 98
            28 4E F6 3E A5 F9 0D DF D8 2B 66 7A 27 2F F1 72
            42 D4 41 C0 73 67 AC 8B F7 AD 80 1F CA 2C AA 34
            D2 0B EE E9 5D 94 18 F8 57 AE 08 C5 13 CD 86 B9
            FF 7D C1 31 F5 8A 6A B1 D1 20 D7 02 22 04 68 71
            07 DB 9D 99 61 BE E6 59 DD 51 90 DC 9A A3 AB D0
            81 0F 47 1A E3 EC 8D BF 96 7B 5C A2 A1 63 23 4D
            C8 9E 9C 3A 0C 2E BA 6E 9F 5A F2 92 F3 49 78 CC
            15 FB 70 75 7F 35 10 03 64 6D C6 74 D5 B4 EA 09
            76 19 FE 40 12 E0 BD 05 FA 01 F0 2A 5E A9 56 43
            85 14 89 9B B0 E5 48 79 97 FC 1E 82 21 8C 1B 5F
            77 54 B2 1D 25 4F 00 46 ED 58 52 EB 7E DA C9 FD
            30 95 65 3C B6 E4 BB 7C 0E 50 39 26 32 84 69 93
            37 E7 24 A4 CB 53 0A 87 D9 4C 83 8F CE 3B 4A B7
            """);

    private final int[] roundKeys = new int[32];

    public SEED(byte[] key) {
        if (key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("SEED key must be 16 bytes");
        }
        expandKey(key);
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public void encryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset) {
        transform(input, inputOffset, output, outputOffset, false);
    }

    @Override
    public void decryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset) {
        transform(input, inputOffset, output, outputOffset, true);
    }

    private void transform(byte[] input, int inputOffset, byte[] output, int outputOffset, boolean decrypt) {
        var left0 = readInt(input, inputOffset);
        var left1 = readInt(input, inputOffset + 4);
        var right0 = readInt(input, inputOffset + 8);
        var right1 = readInt(input, inputOffset + 12);

        for (var round = 0; round < 16; round++) {
            var keyIndex = decrypt ? 30 - round * 2 : round * 2;
            if ((round & 1) == 0) {
                var result = round(right0, right1, keyIndex);
                left0 ^= result[0];
                left1 ^= result[1];
            } else {
                var result = round(left0, left1, keyIndex);
                right0 ^= result[0];
                right1 ^= result[1];
            }
        }

        writeInt(right0, output, outputOffset);
        writeInt(right1, output, outputOffset + 4);
        writeInt(left0, output, outputOffset + 8);
        writeInt(left1, output, outputOffset + 12);
    }

    private int[] round(int right0, int right1, int keyIndex) {
        var value0 = right0 ^ roundKeys[keyIndex];
        var value1 = right1 ^ roundKeys[keyIndex + 1] ^ value0;
        value1 = g(value1);
        value0 = g(value0 + value1);
        value1 = g(value1 + value0);
        return new int[]{value0 + value1, value1};
    }

    private void expandKey(byte[] key) {
        var key0 = readInt(key, 0);
        var key1 = readInt(key, 4);
        var key2 = readInt(key, 8);
        var key3 = readInt(key, 12);

        for (var round = 0; round < 16; round++) {
            roundKeys[round * 2] = g(key0 + key2 - KC[round]);
            roundKeys[round * 2 + 1] = g(key1 - key3 + KC[round]);
            if ((round & 1) == 0) {
                var previous = key0;
                key0 = (key0 >>> 8) | (key1 << 24);
                key1 = (key1 >>> 8) | (previous << 24);
            } else {
                var previous = key2;
                key2 = (key2 << 8) | (key3 >>> 24);
                key3 = (key3 << 8) | (previous >>> 24);
            }
        }
    }

    private static int g(int value) {
        var x0 = S0[value & 0xff] & 0xff;
        var x1 = S1[value >>> 8 & 0xff] & 0xff;
        var x2 = S0[value >>> 16 & 0xff] & 0xff;
        var x3 = S1[value >>> 24] & 0xff;
        var z0 = x0 & 0xfc ^ x1 & 0xf3 ^ x2 & 0xcf ^ x3 & 0x3f;
        var z1 = x0 & 0xf3 ^ x1 & 0xcf ^ x2 & 0x3f ^ x3 & 0xfc;
        var z2 = x0 & 0xcf ^ x1 & 0x3f ^ x2 & 0xfc ^ x3 & 0xf3;
        var z3 = x0 & 0x3f ^ x1 & 0xfc ^ x2 & 0xf3 ^ x3 & 0xcf;
        return z3 << 24 | z2 << 16 | z1 << 8 | z0;
    }

    private static int readInt(byte[] input, int offset) {
        return (input[offset] & 0xff) << 24
                | (input[offset + 1] & 0xff) << 16
                | (input[offset + 2] & 0xff) << 8
                | input[offset + 3] & 0xff;
    }

    private static void writeInt(int value, byte[] output, int offset) {
        output[offset] = (byte) (value >>> 24);
        output[offset + 1] = (byte) (value >>> 16);
        output[offset + 2] = (byte) (value >>> 8);
        output[offset + 3] = (byte) value;
    }

    private static byte[] sBox(String values) {
        return HexFormat.of().parseHex(values.replaceAll("\\s", ""));
    }
}
