package org.dencliv.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.dencliv.crypto.symmetric.algorithm.AES;
import org.dencliv.crypto.symmetric.algorithm.ARIA;
import org.dencliv.crypto.symmetric.algorithm.Blowfish;
import org.dencliv.crypto.symmetric.algorithm.SEED;
import org.dencliv.crypto.symmetric.operation.CBC;
import org.dencliv.crypto.symmetric.operation.CCM;
import org.dencliv.crypto.symmetric.operation.CTR;
import org.dencliv.crypto.symmetric.operation.GCM;
import org.dencliv.crypto.symmetric.operation.OFB;
import org.dencliv.crypto.symmetric.padding.NoPadding;
import org.dencliv.crypto.symmetric.padding.PKCS5Padding;

class OperationTest {
    @Test
    void encryptsAndDecryptsBlowfishBlock() {
        var algorithm = new Blowfish(new byte[8]);
        var plaintext = new byte[8];
        var ciphertext = new byte[8];
        var decrypted = new byte[8];

        algorithm.encryptBlock(plaintext, 0, ciphertext, 0);
        algorithm.decryptBlock(ciphertext, 0, decrypted, 0);

        assertArrayEquals(hex("4ef997456198dd78"), ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void rejectsInvalidBlowfishKeySize() {
        var shortKey = assertThrows(IllegalArgumentException.class, () -> new Blowfish(new byte[3]));
        var longKey = assertThrows(IllegalArgumentException.class, () -> new Blowfish(new byte[57]));

        assertEquals("Blowfish key must be 4 to 56 bytes", shortKey.getMessage());
        assertEquals("Blowfish key must be 4 to 56 bytes", longKey.getMessage());
    }

    @Test
    void rejectsBlowfishForAuthenticatedModes() {
        var algorithm = new Blowfish(new byte[8]);

        assertEquals(
                "CCM requires a 16-byte block cipher",
                assertThrows(IllegalArgumentException.class, () -> new CCM().encrypt(algorithm, new byte[7], new byte[0]))
                        .getMessage());
        assertEquals(
                "GCM requires a 16-byte block cipher",
                assertThrows(IllegalArgumentException.class, () -> new GCM().encrypt(algorithm, new byte[12], new byte[0]))
                        .getMessage());
    }

    @Test
    void encryptsAndDecryptsAriaBlocks() {
        var plaintext = hex("00112233445566778899aabbccddeeff");
        var keys = new String[]{
                "000102030405060708090a0b0c0d0e0f",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        var ciphertexts = new String[]{
                "d718fbd6ab644c739da95f3be6451778",
                "26449c1805dbe7aa25a468ce263a9e79",
                "f92bd7c79fb72e2f2b8f80c1972d24fc"
        };

        for (var index = 0; index < keys.length; index++) {
            var algorithm = new ARIA(hex(keys[index]));
            var ciphertext = new byte[16];
            var decrypted = new byte[16];

            algorithm.encryptBlock(plaintext, 0, ciphertext, 0);
            algorithm.decryptBlock(ciphertext, 0, decrypted, 0);

            assertArrayEquals(hex(ciphertexts[index]), ciphertext);
            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Test
    void rejectsInvalidAriaKeySize() {
        var exception = assertThrows(IllegalArgumentException.class, () -> new ARIA(new byte[20]));

        assertEquals("ARIA key must be 16, 24, or 32 bytes", exception.getMessage());
    }

    @Test
    void encryptsAndDecryptsSeedBlock() {
        var algorithm = new SEED(hex("00000000000000000000000000000000"));
        var plaintext = hex("000102030405060708090a0b0c0d0e0f");
        var ciphertext = new byte[16];
        var decrypted = new byte[16];

        algorithm.encryptBlock(plaintext, 0, ciphertext, 0);
        algorithm.decryptBlock(ciphertext, 0, decrypted, 0);

        assertArrayEquals(hex("5ebac6e0054e166819aff1cc6d346cdb"), ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void encryptsAndDecryptsSeedCbc() {
        var cipher = Crypto.getBlockCipher(SEED.class, CBC.class, PKCS5Padding.class);
        var key = hex("000102030405060708090a0b0c0d0e0f");
        var iv = hex("101112131415161718191a1b1c1d1e1f");
        var plaintext = hex("00112233445566778899aabbccddeeff");

        var ciphertext = cipher.encrypt(key, iv, plaintext);

        assertArrayEquals(plaintext, cipher.decrypt(key, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesCbc() {
        var cipher = Crypto.getBlockCipher(AES.class, CBC.class, PKCS5Padding.class);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172a");

        var ciphertext = cipher.encrypt(key, iv, plaintext);

        assertArrayEquals(hex("7649abac8119b246cee98e9b12e9197d"),
                java.util.Arrays.copyOf(ciphertext, 16));
        assertArrayEquals(plaintext, cipher.decrypt(key, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesCtr() {
        var cipher = Crypto.getBlockCipher(AES.class, CTR.class, NoPadding.class);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a57");

        var ciphertext = cipher.encrypt(key, counter, plaintext);

        assertArrayEquals(hex("874d6191b620e3261bef6864990db6ce9806f66b"), ciphertext);
        assertArrayEquals(plaintext, cipher.decrypt(key, counter, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesOfb() {
        var algorithm = new AES(hex("2b7e151628aed2a6abf7158809cf4f3c"));
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172a");

        var operation = new OFB();
        var ciphertext = operation.encrypt(algorithm, iv, plaintext);

        assertArrayEquals(hex("3b3fd92eb72dad20333449f8e83cfb4a"), ciphertext);
        assertArrayEquals(plaintext, operation.decrypt(algorithm, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesGcm() {
        var algorithm = new AES(new byte[16]);
        var iv = new byte[12];
        var plaintext = new byte[16];

        var ciphertext = new GCM().encrypt(algorithm, iv, plaintext);

        assertArrayEquals(hex(
                "0388dace60b6a392f328c2b971b2fe78"
                        + "ab6e47d42cec13bdf53a67b21257bddf"), ciphertext);
        assertArrayEquals(plaintext, new GCM().decrypt(algorithm, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesCcm() {
        var algorithm = new AES(hex("404142434445464748494a4b4c4d4e4f"));
        var nonce = hex("10111213141516");
        var plaintext = hex("20212223");

        var operation = new CCM();
        var ciphertext = operation.encrypt(algorithm, nonce, plaintext);

        assertArrayEquals(hex("7162015b"), java.util.Arrays.copyOf(ciphertext, 4));
        assertArrayEquals(plaintext, operation.decrypt(algorithm, nonce, ciphertext));
    }

    @Test
    void rejectsModifiedAuthenticationTags() {
        var algorithm = new AES(new byte[16]);
        var operation = new GCM();
        var ciphertext = operation.encrypt(algorithm, new byte[12], new byte[16]);
        ciphertext[ciphertext.length - 1] ^= 1;

        var exception = assertThrows(
                IllegalArgumentException.class,
                () -> operation.decrypt(algorithm, new byte[12], ciphertext));

        assertEquals("Invalid authentication tag", exception.getMessage());
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}
